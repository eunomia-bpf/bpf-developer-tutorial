# eBPF Tutorial by Example: Tracing Intel NPU Kernel Driver Operations

Neural Processing Units (NPUs) are the next frontier in AI acceleration - built directly into modern CPUs to handle machine learning workloads without burning through GPU power budgets. Intel's Lunar Lake and Meteor Lake processors pack dedicated NPU hardware, but when your AI model runs slow, inference fails, or memory allocation crashes, debugging feels impossible. The NPU driver is a black box, firmware communication is opaque, and userspace APIs hide what's really happening in the kernel.

This tutorial shows you how to trace Intel NPU kernel driver operations using eBPF and bpftrace. We'll monitor the complete workflow from Level Zero API calls down to kernel functions, track IPC communication with NPU firmware, measure memory allocation patterns, and diagnose performance bottlenecks. By the end, you'll understand how NPU drivers work internally and have practical tools for debugging AI workload issues.

## Intel NPU Driver Architecture

Intel's NPU driver follows a two-layer architecture similar to GPU drivers. The kernel module (`intel_vpu`) lives in mainline Linux at `drivers/accel/ivpu/` and exposes `/dev/accel/accel0` as the device interface. This handles hardware communication, memory management through an MMU, and IPC (Inter-Processor Communication) with NPU firmware running on the accelerator itself.

The userspace driver (`libze_intel_vpu.so`) implements the Level Zero API - Intel's unified programming interface for accelerators. When you call Level Zero functions like `zeMemAllocHost()` or `zeCommandQueueExecuteCommandLists()`, the library translates these into DRM ioctls that hit the kernel module. The kernel validates requests, sets up memory mappings, submits work to the NPU firmware, and polls for completion.

The NPU firmware itself runs autonomously on the accelerator hardware. It receives command buffers from the kernel, schedules compute kernels, manages on-chip memory, and signals completion through interrupts. All communication happens via IPC channels - shared memory regions where kernel and firmware exchange messages. This architecture means three layers must coordinate correctly: your application, the kernel driver, and NPU firmware.

Understanding this flow is critical for debugging. When an AI inference stalls, is it the kernel waiting for firmware? Is memory allocation thrashing? Are IPC messages backing up? eBPF tracing reveals the kernel side of this story - every ioctl, every memory mapping, every IPC interrupt.

## Level Zero API to Kernel Driver Mapping

Let's trace a simple NPU workload - matrix multiplication running through Level Zero - and see exactly how API calls map to kernel operations. We'll use a test program that allocates host memory for input/output matrices, submits the computation, and waits for results.

The Level Zero workflow breaks down into five phases. Initialization opens the NPU device and queries capabilities. Memory allocation creates buffers for compute data. Command setup builds work queues and command lists. Execution submits the workload to NPU firmware. Synchronization polls for completion and retrieves results.

Here's how each API call translates to kernel operations:

**zeMemAllocHost** allocates host-visible memory accessible by both CPU and NPU. This triggers `DRM_IOCTL_IVPU_BO_CREATE` ioctl, hitting `ivpu_bo_create_ioctl()` in the kernel. The driver calls `ivpu_gem_create_object()` to allocate a GEM (Graphics Execution Manager) buffer object, then `ivpu_mmu_context_map_page()` maps pages into NPU's address space via the MMU. Finally `ivpu_bo_pin()` pins the buffer in memory so it can't be swapped out during compute.

For our matrix multiplication example with three buffers (input matrix A, input matrix B, output matrix C), we see three `zeMemAllocHost()` calls. Each triggers approximately 1,377 `ivpu_mmu_context_map_page()` calls - that's 4,131 total page mappings for setting up compute memory.

**zeCommandQueueCreate** establishes a queue for submitting work. This maps to `DRM_IOCTL_IVPU_GET_PARAM` ioctl calling `ivpu_get_param_ioctl()` to query queue capabilities. The actual queue object lives in userspace - the kernel just provides device parameters.

**zeCommandListCreate** builds a command list in userspace. No kernel call happens here - the library constructs command buffers in memory that will later be submitted to the NPU.

**zeCommandQueueExecuteCommandLists** is where work actually reaches the NPU. This triggers `DRM_IOCTL_IVPU_SUBMIT` ioctl, calling `ivpu_submit_ioctl()` in the kernel. The driver validates the command buffer, sets up DMA transfers, and sends an IPC message to NPU firmware requesting execution. The firmware wakes up, processes the request, schedules compute kernels on NPU hardware, and starts sending IPC interrupts back to signal progress.

During execution, we observe massive IPC traffic: 946 `ivpu_ipc_irq_handler()` calls (interrupt handler for IPC messages from firmware), 945 `ivpu_ipc_receive()` calls (reading messages from shared memory), and 951 `ivpu_hw_ip_ipc_rx_count_get()` calls (polling IPC queue depth). This intense communication is normal - the firmware sends status updates, memory fence signals, and completion notifications throughout the compute operation.

**zeFenceHostSynchronize** blocks until the NPU completes work. This doesn't trigger a dedicated ioctl - instead the library continuously calls `ivpu_get_param_ioctl()` to poll fence status. The kernel checks if the firmware signaled completion via IPC. More `ivpu_ipc_irq_handler()` calls fire as the firmware sends the final completion message.

## Tracing NPU Operations with Bpftrace

Now let's build a practical tracing tool. We'll use bpftrace to attach kprobes to all intel_vpu kernel functions and watch the complete execution flow.

### Complete Bpftrace Tracing Script

```bash
#!/usr/bin/env bpftrace

BEGIN
{
    printf("Tracing Intel NPU kernel driver... Hit Ctrl-C to end.\n");
    printf("%-10s %-40s\n", "TIME(ms)", "FUNCTION");
}

/* Attach to all intel_vpu kernel functions */
kprobe:intel_vpu:ivpu_*
{
    printf("%-10llu %-40s\n",
           nsecs / 1000000,
           probe);

    /* Count function calls */
    @calls[probe] = count();
}

END
{
    printf("\n=== Intel NPU Function Call Statistics ===\n");
    printf("\nTop functions by call count:\n");
    print(@calls, 20);
}
```

This script attaches kprobes to every function in the intel_vpu kernel module (all functions starting with `ivpu_`). When any function executes, we print a timestamp and function name. The `@calls` map tracks how many times each function was called - perfect for identifying hot paths in the driver.

### Understanding the Tracing Output

When you run this while executing an NPU workload, you'll see a sequential trace of kernel operations. Let's walk through a typical execution captured from our matrix multiplication test.

The trace starts with device initialization: `ivpu_open()` opens the `/dev/accel/accel0` device file. Then `ivpu_mmu_context_init()` sets up the MMU context for this process. A burst of `ivpu_get_param_ioctl()` calls queries device capabilities - firmware version, compute engine count, memory size, supported operations.

Memory allocation dominates the middle section. For each `zeMemAllocHost()` call, we see the pattern: `ivpu_bo_create_ioctl()` creates the buffer object, `ivpu_gem_create_object()` allocates backing memory, then hundreds of `ivpu_mmu_context_map_page()` calls map pages into NPU address space. With three buffers for matrix multiplication, this repeats three times - 4,131 page mappings total.

Command submission triggers `ivpu_submit_ioctl()`, which kicks off firmware communication. The `ivpu_boot()` and `ivpu_fw_boot_params_setup()` functions prepare the firmware if it wasn't already running. Then `ivpu_hw_boot_fw()` starts NPU execution, and IPC traffic explodes.

The IPC communication section shows the NPU firmware actively processing work. Every `ivpu_ipc_irq_handler()` indicates a hardware interrupt from the NPU. The pattern `ivpu_hw_ip_ipc_rx_count_get()` → `ivpu_ipc_receive()` reads an IPC message from shared memory. With 945 message receives, we know the firmware sent nearly a thousand status updates during our compute operation - that's how actively it communicates with the kernel.

Finally, cleanup appears: `ivpu_postclose()` closes the device, `ivpu_ms_cleanup()` releases resources, `ivpu_file_priv_put()` drops file handle references, and `ivpu_pgtable_free_page()` unmaps memory pages (517 calls to release our 4,131 mapped pages).

## Analyzing NPU Performance Bottlenecks

The function call statistics reveal where the driver spends time. From our test run of 8,198 total function calls, three categories dominate:

**Memory Management (4,648 calls, 57% of total)**: `ivpu_mmu_context_map_page()` accounts for 4,131 calls, nearly half of all driver activity. This makes sense - mapping memory into NPU address space is page-by-page work. On cleanup, `ivpu_pgtable_free_page()` gets called 517 times to unmap. If memory allocation is slow in your NPU application, this is why - thousands of MMU operations for large buffers.

**IPC Communication (2,842 calls, 35% of total)**: The firmware communication triad of `ivpu_ipc_irq_handler()` (946 calls), `ivpu_hw_ip_ipc_rx_count_get()` (951 calls), and `ivpu_ipc_receive()` (945 calls) shows intense messaging. Nearly 1,000 interrupts and message receives means the firmware actively reports progress. If your NPU workload shows higher IPC counts than expected, the firmware might be thrashing or hitting memory contention.

**Buffer Management (74 calls, <1% of total)**: GEM object operations like `ivpu_bo_create_ioctl()` (24), `ivpu_gem_create_object()` (25), and `ivpu_bo_pin()` (25) are relatively rare. This matches expectations - you create buffers once, then reuse them across many compute operations.

By comparing these ratios against normal workloads, you spot anomalies. If IPC calls explode to 10,000+ on a simple inference, something's wrong - maybe firmware is stuck in a retry loop. If memory mapping calls exceed your buffer count × page count, you're allocating and freeing inefficiently. The trace gives you hard numbers to diagnose these issues.

## Running the Tracing Tools

The bpftrace script works on any Linux system with Intel NPU hardware and the intel_vpu kernel module loaded. Here's how to use it.

First, verify the NPU driver is active:

```bash
# Check if intel_vpu module is loaded
lsmod | grep intel_vpu

# Verify NPU device exists
ls -l /dev/accel/accel0

# Check driver version and supported devices
modinfo intel_vpu
```

You should see the intel_vpu module loaded and `/dev/accel/accel0` device present. The modinfo output shows supported PCI device IDs (0x643E, 0x7D1D, 0xAD1D, 0xB03E) - these correspond to Meteor Lake and Lunar Lake NPU hardware.

Now run the tracing script. Save the bpftrace code above as `trace_npu.bt` and execute:

```bash
# Simple function call tracing
sudo bpftrace -e 'kprobe:intel_vpu:ivpu_* { printf("%s\n", probe); }'

# Or run the full script with statistics
sudo bpftrace trace_npu.bt
```

In another terminal, run your NPU workload - Level Zero applications, OpenVINO inference, or any program using `/dev/accel/accel0`. The trace output streams in real-time. When done, hit Ctrl-C to see the function call statistics sorted by frequency.

For more detailed analysis, redirect output to a file:

```bash
sudo bpftrace trace_npu.bt > npu_trace_$(date +%Y%m%d_%H%M%S).txt
```

This captures the complete execution trace for offline analysis. You can grep for specific patterns, count function call sequences, or correlate timestamps with application-level events.

## Advanced Analysis Techniques

Beyond basic tracing, you can extract deeper insights by filtering specific operations or measuring latencies.

**Track memory allocation patterns** by filtering for buffer object functions:

```bash
sudo bpftrace -e '
kprobe:intel_vpu:ivpu_bo_create_ioctl {
    @alloc_time[tid] = nsecs;
}
kretprobe:intel_vpu:ivpu_bo_create_ioctl /@alloc_time[tid]/ {
    $latency_us = (nsecs - @alloc_time[tid]) / 1000;
    printf("Buffer allocation took %llu us\n", $latency_us);
    delete(@alloc_time[tid]);
    @alloc_latency = hist($latency_us);
}
END {
    printf("\nBuffer Allocation Latency (microseconds):\n");
    print(@alloc_latency);
}'
```

This measures time from `ivpu_bo_create_ioctl()` entry to return, showing allocation latency distribution. High latencies indicate memory pressure or MMU contention.

**Monitor IPC message rates** to detect firmware communication issues:

```bash
sudo bpftrace -e '
kprobe:intel_vpu:ivpu_ipc_receive {
    @last_time = nsecs;
    @ipc_count++;
}
interval:s:1 {
    printf("IPC messages/sec: %llu\n", @ipc_count);
    @ipc_count = 0;
}
END {
    clear(@ipc_count);
}'
```

This counts IPC messages per second. Normal workloads show steady rates (50-200 msg/sec). Spikes indicate firmware distress - retries, errors, or stuck operations.

**Correlate with userspace API calls** using uprobes on libze_intel_vpu.so:

```bash
sudo bpftrace -e '
uprobe:/usr/lib/x86_64-linux-gnu/libze_intel_vpu.so:zeCommandQueueExecuteCommandLists {
    printf("[API] Submit command queue\n");
    @submit_time = nsecs;
}
kprobe:intel_vpu:ivpu_submit_ioctl {
    printf("[KERNEL] Submit ioctl\n");
}
kprobe:intel_vpu:ivpu_ipc_irq_handler {
    printf("[FIRMWARE] IPC interrupt\n");
}
'
```

This correlates userspace API calls with kernel ioctls and firmware IPC, revealing the complete control flow across all three layers.

## Compilation and Execution

The bpftrace scripts in this tutorial require no compilation - they run directly. Ensure you have:

- Linux kernel with intel_vpu driver (mainline kernel 6.2+ includes it)
- Intel NPU hardware (Meteor Lake or Lunar Lake processor)
- bpftrace installed (`apt install bpftrace` on Ubuntu/Debian)
- Root access for running bpftrace

Navigate to the tutorial directory:

```bash
cd /home/yunwei37/workspace/bpf-developer-tutorial/src/xpu/npu-kernel-driver
```

The directory contains:

- **README.md** - This tutorial
- **intel_npu_driver_analysis.md** - Detailed driver architecture analysis
- **intel_vpu_symbols.txt** - Complete list of 1,312 kernel module symbols
- **trace_res.txt** - Example trace output from matrix multiplication workload

To reproduce the trace results:

```bash
# Start tracing
sudo bpftrace -e 'kprobe:intel_vpu:ivpu_* { printf("%s\n", probe); }' > my_trace.txt

# In another terminal, run your NPU workload
# For example, using OpenVINO:
# benchmark_app -m model.xml -d NPU

# Stop tracing with Ctrl-C
# Analyze the output
wc -l my_trace.txt  # Count function calls
sort my_trace.txt | uniq -c | sort -rn | head -20  # Top functions
```

For Level Zero applications, ensure the runtime is installed (`apt install level-zero-loader`). The library will automatically discover the NPU device through `/dev/accel/accel0`.

## Understanding Intel VPU Kernel Module Symbols

The intel_vpu kernel module exports 1,312 symbols visible in `/proc/kallsyms`. These fall into categories based on symbol type:

- **t (text)**: Function symbols like `ivpu_submit_ioctl`, `ivpu_mmu_context_map_page`
- **d (data)**: Global variables and data structures
- **r (read-only data)**: Constant data, string literals, device ID tables
- **b (BSS)**: Uninitialized data allocated at module load

The module doesn't export symbols for external linking (no EXPORT_SYMBOL macros). Instead, it provides functionality through:
1. DRM device file interface (`/dev/accel/accel0`)
2. Standard DRM ioctls for buffer management
3. Custom ioctls for NPU-specific operations
4. IPC protocol with firmware

Key function families to understand:

- `ivpu_bo_*`: Buffer object management (allocation, pinning, mapping)
- `ivpu_mmu_*`: Memory management unit operations (page tables, address translation)
- `ivpu_ipc_*`: Inter-processor communication with firmware
- `ivpu_hw_*`: Hardware-specific operations (power management, register access)
- `ivpu_fw_*`: Firmware loading and boot coordination
- `ivpu_pm_*`: Power management (runtime suspend/resume)

The complete symbol list is available in `intel_vpu_symbols.txt` for reference when tracing specific operations.

> If you'd like to dive deeper into eBPF and accelerator tracing, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- **Intel NPU Driver Source**: <https://github.com/intel/linux-npu-driver>
- **Linux Kernel Accelerator Subsystem**: `drivers/accel/` in kernel tree
- **Intel VPU Kernel Module**: `drivers/accel/ivpu/` in mainline kernel
- **DRM Subsystem Documentation**: `Documentation/gpu/drm-uapi.rst`
- **Bpftrace Reference**: <https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md>
- **Tutorial Repository**: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/xpu/npu-kernel-driver>

Complete source code with trace examples and analysis tools is available in the tutorial repository.
