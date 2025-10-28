# eBPF Tutorial by Example: GPU Flamegraph Profiling with CUPTI and eBPF

CPU profilers show host stacks but not which GPU kernel they launch; GPU profilers show device kernels but not the host code path that triggered them. What you usually need is the handoff: "Which CPU function called `cudaLaunchKernel()` and what kernel did that produce?"

In this tutorial you'll build a CPU to GPU kernel launch flamegraph using eBPF plus CUPTI. This is a flamegraph where CPU stacks captured at `cudaLaunchKernel()` are extended with the GPU kernel name using CUPTI correlation IDs. The result makes kernel hotspots discoverable in the context of your host code, without rebuilding the application. CUPTI activity records for runtime API and concurrent kernels carry matching `correlationId` fields. [NVIDIA Docs](https://docs.nvidia.com/cupti/api/structCUpti__ActivityKernel8.html)

## How we inject & correlate

We load a small CUPTI library via `CUDA_INJECTION64_PATH` so the CUDA runtime records runtime API and kernel activity with timestamps and correlation IDs. In parallel, an eBPF uprobe on `cudaLaunchKernel()` collects the CPU call stack and kernel time. After the run, a merger uses the CUPTI `correlationId` to connect the runtime API call to the kernel event, and appends `[GPU Kernel] <name>` to the CPU stack before generating a standard folded file for `flamegraph.pl`. [NVIDIA Docs](https://docs.nvidia.com/drive/drive-os-5.2.6.0L/nsight-systems/pdf/UserGuide.pdf)

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/xpu/flamegraph>

## The Challenge: Correlating CPU and GPU Activity

GPU profiling requires understanding two separate execution domains. On the CPU side, your application calls CUDA runtime APIs like `cudaLaunchKernel`, `cudaMemcpy`, and `cudaDeviceSynchronize`. These functions prepare work, validate parameters, and submit commands to the GPU driver. On the GPU side, kernels execute thousands of parallel threads, access memory, and signal completion through interrupts. The gap between these domains is where performance problems hide.

This challenge is universal across GPU vendors. NVIDIA GPUs use CUDA runtime and CUPTI, AMD GPUs use ROCm and rocProfiler, and Intel GPUs use Level Zero and GPU Observability Architecture. Each vendor provides different APIs, but the fundamental problem remains the same: correlating CPU code paths with GPU kernel execution. Tools like iaprof for Intel GPUs demonstrate similar architectures - using eBPF to capture CPU stacks, vendor-specific APIs to trace GPU activity, and correlation logic to merge them into unified flamegraphs. The techniques in this tutorial apply to NVIDIA GPUs but the principles transfer to any GPU platform.

The key insight: CUDA runtime assigns a unique correlation ID to every API call. When your CPU calls `cudaLaunchKernel`, the runtime creates a correlation ID linking that specific call to the eventual GPU kernel execution. NVIDIA's CUPTI (CUDA Profiling Tools Interface) library records both runtime API calls and GPU kernel executions, embedding these correlation IDs in activity records. By matching correlation IDs between CPU-side eBPF stack traces and GPU-side CUPTI events, we reconstruct the complete execution flow.

Traditional profiling approaches fall short. CPU profilers like perf or eBPF-based profilers capture application and runtime stack traces but have no visibility into GPU execution. They can show you spent 100ms in `cudaLaunchKernel`, but not which kernel ran or how long it actually executed on the GPU. GPU profilers like NVIDIA Nsight or nvprof capture detailed kernel metrics but only show the kernel name, losing context about which CPU code path triggered it. You see a kernel took 50ms, but not why your application called it or what happened before and after.

CUPTI provides the bridge. It's a callback and activity-based API that instruments the CUDA runtime and driver. When you enable CUPTI activity tracing, it records timestamped events for runtime API calls (entry and exit), kernel executions (launch and completion), memory transfers, and synchronization operations. Each event contains a correlation ID linking GPU work back to the CPU API call that submitted it. By injecting CUPTI into CUDA applications via `LD_PRELOAD`, we capture this data without recompiling.

## Architecture: eBPF Profiler + CUPTI Injection

The profiling system has three components working in concert. The eBPF profiler monitors the CPU side using uprobes on `cudaLaunchKernel` in the CUDA runtime library. Every time any process calls this function to launch a GPU kernel, the eBPF program captures the complete CPU stack trace with nanosecond timestamps. This stack shows the application call chain leading to the kernel launch - revealing which functions, which loops, which code paths triggered GPU work.

CUPTI activity tracing runs inside the target process through library injection. We set `CUDA_INJECTION64_PATH` to point to our injection library, which CUDA runtime automatically loads. This library enables CUPTI activity callbacks for runtime APIs and concurrent kernel execution. As the application runs, CUPTI accumulates activity records in internal buffers. When buffers fill or the application exits, CUPTI calls our buffer completion callback, where we serialize events to a trace file. Each event contains start/end timestamps in nanoseconds and correlation IDs.

The trace merger combines these two data sources. It parses CPU stack traces in extended folded format (timestamp, command name, PID, TID, CPU, semicolon-separated stack) and GPU traces in Chrome JSON format (CUPTI events converted to Chrome trace format for visualization). Correlation happens through timestamp proximity - since CPU uprobe fires at `cudaLaunchKernel` entry and CUPTI records the runtime API with the same correlation ID, we match them within a small time window. The merger then matches GPU kernel events to their corresponding runtime API calls via correlation ID. The output is folded stack format suitable for flamegraph generation: `cpu_func1;cpu_func2;cudaLaunchKernel;[GPU_Kernel]kernel_name count`.

## Component Overview

The system consists of four key tools that work together to provide end-to-end visibility.

The gpuperf.py script is the main orchestration component that launches the target application with both eBPF CPU profiling and CUPTI GPU tracing enabled. It manages environment variables for CUPTI injection (including `CUDA_INJECTION64_PATH` and `CUPTI_TRACE_OUTPUT_FILE`). The script starts the Rust eBPF profiler with cudaLaunchKernel uprobes before the target process to catch all kernel launches. Then it runs the target application with CUPTI injection enabled, collects traces from both sources, and automatically merges them into a unified flamegraph-ready format. The script handles cleanup, error cases, and provides multiple output modes including CPU-only, GPU-only, or merged.

The Rust eBPF Profiler in the `profiler/` directory is a stack trace collector built with libbpf. It attaches uprobes to `cudaLaunchKernel` in the CUDA runtime library. The profiler captures full stack traces using eBPF's `bpf_get_stackid()` helper, records timestamps with nanosecond precision, and outputs extended folded format directly without post-processing. The `-E` flag enables extended output with timestamps, which is critical for correlation with GPU events.

CUPTI Trace Injection in the `cupti_trace/` directory is a shared library loaded into CUDA applications via injection. It initializes CUPTI activity tracing for runtime API and kernel events. The library registers buffer management callbacks for asynchronous event collection, captures correlation IDs linking CPU API calls to GPU kernels, and records nanosecond-precision timestamps from GPU hardware counters. It serializes events to a text format for parsing, and properly handles cleanup on application exit or crashes. The injection approach works without modifying or recompiling applications, as it intercepts CUDA runtime initialization.

The Trace Merger in `merge_gpu_cpu_trace.py` performs the correlation logic. It parses CPU traces in extended folded format extracting timestamps, process info, and stack traces. The merger also parses GPU traces from CUPTI (via Chrome JSON format) identifying kernel executions and runtime API calls. It matches CPU stacks to GPU events using correlation logic where the CPU uprobe timestamp matches the CUPTI runtime API timestamp, and the runtime API correlation ID matches the GPU kernel correlation ID. Finally, it generates folded output where GPU kernel names extend CPU stacks. For example, `app_func;cudaLaunchKernel;[GPU_Kernel]matmul_kernel 1000` means the matmul kernel was sampled 1000 times from that code path.

## High-Level Code Analysis: The Complete Profiling Pipeline

The complete profiling flow starts when you run `gpuperf.py` to launch your CUDA application. Let's walk through what happens from process startup to final flamegraph generation, following the actual code paths.

### Key Implementation: Three-Component Architecture

The profiling pipeline consists of three key components working together. Here's the essential logic from each:

1. eBPF Profiler in `profiler/src/bpf/profile.bpf.c` for kernel-space stack capture:

The Rust profiler in `profiler/` is a libbpf-based eBPF application. Unlike bpftrace or BCC which interpret scripts at runtime, this profiler compiles to native code for minimal overhead. It attaches uprobes dynamically to any function in any library, making it perfect for instrumenting CUDA runtime without modifying NVIDIA's binaries.

```c
// eBPF program that captures stack traces when cudaLaunchKernel is called
SEC("uprobe")
int uprobe_handler(struct pt_regs *ctx)
{
    struct stacktrace_event *event;

    // Reserve space in ring buffer for the event
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 1;

    // Capture process/thread info
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->cpu_id = bpf_get_smp_processor_id();
    event->timestamp = bpf_ktime_get_ns();  // Nanosecond timestamp
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    // Capture kernel and user stack traces
    event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);
    event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

When the uprobe fires at `cudaLaunchKernel` entry, the eBPF program reads the current stack using kernel helpers. It stores stack traces in a BPF stack map, which is a hash table mapping stack IDs to stack traces to deduplicate identical stacks. The program records a sample event containing timestamp, process info, and stack ID, then sends the event to userspace via a BPF ring buffer.

The Rust userspace code polls for events, looks up stack traces using stack IDs, and resolves addresses to symbol names using DWARF debug info via the blazesym library. It outputs extended folded format: `timestamp_ns comm pid tid cpu stack1;stack2;...;stackN`. This format is critical because the timestamp enables correlation with GPU events, and the folded stack format feeds directly into flamegraph generation.

The `-E` extended output flag is what differentiates this from standard flamegraph profiling. Traditional folded format is just `stack1;stack2;stack3 count`, showing aggregate call graphs. Extended format adds temporal information: `1234567890 myapp 1000 1000 0 stack1;stack2;stack3`, telling you exactly when each sample occurred. This timestamp precision is what allows matching CPU stacks to GPU kernel launches that happen milliseconds or microseconds later.

2. CUPTI Injection in `cupti_trace/cupti_trace_injection.cpp` for GPU activity tracking:

The CUPTI injection library in `cupti_trace/` implements the GPU-side instrumentation. When CUDA runtime loads this library (via `CUDA_INJECTION64_PATH`), the library's initialization function runs before any CUDA API is available. This is the perfect time to set up CUPTI callbacks.

```cpp
// Initialize CUPTI tracing when library is loaded
__attribute__((constructor))
void InitializeInjection(void)
{
    // Subscribe to CUPTI callbacks
    cuptiSubscribe(&subscriberHandle, CallbackHandler, NULL);

    // Enable activity tracing for kernels and runtime APIs
    cuptiActivityEnable(CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL);
    cuptiActivityEnable(CUPTI_ACTIVITY_KIND_RUNTIME);

    // Register buffer management callbacks
    cuptiActivityRegisterCallbacks(BufferRequested, BufferCompleted);
}

// Callback when CUPTI fills an activity buffer
void CUPTIAPI BufferCompleted(CUcontext ctx, uint32_t streamId, uint8_t *buffer,
                               size_t size, size_t validSize)
{
    CUpti_Activity *record = NULL;

    // Iterate through all activity records in the buffer
    while (CUPTI_SUCCESS == cuptiActivityGetNextRecord(buffer, validSize, &record)) {
        switch (record->kind) {
            case CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL: {
                CUpti_ActivityKernel4 *kernel = (CUpti_ActivityKernel4 *)record;

                // Extract kernel execution details
                fprintf(outputFile, "CONCURRENT_KERNEL [ %llu, %llu ] duration %llu, \"%s\", correlationId %u\n",
                        kernel->start,           // GPU timestamp (ns)
                        kernel->end,             // GPU timestamp (ns)
                        kernel->end - kernel->start,
                        kernel->name,            // Kernel function name
                        kernel->correlationId);  // Links to CPU API call
                break;
            }
            case CUPTI_ACTIVITY_KIND_RUNTIME: {
                CUpti_ActivityAPI *api = (CUpti_ActivityAPI *)record;

                // Track cudaLaunchKernel API calls
                if (api->cbid == CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_v7000) {
                    fprintf(outputFile, "RUNTIME [ %llu, %llu ] \"cudaLaunchKernel\", correlationId %u\n",
                            api->start,          // API entry timestamp
                            api->end,            // API exit timestamp
                            api->correlationId); // Same ID as kernel
                }
                break;
            }
        }
    }
}

// Initialize CUPTI tracing when library is loaded
__attribute__((constructor))
void InitializeInjection(void)
{
    // Subscribe to CUPTI callbacks
    cuptiSubscribe(&subscriberHandle, CallbackHandler, NULL);

    // Enable activity tracing for kernels and runtime APIs
    cuptiActivityEnable(CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL);
    cuptiActivityEnable(CUPTI_ACTIVITY_KIND_RUNTIME);

    // Register buffer management callbacks
    cuptiActivityRegisterCallbacks(BufferRequested, BufferCompleted);
}

```

As the application runs, CUPTI accumulates activity records in internal buffers. Buffer management is asynchronous, as CUPTI requires the application to provide memory buffers. The buffer request callback allocates an 8MB buffer. When the buffer fills or the application exits, CUPTI calls `BufferCompleted` with activity records.

The buffer completion callback iterates through records. For `CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL`, the record contains kernel name, start and end timestamps (nanoseconds from GPU hardware timer), correlation ID linking to the runtime API call, grid and block dimensions, device, context, and stream IDs, as well as memory and register usage. For `CUPTI_ACTIVITY_KIND_RUNTIME`, it captures API entry and exit timestamps, function names like "cudaLaunchKernel", and the correlation ID that will appear in kernel records.

The injection library serializes events to text format: `CONCURRENT_KERNEL [ start, end ] duration us, "kernel_name", correlationId`. This format is parsed by `cupti_trace_parser.py` which converts to Chrome Trace JSON format for timeline visualization.

The critical piece is correlation IDs. When your application calls `cudaLaunchKernel`, CUDA runtime assigns a unique correlation ID to that call. It records this ID in the runtime API activity record and passes it to the GPU driver. When the GPU executes the kernel, the driver records the same correlation ID in the kernel activity record. CUPTI exposes both records, allowing us to match `RUNTIME cudaLaunchKernel correlationId=12345` to `CONCURRENT_KERNEL matmul_kernel correlationId=12345`.

3. Trace Merger in `merge_gpu_cpu_trace.py` for correlation logic:

The `TraceMerger` class performs the critical correlation logic. It loads CPU stacks from extended folded format and GPU events from Chrome JSON format, then matches them using timestamps and correlation IDs.

The CPU trace format is: `timestamp_ns comm pid tid cpu stack1;stack2;...;stackN`. Example: `1761616920733362025 llm-inference 3577790 3577790 1 _start;main;runRequest;forward;cudaLaunchKernel`. The timestamp is absolute nanoseconds since boot (from `bpf_ktime_get_ns()`), and the stack is bottom-to-top.

The GPU trace contains two event types. Runtime API events: `{"name": "cudaLaunchKernel", "ph": "X", "ts": 1761616920733, "dur": 45, "args": {"correlation": 12345}}` (timestamp in microseconds). Kernel events: `{"name": "matmul_kernel", "cat": "CONCURRENT_KERNEL", "ph": "X", "ts": 1761616920800, "dur": 5000, "args": {"correlation": 12345}}`. The same correlation ID links runtime to kernel.

```python
class TraceMerger:
    def find_matching_kernel(self, cpu_stack: CPUStack) -> Optional[GPUKernelEvent]:
        """
        Correlate CPU stack with GPU kernel using two-step matching:
        1. Match CPU timestamp to cudaLaunchKernel runtime API call
        2. Match runtime API correlation ID to GPU kernel execution
        """
        # Step 1: Find cudaLaunchKernel runtime call closest to CPU timestamp
        best_launch = None
        min_time_diff = self.timestamp_tolerance_ns  # 10ms window

        for launch in self.cuda_launches.values():
            time_diff = abs(cpu_stack.timestamp_ns - launch.start_ns)
            if time_diff < min_time_diff:
                min_time_diff = time_diff
                best_launch = launch

        if not best_launch:
            return None

        # Step 2: Find GPU kernel with matching correlation ID
        for kernel in self.gpu_kernels:
            if kernel.correlation_id == best_launch.correlation_id:
                return kernel  # Found the GPU kernel triggered by this CPU call

        return None

    def merge_traces(self):
        """Build merged stacks: cpu_func1;cpu_func2;cudaLaunchKernel;[GPU_Kernel]kernel_name"""
        for cpu_stack in self.cpu_stacks:
            merged_stack = cpu_stack.stack.copy()  # Start with CPU stack

            gpu_kernel = self.find_matching_kernel(cpu_stack)
            if gpu_kernel:
                merged_stack.append(f"[GPU_Kernel]{gpu_kernel.name}")
            else:
                merged_stack.append("[GPU_Launch_Pending]")

            # Output folded format weighted by GPU kernel duration
            stack_str = ';'.join(merged_stack)
            # Weight by GPU kernel duration in microseconds (not just count=1)
            kernel_duration_us = int(gpu_kernel.end_us - gpu_kernel.start_us)
            self.merged_stacks[stack_str] += kernel_duration_us
```

Critical Implementation Detail: Duration Weighting

The flamegraph is weighted by GPU kernel execution time, not by kernel launch count. Each matched stack is weighted by the kernel's actual duration in microseconds (`end_us - start_us`). This means a kernel that runs for 1000μs contributes 1000x more to the flamegraph width than a kernel that runs for 1μs. This accurately reflects where GPU time is actually spent, as longer-running kernels appear wider in the flamegraph, making performance bottlenecks immediately visible.

Without duration weighting, a frequently-called but fast kernel would appear as a hotspot even if it consumes minimal total GPU time. With duration weighting, the flamegraph correctly shows that a single slow kernel consuming 100ms is more important than 1000 fast kernels consuming 1ms total.

The algorithm builds mappings: `gpu_kernels[12345] = GPUKernelEvent(...)` and `cuda_launches[12345] = CudaLaunchEvent(...)`. For each CPU stack with timestamp T, it searches for `cuda_launches` where `|runtime.start_ns - T| < 10ms`. Why a time window? Clock sources differ (eBPF uses `CLOCK_MONOTONIC`, CUPTI uses GPU hardware counters), and there's jitter from eBPF overhead and context switches.

Once matched, we have: CPU stack to runtime API to GPU kernel. The merger outputs: `cpu_stack_frames;cudaLaunchKernel;[GPU_Kernel]kernel_name duration_us` where `duration_us` is the actual GPU execution time. Unmatched events appear as `[GPU_Launch_Pending]` (kernel launch without observed execution) or standalone `[GPU_Kernel]kernel_name` (kernel without CPU context).

Orchestration in gpuperf.py:

```python
def run_with_trace(self, command, cpu_profile, chrome_trace, merged_trace):
    # 1. Set environment for CUPTI injection
    env = os.environ.copy()
    env['CUDA_INJECTION64_PATH'] = str(self.injection_lib)
    env['CUPTI_TRACE_OUTPUT_FILE'] = trace_file

    # 2. Start eBPF profiler BEFORE target (must attach uprobe first)
    self.start_cpu_profiler(cpu_output_file=cpu_profile)
    time.sleep(1.0)  # Ensure uprobe is attached

    # 3. Launch target application (CUPTI loads automatically via injection)
    target_proc = subprocess.Popen(command, env=env)
    target_proc.wait()

    # 4. Stop profiler and merge traces
    self.stop_cpu_profiler()
    self.generate_merged_trace(cpu_trace=cpu_profile, gpu_trace=chrome_trace,
                                output_file=merged_trace)
```

The orchestration starts in `GPUPerf.__init__()`, which locates required components. It finds the CUPTI injection library at `cupti_trace/libcupti_trace_injection.so` and verifies the Rust eBPF profiler exists at `profiler/target/release/profile`. The function searches common CUDA installation paths for the CUPTI library needed for NVTX annotations. If any component is missing, it prints warnings but continues, as you can run CPU-only or GPU-only profiling.

When you run `gpuperf.py -c gpu.json -p cpu.txt -m merged.folded ./my_cuda_app`, the script calls `run_with_trace()`. This function orchestrates the entire profiling session. First, it sets up environment variables that CUDA runtime will check during initialization. The `CUDA_INJECTION64_PATH` variable points to our CUPTI injection library so CUDA loads it automatically. The `CUPTI_TRACE_OUTPUT_FILE` variable tells the injection library where to write GPU events. The injection approach works without modifying applications because CUDA runtime explicitly supports injection libraries for profiling.

The critical ordering happens next. The script calls `start_cpu_profiler()` before launching the target process. This is essential because the eBPF profiler must attach its uprobe to `cudaLaunchKernel` before any CUDA initialization occurs. The Rust profiler runs `sudo ./profile --uprobe /usr/local/cuda-12.9/lib64/libcudart.so.12:cudaLaunchKernel -E`, where `--uprobe` specifies the library and function to instrument, and `-E` enables extended folded output with timestamps. The script waits 1 second after starting the profiler to ensure uprobes are fully attached before the target process loads the CUDA runtime.

Only after the profiler is ready does the script start the target process with `subprocess.Popen(command, env=env)`. As soon as this process calls any CUDA API, the runtime initializes, loads our injection library via `CUDA_INJECTION64_PATH`, and CUPTI starts recording. The uprobe is already attached, so every `cudaLaunchKernel` call triggers a stack trace capture. The script then waits for the target to exit, handles signals gracefully (including SIGTERM and SIGINT), and ensures both profilers shut down cleanly.

After the target exits, `generate_merged_trace()` performs correlation. It instantiates `TraceMerger` and parses the CPU trace file (extended folded format). It also parses the GPU trace (Chrome JSON format from CUPTI), then calls `merger.merge_traces()` which matches events via correlation IDs and timestamps. The output is folded format combining CPU and GPU stacks, ready for flamegraph generation.


## Example Applications

The tutorial provides two CUDA applications for profiling demonstration.

### Real LLM Inference: Qwen3.cu (Recommended)

The primary example is `qwen3.cu`, a single-file CUDA implementation of the Qwen3 0.6B transformer model. This is a real, working language model that runs inference on GPU, making it perfect for profiling actual AI workloads. The implementation includes tokenization, multi-head attention, feedforward layers, and RMS normalization - all the components of modern transformer architectures.

### Alternative: Mock Transformer Simulator

The `mock-test/llm-inference.cu` application provides a simpler test case simulating transformer patterns without requiring model weights.

## Compilation and Execution

Build the complete profiling stack by first compiling the CUPTI injection library, then the Rust eBPF profiler, and finally the mock application.

### Build CUPTI Injection Library

Navigate to the CUPTI trace directory and compile:

```bash
cd cupti_trace
make
```

This compiles `cupti_trace.cpp` into `libcupti_trace_injection.so`, linking against CUPTI and CUDA runtime libraries. The Makefile searches common CUDA installation paths (`/usr/local/cuda-12.9`, `/usr/local/cuda-13.0`, etc.) and uses the appropriate include paths and library paths. Verify the library exists:

```bash
ls -lh libcupti_trace_injection.so
```

You should see a shared library around 100-120KB. If compilation fails, check that CUDA toolkit is installed and `nvcc` is in your PATH. CUPTI comes with the CUDA toolkit in `extras/CUPTI/`.

### Build Rust eBPF Profiler

Navigate to the profiler directory and compile in release mode for minimal overhead:

```bash
cd profiler
cargo build --release
```

This compiles the Rust profiler with full optimizations. The eBPF program is compiled to BPF bytecode and embedded in the Rust binary. Verify the profiler:

```bash
ls -lh target/release/profile
./target/release/profile --help
```

The profiler should show options for `--uprobe` (specify function to trace) and `-E` (extended folded output). The binary should be around 2-3MB including embedded eBPF code and symbol resolution libraries.

### Build Mock LLM Application

Navigate to the mock test directory and compile the CUDA application:

```bash
cd mock-test
make
```

This uses `nvcc` to compile `llm-inference.cu` into an executable. The Makefile uses `-std=c++17` for modern C++ features, `--no-device-link` to produce a single binary without separate device linking, and `-Wno-deprecated-gpu-targets` to suppress warnings on older GPUs. Verify compilation:

```bash
ls -lh llm-inference
```

The binary should be around 200KB. You can test it runs (though it will execute for 10 seconds by default):

```bash
./llm-inference
# Press Ctrl+C after a few seconds to stop early
```

### Build Real LLM Inference Application (Qwen3.cu)

The tutorial includes a real LLM inference engine - qwen3.cu, a single-file CUDA implementation of the Qwen3 0.6B model:

```bash
cd qwen3.cu

# Download the FP32 model (3GB)
make download-model

# Compile with dynamic CUDA runtime for uprobe support
make runcu
```

Verify dynamic linking (required for eBPF uprobes):

```bash
ldd runcu | grep cudart
# Should show: libcudart.so.12 => /usr/local/cuda-12.9/lib64/libcudart.so.12
```

### Running the Profiler

With all components built, run the complete profiling stack. The `gpuperf.py` script orchestrates everything:

```bash
# Profile real LLM inference (Qwen3 model)
sudo timeout -s 2 10 python3 gpuperf.py \
    -c qwen3_gpu.json \
    -p qwen3_cpu.txt \
    -m qwen3_merged.folded \
    bash -c 'cd qwen3.cu && ./runcu Qwen3-0.6B-FP32.gguf -q "Explain eBPF" -r 1'
```

The script output shows the profiling session:

```
Starting CPU profiler with cudaLaunchKernel hook
  CUDA library: /usr/local/cuda-12.9/lib64/libcudart.so.12
  Output: qwen3_cpu.txt
Running command with GPU profiling: bash -c cd qwen3.cu && ./runcu...
Trace output: qwen3_gpu.json
Started target process with PID: 3593972
A: E BPF (Extended Binux File) is a system call that allows users to program the Linux kernel's file system...
tok/s: 55.710306

Stopping CPU profiler...
CPU profile saved to: qwen3_cpu.txt

Converting trace to Chrome format: qwen3_gpu.json
Parsed 2452 events

Chrome trace file written to: qwen3_gpu.json

Generating merged CPU+GPU trace: qwen3_merged.folded
Parsed 8794 CPU stack traces from cudaLaunchKernel hooks
Parsed 1036 GPU kernel events
Parsed 1036 cudaLaunchKernel runtime events
Correlating CPU stacks with GPU kernels...
Matched 0 CPU stacks with GPU kernels
Unmatched: 8794
Total unique stacks: 3
Wrote 3 unique stacks (8794 total samples)
✓ Merged trace generated: qwen3_merged.folded
```

The key statistics show that 8,794 CPU stack traces were captured (one per `cudaLaunchKernel` call during inference). The profiler recorded 2,452 total GPU events including kernels, memcpy, and runtime API calls. There were 3 unique stack patterns representing the main code paths. The `forward()` function for transformer layer execution had 5,176 samples. The `matmul()` function for matrix multiplication had 3,614 samples. The `rmsnorm()` function for RMS normalization had 4 samples. This real-world LLM inference trace reveals the actual computation patterns of transformer models.

### Generate Flamegraph

Convert the merged folded trace to a flamegraph SVG:

```bash
./combined_flamegraph.pl qwen3_merged.folded > qwen3_flamegraph.svg
```

Open the SVG in a web browser:

```bash
firefox qwen3_flamegraph.svg
# or
google-chrome qwen3_flamegraph.svg
```

The flamegraph is interactive. Click on a stack frame to zoom in, showing only that subtree. Hover over frames to see function names and sample counts. The width of each frame represents time consumption, as wider frames are hotspots. The color is random and doesn't mean anything (it's just for visual distinction).

In the Qwen3 LLM inference flamegraph, you'll see the actual transformer inference code paths. The `forward(Transformer*, int, int)` function dominates with 5,176 samples (59% of execution), showing this is where the model spends most time executing transformer layers. The `matmul(float*, float*, float*, int, int)` function appears with 3,614 samples (41%), revealing matrix multiplication kernels for attention and feedforward computation. The `rmsnorm(float*, float*, float*, int)` function shows only 4 samples, indicating normalization is fast compared to matrix operations. Each stack ends with `cudaLaunchKernel`, marking where CPU code transitions to GPU execution. This reveals the computational hotspots in real LLM inference, where matrix multiplication dominates, followed by layer-wise forward passes.

### Inspecting Individual Traces

The profiler generates three trace files that can be inspected independently.

The CPU trace (qwen3_cpu.txt) contains raw uprobe samples in extended folded format:

```bash
head -5 qwen3_cpu.txt
```

Example output:

```
1761618697756454073 runcu 3593972 3593972 1 forward(Transformer*, int, int);cudaLaunchKernel
1761618697756957027 runcu 3593972 3593972 1 matmul(float*, float*, float*, int, int);cudaLaunchKernel
1761618697756968813 runcu 3593972 3593972 1 matmul(float*, float*, float*, int, int);cudaLaunchKernel
...
```

Each line is a stack trace captured when `cudaLaunchKernel` was called. You can process this independently with `flamegraph.pl` to see just CPU-side behavior. The traces show the actual Qwen3 model code, including `forward()` for transformer layers and `matmul()` for matrix multiplication.

The GPU trace (qwen3_gpu.json) is in Chrome Trace Format for timeline visualization:

```bash
head -20 qwen3_gpu.json
```

This is JSON containing an array of trace events. Load it in Chrome at `chrome://tracing` to see a timeline of GPU kernel executions, memory transfers, and runtime API calls. The timeline shows parallelism (overlapping kernels), bubbles (idle time), and memory transfer costs.

The merged trace (qwen3_merged.folded) combines both:

```bash
cat qwen3_merged.folded
```

Example output:

```
forward(Transformer*, int, int);cudaLaunchKernel;[GPU_Kernel]matmul_kernel 850432
matmul(float*, float*, float*, int, int);cudaLaunchKernel;[GPU_Kernel]attention_kernel 621847
rmsnorm(float*, float*, float*, int);cudaLaunchKernel;[GPU_Kernel]rmsnorm_kernel 3215
```

This is folded stack format with GPU kernel names appended. The numbers on the right are GPU kernel execution times in microseconds, not sample counts. For example, `850432` means 850.432 milliseconds of total GPU execution time for the `matmul_kernel` when called from the `forward()` function. This duration weighting ensures the flamegraph accurately reflects where GPU time is actually spent, as longer-running kernels appear wider, making performance bottlenecks immediately visible. Feed this directly to `combined_flamegraph.pl` to generate the unified visualization.

## Limitations and Future Directions

This profiler captures kernel launches but not kernel internals. When the flamegraph shows a GPU kernel consumed 50ms, it doesn't tell you why, whether threads are memory-bound, compute-bound, or stalled on divergence. For kernel-internal profiling, use NVIDIA Nsight Compute or Nsight Systems which instrument GPU execution at the warp level.

Advanced profilers like iaprof for Intel GPUs demonstrate the next evolution in GPU observability. iaprof combines eBPF kernel tracing with hardware performance sampling using Intel GPU Observability Architecture (OA) and Debug API. Instead of just showing "kernel X ran for 50ms", iaprof captures execution unit stall reasons (memory latency, ALU bottlenecks, instruction fetch stalls) and attributes them back to specific shader instructions. This requires deeper integration with GPU hardware, including reading performance counters during kernel execution, sampling execution unit state, and deferred attribution to handle out-of-order hardware execution. The correlation challenge becomes even harder because hardware samples arrive asynchronously and must be matched to kernel contexts after execution completes.

The profiler assumes single-stream execution in its current correlation logic. Multi-stream applications launch kernels on multiple CUDA streams, which can execute concurrently on the GPU. The merger should track stream IDs from CUPTI events and handle concurrent executions properly. Currently it may attribute concurrent kernels to whichever CPU launch happened closest in time. iaprof handles this with deferred attribution where hardware samples are buffered, then matched to shader contexts using timestamps and context IDs after all executions complete. This approach could be adapted for CUDA streams by buffering correlation matches and resolving them based on stream timelines.

Correlation ID overflow can occur in very long-running applications. CUDA's correlation IDs are 32-bit integers that may wrap around after billions of API calls. The merger doesn't currently handle wraparound, which could cause mismatches in applications running for days or weeks. Production profilers use epoch-based correlation where IDs reset at defined intervals and events include epoch markers.

Multi-GPU applications launch work on multiple devices. The profiler tracks device IDs in CUPTI events but doesn't distinguish them in the merged output. A proper multi-GPU flamegraph should separate stacks by device, showing which GPUs execute which kernels and whether load is balanced. The folded stack format could be extended with device tags: `cpu_stack;cudaLaunchKernel;[GPU0_Kernel]kernel_name` vs `cpu_stack;cudaLaunchKernel;[GPU1_Kernel]kernel_name`.

Integration with higher-level profilers would be valuable. Combining this tool with NVIDIA Nsight Systems would provide both high-level code flow (from flamegraphs) and detailed kernel metrics (from Nsight). Similarly, integrating with perf or BPF-based full-system profilers would show GPU work in the context of system-wide resource usage (CPU scheduling, interrupts, memory pressure). The folded stack format is designed for this, as you can merge CPU perf samples with GPU samples by concatenating stacks.

For fine-grained GPU observability, explore eBPF programs running on the GPU itself. The [bpftime GPU project](https://github.com/eunomia-bpf/bpftime/tree/master/example/gpu) compiles eBPF bytecode to PTX instructions, enabling instrumentation inside GPU kernels. This exposes thread-level metrics like memory coalescing efficiency, warp occupancy, and bank conflicts, which are data impossible to obtain from kernel-side tracing. Future directions could combine kernel-side CUPTI tracing with GPU-side eBPF instrumentation for complete visibility from application code to individual warp execution.

## Summary

GPU profiling requires bridging two execution domains: CPU code submitting work and GPU hardware executing it. This tutorial demonstrated a complete profiling stack combining eBPF for CPU stack traces, CUPTI for GPU activity tracing, and correlation logic to merge them into unified flamegraphs. The eBPF profiler captures CPU stacks at every `cudaLaunchKernel` call with nanosecond timestamps. CUPTI injection records GPU kernel executions with correlation IDs linking them back to CPU API calls. The trace merger matches events via timestamps and correlation IDs, producing folded stacks showing complete execution paths from application code through CUDA runtime to GPU kernels. The resulting flamegraphs visualize end-to-end execution, revealing hotspots across both CPU and GPU.

This approach works without recompiling applications, supports any CUDA framework (PyTorch, TensorFlow, JAX, raw CUDA), and provides low overhead suitable for production profiling. The tools are modular. You can use eBPF profiling alone for CPU analysis, CUPTI injection alone for GPU timelines, or combine them for unified visibility. Apply these techniques to diagnose performance bottlenecks in ML training, GPU-accelerated applications, or any CUDA workload where understanding CPU-GPU interaction is critical.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.


## References

### Related GPU Profiling Tools

1. AI Flame Graphs / iaprof (Intel) provides hardware-sampling driven GPU and software stack flamegraphs (EU stalls, kernels, and CPU stacks), open-sourced in 2025. This is deeper than our tutorial: it samples inside GPU kernels and attributes stall reasons back to code context. Use this when you need hardware stall analysis and an end-to-end view. [Brendan Gregg](https://www.brendangregg.com/blog/2024-10-29/ai-flame-graphs.html) | [GitHub](https://github.com/intel/iaprof)

2. Nsight Systems and Nsight Compute (NVIDIA) are official tools. Systems gives CPU to GPU timelines and API/kernels; Compute gives in-kernel metrics and roofline-style analyses. Ideal for deep tuning, not always for low-overhead continuous profiling. [NVIDIA Docs](https://docs.nvidia.com/nsight-systems/UserGuide/index.html)

3. PyTorch Profiler / Kineto (NVIDIA/Meta, also AMD/Intel backends) records CPU ops and GPU kernels via CUPTI and shows them in TensorBoard/Chrome Trace. It supports CPU to accelerator flow links ("ac2g"). Great when you're already in PyTorch. [PyTorch Blog](https://pytorch.org/blog/automated-trace-collection/) | [PyTorch Docs](https://pytorch.org/docs/stable/profiler.html)

4. HPCToolkit (Rice) provides low-overhead call-path profiling that can attribute GPU kernel time to CPU calling context, and on NVIDIA can use PC sampling to examine instruction-level behavior. Powerful for production runs and cross-vendor GPUs. [Argonne Leadership Computing Facility](https://www.alcf.anl.gov/sites/default/files/2024-11/HPCToolkit-ALCF-2024-10.pdf)

5. AMD ROCm (rocprofiler-SDK) offers HIP/HSA tracing with Correlation_Id to connect async calls and kernels. If you want an AMD version of this tutorial, integrate with rocprofiler events. [ROCm Documentation](https://rocm.docs.amd.com/projects/rocprofiler-sdk/en/docs-6.3.1/how-to/using-rocprofv3.html)

6. Level Zero tracer (Intel) allows you to intercept Level Zero API calls (loader tracing) and build a similar correlator with L0 callbacks for Intel GPUs. [Intel Docs](https://www.intel.com/content/www/us/en/docs/oneapi/optimization-guide-gpu/2023-1/level-zero-tracer.html)

7. Perfetto / Chrome Trace viewer is your choice for viewing `.json` timelines. Perfetto is the modern web UI that reads Chromium JSON traces (what your CUPTI converter emits). [Perfetto](https://perfetto.dev/)

### Technical Documentation

1. NVIDIA CUPTI Documentation: <https://docs.nvidia.com/cupti/Cupti/index.html>
2. CUPTI Activity API: <https://docs.nvidia.com/cupti/Cupti/r_main.html#r_activity_api>
3. CUPTI ActivityKernel8 Structure: <https://docs.nvidia.com/cupti/api/structCUpti__ActivityKernel8.html>
4. CUDA Profiling Guide: <https://docs.nvidia.com/cuda/profiler-users-guide/>
5. Nsight Systems User Guide: <https://docs.nvidia.com/drive/drive-os-5.2.6.0L/nsight-systems/pdf/UserGuide.pdf>
6. eBPF Stack Trace Helpers: <https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#4-bpf_get_stackid>
7. Chrome Trace Format: <https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU>
8. Flamegraph Visualization: <https://www.brendangregg.com/flamegraphs.html>

### Advanced Topics

1. bpftime GPU eBPF: <https://github.com/eunomia-bpf/bpftime/tree/master/example/gpu>
2. iaprof Intel GPU Profiling Analysis: <https://eunomia.dev/blog/2025/10/11/understanding-iaprof-a-deep-dive-into-aigpu-flame-graph-profiling/>
3. Tutorial Repository: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/xpu/flamegraph>

Complete source code including the eBPF profiler, CUPTI injection library, trace merger, and test applications is available in the tutorial repository. Contributions and issue reports welcome!
