# eBPF Tutorial by Example: Monitoring GPU Activity with Kernel Tracepoints

Ever wondered what your GPU is really doing under the hood? When games stutter, ML training slows down, or video encoding freezes, the answers lie deep inside the kernel's GPU driver. Traditional debugging relies on guesswork and vendor-specific tools, but there's a better way. Linux kernel GPU tracepoints expose real-time insights into job scheduling, memory allocation, and command submission - and eBPF lets you analyze this data with minimal overhead.

In this tutorial, we'll explore GPU kernel tracepoints across DRM scheduler, Intel i915, and AMD AMDGPU drivers. We'll write bpftrace scripts to monitor live GPU activity, track memory pressure, measure job latency, and diagnose performance bottlenecks. By the end, you'll have production-ready monitoring tools and deep knowledge of how GPUs interact with the kernel.

## Understanding GPU Kernel Tracepoints

GPU tracepoints are instrumentation points built directly into the kernel's Direct Rendering Manager (DRM) subsystem. When your GPU schedules a job, allocates memory, or signals a fence, these tracepoints fire - capturing precise timing, resource identifiers, and driver state. Unlike userspace profiling tools that sample periodically and miss events, kernel tracepoints catch every single operation with nanosecond timestamps.

### Why Kernel Tracepoints Matter for GPU Monitoring

Think about what happens when you launch a GPU workload. Your application submits commands through the graphics API (Vulkan, OpenGL, CUDA). The userspace driver translates these into hardware-specific command buffers. The kernel driver receives an ioctl, validates the work, allocates GPU memory, binds resources to GPU address space, schedules the job on a hardware ring, and waits for completion. Traditional profiling sees the start and end - kernel tracepoints see every step in between.

The performance implications are significant. Polling-based monitoring checks GPU state every 100ms and consumes CPU cycles on every check. Tracepoints activate only when events occur, adding mere nanoseconds of overhead per event, and capture 100% of activity including microsecond-duration jobs. For production monitoring of Kubernetes GPU workloads or debugging ML training performance, this difference is critical.

### The DRM Tracepoint Ecosystem

GPU tracepoints span three layers of the graphics stack. **DRM scheduler tracepoints** (gpu_scheduler event group) are marked as stable uAPI - their format will never change. These work identically across Intel, AMD, and Nouveau drivers, making them perfect for vendor-neutral monitoring. They track job submission (`drm_run_job`), completion (`drm_sched_process_job`), and dependency waits (`drm_sched_job_wait_dep`).

**Vendor-specific tracepoints** expose driver internals. Intel i915 tracepoints track GEM object creation (`i915_gem_object_create`), VMA binding to GPU address space (`i915_vma_bind`), memory pressure events (`i915_gem_shrink`), and page faults (`i915_gem_object_fault`). AMD AMDGPU tracepoints monitor buffer object lifecycle (`amdgpu_bo_create`), command submission from userspace (`amdgpu_cs_ioctl`), scheduler execution (`amdgpu_sched_run_job`), and GPU interrupts (`amdgpu_iv`). Note that Intel low-level tracepoints require `CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS=y` in your kernel config.

**Generic DRM tracepoints** handle display synchronization through vblank events - critical for diagnosing frame drops and compositor latency. Events include vblank occurrence (`drm_vblank_event`), userspace queueing (`drm_vblank_event_queued`), and delivery (`drm_vblank_event_delivered`).

### Real-World Use Cases

GPU tracepoints solve problems that traditional tools can't touch. **Diagnosing stuttering in games**: You notice frame drops every few seconds. Vblank tracepoints reveal missed vertical blanks. Job scheduling traces show CPU-side delays in command submission. Memory tracepoints expose allocations triggering evictions during critical frames. Within minutes you identify that texture uploads are blocking the rendering pipeline.

**Optimizing ML training performance**: Your PyTorch training is 40% slower than expected. AMDGPU command submission tracing reveals excessive synchronization - the CPU waits for GPU completion too often. Job dependency tracepoints show unnecessary fences between independent operations. Memory traces expose thrashing between VRAM and system RAM. You reorganize batching to eliminate stalls.

**Cloud GPU billing accuracy**: Multi-tenant systems need fair energy and resource accounting. DRM scheduler tracepoints attribute exact GPU time to each container. Memory tracepoints track allocation per workload. This data feeds into accurate billing systems that charge based on actual resource consumption rather than time-based estimates.

**Thermal throttling investigation**: GPU performance degrades under load. Interrupt tracing shows thermal events from the GPU. Job scheduling traces reveal frequency scaling impacting execution time. Memory migration traces show the driver moving workloads to cooler GPU dies. You adjust power limits and improve airflow.

## Tracepoint Reference Guide

Let's examine each tracepoint category in detail, understanding the data they expose and how to interpret it.

### DRM Scheduler Tracepoints: The Universal GPU Monitor

The DRM scheduler provides a vendor-neutral view of GPU job management. These tracepoints work identically whether you're running Intel integrated graphics, AMD discrete GPUs, or Nouveau on NVIDIA hardware.

#### drm_run_job: When GPU Work Starts Executing

When the scheduler assigns a job to GPU hardware, `drm_run_job` fires. This marks the transition from "queued in software" to "actively running on silicon." The tracepoint captures the job ID (unique identifier for correlation), ring name (which execution engine: graphics, compute, video decode), queue depth (how many jobs are waiting), and hardware job count (jobs currently executing on GPU).

The format looks like: `entity=0xffff888... id=12345 fence=0xffff888... ring=gfx job count:5 hw job count:2`. This tells you job 12345 on the graphics ring started executing. Five jobs are queued behind it, and two jobs are currently running on hardware (multi-engine GPUs can run jobs in parallel).

Use this to measure job scheduling latency. Record the timestamp when userspace submits work (using command submission tracepoints), then measure time until `drm_run_job` fires. Latencies over 1ms indicate CPU-side scheduling delays. Per-ring statistics reveal if specific engines (video encode, compute) are bottlenecked.

#### drm_sched_process_job: Job Completion Signal

When GPU hardware completes a job and signals its fence, this tracepoint fires. The fence pointer identifies the completed job - correlate it with `drm_run_job` to calculate GPU execution time. Format: `fence=0xffff888... signaled`.

Combine with `drm_run_job` timestamps to compute job execution time: `completion_time - run_time = GPU_execution_duration`. If jobs that should take 5ms are taking 50ms, you've found a GPU performance problem. Throughput metrics (jobs completed per second) indicate overall GPU utilization.

#### drm_sched_job_wait_dep: Dependency Stalls

Before a job can execute, its dependencies (previous jobs it waits for) must complete. This tracepoint fires when a job blocks waiting for a fence. Format: `job ring=gfx id=12345 depends fence=0xffff888... context=1234 seq=567`.

This reveals pipeline stalls. If compute jobs constantly wait for graphics jobs, you're not exploiting parallelism. If wait times are long, dependency chains are too deep - consider batching independent work. Excessive dependencies indicate a CPU-side scheduling inefficiency.

### Intel i915 Tracepoints: Memory and I/O Deep Dive

Intel's i915 driver exposes detailed tracepoints for memory management and data transfer. These require `CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS=y` - check with `grep CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS /boot/config-$(uname -r)`.

#### i915_gem_object_create: GPU Memory Allocation

When the driver allocates a GEM (Graphics Execution Manager) object - the fundamental unit of GPU-accessible memory - this fires. Format: `obj=0xffff888... size=0x100000` indicates allocating a 1MB object.

Track total allocated memory over time to detect leaks. Sudden allocation spikes before performance drops suggest memory pressure. Correlate object pointers with subsequent bind/fault events to understand object lifecycle. High-frequency small allocations indicate inefficient batching.

#### i915_vma_bind: Mapping Memory to GPU Address Space

Allocating memory isn't enough - it must be mapped (bound) into GPU address space. This tracepoint fires on VMA (Virtual Memory Area) binding. Format: `obj=0xffff888... offset=0x0000100000 size=0x10000 mappable vm=0xffff888...` shows 64KB bound at GPU virtual address 0x100000.

Binding overhead impacts performance. Frequent rebinding indicates memory thrashing - the driver evicting and rebinding objects under pressure. GPU page faults often correlate with bind operations - the CPU bound memory just before GPU accessed it. Flags like `PIN_MAPPABLE` indicate memory accessible by both CPU and GPU.

#### i915_gem_shrink: Memory Pressure Response

Under memory pressure, the driver reclaims GPU memory. Format: `dev=0 target=0x1000000 flags=0x3` means the driver tries to reclaim 16MB. High shrink activity indicates undersized GPU memory for the workload.

Correlate with performance drops - if shrinking happens during frame rendering, it causes stutters. Flags indicate shrink aggressiveness. Repeated shrinks with small targets suggest memory fragmentation. Compare target with actual freed amount (track object destructions) to measure reclaim efficiency.

#### i915_gem_object_fault: GPU Page Faults

When CPU or GPU accesses unmapped memory, a fault occurs. Format: `obj=0xffff888... GTT index=128 writable` indicates a write fault on Graphics Translation Table page 128. Faults are expensive - they stall execution while the kernel resolves the missing mapping.

Excessive faults kill performance. Write faults are more expensive than reads (require invalidating caches). GTT faults (GPU accessing unmapped memory) indicate incomplete resource binding before job submission. CPU faults suggest inefficient CPU/GPU synchronization - CPU accessing objects while GPU is using them.

### AMD AMDGPU Tracepoints: Command Flow and Interrupts

AMD's AMDGPU driver provides comprehensive tracing of command submission and hardware interrupts.

#### amdgpu_cs_ioctl: Userspace Command Submission

When an application submits GPU work via ioctl, this captures the request. Format: `sched_job=12345 timeline=gfx context=1000 seqno=567 ring_name=gfx_0.0.0 num_ibs=2` shows job 12345 submitted to graphics ring with 2 indirect buffers.

This marks when userspace hands off work to kernel. Record timestamp to measure submission-to-execution latency when combined with `amdgpu_sched_run_job`. High frequency indicates small batches - potential for better batching. Per-ring distribution shows workload balance across engines.

#### amdgpu_sched_run_job: Kernel Schedules Job

The kernel scheduler starts executing a previously submitted job. Comparing timestamps with `amdgpu_cs_ioctl` reveals submission latency. Format includes job ID and ring for correlation.

Submission latencies over 100μs indicate kernel scheduling delays. Per-ring latencies show if specific engines are scheduling-bound. Correlate with CPU scheduler traces to identify if kernel threads are being preempted.

#### amdgpu_bo_create: Buffer Object Allocation

AMD's equivalent to i915 GEM objects. Format: `bo=0xffff888... pages=256 type=2 preferred=4 allowed=7 visible=1` allocates 1MB (256 pages). Type indicates VRAM vs GTT (system memory accessible by GPU). Preferred/allowed domains show placement policy.

Track VRAM allocations to monitor memory usage. Type mismatches (requesting VRAM but falling back to GTT) indicate VRAM exhaustion. Visible flag indicates CPU-accessible memory - expensive, use sparingly.

#### amdgpu_bo_move: Memory Migration

When buffer objects migrate between VRAM and GTT, this fires. Migrations are expensive (require copying data over PCIe). Excessive moves indicate memory thrashing - working set exceeds VRAM capacity.

Measure move frequency and size to quantify PCIe bandwidth consumption. Correlate with performance drops - migrations stall GPU execution. Optimize by reducing working set or using smarter placement policies (keep frequently accessed data in VRAM).

#### amdgpu_iv: GPU Interrupts

The GPU signals interrupts for completed work, errors, and events. Format: `ih:0 client_id:1 src_id:42 ring:0 vmid:5 timestamp:1234567890 pasid:100 src_data: 00000001...` captures interrupt details.

Source ID indicates interrupt type (completion, fault, thermal). High interrupt rates impact CPU performance. Unexpected interrupts suggest hardware errors. VMID and PASID identify which process/VM triggered the interrupt - critical for multi-tenant debugging.

### DRM Vblank Tracepoints: Display Synchronization

Vblank (vertical blanking) events synchronize rendering with display refresh. Missing vblanks causes dropped frames and stutter.

#### drm_vblank_event: Vertical Blank Occurs

When the display enters vertical blanking period, this fires. Format: `crtc=0 seq=12345 time=1234567890 high-prec=true` indicates vblank on display controller 0, sequence number 12345.

Track vblank frequency to verify refresh rate (60Hz = 60 vblanks/second). Missed sequences indicate frame drops. High-precision timestamps enable sub-millisecond frame timing analysis. Per-CRTC tracking for multi-monitor setups.

#### drm_vblank_event_queued and drm_vblank_event_delivered

These track vblank event delivery to userspace. Queuing latency (queue to delivery) measures kernel scheduling delay. Total latency (vblank to delivery) includes both kernel and driver processing.

Latencies over 1ms indicate compositor problems. Compare across CRTCs to identify problematic displays. Correlate with frame drops visible to users - events delivered late mean missed frames.

## Monitoring with Bpftrace Scripts

We've created vendor-specific bpftrace scripts for production monitoring. Each script focuses on its GPU vendor's specific tracepoints while sharing a common output format.

### DRM Scheduler Monitor: Universal GPU Tracking

The `drm_scheduler.bt` script works on **all GPU drivers** because it uses stable uAPI tracepoints. It tracks jobs across all rings, measures completion rates, and identifies dependency stalls.

The script attaches to `gpu_scheduler:drm_run_job`, `gpu_scheduler:drm_sched_process_job`, and `gpu_scheduler:drm_sched_job_wait_dep`. On job start, it records timestamps in a map keyed by job ID for later latency calculation. It increments per-ring counters to show workload distribution. On completion, it prints fence information. On dependency wait, it shows which job blocks which fence.

Output shows timestamp, event type (RUN/COMPLETE/WAIT_DEP), job ID, ring name, and queue depth. At program end, statistics summarize jobs per ring and dependency wait counts. This reveals if specific rings are saturated, whether jobs are blocked by dependencies, and overall GPU utilization patterns.

### Intel i915 Monitor: Memory and I/O Profiling

The `intel_i915.bt` script tracks Intel GPU memory operations, I/O transfers, and page faults. It requires `CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS=y`.

On `i915_gem_object_create`, it accumulates total allocated memory and stores per-object sizes. VMA bind/unbind events track GPU address space changes. Shrink events measure memory pressure. Pwrite/pread track CPU-GPU data transfers. Faults categorize by type (GTT vs CPU, read vs write).

Output reports allocation size and running total in MB. Bind operations show GPU virtual address and flags. I/O operations track offset and length. Faults indicate type and whether they're reads or writes. End statistics summarize total allocations, VMA operations, memory pressure (shrink operations and bytes reclaimed), I/O volume (read/write counts and sizes), and fault analysis (total faults, write vs read).

This reveals memory leaks (allocations without corresponding frees), binding overhead (frequent rebinds indicate thrashing), memory pressure timing (correlate shrinks with performance drops), I/O patterns (large transfers vs many small ones), and fault hotspots (expensive operations to optimize).

### AMD AMDGPU Monitor: Command Submission Analysis

The `amd_amdgpu.bt` script focuses on AMD's command submission pipeline, measuring latency from ioctl to execution.

On `amdgpu_cs_ioctl`, it records submission timestamp keyed by job ID. When `amdgpu_sched_run_job` fires, it calculates latency: `(current_time - submit_time)`. Buffer object create/move events track memory. Interrupt events count by source ID. Virtual memory operations (flush, map, unmap) measure TLB activity.

Output shows timestamp, event type, job ID, ring name, and calculated latency in microseconds. End statistics include memory allocation totals, command submission counts per ring, average and distribution of submission latency (histogram showing how many jobs experienced different latency buckets), interrupt counts by source, and virtual memory operation counts.

Latency histograms are critical - most jobs should have <50μs latency. A tail of high-latency jobs indicates scheduling problems. Per-ring statistics show if compute workloads have different latency than graphics. Memory migration tracking helps diagnose VRAM pressure.

### Display Vblank Monitor: Frame Timing Analysis

The `drm_vblank.bt` script tracks display synchronization for diagnosing frame drops.

On `drm_vblank_event`, it records timestamp keyed by CRTC and sequence. When `drm_vblank_event_queued` fires, it timestamps queue time. On `drm_vblank_event_delivered`, it calculates queue-to-delivery latency and total vblank-to-delivery latency.

Output shows vblank events, queued events, and delivered events with timestamps. End statistics include total vblank counts per CRTC, event delivery counts, average delivery latency, latency distribution histogram, and total event latency (vblank occurrence to userspace delivery).

Delivery latencies over 1ms indicate compositor scheduling issues. Total latencies reveal end-to-end delay visible to applications. Per-CRTC statistics show if specific monitors have problems. Latency histograms expose outliers causing visible stutter.

## Running the Monitors

Let's trace live GPU activity. Navigate to the scripts directory and run any monitor with bpftrace. The DRM scheduler monitor works on all GPUs:

```bash
cd bpf-developer-tutorial/srcsrc/xpu/gpu-kernel-driver/scripts
sudo bpftrace drm_scheduler.bt
```

You'll see output like:

```
Tracing DRM GPU scheduler... Hit Ctrl-C to end.
TIME(ms)           EVENT        JOB_ID           RING         QUEUED   DETAILS
296119090          RUN          12345            gfx          5        hw=2
296120190          COMPLETE     0xffff888...

=== DRM Scheduler Statistics ===

Jobs per ring:
@jobs_per_ring[gfx]: 1523
@jobs_per_ring[compute]: 89

Waits per ring:
@waits_per_ring[gfx]: 12
```

This shows graphics jobs dominating workload (1523 vs 89 compute jobs). Few dependency waits (12) indicate good pipeline parallelism.

For Intel GPUs, run the i915 monitor:

```bash
sudo bpftrace intel_i915.bt
```

For AMD GPUs:

```bash
sudo bpftrace amd_amdgpu.bt
```

For display timing:

```bash
sudo bpftrace drm_vblank.bt
```

Each script outputs real-time events and end-of-run statistics. Run them during GPU workloads (gaming, ML training, video encoding) to capture characteristic patterns.

## Verifying Tracepoint Availability

Before running scripts, verify tracepoints exist on your system. We've included a test script:

```bash
cd bpf-developer-tutorial/srcsrc/xpu/gpu-kernel-driver/tests
sudo ./test_basic_tracing.sh
```

This checks for gpu_scheduler, drm, i915, and amdgpu event groups. It reports which tracepoints are available and recommends appropriate monitoring scripts for your hardware. For Intel systems, it verifies if low-level tracepoints are enabled in kernel config.

You can also manually inspect available tracepoints:

```bash
# All GPU tracepoints
sudo cat /sys/kernel/debug/tracing/available_events | grep -E '(gpu_scheduler|i915|amdgpu|^drm:)'

# DRM scheduler (stable, all vendors)
sudo cat /sys/kernel/debug/tracing/available_events | grep gpu_scheduler

# Intel i915
sudo cat /sys/kernel/debug/tracing/available_events | grep i915

# AMD AMDGPU
sudo cat /sys/kernel/debug/tracing/available_events | grep amdgpu
```

To manually enable a tracepoint and view raw output:

```bash
# Enable drm_run_job
echo 1 | sudo tee /sys/kernel/debug/tracing/events/gpu_scheduler/drm_run_job/enable

# View trace output
sudo cat /sys/kernel/debug/tracing/trace

# Disable when done
echo 0 | sudo tee /sys/kernel/debug/tracing/events/gpu_scheduler/drm_run_job/enable
```

## Summary and Next Steps

GPU kernel tracepoints provide unprecedented visibility into graphics driver behavior. The DRM scheduler's stable uAPI tracepoints work across all vendors, making them perfect for production monitoring. Vendor-specific tracepoints from Intel i915 and AMD AMDGPU expose detailed memory management, command submission pipelines, and hardware interrupt patterns.

Our bpftrace scripts demonstrate practical monitoring: measuring job scheduling latency, tracking memory pressure, analyzing command submission bottlenecks, and diagnosing frame drops. These techniques apply directly to real-world problems - optimizing ML training performance, debugging game stutters, implementing fair GPU resource accounting in cloud environments, and investigating thermal throttling.

The key advantage over traditional tools is completeness and overhead. Kernel tracepoints capture every event with nanosecond precision at negligible cost. No polling, no sampling gaps, no missed short-lived jobs. This data feeds production monitoring systems (Prometheus exporters reading bpftrace output), ad-hoc performance debugging (run a script when users report issues), and automated optimization (trigger workload rebalancing based on latency thresholds).

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- **Linux Kernel Source**: `/drivers/gpu/drm/`
- **DRM Scheduler**: `/drivers/gpu/drm/scheduler/gpu_scheduler_trace.h`
- **Intel i915**: `/drivers/gpu/drm/i915/i915_trace.h`
- **AMD AMDGPU**: `/drivers/gpu/drm/amd/amdgpu/amdgpu_trace.h`
- **Generic DRM**: `/drivers/gpu/drm/drm_trace.h`
- **Kernel Tracepoint Documentation**: `Documentation/trace/tracepoints.rst`
- **Tutorial Repository**: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/xpu/gpu-kernel-driver>

Complete source code including all bpftrace scripts and test cases is available in the tutorial repository. Contributions and issue reports welcome!
