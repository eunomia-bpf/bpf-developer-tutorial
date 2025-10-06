# eBPF Tutorial by Example: Monitoring GPU Driver Activity with Kernel Tracepoints

When games stutter or ML training slows down, the answers lie inside the GPU kernel driver. Linux kernel tracepoints expose real-time job scheduling, memory allocation, and command submission data. Unlike userspace profiling tools that sample periodically and miss events, kernel tracepoints catch every operation with nanosecond timestamps and minimal overhead.

This tutorial shows how to monitor GPU activity using eBPF and bpftrace. We'll track DRM scheduler jobs, measure latency, and diagnose bottlenecks using stable kernel tracepoints that work across Intel, AMD, and Nouveau drivers.

## GPU Kernel Tracepoints: Zero-Overhead Observability

GPU tracepoints are instrumentation points built into the kernel's Direct Rendering Manager (DRM) subsystem. When your GPU schedules a job, allocates memory, or signals a fence, these tracepoints fire with precise timing and driver state.

The key insight: kernel tracepoints activate only when events occur, adding nanoseconds of overhead per event. They capture 100% of activity including microsecond-duration jobs. Polling-based monitoring checks GPU state every 100ms and misses short-lived operations entirely.

GPU tracepoints span three layers. **DRM scheduler tracepoints** (`gpu_scheduler` event group) are stable uAPI - their format never changes. They work identically across Intel, AMD, and Nouveau drivers for vendor-neutral monitoring. **Vendor-specific tracepoints** expose driver internals - Intel i915 tracks GEM object creation and VMA binding, AMD AMDGPU monitors buffer objects and command submission. **Generic DRM tracepoints** handle display synchronization through vblank events for diagnosing frame drops.

## DRM Scheduler Monitor: Universal GPU Tracking

The `drm_scheduler.bt` script works on **all GPU drivers** because it uses stable uAPI tracepoints. It tracks job submission (`drm_run_job`), completion (`drm_sched_process_job`), and dependency waits (`drm_sched_job_wait_dep`) across all rings.

### Complete Bpftrace Script: drm_scheduler.bt

```c
#!/usr/bin/env bpftrace
/*
 * drm_scheduler.bt - Monitor DRM GPU scheduler activity
 *
 * This script tracks GPU job scheduling using stable DRM scheduler tracepoints.
 * Works across ALL modern GPU drivers (Intel i915, AMD AMDGPU, Nouveau, etc.)
 *
 * The gpu_scheduler tracepoints are stable uAPI - guaranteed not to change.
 *
 * Usage: sudo bpftrace drm_scheduler.bt
 */

BEGIN
{
    printf("Tracing DRM GPU scheduler... Hit Ctrl-C to end.\n");
    printf("%-18s %-12s %-16s %-12s %-8s %s\n",
           "TIME(ms)", "EVENT", "JOB_ID", "RING", "QUEUED", "DETAILS");
}

/* GPU job starts executing */
tracepoint:gpu_scheduler:drm_run_job
{
    $job_id = args->id;
    $ring = str(args->name);
    $queue = args->job_count;
    $hw_queue = args->hw_job_count;

    /* Record start time for latency calculation */
    @start[$job_id] = nsecs;

    printf("%-18llu %-12s %-16llu %-12s %-8u hw=%d\n",
           nsecs / 1000000,
           "RUN",
           $job_id,
           $ring,
           $queue,
           $hw_queue);

    /* Track per-ring statistics */
    @jobs_per_ring[$ring] = count();
}

/* GPU job completes (fence signaled) */
tracepoint:gpu_scheduler:drm_sched_process_job
{
    $fence = args->fence;

    printf("%-18llu %-12s %-16p\n",
           nsecs / 1000000,
           "COMPLETE",
           $fence);

    @completion_count = count();
}

/* Job waiting for dependencies */
tracepoint:gpu_scheduler:drm_sched_job_wait_dep
{
    $job_id = args->id;
    $ring = str(args->name);
    $dep_ctx = args->ctx;
    $dep_seq = args->seqno;

    printf("%-18llu %-12s %-16llu %-12s %-8s ctx=%llu seq=%u\n",
           nsecs / 1000000,
           "WAIT_DEP",
           $job_id,
           $ring,
           "-",
           $dep_ctx,
           $dep_seq);

    @wait_count = count();
    @waits_per_ring[$ring] = count();
}

END
{
    printf("\n=== DRM Scheduler Statistics ===\n");
    printf("\nJobs per ring:\n");
    print(@jobs_per_ring);
    printf("\nWaits per ring:\n");
    print(@waits_per_ring);
}
```

### Understanding the Script

The script attaches to three stable DRM scheduler tracepoints. When `drm_run_job` fires, a job transitions from "queued in software" to "running on silicon." The tracepoint captures `args->id` (job ID for correlation), `args->name` (ring name - which execution engine like graphics, compute, or video decode), `args->job_count` (queue depth - how many jobs are waiting), and `args->hw_job_count` (jobs currently executing on GPU hardware).

The format `entity=0xffff888... id=12345 fence=0xffff888... ring=gfx job count:5 hw job count:2` tells you job 12345 on the graphics ring started executing with 5 jobs queued behind it and 2 jobs currently running on hardware. Multi-engine GPUs can run jobs in parallel across different rings.

We record `@start[$job_id] = nsecs` to enable latency calculation. The script stores the timestamp keyed by job ID. Later, when tracking completion or measuring end-to-end latency, you can compute `nsecs - @start[$job_id]` to get execution time. The `@jobs_per_ring[$ring] = count()` line increments per-ring counters, showing workload distribution across engines.

When `drm_sched_process_job` fires, GPU hardware completed a job and signaled its fence. The fence pointer `args->fence` identifies the completed job. Correlating fence pointers between `drm_run_job` and this tracepoint lets you calculate GPU execution time: `completion_time - run_time = GPU_execution_duration`. If jobs that should take 5ms are taking 50ms, you've found a GPU performance problem.

The `drm_sched_job_wait_dep` tracepoint fires when a job blocks waiting for a fence. Before a job executes, its dependencies (previous jobs it waits for) must complete. The format shows `args->ctx` (dependency context) and `args->seqno` (sequence number) identifying which fence blocks this job.

This reveals pipeline stalls. If compute jobs constantly wait for graphics jobs, you're not exploiting parallelism. Long wait times suggest dependency chains are too deep - consider batching independent work. Excessive dependencies indicate CPU-side scheduling inefficiency. The `@waits_per_ring[$ring] = count()` metric tracks which rings experience the most dependency stalls.

At program end, the `END` block prints statistics. `@jobs_per_ring` shows job counts per execution engine - revealing if specific rings (video encode, compute) are saturated. `@waits_per_ring` exposes dependency bottlenecks. This data reveals overall GPU utilization patterns and whether jobs are blocked by dependencies.

## Intel i915 Tracepoints: Memory Management Deep Dive

Intel's i915 driver exposes detailed tracepoints for memory operations. These require `CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS=y` in your kernel config - check with `grep CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS /boot/config-$(uname -r)`.

**i915_gem_object_create** fires when the driver allocates a GEM (Graphics Execution Manager) object - the fundamental unit of GPU-accessible memory. Format: `obj=0xffff888... size=0x100000` indicates allocating a 1MB object. Track total allocated memory over time to detect leaks. Sudden allocation spikes before performance drops suggest memory pressure. Correlate object pointers with subsequent bind/fault events to understand object lifecycle.

**i915_vma_bind** tracks mapping memory into GPU address space. Allocating memory isn't enough - it must be bound into GPU virtual address space. Format: `obj=0xffff888... offset=0x0000100000 size=0x10000 mappable vm=0xffff888...` shows 64KB bound at GPU virtual address 0x100000. Frequent rebinding indicates memory thrashing - the driver evicting and rebinding objects under pressure. GPU page faults often correlate with bind operations.

**i915_gem_shrink** captures memory pressure response. Under memory pressure, the driver reclaims GPU memory. Format: `dev=0 target=0x1000000 flags=0x3` means the driver tries to reclaim 16MB. High shrink activity indicates undersized GPU memory for the workload. Correlate with performance drops - if shrinking happens during frame rendering, it causes stutters.

**i915_gem_object_fault** tracks page faults when CPU or GPU accesses unmapped memory. Format: `obj=0xffff888... GTT index=128 writable` indicates a write fault on Graphics Translation Table page 128. Faults are expensive - they stall execution while the kernel resolves the missing mapping. Write faults are more expensive than reads (require invalidating caches). GTT faults indicate incomplete resource binding before job submission.

## AMD AMDGPU Tracepoints: Command Submission Pipeline

AMD's AMDGPU driver provides comprehensive tracing of command submission and hardware interrupts.

**amdgpu_cs_ioctl** captures userspace command submission. When an application submits GPU work via ioctl, this tracepoint fires. Format: `sched_job=12345 timeline=gfx context=1000 seqno=567 ring_name=gfx_0.0.0 num_ibs=2` shows job 12345 submitted to graphics ring with 2 indirect buffers. This marks when userspace hands off work to kernel. Record timestamp to measure submission-to-execution latency when combined with `amdgpu_sched_run_job`. High frequency indicates small batches - potential for better batching.

**amdgpu_sched_run_job** fires when the kernel scheduler starts executing a previously submitted job. Comparing timestamps with `amdgpu_cs_ioctl` reveals submission latency. Submission latencies over 100μs indicate kernel scheduling delays. Per-ring latencies show if specific engines are scheduling-bound.

**amdgpu_bo_create** tracks buffer object allocation - AMD's equivalent to i915 GEM objects. Format: `bo=0xffff888... pages=256 type=2 preferred=4 allowed=7 visible=1` allocates 1MB (256 pages). Type indicates VRAM vs GTT (system memory accessible by GPU). Preferred/allowed domains show placement policy. Type mismatches (requesting VRAM but falling back to GTT) indicate VRAM exhaustion. Visible flag indicates CPU-accessible memory - expensive, use sparingly.

**amdgpu_bo_move** fires when buffer objects migrate between VRAM and GTT. Migrations are expensive (require copying data over PCIe). Excessive moves indicate memory thrashing - working set exceeds VRAM capacity. Measure move frequency and size to quantify PCIe bandwidth consumption. Correlate with performance drops - migrations stall GPU execution.

**amdgpu_iv** captures GPU interrupts. The GPU signals interrupts for completed work, errors, and events. Format: `ih:0 client_id:1 src_id:42 ring:0 vmid:5 timestamp:1234567890 pasid:100 src_data: 00000001...` captures interrupt details. Source ID indicates interrupt type (completion, fault, thermal). High interrupt rates impact CPU performance. VMID and PASID identify which process/VM triggered the interrupt - critical for multi-tenant debugging.

## DRM Vblank Tracepoints: Display Synchronization

Vblank (vertical blanking) events synchronize rendering with display refresh. Missing vblanks causes dropped frames and stutter.

**drm_vblank_event** fires when the display enters vertical blanking period. Format: `crtc=0 seq=12345 time=1234567890 high-prec=true` indicates vblank on display controller 0, sequence number 12345. Track vblank frequency to verify refresh rate (60Hz = 60 vblanks/second). Missed sequences indicate frame drops. High-precision timestamps enable sub-millisecond frame timing analysis.

**drm_vblank_event_queued** and **drm_vblank_event_delivered** track vblank event delivery to userspace. Queuing latency (queue to delivery) measures kernel scheduling delay. Total latency (vblank to delivery) includes both kernel and driver processing. Latencies over 1ms indicate compositor problems. Correlate with frame drops visible to users - events delivered late mean missed frames.

## Running the Monitor Scripts

Navigate to the scripts directory and run the DRM scheduler monitor. It works on all GPUs:

```bash
cd bpf-developer-tutorial/src/xpu/gpu-kernel-driver/scripts
sudo bpftrace drm_scheduler.bt
```

Expected output:

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

Graphics jobs dominate (1523 vs 89 compute jobs). Few dependency waits (12) indicate good pipeline parallelism. For Intel GPUs, use `intel_i915.bt`. For AMD GPUs, use `amd_amdgpu.bt`. For display timing, use `drm_vblank.bt`. Run these during GPU workloads (gaming, ML training, video encoding) to capture activity patterns.

Verify tracepoints exist on your system before running scripts:

```bash
# All GPU tracepoints
sudo cat /sys/kernel/debug/tracing/available_events | grep -E '(gpu_scheduler|i915|amdgpu|^drm:)'
```

## Summary

GPU kernel tracepoints provide zero-overhead visibility into driver internals. DRM scheduler's stable uAPI tracepoints work across all vendors for production monitoring. Vendor-specific tracepoints expose detailed memory management and command submission pipelines. The bpftrace script demonstrates tracking job scheduling, measuring latency, and identifying dependency stalls - all critical for diagnosing performance issues in games, ML training, and cloud GPU workloads.

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
