# eBPF 实例教程：使用内核跟踪点监控 GPU 驱动活动

当游戏卡顿或机器学习训练变慢时，答案就隐藏在 GPU 内核驱动内部。Linux 内核跟踪点暴露了实时的作业调度、内存分配和命令提交数据。与周期性采样并错过事件的用户空间分析工具不同，内核跟踪点以纳秒级时间戳和最小开销捕获每个操作。

本教程展示如何使用 eBPF 和 bpftrace 监控 GPU 活动。我们将跟踪 DRM 调度器作业、测量延迟，并使用跨 Intel、AMD 和 Nouveau 驱动工作的稳定内核跟踪点诊断瓶颈。

## GPU 内核跟踪点：零开销可观测性

GPU 跟踪点是内核直接渲染管理器（DRM）子系统中内置的仪器点。当 GPU 调度作业、分配内存或发出栅栏信号时，这些跟踪点会以精确的时序和驱动状态触发。

关键洞察：内核跟踪点仅在事件发生时激活，每个事件添加纳秒级开销。它们捕获 100% 的活动，包括微秒级持续时间的作业。基于轮询的监控每 100ms 检查一次 GPU 状态，完全错过短期操作。

GPU 跟踪点跨越三层。**DRM 调度器跟踪点**（`gpu_scheduler` 事件组）是稳定的 uAPI - 格式永不改变。它们在 Intel、AMD 和 Nouveau 驱动上工作完全相同，适合供应商中立的监控。**供应商特定跟踪点**暴露驱动内部 - Intel i915 跟踪 GEM 对象创建和 VMA 绑定，AMD AMDGPU 监控缓冲对象和命令提交。**通用 DRM 跟踪点**通过 vblank 事件处理显示同步，用于诊断丢帧。

## DRM 调度器监视器：通用 GPU 跟踪

`drm_scheduler.bt` 脚本在**所有 GPU 驱动**上工作，因为它使用稳定的 uAPI 跟踪点。它跟踪作业提交（`drm_run_job`）、完成（`drm_sched_process_job`）和依赖等待（`drm_sched_job_wait_dep`）跨所有环。

### 完整的 Bpftrace 脚本：drm_scheduler.bt

```c
#!/usr/bin/env bpftrace
/*
 * drm_scheduler.bt - 监控 DRM GPU 调度器活动
 *
 * 此脚本使用稳定的 DRM 调度器跟踪点跟踪 GPU 作业调度。
 * 适用于所有现代 GPU 驱动（Intel i915、AMD AMDGPU、Nouveau 等）
 *
 * gpu_scheduler 跟踪点是稳定的 uAPI - 保证不会改变。
 *
 * 使用方法：sudo bpftrace drm_scheduler.bt
 */

BEGIN
{
    printf("正在跟踪 DRM GPU 调度器... 按 Ctrl-C 结束。\n");
    printf("%-18s %-12s %-16s %-12s %-8s %s\n",
           "时间(ms)", "事件", "作业ID", "环", "排队", "详情");
}

/* GPU 作业开始执行 */
tracepoint:gpu_scheduler:drm_run_job
{
    $job_id = args->id;
    $ring = str(args->name);
    $queue = args->job_count;
    $hw_queue = args->hw_job_count;

    /* 记录开始时间用于延迟计算 */
    @start[$job_id] = nsecs;

    printf("%-18llu %-12s %-16llu %-12s %-8u hw=%d\n",
           nsecs / 1000000,
           "RUN",
           $job_id,
           $ring,
           $queue,
           $hw_queue);

    /* 跟踪每个环的统计 */
    @jobs_per_ring[$ring] = count();
}

/* GPU 作业完成（栅栏已发出信号）*/
tracepoint:gpu_scheduler:drm_sched_process_job
{
    $fence = args->fence;

    printf("%-18llu %-12s %-16p\n",
           nsecs / 1000000,
           "COMPLETE",
           $fence);

    @completion_count = count();
}

/* 作业等待依赖 */
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
    printf("\n=== DRM 调度器统计 ===\n");
    printf("\n每个环的作业数：\n");
    print(@jobs_per_ring);
    printf("\n每个环的等待数：\n");
    print(@waits_per_ring);
}
```

### 理解脚本

脚本附加到三个稳定的 DRM 调度器跟踪点。当 `drm_run_job` 触发时，作业从"在软件中排队"转换为"在硅上运行"。跟踪点捕获 `args->id`（用于关联的作业 ID）、`args->name`（环名称 - 哪个执行引擎如图形、计算或视频解码）、`args->job_count`（队列深度 - 有多少作业在等待）和 `args->hw_job_count`（当前在 GPU 硬件上执行的作业）。

格式 `entity=0xffff888... id=12345 fence=0xffff888... ring=gfx job count:5 hw job count:2` 告诉你图形环上的作业 12345 开始执行，后面有 5 个作业排队，硬件上当前运行 2 个作业。多引擎 GPU 可以跨不同环并行运行作业。

我们记录 `@start[$job_id] = nsecs` 以启用延迟计算。脚本存储按作业 ID 键控的时间戳。稍后，在跟踪完成或测量端到端延迟时，你可以计算 `nsecs - @start[$job_id]` 以获得执行时间。`@jobs_per_ring[$ring] = count()` 行递增每个环的计数器，显示跨引擎的工作负载分布。

当 `drm_sched_process_job` 触发时，GPU 硬件完成了作业并发出其栅栏信号。栅栏指针 `args->fence` 标识已完成的作业。在 `drm_run_job` 和此跟踪点之间关联栅栏指针，让你可以计算 GPU 执行时间：`completion_time - run_time = GPU_execution_duration`。如果应该需要 5ms 的作业需要 50ms，你就发现了 GPU 性能问题。

`drm_sched_job_wait_dep` 跟踪点在作业阻塞等待栅栏时触发。在作业执行之前，其依赖项（它等待的先前作业）必须完成。格式显示 `args->ctx`（依赖上下文）和 `args->seqno`（序列号）标识哪个栅栏阻塞此作业。

这揭示了管道停顿。如果计算作业不断等待图形作业，你就没有利用并行性。长等待时间表明依赖链太深 - 考虑批处理独立工作。过度的依赖表示 CPU 端调度效率低下。`@waits_per_ring[$ring] = count()` 指标跟踪哪些环经历最多的依赖停顿。

程序结束时，`END` 块打印统计信息。`@jobs_per_ring` 显示每个执行引擎的作业计数 - 揭示特定环（视频编码、计算）是否饱和。`@waits_per_ring` 暴露依赖瓶颈。这些数据揭示了总体 GPU 利用率模式以及作业是否被依赖阻塞。

## Intel i915 跟踪点：内存管理深入分析

Intel 的 i915 驱动暴露了内存操作的详细跟踪点。这些需要内核配置中的 `CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS=y` - 使用 `grep CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS /boot/config-$(uname -r)` 检查。

**i915_gem_object_create** 在驱动分配 GEM（图形执行管理器）对象时触发 - GPU 可访问内存的基本单位。格式：`obj=0xffff888... size=0x100000` 表示分配 1MB 对象。随时间跟踪总分配内存以检测泄漏。性能下降前的突然分配峰值表示内存压力。将对象指针与后续绑定/故障事件关联以了解对象生命周期。

**i915_vma_bind** 跟踪将内存映射到 GPU 地址空间。分配内存还不够 - 它必须绑定到 GPU 虚拟地址空间。格式：`obj=0xffff888... offset=0x0000100000 size=0x10000 mappable vm=0xffff888...` 显示在 GPU 虚拟地址 0x100000 处绑定的 64KB。频繁的重新绑定表示内存抖动 - 驱动在压力下驱逐和重新绑定对象。GPU 页面故障通常与绑定操作相关。

**i915_gem_shrink** 捕获内存压力响应。在内存压力下，驱动回收 GPU 内存。格式：`dev=0 target=0x1000000 flags=0x3` 意味着驱动尝试回收 16MB。高收缩活动表示工作负载的 GPU 内存过小。与性能下降关联 - 如果在帧渲染期间发生收缩，会导致卡顿。

**i915_gem_object_fault** 跟踪 CPU 或 GPU 访问未映射内存时的页面故障。格式：`obj=0xffff888... GTT index=128 writable` 表示图形转换表页 128 上的写故障。故障代价昂贵 - 它们在内核解决缺失映射时停止执行。写故障比读故障更昂贵（需要使缓存失效）。GTT 故障表示作业提交前资源绑定不完整。

## AMD AMDGPU 跟踪点：命令提交管道

AMD 的 AMDGPU 驱动提供命令提交和硬件中断的全面跟踪。

**amdgpu_cs_ioctl** 捕获用户空间命令提交。当应用通过 ioctl 提交 GPU 工作时，此跟踪点触发。格式：`sched_job=12345 timeline=gfx context=1000 seqno=567 ring_name=gfx_0.0.0 num_ibs=2` 显示提交到图形环的作业 12345 有 2 个间接缓冲区。这标志着用户空间将工作交给内核的时间。记录时间戳以在与 `amdgpu_sched_run_job` 结合时测量提交到执行的延迟。高频率表示小批次 - 更好批处理的潜力。

**amdgpu_sched_run_job** 在内核调度器开始执行先前提交的作业时触发。将时间戳与 `amdgpu_cs_ioctl` 比较可揭示提交延迟。超过 100μs 的提交延迟表示内核调度延迟。每个环的延迟显示特定引擎是否受调度限制。

**amdgpu_bo_create** 跟踪缓冲对象分配 - AMD 的 i915 GEM 对象等价物。格式：`bo=0xffff888... pages=256 type=2 preferred=4 allowed=7 visible=1` 分配 1MB（256 页）。类型表示 VRAM 与 GTT（GPU 可访问的系统内存）。首选/允许域显示放置策略。类型不匹配（请求 VRAM 但回退到 GTT）表示 VRAM 耗尽。可见标志表示 CPU 可访问的内存 - 昂贵，谨慎使用。

**amdgpu_bo_move** 在缓冲对象在 VRAM 和 GTT 之间迁移时触发。迁移代价昂贵（需要通过 PCIe 复制数据）。过度的移动表示内存抖动 - 工作集超过 VRAM 容量。测量移动频率和大小以量化 PCIe 带宽消耗。与性能下降关联 - 迁移停止 GPU 执行。

**amdgpu_iv** 捕获 GPU 中断。GPU 为完成的工作、错误和事件发出中断信号。格式：`ih:0 client_id:1 src_id:42 ring:0 vmid:5 timestamp:1234567890 pasid:100 src_data: 00000001...` 捕获中断详细信息。源 ID 表示中断类型（完成、故障、热）。高中断率影响 CPU 性能。VMID 和 PASID 识别哪个进程/VM 触发了中断 - 对于多租户调试至关重要。

## DRM Vblank 跟踪点：显示同步

Vblank（垂直消隐）事件将渲染与显示刷新同步。错过 vblank 会导致丢帧和卡顿。

**drm_vblank_event** 在显示进入垂直消隐期时触发。格式：`crtc=0 seq=12345 time=1234567890 high-prec=true` 表示显示控制器 0 上的 vblank，序列号 12345。跟踪 vblank 频率以验证刷新率（60Hz = 60 vblanks/秒）。错过的序列表示丢帧。高精度时间戳启用亚毫秒帧时序分析。

**drm_vblank_event_queued** 和 **drm_vblank_event_delivered** 跟踪 vblank 事件传递到用户空间。排队延迟（队列到传递）测量内核调度延迟。总延迟（vblank 到传递）包括内核和驱动处理。超过 1ms 的延迟表示合成器问题。与用户可见的丢帧关联 - 延迟传递的事件意味着错过的帧。

## 运行监控脚本

导航到脚本目录并运行 DRM 调度器监视器。它在所有 GPU 上工作：

```bash
cd bpf-developer-tutorial/src/xpu/gpu-kernel-driver/scripts
sudo bpftrace drm_scheduler.bt
```

预期输出：

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

图形作业占主导地位（1523 对 89 个计算作业）。很少的依赖等待（12）表示良好的管道并行性。对于 Intel GPU，使用 `intel_i915.bt`。对于 AMD GPU，使用 `amd_amdgpu.bt`。对于显示时序，使用 `drm_vblank.bt`。在 GPU 工作负载（游戏、ML 训练、视频编码）期间运行这些脚本以捕获活动模式。

在运行脚本之前验证跟踪点存在于你的系统上：

```bash
# 所有 GPU 跟踪点
sudo cat /sys/kernel/debug/tracing/available_events | grep -E '(gpu_scheduler|i915|amdgpu|^drm:)'
```

## 总结

GPU 内核跟踪点提供零开销的驱动内部可见性。DRM 调度器的稳定 uAPI 跟踪点跨所有供应商工作，适合生产监控。供应商特定跟踪点暴露详细的内存管理和命令提交管道。bpftrace 脚本演示了跟踪作业调度、测量延迟和识别依赖停顿 - 所有这些对于诊断游戏、ML 训练和云 GPU 工作负载中的性能问题都至关重要。

> 如果你想深入了解 eBPF，请查看我们的教程仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- **Linux 内核源码**: `/drivers/gpu/drm/`
- **DRM 调度器**: `/drivers/gpu/drm/scheduler/gpu_scheduler_trace.h`
- **Intel i915**: `/drivers/gpu/drm/i915/i915_trace.h`
- **AMD AMDGPU**: `/drivers/gpu/drm/amd/amdgpu/amdgpu_trace.h`
- **通用 DRM**: `/drivers/gpu/drm/drm_trace.h`
- **内核跟踪点文档**: `Documentation/trace/tracepoints.rst`
- **教程仓库**: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/xpu/gpu-kernel-driver>

完整的源代码包括所有 bpftrace 脚本和测试用例可在教程仓库中获得。欢迎贡献和问题报告！
