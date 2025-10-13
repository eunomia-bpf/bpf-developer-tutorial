# eBPF 实例教程：使用内核跟踪点监控 GPU 驱动活动

当游戏卡顿或机器学习训练变慢时，答案就隐藏在 GPU 内核驱动内部。Linux 内核跟踪点暴露了实时的作业调度、内存分配和命令提交数据。与周期性采样并错过事件的用户空间分析工具不同，内核跟踪点以纳秒级时间戳和最小开销捕获每个操作。

本教程展示如何使用 eBPF 和 bpftrace 监控 GPU 活动。我们将跟踪 DRM 调度器作业、测量延迟，并使用跨 Intel、AMD 和 Nouveau 驱动工作的稳定内核跟踪点诊断瓶颈。

## GPU 内核跟踪点：零开销可观测性

GPU 跟踪点是内核直接渲染管理器（DRM）子系统中内置的仪器点。当 GPU 调度作业、分配内存或发出栅栏信号时，这些跟踪点会以精确的时序和驱动状态触发。

关键洞察：内核跟踪点仅在事件发生时激活，每个事件添加纳秒级开销。它们捕获 100% 的活动，包括微秒级持续时间的作业。基于轮询的监控每 100ms 检查一次 GPU 状态，完全错过短期操作。

GPU 跟踪点跨越三层。DRM 调度器跟踪点(`gpu_scheduler` 事件组)是稳定的 uAPI,格式永不改变。它们在 Intel、AMD 和 Nouveau 驱动上工作完全相同，适合供应商中立的监控。供应商特定跟踪点暴露驱动内部。Intel i915 跟踪 GEM 对象创建和 VMA 绑定，而 AMD AMDGPU 监控缓冲对象和命令提交。通用 DRM 跟踪点通过 vblank 事件处理显示同步，用于诊断丢帧。

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

Intel 的 i915 驱动暴露了内存操作的详细跟踪点。这些需要内核配置中的 `CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS=y`,使用 `grep CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS /boot/config-$(uname -r)` 检查。

i915_gem_object_create 在驱动分配 GEM(图形执行管理器)对象时触发,这是 GPU 可访问内存的基本单位。格式：`obj=0xffff888... size=0x100000` 表示分配 1MB 对象。随时间跟踪总分配内存以检测泄漏。性能下降前的突然分配峰值表示内存压力。将对象指针与后续绑定/故障事件关联以了解对象生命周期。

i915_vma_bind 跟踪将内存映射到 GPU 地址空间。分配内存还不够,它必须绑定到 GPU 虚拟地址空间。格式：`obj=0xffff888... offset=0x0000100000 size=0x10000 mappable vm=0xffff888...` 显示在 GPU 虚拟地址 0x100000 处绑定的 64KB。频繁的重新绑定表示内存抖动,即驱动在压力下驱逐和重新绑定对象。GPU 页面故障通常与绑定操作相关。

i915_gem_shrink 捕获内存压力响应。在内存压力下，驱动回收 GPU 内存。格式：`dev=0 target=0x1000000 flags=0x3` 意味着驱动尝试回收 16MB。高收缩活动表示工作负载的 GPU 内存过小。与性能下降关联,如果在帧渲染期间发生收缩，会导致卡顿。

i915_gem_object_fault 跟踪 CPU 或 GPU 访问未映射内存时的页面故障。格式：`obj=0xffff888... GTT index=128 writable` 表示图形转换表页 128 上的写故障。故障代价昂贵,因为它们在内核解决缺失映射时停止执行。写故障比读故障更昂贵,因为需要使缓存失效。GTT 故障表示作业提交前资源绑定不完整。

## AMD AMDGPU 跟踪点：命令提交管道

AMD 的 AMDGPU 驱动提供命令提交和硬件中断的全面跟踪。

amdgpu_cs_ioctl 捕获用户空间命令提交。当应用通过 ioctl 提交 GPU 工作时，此跟踪点触发。格式：`sched_job=12345 timeline=gfx context=1000 seqno=567 ring_name=gfx_0.0.0 num_ibs=2` 显示提交到图形环的作业 12345 有 2 个间接缓冲区。这标志着用户空间将工作交给内核的时间。记录时间戳以在与 `amdgpu_sched_run_job` 结合时测量提交到执行的延迟。高频率表示小批次和更好批处理的潜力。

amdgpu_sched_run_job 在内核调度器开始执行先前提交的作业时触发。将时间戳与 `amdgpu_cs_ioctl` 比较可揭示提交延迟。超过 100μs 的提交延迟表示内核调度延迟。每个环的延迟显示特定引擎是否受调度限制。

amdgpu_bo_create 跟踪缓冲对象分配,这是 AMD 的 i915 GEM 对象等价物。格式：`bo=0xffff888... pages=256 type=2 preferred=4 allowed=7 visible=1` 分配 1MB(256 页)。类型表示 VRAM 与 GTT(GPU 可访问的系统内存)。首选/允许域显示放置策略。请求 VRAM 但使用 GTT 的类型不匹配表示 VRAM 耗尽。可见标志表示 CPU 可访问的内存,这很昂贵，应谨慎使用。

amdgpu_bo_move 在缓冲对象在 VRAM 和 GTT 之间迁移时触发。迁移代价昂贵,因为需要通过 PCIe 复制数据。过度的移动表示内存抖动,即工作集超过 VRAM 容量。测量移动频率和大小以量化 PCIe 带宽消耗。与性能下降关联,因为迁移会停止 GPU 执行。

amdgpu_iv 捕获 GPU 中断。GPU 为完成的工作、错误和事件发出中断信号。格式：`ih:0 client_id:1 src_id:42 ring:0 vmid:5 timestamp:1234567890 pasid:100 src_data: 00000001...` 捕获中断详细信息。源 ID 表示中断类型(完成、故障、热)。高中断率影响 CPU 性能。VMID 和 PASID 识别哪个进程/VM 触发了中断,这对于多租户调试至关重要。

## DRM Vblank 跟踪点：显示同步

Vblank（垂直消隐）事件将渲染与显示刷新同步。错过 vblank 会导致丢帧和卡顿。

**drm_vblank_event** 在显示进入垂直消隐期时触发。格式：`crtc=0 seq=12345 time=1234567890 high-prec=true` 表示显示控制器 0 上的 vblank，序列号 12345。跟踪 vblank 频率以验证刷新率（60Hz = 60 vblanks/秒）。错过的序列表示丢帧。高精度时间戳启用亚毫秒帧时序分析。

**drm_vblank_event_queued** 和 **drm_vblank_event_delivered** 跟踪 vblank 事件传递到用户空间。排队延迟（队列到传递）测量内核调度延迟。总延迟（vblank 到传递）包括内核和驱动处理。超过 1ms 的延迟表示合成器问题。与用户可见的丢帧关联 - 延迟传递的事件意味着错过的帧。

## NVIDIA 专有驱动：不同的架构

与使用内核直接渲染管理器（DRM）子系统的 Intel、AMD 和 Nouveau 不同，**NVIDIA 的专有驱动（nvidia.ko）在 DRM 之外运行**。它实现了自己的内核模块接口，带有供应商特定的函数和单个跟踪点。这种架构差异意味着 NVIDIA GPU 需要不同的监控方法 - 我们附加到 nvidia.ko 函数的内核探针，而不是 DRM 跟踪点。

关键区别：DRM 驱动暴露标准化的 `gpu_scheduler` 跟踪点，在供应商之间工作完全相同。NVIDIA 的闭源驱动只提供一个跟踪点（`nvidia:nvidia_dev_xid` 用于硬件错误），需要监控内部内核函数如 `nvidia_open`、`nvidia_unlocked_ioctl` 和 `nvidia_isr`。这使得 NVIDIA 监控更脆弱 - 函数名称可能在驱动版本之间改变 - 但仍然提供有价值的 GPU 活动洞察。

### NVIDIA 驱动监控：nvidia_driver.bt

`nvidia_driver.bt` 脚本通过对专有驱动的内核探针跟踪 NVIDIA GPU 操作。与供应商中立的 DRM 调度器监控不同，此脚本是 NVIDIA 特定的，需要加载专有 nvidia.ko 模块。完整源代码可在 `scripts/nvidia_driver.bt` 中找到。

**关键脚本特性：**

脚本附加 18 个内核探针以监控：
- **设备操作**：open、close、ioctl（采样 1% 以降低开销）
- **内存管理**：mmap、页故障、VMA 操作
- **中断处理**：ISR、MSI-X、下半部处理程序及延迟直方图
- **P2P 通信**：GPU 到 GPU 的页面请求和 DMA 映射
- **电源管理**：挂起/恢复周期及持续时间跟踪
- **错误报告**：通过 `nvidia:nvidia_dev_xid` 跟踪点报告 Xid 硬件/驱动错误

**运行 NVIDIA 驱动监视器**

验证 NVIDIA 驱动已加载并检查可用探针：

```bash
# 检查 NVIDIA 驱动模块
lsmod | grep nvidia

# 列出可用的 NVIDIA 探针
sudo bpftrace -l 'kprobe:nvidia_*' | head -20
sudo bpftrace -l 'tracepoint:nvidia:*'
```

在 GPU 工作负载期间运行监视器：

```bash
cd bpf-developer-tutorial/src/xpu/gpu-kernel-driver
sudo bpftrace scripts/nvidia_driver.bt
```

**真实执行输出**（捕获 llama-server（LLM 推理）、nvtop（GPU 监控）和 CUDA 应用清理）：

```
Attaching 18 probes...
Tracing NVIDIA GPU driver activity... Hit Ctrl-C to end.
TIME(ms)     EVENT              COMM             PID      GPU_ID   DETAILS
2627         IOCTL              nvtop            759434   -        cmd=0xc020462a
38984        CLOSE              python           783815   -        GPU device closed
70693        CLOSE              cuda00001400006  781802   -        GPU device closed
72427        OPEN               llama-server     800150   -        GPU device opened
72427        CLOSE              llama-server     800150   -        GPU device closed
72427        OPEN               llama-server     800150   -        GPU device opened
72428        OPEN               llama-server     800150   -        GPU device opened
72431        MMAP               llama-server     800150   -        offset=0xffff968357d37140 size=...
72448        OPEN               llama-server     800150   -        GPU device opened
... (在初始化期间 llama-server 的 39 次 open，26 次 mmap)

========================================
  NVIDIA GPU Driver Statistics
========================================

--- Device Operations ---
Opens by process:
@opens[llama-server]: 39

Closes by process:
@closes[llama-server]: 1
@closes[python]: 8
@closes[cuda00001400006]: 38

Total ioctls:
@ioctl_count: 2779
Top ioctl callers:
@ioctls_per_process[llama-server]: 422
@ioctls_per_process[nvtop]: 2357

Total mmaps:
@mmap_count: 26

--- Async Operations ---
Poll calls:
@poll_count: 24254

Currently open PIDs:
@open_pids[800150]: 1
```

**分析**：这个真实世界的跟踪揭示了几个模式。llama-server 进程在初始化期间打开了 GPU 设备 39 次 - 对于为不同模型层或批处理策略初始化多个 CUDA 上下文的 LLM 推理引擎来说很典型。来自 llama-server 的 422 次 ioctl 表示活跃的推理工作。nvtop 监控工具发出了 2,357 次 ioctl 轮询 GPU 状态。脚本捕获了来自终止 CUDA 应用（cuda00001400006）的 38 次设备关闭和来自 Python 进程的 8 次 - 显示清理模式。24,254 次轮询调用表示来自监控工具的高异步 I/O 活动。零页故障表明所有内存都已正确预分配。零 Xid 错误意味着硬件运行正常。当前打开的 PID 800150（llama-server）在跟踪结束后仍保持活动状态。

## 运行监控脚本

导航到教程目录并根据你的 GPU 运行适当的监视器。

**对于基于 DRM 的 GPU（Intel、AMD、Nouveau）** - 通用监控：

```bash
cd bpf-developer-tutorial/src/xpu/gpu-kernel-driver
sudo bpftrace scripts/drm_scheduler.bt
```

**对于 NVIDIA 专有驱动**：

```bash
cd bpf-developer-tutorial/src/xpu/gpu-kernel-driver
sudo bpftrace scripts/nvidia_driver.bt
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

## 局限性：内核追踪 vs GPU 侧可观测性

本教程主要关注内核侧的 GPU 驱动追踪，这为我们提供了作业调度、内存管理和驱动-固件通信的可见性。然而，内核跟踪点存在根本性的局限。当 `drm_run_job` 触发时，我们知道作业开始在 GPU 硬件上执行，但无法观察到 GPU 内部实际发生了什么。成千上万个并行线程的执行、它们的内存访问模式、分支分化、warp 占用率和指令级行为都是不可见的。这些细节对于理解性能瓶颈至关重要 - 内存合并是否失败、线程分化是否降低了效率，或者共享内存 bank 冲突是否导致执行停顿。

要实现细粒度的 GPU 可观测性，eBPF 程序必须直接在 GPU 上运行。这正是 eGPU 论文和 [bpftime GPU 示例](https://github.com/eunomia-bpf/bpftime/tree/master/example/gpu)所探索的方向。bpftime 将 eBPF 字节码转换为 GPU 可以执行的 PTX 指令，然后在运行时动态修补 CUDA 二进制文件，将这些 eBPF 程序注入到内核入口/出口点。这使得开发者可以观察 GPU 特有的信息，如块索引、线程索引、全局计时器和 warp 级指标。开发者可以在 GPU 内核的关键路径上进行插桩，测量执行行为并诊断内核侧追踪无法触及的复杂性能问题。这种 GPU 内部的可观测性与内核跟踪点互补 - 它们一起提供了从 API 调用通过内核驱动到 GPU 执行的端到端可见性。

## 总结

GPU 内核跟踪点提供零开销的驱动内部可见性。DRM 调度器的稳定 uAPI 跟踪点跨所有供应商工作，适合生产监控。供应商特定跟踪点暴露详细的内存管理和命令提交管道。bpftrace 脚本演示了跟踪作业调度、测量延迟和识别依赖停顿 - 所有这些对于诊断游戏、ML 训练和云 GPU 工作负载中的性能问题都至关重要。对于超越内核追踪的 GPU 内部可观测性，请探索 bpftime 的 GPU eBPF 能力。

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
