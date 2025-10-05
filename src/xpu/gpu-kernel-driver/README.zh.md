# eBPF 教程：使用内核跟踪点监控 GPU 驱动活动

你是否曾经想知道你的 GPU 在底层到底在做什么？当游戏卡顿、机器学习训练变慢或视频编码冻结时，答案就隐藏在内核 GPU 驱动的深处。传统调试依赖于猜测和供应商特定的工具，但有更好的方法。Linux 内核 GPU 跟踪点暴露了作业调度、内存分配和命令提交的实时洞察 - 而 eBPF 让你可以以最小的开销分析这些数据。

在本教程中，我们将探索跨 DRM 调度器、Intel i915 和 AMD AMDGPU 驱动的 GPU 内核跟踪点。我们将编写 bpftrace 脚本来监控实时 GPU 活动、跟踪内存压力、测量作业延迟并诊断性能瓶颈。最后，你将拥有生产就绪的监控工具以及对 GPU 如何与内核交互的深入了解。

## 理解 GPU 内核跟踪点

GPU 跟踪点是直接内置在内核的直接渲染管理器（DRM）子系统中的仪器点。当你的 GPU 调度作业、分配内存或发出栅栏信号时，这些跟踪点会触发 - 捕获精确的时序、资源标识符和驱动状态。与周期性采样并错过事件的用户空间分析工具不同，内核跟踪点以纳秒级时间戳捕获每一个操作。

### 为什么内核跟踪点对 GPU 监控很重要

想想当你启动 GPU 工作负载时会发生什么。你的应用通过图形 API（Vulkan、OpenGL、CUDA）提交命令。用户空间驱动将这些转换为硬件特定的命令缓冲区。内核驱动接收 ioctl，验证工作，分配 GPU 内存，将资源绑定到 GPU 地址空间，在硬件环上调度作业，并等待完成。传统分析看到开始和结束 - 内核跟踪点看到每一步。

性能影响是显著的。基于轮询的监控每 100ms 检查一次 GPU 状态，每次检查都会消耗 CPU 周期。跟踪点仅在事件发生时激活，每个事件仅添加纳秒级的开销，并捕获 100% 的活动，包括微秒级持续时间的作业。对于 Kubernetes GPU 工作负载的生产监控或调试 ML 训练性能，这种差异至关重要。

### DRM 跟踪点生态系统

GPU 跟踪点跨越图形堆栈的三层。**DRM 调度器跟踪点**（gpu_scheduler 事件组）被标记为稳定的 uAPI - 它们的格式永远不会改变。这些在 Intel、AMD 和 Nouveau 驱动上工作完全相同，使它们成为供应商中立监控的完美选择。它们跟踪作业提交（`drm_run_job`）、完成（`drm_sched_process_job`）和依赖等待（`drm_sched_job_wait_dep`）。

**供应商特定跟踪点**暴露驱动内部。Intel i915 跟踪点跟踪 GEM 对象创建（`i915_gem_object_create`）、VMA 绑定到 GPU 地址空间（`i915_vma_bind`）、内存压力事件（`i915_gem_shrink`）和页面故障（`i915_gem_object_fault`）。AMD AMDGPU 跟踪点监控缓冲对象生命周期（`amdgpu_bo_create`）、从用户空间提交命令（`amdgpu_cs_ioctl`）、调度器执行（`amdgpu_sched_run_job`）和 GPU 中断（`amdgpu_iv`）。注意 Intel 低级跟踪点需要在内核配置中启用 `CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS=y`。

**通用 DRM 跟踪点**通过 vblank 事件处理显示同步 - 对于诊断丢帧和合成器延迟至关重要。事件包括 vblank 发生（`drm_vblank_event`）、用户空间排队（`drm_vblank_event_queued`）和传递（`drm_vblank_event_delivered`）。

### 实际应用场景

GPU 跟踪点解决了传统工具无法触及的问题。**诊断游戏卡顿**：你注意到每隔几秒就会丢帧。Vblank 跟踪点揭示了错过的垂直消隐。作业调度跟踪显示命令提交中的 CPU 端延迟。内存跟踪点暴露在关键帧期间触发驱逐的分配。几分钟内你就能识别出纹理上传正在阻塞渲染管道。

**优化 ML 训练性能**：你的 PyTorch 训练比预期慢 40%。AMDGPU 命令提交跟踪揭示了过度同步 - CPU 过于频繁地等待 GPU 完成。作业依赖跟踪点显示独立操作之间不必要的栅栏。内存跟踪暴露了 VRAM 和系统 RAM 之间的抖动。你重新组织批处理以消除停顿。

**云 GPU 计费准确性**：多租户系统需要公平的能源和资源核算。DRM 调度器跟踪点将确切的 GPU 时间归因于每个容器。内存跟踪点跟踪每个工作负载的分配。这些数据馈送到基于实际资源消耗而非基于时间估计收费的准确计费系统。

**热节流调查**：GPU 性能在负载下降级。中断跟踪显示来自 GPU 的热事件。作业调度跟踪揭示影响执行时间的频率缩放。内存迁移跟踪显示驱动将工作负载移动到更冷的 GPU 芯片。你调整功率限制并改善气流。

## 跟踪点参考指南

让我们详细检查每个跟踪点类别，了解它们暴露的数据以及如何解释它。

### DRM 调度器跟踪点：通用 GPU 监视器

DRM 调度器提供 GPU 作业管理的供应商中立视图。无论你运行的是 Intel 集成显卡、AMD 独立 GPU 还是 NVIDIA 硬件上的 Nouveau，这些跟踪点的工作方式都完全相同。

#### drm_run_job：GPU 工作开始执行时

当调度器将作业分配给 GPU 硬件时，`drm_run_job` 触发。这标志着从"在软件中排队"到"在硅上主动运行"的转换。跟踪点捕获作业 ID（关联的唯一标识符）、环名称（哪个执行引擎：图形、计算、视频解码）、队列深度（有多少作业在等待）和硬件作业计数（当前在 GPU 上执行的作业）。

格式看起来像：`entity=0xffff888... id=12345 fence=0xffff888... ring=gfx job count:5 hw job count:2`。这告诉你图形环上的作业 12345 开始执行。五个作业在它后面排队，两个作业当前在硬件上运行（多引擎 GPU 可以并行运行作业）。

使用此来测量作业调度延迟。记录用户空间提交工作时的时间戳（使用命令提交跟踪点），然后测量到 `drm_run_job` 触发的时间。超过 1ms 的延迟表示 CPU 端调度延迟。每个环的统计数据揭示特定引擎（视频编码、计算）是否存在瓶颈。

#### drm_sched_process_job：作业完成信号

当 GPU 硬件完成作业并发出其栅栏信号时，此跟踪点触发。栅栏指针标识已完成的作业 - 将其与 `drm_run_job` 关联以计算 GPU 执行时间。格式：`fence=0xffff888... signaled`。

与 `drm_run_job` 时间戳结合以计算作业执行时间：`completion_time - run_time = GPU_execution_duration`。如果应该需要 5ms 的作业需要 50ms，你就发现了 GPU 性能问题。吞吐量指标（每秒完成的作业）表示总体 GPU 利用率。

#### drm_sched_job_wait_dep：依赖停顿

在作业可以执行之前，其依赖项（它等待的先前作业）必须完成。此跟踪点在作业阻塞等待栅栏时触发。格式：`job ring=gfx id=12345 depends fence=0xffff888... context=1234 seq=567`。

这揭示了管道停顿。如果计算作业不断等待图形作业，你就没有利用并行性。如果等待时间很长，依赖链太深 - 考虑批处理独立工作。过度的依赖表示 CPU 端调度效率低下。

### Intel i915 跟踪点：内存和 I/O 深入分析

Intel 的 i915 驱动暴露了内存管理和数据传输的详细跟踪点。这些需要 `CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS=y` - 使用 `grep CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS /boot/config-$(uname -r)` 检查。

#### i915_gem_object_create：GPU 内存分配

当驱动分配 GEM（图形执行管理器）对象 - GPU 可访问内存的基本单位时，此触发。格式：`obj=0xffff888... size=0x100000` 表示分配 1MB 对象。

随时间跟踪总分配内存以检测泄漏。性能下降前的突然分配峰值表示内存压力。将对象指针与后续绑定/故障事件关联以了解对象生命周期。高频率小分配表示低效批处理。

#### i915_vma_bind：将内存映射到 GPU 地址空间

分配内存还不够 - 它必须映射（绑定）到 GPU 地址空间。此跟踪点在 VMA（虚拟内存区域）绑定时触发。格式：`obj=0xffff888... offset=0x0000100000 size=0x10000 mappable vm=0xffff888...` 显示在 GPU 虚拟地址 0x100000 处绑定的 64KB。

绑定开销影响性能。频繁的重新绑定表示内存抖动 - 驱动在压力下驱逐和重新绑定对象。GPU 页面故障通常与绑定操作相关 - CPU 在 GPU 访问之前绑定内存。像 `PIN_MAPPABLE` 这样的标志表示 CPU 和 GPU 都可以访问的内存。

#### i915_gem_shrink：内存压力响应

在内存压力下，驱动回收 GPU 内存。格式：`dev=0 target=0x1000000 flags=0x3` 意味着驱动尝试回收 16MB。高收缩活动表示工作负载的 GPU 内存过小。

与性能下降关联 - 如果在帧渲染期间发生收缩，会导致卡顿。标志表示收缩的激进程度。反复收缩小目标表示内存碎片。将目标与实际释放量（跟踪对象销毁）进行比较以测量回收效率。

#### i915_gem_object_fault：GPU 页面故障

当 CPU 或 GPU 访问未映射的内存时，会发生故障。格式：`obj=0xffff888... GTT index=128 writable` 表示图形转换表页 128 上的写故障。故障代价昂贵 - 它们在内核解决缺失映射时停止执行。

过度的故障会降低性能。写故障比读故障更昂贵（需要使缓存失效）。GTT 故障（GPU 访问未映射的内存）表示作业提交前资源绑定不完整。CPU 故障表示低效的 CPU/GPU 同步 - CPU 在 GPU 使用对象时访问它们。

### AMD AMDGPU 跟踪点：命令流和中断

AMD 的 AMDGPU 驱动提供命令提交和硬件中断的全面跟踪。

#### amdgpu_cs_ioctl：用户空间命令提交

当应用通过 ioctl 提交 GPU 工作时，此捕获请求。格式：`sched_job=12345 timeline=gfx context=1000 seqno=567 ring_name=gfx_0.0.0 num_ibs=2` 显示提交到图形环的作业 12345 有 2 个间接缓冲区。

这标志着用户空间将工作交给内核的时间。记录时间戳以在与 `amdgpu_sched_run_job` 结合时测量提交到执行的延迟。高频率表示小批次 - 更好批处理的潜力。每个环的分布显示跨引擎的工作负载平衡。

#### amdgpu_sched_run_job：内核调度作业

内核调度器开始执行先前提交的作业。将时间戳与 `amdgpu_cs_ioctl` 比较可揭示提交延迟。格式包括作业 ID 和用于关联的环。

超过 100μs 的提交延迟表示内核调度延迟。每个环的延迟显示特定引擎是否受调度限制。与 CPU 调度器跟踪关联以识别内核线程是否被抢占。

#### amdgpu_bo_create：缓冲对象分配

AMD 的 i915 GEM 对象等价物。格式：`bo=0xffff888... pages=256 type=2 preferred=4 allowed=7 visible=1` 分配 1MB（256 页）。类型表示 VRAM 与 GTT（GPU 可访问的系统内存）。首选/允许域显示放置策略。

跟踪 VRAM 分配以监控内存使用。类型不匹配（请求 VRAM 但回退到 GTT）表示 VRAM 耗尽。可见标志表示 CPU 可访问的内存 - 昂贵，谨慎使用。

#### amdgpu_bo_move：内存迁移

当缓冲对象在 VRAM 和 GTT 之间迁移时，此触发。迁移代价昂贵（需要通过 PCIe 复制数据）。过度的移动表示内存抖动 - 工作集超过 VRAM 容量。

测量移动频率和大小以量化 PCIe 带宽消耗。与性能下降关联 - 迁移停止 GPU 执行。通过减少工作集或使用更智能的放置策略（将频繁访问的数据保留在 VRAM 中）进行优化。

#### amdgpu_iv：GPU 中断

GPU 为完成的工作、错误和事件发出中断信号。格式：`ih:0 client_id:1 src_id:42 ring:0 vmid:5 timestamp:1234567890 pasid:100 src_data: 00000001...` 捕获中断详细信息。

源 ID 表示中断类型（完成、故障、热）。高中断率影响 CPU 性能。意外中断表示硬件错误。VMID 和 PASID 识别哪个进程/VM 触发了中断 - 对于多租户调试至关重要。

### DRM Vblank 跟踪点：显示同步

Vblank（垂直消隐）事件将渲染与显示刷新同步。错过 vblank 会导致丢帧和卡顿。

#### drm_vblank_event：垂直消隐发生

当显示进入垂直消隐期时，此触发。格式：`crtc=0 seq=12345 time=1234567890 high-prec=true` 表示显示控制器 0 上的 vblank，序列号 12345。

跟踪 vblank 频率以验证刷新率（60Hz = 60 vblanks/秒）。错过的序列表示丢帧。高精度时间戳启用亚毫秒帧时序分析。多显示器设置的每 CRTC 跟踪。

#### drm_vblank_event_queued 和 drm_vblank_event_delivered

这些跟踪 vblank 事件传递到用户空间。排队延迟（队列到传递）测量内核调度延迟。总延迟（vblank 到传递）包括内核和驱动处理。

超过 1ms 的延迟表示合成器问题。跨 CRTC 比较以识别有问题的显示。与用户可见的丢帧关联 - 延迟传递的事件意味着错过的帧。

## 使用 Bpftrace 脚本监控

我们为生产监控创建了供应商特定的 bpftrace 脚本。每个脚本专注于其 GPU 供应商的特定跟踪点，同时共享通用输出格式。

### DRM 调度器监视器：通用 GPU 跟踪

`drm_scheduler.bt` 脚本在**所有 GPU 驱动**上工作，因为它使用稳定的 uAPI 跟踪点。它跟踪所有环上的作业，测量完成率，并识别依赖停顿。

脚本附加到 `gpu_scheduler:drm_run_job`、`gpu_scheduler:drm_sched_process_job` 和 `gpu_scheduler:drm_sched_job_wait_dep`。在作业开始时，它在按作业 ID 键控的 map 中记录时间戳以供以后计算延迟。它递增每个环的计数器以显示工作负载分布。在完成时，它打印栅栏信息。在依赖等待时，它显示哪个作业阻塞哪个栅栏。

输出显示时间戳、事件类型（RUN/COMPLETE/WAIT_DEP）、作业 ID、环名称和队列深度。程序结束时，统计数据总结每个环的作业和依赖等待计数。这揭示了特定环是否饱和、作业是否被依赖阻塞以及总体 GPU 利用率模式。

### Intel i915 监视器：内存和 I/O 分析

`intel_i915.bt` 脚本跟踪 Intel GPU 内存操作、I/O 传输和页面故障。它需要 `CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS=y`。

在 `i915_gem_object_create` 上，它累积总分配内存并存储每个对象的大小。VMA 绑定/解绑事件跟踪 GPU 地址空间更改。收缩事件测量内存压力。Pwrite/pread 跟踪 CPU-GPU 数据传输。故障按类型分类（GTT 与 CPU，读与写）。

输出报告分配大小和以 MB 为单位的运行总计。绑定操作显示 GPU 虚拟地址和标志。I/O 操作跟踪偏移量和长度。故障指示类型以及它们是读还是写。结束统计汇总总分配、VMA 操作、内存压力（收缩操作和回收字节）、I/O 量（读/写计数和大小）以及故障分析（总故障，写与读）。

这揭示了内存泄漏（没有相应释放的分配）、绑定开销（频繁的重新绑定表示抖动）、内存压力时序（将收缩与性能下降关联）、I/O 模式（大传输与许多小传输）和故障热点（要优化的昂贵操作）。

### AMD AMDGPU 监视器：命令提交分析

`amd_amdgpu.bt` 脚本专注于 AMD 的命令提交管道，测量从 ioctl 到执行的延迟。

在 `amdgpu_cs_ioctl` 上，它记录按作业 ID 键控的提交时间戳。当 `amdgpu_sched_run_job` 触发时，它计算延迟：`(current_time - submit_time)`。缓冲对象创建/移动事件跟踪内存。中断事件按源 ID 计数。虚拟内存操作（刷新、映射、取消映射）测量 TLB 活动。

输出显示时间戳、事件类型、作业 ID、环名称和以微秒为单位的计算延迟。结束统计包括内存分配总计、每个环的命令提交计数、提交延迟的平均值和分布（直方图显示有多少作业经历了不同的延迟桶）、按源的中断计数以及虚拟内存操作计数。

延迟直方图至关重要 - 大多数作业应该有 <50μs 的延迟。高延迟作业的尾部表示调度问题。每个环的统计显示计算工作负载是否具有与图形不同的延迟。内存迁移跟踪有助于诊断 VRAM 压力。

### 显示 Vblank 监视器：帧时序分析

`drm_vblank.bt` 脚本跟踪显示同步以诊断丢帧。

在 `drm_vblank_event` 上，它记录按 CRTC 和序列键控的时间戳。当 `drm_vblank_event_queued` 触发时，它时间戳队列时间。在 `drm_vblank_event_delivered` 上，它计算队列到传递延迟和总 vblank 到传递延迟。

输出显示 vblank 事件、排队事件和带时间戳的传递事件。结束统计包括每个 CRTC 的总 vblank 计数、事件传递计数、平均传递延迟、延迟分布直方图以及总事件延迟（vblank 发生到用户空间传递）。

超过 1ms 的传递延迟表示合成器调度问题。总延迟揭示应用可见的端到端延迟。每 CRTC 统计显示特定显示器是否有问题。延迟直方图暴露导致可见卡顿的异常值。

## 运行监视器

让我们跟踪实时 GPU 活动。导航到脚本目录并使用 bpftrace 运行任何监视器。DRM 调度器监视器在所有 GPU 上工作：

```bash
cd bpf-developer-tutorial/src/xpu/gpu-kernel-driver/scripts
sudo bpftrace drm_scheduler.bt
```

你将看到如下输出：

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

这显示图形作业主导工作负载（1523 对 89 个计算作业）。很少的依赖等待（12）表示良好的管道并行性。

对于 Intel GPU，运行 i915 监视器：

```bash
sudo bpftrace intel_i915.bt
```

对于 AMD GPU：

```bash
sudo bpftrace amd_amdgpu.bt
```

对于显示时序：

```bash
sudo bpftrace drm_vblank.bt
```

每个脚本都输出实时事件和运行结束统计。在 GPU 工作负载（游戏、ML 训练、视频编码）期间运行它们以捕获特征模式。

## 验证跟踪点可用性

在运行脚本之前，验证你的系统上存在跟踪点。我们包含了一个测试脚本：

```bash
cd bpf-developer-tutorial/src/xpu/gpu-kernel-driver/tests
sudo ./test_basic_tracing.sh
```

这检查 gpu_scheduler、drm、i915 和 amdgpu 事件组。它报告哪些跟踪点可用并为你的硬件推荐适当的监控脚本。对于 Intel 系统，它验证内核配置中是否启用了低级跟踪点。

你还可以手动检查可用的跟踪点：

```bash
# 所有 GPU 跟踪点
sudo cat /sys/kernel/debug/tracing/available_events | grep -E '(gpu_scheduler|i915|amdgpu|^drm:)'

# DRM 调度器（稳定，所有供应商）
sudo cat /sys/kernel/debug/tracing/available_events | grep gpu_scheduler

# Intel i915
sudo cat /sys/kernel/debug/tracing/available_events | grep i915

# AMD AMDGPU
sudo cat /sys/kernel/debug/tracing/available_events | grep amdgpu
```

要手动启用跟踪点并查看原始输出：

```bash
# 启用 drm_run_job
echo 1 | sudo tee /sys/kernel/debug/tracing/events/gpu_scheduler/drm_run_job/enable

# 查看跟踪输出
sudo cat /sys/kernel/debug/tracing/trace

# 完成后禁用
echo 0 | sudo tee /sys/kernel/debug/tracing/events/gpu_scheduler/drm_run_job/enable
```

## 总结和下一步

GPU 内核跟踪点提供对图形驱动行为的前所未有的可见性。DRM 调度器的稳定 uAPI 跟踪点在所有供应商上工作，使它们成为生产监控的完美选择。来自 Intel i915 和 AMD AMDGPU 的供应商特定跟踪点暴露详细的内存管理、命令提交管道和硬件中断模式。

我们的 bpftrace 脚本演示了实际监控：测量作业调度延迟、跟踪内存压力、分析命令提交瓶颈以及诊断丢帧。这些技术直接应用于实际问题 - 优化 ML 训练性能、调试游戏卡顿、在云环境中实现公平的 GPU 资源核算以及调查热节流。

与传统工具相比，关键优势是完整性和开销。内核跟踪点以纳秒级精度捕获每个事件，成本可忽略不计。没有轮询，没有采样间隙，没有错过的短期作业。这些数据馈送生产监控系统（Prometheus 导出器读取 bpftrace 输出）、临时性能调试（用户报告问题时运行脚本）和自动化优化（基于延迟阈值触发工作负载重新平衡）。

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
