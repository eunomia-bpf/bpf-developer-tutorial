# eBPF 实例教程：跟踪 Intel NPU 内核驱动操作

神经处理单元(NPU)是 AI 加速的下一个前沿 - 直接内置于现代 CPU 中，无需消耗 GPU 功耗预算即可处理机器学习工作负载。Intel 的 Lunar Lake 和 Meteor Lake 处理器集成了专用 NPU 硬件，但当 AI 模型运行缓慢、推理失败或内存分配崩溃时，调试几乎不可能。NPU 驱动是一个黑盒，固件通信不透明，用户空间 API 隐藏了内核中真正发生的事情。

本教程展示如何使用 eBPF 和 bpftrace 跟踪 Intel NPU 内核驱动操作。我们将监控从 Level Zero API 调用到内核函数的完整工作流，跟踪与 NPU 固件的 IPC 通信，测量内存分配模式，并诊断性能瓶颈。最后，你将理解 NPU 驱动的内部工作原理，并拥有调试 AI 工作负载问题的实用工具。

## Intel NPU 驱动架构

Intel 的 NPU 驱动遵循类似 GPU 驱动的两层架构。内核模块(`intel_vpu`)位于主线 Linux 的 `drivers/accel/ivpu/` 中，并将 `/dev/accel/accel0` 暴露为设备接口。它处理硬件通信、通过 MMU 进行内存管理，以及与加速器上运行的 NPU 固件的 IPC(进程间通信)。

用户空间驱动(`libze_intel_vpu.so`)实现 Level Zero API - Intel 的加速器统一编程接口。当你调用 `zeMemAllocHost()` 或 `zeCommandQueueExecuteCommandLists()` 等 Level Zero 函数时，库将这些转换为 DRM ioctl 调用内核模块。内核验证请求，设置内存映射，向 NPU 固件提交工作，并轮询完成。

NPU 固件本身在加速器硬件上自主运行。它从内核接收命令缓冲区，调度计算内核，管理片上内存，并通过中断发出完成信号。所有通信都通过 IPC 通道进行 - 内核和固件交换消息的共享内存区域。这种架构意味着三层必须正确协调：应用程序、内核驱动和 NPU 固件。

理解这个流程对于调试至关重要。当 AI 推理停顿时，是内核在等待固件吗？内存分配在抖动吗？IPC 消息在积压吗？eBPF 跟踪揭示了这个故事的内核侧 - 每个 ioctl、每个内存映射、每个 IPC 中断。

## Level Zero API 到内核驱动的映射

让我们跟踪一个简单的 NPU 工作负载 - 通过 Level Zero 运行的矩阵乘法 - 看看 API 调用如何精确映射到内核操作。我们将使用一个测试程序，为输入/输出矩阵分配主机内存，提交计算，并等待结果。

Level Zero 工作流分为五个阶段。初始化打开 NPU 设备并查询能力。内存分配为计算数据创建缓冲区。命令设置构建工作队列和命令列表。执行向 NPU 固件提交工作负载。同步轮询完成并检索结果。

以下是每个 API 调用如何转换为内核操作：

**zeMemAllocHost** 分配 CPU 和 NPU 都可访问的主机可见内存。这触发 `DRM_IOCTL_IVPU_BO_CREATE` ioctl，在内核中调用 `ivpu_bo_create_ioctl()`。驱动调用 `ivpu_gem_create_object()` 分配 GEM(图形执行管理器)缓冲对象，然后 `ivpu_mmu_context_map_page()` 通过 MMU 将页面映射到 NPU 地址空间。最后 `ivpu_bo_pin()` 将缓冲区固定在内存中，使其在计算期间无法被换出。

对于我们的矩阵乘法示例，有三个缓冲区(输入矩阵 A、输入矩阵 B、输出矩阵 C)，我们看到三个 `zeMemAllocHost()` 调用。每个触发大约 1,377 次 `ivpu_mmu_context_map_page()` 调用 - 设置计算内存总共 4,131 次页面映射。

**zeCommandQueueCreate** 建立用于提交工作的队列。这映射到 `DRM_IOCTL_IVPU_GET_PARAM` ioctl 调用 `ivpu_get_param_ioctl()` 查询队列能力。实际的队列对象存在于用户空间 - 内核只提供设备参数。

**zeCommandListCreate** 在用户空间构建命令列表。这里不发生内核调用 - 库在内存中构造命令缓冲区，稍后将提交到 NPU。

**zeCommandQueueExecuteCommandLists** 是工作实际到达 NPU 的地方。这触发 `DRM_IOCTL_IVPU_SUBMIT` ioctl，在内核中调用 `ivpu_submit_ioctl()`。驱动验证命令缓冲区，设置 DMA 传输，并向 NPU 固件发送 IPC 消息请求执行。固件唤醒，处理请求，在 NPU 硬件上调度计算内核，并开始发送 IPC 中断以发出进度信号。

执行期间，我们观察到大量 IPC 流量：946 次 `ivpu_ipc_irq_handler()` 调用(来自固件的 IPC 消息中断处理程序)，945 次 `ivpu_ipc_receive()` 调用(从共享内存读取消息)，以及 951 次 `ivpu_hw_ip_ipc_rx_count_get()` 调用(轮询 IPC 队列深度)。这种密集的通信是正常的 - 固件在整个计算操作期间发送状态更新、内存栅栏信号和完成通知。

**zeFenceHostSynchronize** 阻塞直到 NPU 完成工作。这不会触发专用的 ioctl - 相反，库持续调用 `ivpu_get_param_ioctl()` 轮询栅栏状态。内核检查固件是否通过 IPC 发出完成信号。当固件发送最终完成消息时，会触发更多 `ivpu_ipc_irq_handler()` 调用。

## 使用 Bpftrace 跟踪 NPU 操作

现在让我们构建一个实用的跟踪工具。我们将使用 bpftrace 将 kprobe 附加到所有 intel_vpu 内核函数，并观察完整的执行流程。

### 完整的 Bpftrace 跟踪脚本

```bash
#!/usr/bin/env bpftrace

BEGIN
{
    printf("正在跟踪 Intel NPU 内核驱动... 按 Ctrl-C 结束。\n");
    printf("%-10s %-40s\n", "时间(ms)", "函数");
}

/* 附加到所有 intel_vpu 内核函数 */
kprobe:intel_vpu:ivpu_*
{
    printf("%-10llu %-40s\n",
           nsecs / 1000000,
           probe);

    /* 统计函数调用次数 */
    @calls[probe] = count();
}

END
{
    printf("\n=== Intel NPU 函数调用统计 ===\n");
    printf("\n按调用次数排序的前 20 个函数：\n");
    print(@calls, 20);
}
```

此脚本将 kprobe 附加到 intel_vpu 内核模块中的每个函数(所有以 `ivpu_` 开头的函数)。当任何函数执行时，我们打印时间戳和函数名。`@calls` map 跟踪每个函数被调用了多少次 - 非常适合识别驱动中的热点路径。

### 理解跟踪输出

在执行 NPU 工作负载时运行此脚本，你将看到内核操作的顺序跟踪。让我们逐步了解从我们的矩阵乘法测试中捕获的典型执行。

跟踪从设备初始化开始：`ivpu_open()` 打开 `/dev/accel/accel0` 设备文件。然后 `ivpu_mmu_context_init()` 为此进程设置 MMU 上下文。一连串的 `ivpu_get_param_ioctl()` 调用查询设备能力 - 固件版本、计算引擎数量、内存大小、支持的操作。

内存分配占据了中间部分。对于每个 `zeMemAllocHost()` 调用，我们看到模式：`ivpu_bo_create_ioctl()` 创建缓冲对象，`ivpu_gem_create_object()` 分配后备内存，然后数百次 `ivpu_mmu_context_map_page()` 调用将页面映射到 NPU 地址空间。对于矩阵乘法的三个缓冲区，这重复三次 - 总共 4,131 次页面映射。

命令提交触发 `ivpu_submit_ioctl()`，启动固件通信。如果固件尚未运行，`ivpu_boot()` 和 `ivpu_fw_boot_params_setup()` 函数准备固件。然后 `ivpu_hw_boot_fw()` 启动 NPU 执行，IPC 流量激增。

IPC 通信部分显示 NPU 固件正在主动处理工作。每个 `ivpu_ipc_irq_handler()` 表示来自 NPU 的硬件中断。模式 `ivpu_hw_ip_ipc_rx_count_get()` → `ivpu_ipc_receive()` 从共享内存读取 IPC 消息。有 945 次消息接收，我们知道固件在计算操作期间发送了近一千次状态更新 - 这就是它与内核通信的活跃程度。

最后，清理出现：`ivpu_postclose()` 关闭设备，`ivpu_ms_cleanup()` 释放资源，`ivpu_file_priv_put()` 释放文件句柄引用，`ivpu_pgtable_free_page()` 取消映射内存页面(517 次调用释放我们的 4,131 个映射页面)。

## 分析 NPU 性能瓶颈

函数调用统计揭示了驱动花费时间的地方。从我们的测试运行的 8,198 次总函数调用中，三个类别占主导地位：

**内存管理(4,648 次调用，占总数的 57%)**：`ivpu_mmu_context_map_page()` 占 4,131 次调用，几乎是所有驱动活动的一半。这是有道理的 - 将内存映射到 NPU 地址空间是逐页工作。在清理时，`ivpu_pgtable_free_page()` 被调用 517 次以取消映射。如果你的 NPU 应用程序中内存分配很慢，这就是原因 - 大缓冲区需要数千次 MMU 操作。

**IPC 通信(2,842 次调用，占总数的 35%)**：固件通信三元组 `ivpu_ipc_irq_handler()`(946 次调用)、`ivpu_hw_ip_ipc_rx_count_get()`(951 次调用)和 `ivpu_ipc_receive()`(945 次调用)显示了密集的消息传递。近 1,000 次中断和消息接收意味着固件主动报告进度。如果你的 NPU 工作负载显示的 IPC 计数高于预期，固件可能在抖动或遇到内存争用。

**缓冲区管理(74 次调用，<1% 的总数)**：GEM 对象操作如 `ivpu_bo_create_ioctl()`(24)、`ivpu_gem_create_object()`(25)和 `ivpu_bo_pin()`(25)相对较少。这符合预期 - 你创建缓冲区一次，然后在许多计算操作中重用它们。

通过将这些比率与正常工作负载进行比较，你可以发现异常。如果简单推理的 IPC 调用激增到 10,000+，那就有问题 - 也许固件卡在重试循环中。如果内存映射调用超过缓冲区数量 × 页面数量，你的分配和释放效率低下。跟踪为你提供了诊断这些问题的硬数据。

## 运行跟踪工具

bpftrace 脚本适用于任何具有 Intel NPU 硬件和加载了 intel_vpu 内核模块的 Linux 系统。以下是使用方法。

首先，验证 NPU 驱动是否活动：

```bash
# 检查 intel_vpu 模块是否已加载
lsmod | grep intel_vpu

# 验证 NPU 设备是否存在
ls -l /dev/accel/accel0

# 检查驱动版本和支持的设备
modinfo intel_vpu
```

你应该看到 intel_vpu 模块已加载，并且 `/dev/accel/accel0` 设备存在。modinfo 输出显示支持的 PCI 设备 ID(0x643E、0x7D1D、0xAD1D、0xB03E) - 这些对应于 Meteor Lake 和 Lunar Lake NPU 硬件。

现在运行跟踪脚本。将上面的 bpftrace 代码保存为 `trace_npu.bt` 并执行：

```bash
# 简单函数调用跟踪
sudo bpftrace -e 'kprobe:intel_vpu:ivpu_* { printf("%s\n", probe); }'

# 或运行带统计信息的完整脚本
sudo bpftrace trace_npu.bt
```

在另一个终端中，运行你的 NPU 工作负载 - Level Zero 应用程序、OpenVINO 推理或任何使用 `/dev/accel/accel0` 的程序。跟踪输出实时流式传输。完成后，按 Ctrl-C 查看按频率排序的函数调用统计信息。

要进行更详细的分析，将输出重定向到文件：

```bash
sudo bpftrace trace_npu.bt > npu_trace_$(date +%Y%m%d_%H%M%S).txt
```

这会捕获完整的执行跟踪以供离线分析。你可以 grep 特定模式、计算函数调用序列，或将时间戳与应用程序级事件关联。

## 高级分析技术

除了基本跟踪之外，你还可以通过过滤特定操作或测量延迟来提取更深入的见解。

**跟踪内存分配模式** 通过过滤缓冲对象函数：

```bash
sudo bpftrace -e '
kprobe:intel_vpu:ivpu_bo_create_ioctl {
    @alloc_time[tid] = nsecs;
}
kretprobe:intel_vpu:ivpu_bo_create_ioctl /@alloc_time[tid]/ {
    $latency_us = (nsecs - @alloc_time[tid]) / 1000;
    printf("缓冲区分配耗时 %llu us\n", $latency_us);
    delete(@alloc_time[tid]);
    @alloc_latency = hist($latency_us);
}
END {
    printf("\n缓冲区分配延迟(微秒):\n");
    print(@alloc_latency);
}'
```

这测量从 `ivpu_bo_create_ioctl()` 进入到返回的时间，显示分配延迟分布。高延迟表示内存压力或 MMU 争用。

**监控 IPC 消息速率** 以检测固件通信问题：

```bash
sudo bpftrace -e '
kprobe:intel_vpu:ivpu_ipc_receive {
    @last_time = nsecs;
    @ipc_count++;
}
interval:s:1 {
    printf("IPC 消息/秒: %llu\n", @ipc_count);
    @ipc_count = 0;
}
END {
    clear(@ipc_count);
}'
```

这计算每秒的 IPC 消息数。正常工作负载显示稳定的速率(50-200 msg/sec)。峰值表示固件困境 - 重试、错误或卡住的操作。

**与用户空间 API 调用关联** 使用 libze_intel_vpu.so 上的 uprobe：

```bash
sudo bpftrace -e '
uprobe:/usr/lib/x86_64-linux-gnu/libze_intel_vpu.so:zeCommandQueueExecuteCommandLists {
    printf("[API] 提交命令队列\n");
    @submit_time = nsecs;
}
kprobe:intel_vpu:ivpu_submit_ioctl {
    printf("[内核] 提交 ioctl\n");
}
kprobe:intel_vpu:ivpu_ipc_irq_handler {
    printf("[固件] IPC 中断\n");
}
'
```

这将用户空间 API 调用与内核 ioctl 和固件 IPC 关联，揭示跨所有三层的完整控制流。

## 编译和执行

本教程中的 bpftrace 脚本无需编译 - 它们可以直接运行。确保你有：

- 带有 intel_vpu 驱动的 Linux 内核(主线内核 6.2+ 包含它)
- Intel NPU 硬件(Meteor Lake 或 Lunar Lake 处理器)
- 安装了 bpftrace(在 Ubuntu/Debian 上为 `apt install bpftrace`)
- 运行 bpftrace 的 root 访问权限

导航到教程目录：

```bash
cd /home/yunwei37/workspace/bpf-developer-tutorial/src/xpu/npu-kernel-driver
```

目录包含：

- **README.md** - 英文教程
- **README.zh.md** - 本教程
- **intel_npu_driver_analysis.md** - 详细的驱动架构分析
- **intel_vpu_symbols.txt** - 1,312 个内核模块符号的完整列表
- **trace_res.txt** - 矩阵乘法工作负载的示例跟踪输出

要重现跟踪结果：

```bash
# 开始跟踪
sudo bpftrace -e 'kprobe:intel_vpu:ivpu_* { printf("%s\n", probe); }' > my_trace.txt

# 在另一个终端中，运行你的 NPU 工作负载
# 例如，使用 OpenVINO：
# benchmark_app -m model.xml -d NPU

# 使用 Ctrl-C 停止跟踪
# 分析输出
wc -l my_trace.txt  # 计算函数调用次数
sort my_trace.txt | uniq -c | sort -rn | head -20  # 前 20 个函数
```

对于 Level Zero 应用程序，确保已安装运行时(`apt install level-zero-loader`)。库将通过 `/dev/accel/accel0` 自动发现 NPU 设备。

## 理解 Intel VPU 内核模块符号

intel_vpu 内核模块在 `/proc/kallsyms` 中导出 1,312 个可见符号。这些根据符号类型分为以下类别：

- **t (text)**：函数符号，如 `ivpu_submit_ioctl`、`ivpu_mmu_context_map_page`
- **d (data)**：全局变量和数据结构
- **r (read-only data)**：常量数据、字符串字面量、设备 ID 表
- **b (BSS)**：模块加载时分配的未初始化数据

模块不导出用于外部链接的符号(没有 EXPORT_SYMBOL 宏)。相反，它通过以下方式提供功能：
1. DRM 设备文件接口(`/dev/accel/accel0`)
2. 用于缓冲区管理的标准 DRM ioctl
3. NPU 特定操作的自定义 ioctl
4. 与固件的 IPC 协议

要理解的关键函数系列：

- `ivpu_bo_*`：缓冲对象管理(分配、固定、映射)
- `ivpu_mmu_*`：内存管理单元操作(页表、地址转换)
- `ivpu_ipc_*`：与固件的进程间通信
- `ivpu_hw_*`：硬件特定操作(电源管理、寄存器访问)
- `ivpu_fw_*`：固件加载和引导协调
- `ivpu_pm_*`：电源管理(运行时挂起/恢复)

完整的符号列表在 `intel_vpu_symbols.txt` 中可供参考，用于跟踪特定操作。

> 如果你想深入了解 eBPF 和加速器跟踪，请查看我们的教程仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- **Intel NPU 驱动源码**: <https://github.com/intel/linux-npu-driver>
- **Linux 内核加速器子系统**: 内核树中的 `drivers/accel/`
- **Intel VPU 内核模块**: 主线内核中的 `drivers/accel/ivpu/`
- **DRM 子系统文档**: `Documentation/gpu/drm-uapi.rst`
- **Bpftrace 参考**: <https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md>
- **教程仓库**: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/xpu/npu-kernel-driver>

完整的源代码以及跟踪示例和分析工具可在教程仓库中获得。
