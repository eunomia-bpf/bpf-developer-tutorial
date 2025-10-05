# eBPF 实例教程：构建高性能 XDP 数据包生成器

需要对网络栈进行压力测试或测量 XDP 程序性能吗？传统的数据包生成器如 `pktgen` 需要内核模块或在用户态运行，开销很大。有更好的方法 - XDP 的 BPF_PROG_RUN 功能让你可以直接从用户态向内核快速路径注入数据包，速度可达每秒数百万包，而且不需要加载网络驱动。

在本教程中，我们将构建一个基于 XDP 的数据包生成器，利用内核的 BPF_PROG_RUN 测试基础设施。我们将探索 XDP 的 `XDP_TX` 动作如何创建数据包反射循环，理解启用真实数据包注入的实时帧模式，并测量高负载下 XDP 程序的性能特征。最后，你将拥有一个用于网络测试和 XDP 基准测试的生产级工具。

## 理解 XDP 数据包生成

XDP（eXpress Data Path）通过在内核网络栈分配套接字缓冲区之前挂钩到网络驱动程序，提供了 Linux 中最快的可编程数据包处理。通常，XDP 程序处理从网络接口到达的数据包。但是，如果你想在没有真实网络流量的情况下测试 XDP 程序的性能怎么办？或者注入合成数据包来对网络基础设施进行压力测试？

### BPF_PROG_RUN 测试接口

内核通过 `bpf_prog_test_run()`（BPF_PROG_RUN）暴露了一个用于测试 BPF 程序的机制。最初设计用于单元测试，这个系统调用让用户空间可以使用合成输入调用 BPF 程序并捕获其输出。对于 XDP 程序，你提供一个数据包缓冲区和描述数据包元数据（接口索引、RX 队列）的 `xdp_md` 上下文。内核运行你的 XDP 程序并返回动作代码（XDP_DROP、XDP_PASS、XDP_TX 等）以及任何数据包修改。

传统的 BPF_PROG_RUN 在"空运行"模式下操作 - 数据包被处理但从不实际传输。XDP 程序运行，修改数据包数据，返回一个动作，但没有任何东西到达网络。这对于测试数据包解析逻辑或在隔离环境中测量程序执行时间非常完美。

### 实时帧模式：真实数据包注入

在 Linux 5.18+ 中，内核通过 `BPF_F_TEST_XDP_LIVE_FRAMES` 标志引入了**实时帧模式**。这从根本上改变了 BPF_PROG_RUN 的行为。当启用时，XDP_TX 动作不仅仅是返回 - 它们实际上通过指定的网络接口在网络上传输数据包。这将 BPF_PROG_RUN 变成了一个强大的数据包生成器。

工作原理如下：你的用户空间程序构造一个数据包（带有 IP 头、UDP 负载等的以太网帧），并在启用实时帧的情况下将其传递给 `bpf_prog_test_run()`。XDP 程序在其 `xdp_md` 上下文中接收这个数据包。如果程序返回 `XDP_TX`，内核会通过网络驱动传输数据包，就像它到达接口并被反射回去一样。数据包出现在网络上，完全支持硬件卸载（校验和、分段等）。

这启用了几个强大的用例。**网络栈压力测试**：用每秒数百万个数据包淹没你的系统，以找到网络栈、驱动程序或应用层的瓶颈。**XDP 程序基准测试**：在没有外部数据包生成器的情况下，测量 XDP 程序在真实负载下每秒可以处理多少个数据包。**协议模糊测试**：生成格式错误的数据包或不寻常的协议序列来测试健壮性。**合成流量生成**：创建真实的流量模式来测试负载均衡器、防火墙或入侵检测系统。

### XDP_TX 反射循环

最简单的 XDP 数据包生成器使用 `XDP_TX` 动作。这告诉内核"将这个数据包传输回它到达的接口"。我们的最小 XDP 程序字面上只有三行：

```c
SEC("xdp")
int xdp_redirect_notouch(struct xdp_md *ctx)
{
    return XDP_TX;
}
```

就是这样。没有数据包解析，没有头部修改 - 只是反射所有内容。结合实时帧模式下的 BPF_PROG_RUN，这创建了一个数据包生成循环：用户空间注入一个数据包，XDP 将其反射到网络，以每秒数百万个数据包的速度重复。

为什么这么快？XDP 程序在驱动程序的接收路径中运行，直接访问 DMA 缓冲区。没有套接字缓冲区分配，没有协议栈遍历，数据包之间没有上下文切换到用户空间。内核可以批量处理多个帧的数据包，摊销每个数据包的开销。在现代硬件上，单个 CPU 核心可以生成 500-1000 万个数据包每秒。

## 构建数据包生成器

让我们检查完整的数据包生成器如何工作，从用户空间控制到内核数据包注入。

### 完整的 XDP 程序：xdp-pktgen.bpf.c

```c
/* SPDX-License-Identifier: MIT */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_redirect_notouch(struct xdp_md *ctx)
{
	return XDP_TX;
}
```

这就是整个 XDP 程序。`SEC("xdp")` 属性将其标记为 libbpf 程序加载器的 XDP 程序。该函数接收一个 `xdp_md` 上下文，其中包含数据包元数据 - `data` 和 `data_end` 指针框定数据包缓冲区，`ingress_ifindex` 标识接收接口，并且 RX 队列信息可用于多队列网卡。

我们立即返回 `XDP_TX` 而不触碰数据包。在实时帧模式下，这会导致内核传输数据包。数据包数据本身来自用户空间 - 我们将构造 UDP 或自定义协议数据包，并通过 BPF_PROG_RUN 注入它们。

这种最小化方法的美妙之处在于所有数据包构造都发生在用户空间，你可以完全控制。想要模糊测试协议？在 C 中生成具有任意头字段的数据包。需要真实的流量模式？读取 pcap 文件并通过 XDP 程序重放它们。测试特定的边缘情况？逐字节制作数据包。XDP 程序只是将数据包以线速发送到网络的工具。

### 用户空间控制程序：xdp-pktgen.c

用户空间程序处理数据包构造、BPF 程序加载和注入控制。让我们逐步了解关键组件。

#### 数据包构造和配置

```c
struct config {
	int ifindex;        // 在哪个接口上注入数据包
	int xdp_flags;      // XDP 附加标志
	int repeat;         // 注入每个数据包的次数
	int batch_size;     // BPF_PROG_RUN 的批量大小（0 = 自动）
};

struct config cfg = {
	.ifindex = 6,              // 网络接口（例如，eth0）
	.repeat = 1 << 20,         // 每批 100 万次重复
	.batch_size = 0,           // 让内核选择最佳批次
};
```

配置控制数据包注入参数。接口索引标识要使用的网卡 - 使用 `ip link show` 查找。重复计数确定在单个 BPF_PROG_RUN 调用中注入每个数据包的次数。更高的计数可以摊销系统调用开销，但会增加下一个数据包模板之前的延迟。批量大小允许你在一次系统调用中注入多个不同的数据包（高级功能，0 表示单数据包模式）。

数据包构造支持两种模式。默认情况下，它生成一个合成的 UDP/IPv4 数据包：

```c
struct test_udp_packet_v4 pkt_udp = create_test_udp_packet_v4();
size = sizeof(pkt_udp);
memcpy(pkt_file_buffer, &pkt_udp, size);
```

这创建了一个最小的有效 UDP 数据包 - 带有源/目标 MAC 的以太网帧、带有地址和校验和的 IPv4 头、带有端口的 UDP 头和小的负载。`create_test_udp_packet_v4()` 辅助函数（来自 test_udp_pkt.h）构造一个网络栈可以接受的线格式数据包。

对于自定义数据包，将 `PKTGEN_FILE` 环境变量设置为包含原始数据包字节的文件：

```c
if ((pkt_file = getenv("PKTGEN_FILE")) != NULL) {
    FILE* file = fopen(pkt_file, "r");
    size = fread(pkt_file_buffer, 1, 1024, file);
    fclose(file);
}
```

这允许你注入任意数据包 - pcap 提取、模糊测试负载或协议测试向量。任何二进制数据都可以工作，只要它形成一个有效的以太网帧。

#### BPF_PROG_RUN 调用和实时帧

数据包注入循环使用 `bpf_prog_test_run_opts()` 重复调用 XDP 程序：

```c
struct xdp_md ctx_in = {
    .data_end = size,                 // 数据包长度
    .ingress_ifindex = cfg.ifindex    // 哪个接口
};

DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
    .data_in = pkt_file_buffer,       // 数据包数据
    .data_size_in = size,             // 数据包长度
    .ctx_in = &ctx_in,                // XDP 元数据
    .ctx_size_in = sizeof(ctx_in),
    .repeat = cfg.repeat,             // 重复计数
    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,  // 启用实时传输
    .batch_size = cfg.batch_size,
    .cpu = 0,                         // 固定到 CPU 0
);
```

关键标志是 `BPF_F_TEST_XDP_LIVE_FRAMES`。如果没有它，XDP 程序会运行但数据包保留在内存中。有了它，XDP_TX 动作实际上通过驱动程序传输数据包。内核验证接口索引是否有效且接口是否启动，确保数据包到达网络。

CPU 固定（`cpu = 0`）对性能测量很重要。通过将注入线程固定到 CPU 0，你可以获得一致的性能数字并避免跨核心的缓存抖动。为了获得最大吞吐量，你可以生成多个固定到不同 CPU 的线程，每个线程在单独的接口或队列上注入数据包。

注入循环一直持续到中断：

```c
do {
    err = bpf_prog_test_run_opts(run_prog_fd, &opts);
    if (err)
        return -errno;
    iterations += opts.repeat;
} while ((count == 0 || iterations < count) && !exiting);
```

每次 `bpf_prog_test_run_opts()` 调用注入 `repeat` 个数据包（默认 100 万个）。使用快速的 XDP 程序，这在几毫秒内完成。内核批量处理数据包，最小化每个数据包的开销。总吞吐量取决于数据包大小、网卡能力和 CPU 性能，但每个核心可以实现 500-1000 万 pps。

#### 内核支持检测

并非所有内核都支持实时帧模式。程序在开始注入之前探测支持：

```c
static int probe_kernel_support(int run_prog_fd)
{
    int err = run_prog(run_prog_fd, 1);  // 尝试注入 1 个数据包
    if (err == -EOPNOTSUPP) {
        printf("BPF_PROG_RUN with batch size support is missing from libbpf.\n");
    } else if (err == -EINVAL) {
        err = -EOPNOTSUPP;
        printf("Kernel doesn't support live packet mode for XDP BPF_PROG_RUN.\n");
    } else if (err) {
        printf("Error probing kernel support: %s\n", strerror(-err));
    } else {
        printf("Kernel supports live packet mode for XDP BPF_PROG_RUN.\n");
    }
    return err;
}
```

这尝试单个数据包注入。如果内核缺乏支持（Linux <5.18 或未启用 CONFIG_XDP_SOCKETS），它返回 `-EINVAL`。没有批量支持的旧 libbpf 版本返回 `-EOPNOTSUPP`。成功意味着你可以继续完整的数据包生成。

## 运行数据包生成器

导航到教程目录并构建项目：

```bash
cd /home/yunwei37/workspace/bpf-developer-tutorial/src/46-xdp-test
make build
```

这会编译 XDP 程序（`xdp-pktgen.bpf.o`）和用户空间控制程序（`xdp-pktgen`）。构建需要 Clang 用于 BPF 编译和 libbpf 用于骨架生成。

在运行之前，识别你的网络接口索引。使用 `ip link show` 列出接口：

```bash
ip link show
```

你会看到类似以下的输出：

```
1: lo: <LOOPBACK,UP,LOWER_UP> ...
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
6: veth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
```

注意接口编号（例如，veth0 为 6）。如果需要，在 xdp-pktgen.c 中更新配置：

```c
struct config cfg = {
    .ifindex = 6,  // 更改为你的接口索引
    ...
};
```

使用 root 权限运行数据包生成器（BPF_PROG_RUN 需要）：

```bash
sudo ./xdp-pktgen
```

你会看到类似以下的输出：

```
Kernel supports live packet mode for XDP BPF_PROG_RUN.
pkt size: 42
[Generating packets...]
```

程序一直运行直到使用 Ctrl-C 中断。使用以下命令监控数据包传输：

```bash
# 在另一个终端中，监视接口统计信息
watch -n 1 'ip -s link show veth0'
```

你会看到 TX 数据包计数器快速增加。在现代 CPU 上，对于最小大小的数据包，预计每个核心每秒 500-1000 万个数据包。

### 自定义数据包注入

要注入自定义数据包，创建一个二进制数据包文件并设置环境变量：

```bash
# 创建自定义数据包（例如，使用 scapy 或 hping3 生成二进制文件）
echo -n -e '\x00\x01\x02\x03\x04\x05...' > custom_packet.bin

# 注入它
sudo PKTGEN_FILE=custom_packet.bin ./xdp-pktgen
```

生成器从文件中读取最多 1024 字节并重复注入该数据包。这适用于任何协议 - IPv6、ICMP、自定义 L2 协议，甚至用于模糊测试的格式错误的数据包。

## 性能特征和调优

XDP 数据包生成性能取决于几个因素。让我们了解什么限制了吞吐量以及如何最大化它。

**数据包大小影响**：较小的数据包实现更高的包速率，但每秒字节数的吞吐量较低。64 字节的数据包在 1000 万 pps 时提供 5 Gbps。1500 字节的数据包在 200 万 pps 时提供 24 Gbps。CPU 以大致恒定的每秒包速率处理数据包，因此较大的数据包实现更高的带宽。

**CPU 频率和微架构**：具有更高频率和更好 IPC（每周期指令数）的新 CPU 实现更高的速率。Intel Xeon 或 AMD EPYC 服务器 CPU 每个核心可以达到 1000 万以上 pps。较旧或低功耗 CPU 可能只能达到 200-500 万 pps。

**网卡能力**：网络驱动程序必须跟上注入速率。高端网卡（Intel X710、Mellanox ConnectX）支持每秒数百万个数据包。消费级千兆网卡由于驱动程序限制或硬件缓冲，通常在 100-200 万 pps 时饱和。

**内存带宽**：在高速率下，往返于网卡 DMA 缓冲区的数据包数据传输可能成为瓶颈。确保系统有足够的内存带宽（使用 `perf stat` 监控内存控制器利用率）。

**中断和轮询开销**：网络驱动程序使用中断或轮询（NAPI）来处理数据包。在极端负载下，中断开销可能会减慢处理速度。考虑调整中断合并或使用忙轮询。

为了获得最大性能，将注入线程固定到专用 CPU 核心，禁用 CPU 频率缩放（将调节器设置为 performance），使用大页面用于数据包缓冲区以减少 TLB 未命中，并考虑带有 RSS（接收侧缩放）的多队列网卡 - 为每个队列生成线程以进行并行注入。

## 总结与下一步

XDP 数据包生成器利用内核的 BPF_PROG_RUN 基础设施以线速从用户空间注入数据包。通过将返回 XDP_TX 的最小 XDP 程序与实时帧模式相结合，你可以在没有外部硬件或内核模块的情况下每秒传输数百万个数据包。这使得网络栈压力测试、XDP 程序基准测试、协议模糊测试和合成流量生成成为可能。

我们的实现演示了核心概念：一个简单的 XDP 反射程序、使用自定义或默认 UDP 数据包的用户空间数据包构造、带有实时帧标志的 BPF_PROG_RUN 调用，以及内核支持检测。结果是一个灵活的、高性能的数据包生成器，适用于测试网络基础设施、测量 XDP 程序性能或生成真实的流量模式。

除了基本生成之外，你可以扩展这种方法来创建复杂的测试工具。为不同的协议添加数据包模板（TCP SYN 洪水、ICMP echo、DNS 查询）。实现流量整形（改变数据包间延迟）。同时支持多个接口以进行吞吐量聚合。与网络监控集成以测量丢包率或延迟。XDP 数据包生成器框架为高级网络测试功能提供了基础。

> 如果你想深入了解 eBPF 和 XDP，请查看我们的教程仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- **教程仓库**: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/46-xdp-test>
- **Linux 内核 XDP 文档**: `Documentation/networking/xdp.rst`
- **BPF_PROG_RUN 文档**: `tools/testing/selftests/bpf/README.rst`
- **XDP 教程**: <https://github.com/xdp-project/xdp-tutorial>
- **libbpf 文档**: <https://libbpf.readthedocs.io/>

完整的源代码及构建说明和示例数据包模板可在教程仓库中获取。欢迎贡献！
