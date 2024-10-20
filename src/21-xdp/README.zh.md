# eBPF 入门实践教程二十一： 使用 XDP 进行可编程数据包处理

在本教程中，我们将介绍 XDP（eXpress Data Path），并通过一个简单的例子帮助你入门。之后，我们将探讨更高级的 XDP 应用，例如负载均衡器、防火墙及其他实际应用。如果你对 eBPF 或 XDP 感兴趣，请在 [Github](https://github.com/eunomia-bpf/bpf-developer-tutorial) 上为我们点赞！

## 什么是 XDP？

XDP 是 Linux 内核中的一种高性能可编程数据路径，专为网络接口级的数据包处理而设计。通过将 eBPF 程序直接附加到网络设备驱动程序上，XDP 能够在数据包到达内核网络栈之前拦截并处理它们。这使得 XDP 能够进行极低延迟和高效的数据包处理，非常适合如 DDoS 防护、负载均衡和流量过滤等任务。实际上，XDP 每核心的吞吐量可以高达 **每秒 2400 万包（Mpps）**。

### 为什么选择 XDP？

XDP 运行在比传统 Linux 网络组件（如 cBPF）更低的层级，在网络设备驱动程序的软中断上下文中执行。它能够在数据包被内核标准网络栈处理之前对其进行处理，避免了创建 Linux 中表示网络数据包的 `skb_buff` 结构。这种早期处理为简单但频繁的操作（如丢弃恶意数据包或负载均衡服务器）带来了显著的性能提升。

与其他数据包处理机制相比，XDP 在性能和可用性之间取得了平衡，它利用了 Linux 内核的安全性和可靠性，同时通过可编程的 eBPF 提供了灵活性。

## XDP 与其他方法的比较

在 XDP 出现之前，一些解决方案通过完全绕过内核来加速数据包处理。其中一个显著的例子是 **DPDK**（数据平面开发工具包）。DPDK 允许用户空间应用程序直接控制网络设备，从而实现非常高的性能。然而，这种方法也存在一些权衡：

1. **缺乏内核集成**：DPDK 及其他内核绕过解决方案无法利用现有的内核网络功能，开发者必须在用户空间重新实现许多协议和功能。

2. **安全边界**：这些绕过技术破坏了内核的安全模型，使得难以利用内核提供的安全工具。
3. **用户空间与内核的转换开销**：当用户空间数据包处理需要与传统内核网络交互时（例如基于套接字的应用程序），数据包必须重新注入到内核中，增加了开销和复杂性。
4. **专用 CPU 使用**：为了处理高流量，DPDK 和类似解决方案通常需要专用的 CPU 核心来处理数据包，这限制了通用系统的可扩展性和效率。

另一个替代 XDP 的方法是使用 Linux 网络栈中的 **内核模块** 或 **挂钩**。虽然这种方法可以很好地集成现有的内核功能，但它需要大量的内核修改，且由于在数据包处理管道的后期运行，无法提供与 XDP 相同的性能优势。

### XDP + eBPF 的优势

XDP 与 eBPF 结合提供了介于内核绕过方案（如 DPDK）和内核集成方案之间的中间地带。以下是 XDP + eBPF 脱颖而出的原因：

- **高性能**：通过在网络接口卡（NIC）驱动程序级别拦截数据包，XDP 可以实现接近线速的性能，用于丢弃、重定向或负载均衡数据包，同时保持低资源消耗。
  
- **内核集成**：与 DPDK 不同，XDP 在 Linux 内核中工作，允许与现有的内核网络栈和工具（如 `iptables`、`nftables` 或套接字）无缝交互。无需在用户空间重新实现网络协议。

- **安全性**：eBPF 虚拟机确保用户定义的 XDP 程序是被隔离的，不会对内核造成不稳定影响。eBPF 的安全模型防止恶意或有缺陷的代码损害系统，提供了一个安全的可编程数据包处理环境。

- **不需要专用 CPU**：XDP 允许数据包处理而无需将整个 CPU 核心专用于网络任务。这提高了系统的整体效率，允许更灵活的资源分配。

总的来说，XDP + eBPF 提供了一种强大的可编程数据包处理解决方案，结合了高性能与内核集成的灵活性和安全性。它消除了完全绕过内核方案的缺点，同时保留了内核安全性和功能的优势。

## XDP 的项目和应用案例

XDP 已经在许多高调的项目中得到应用，这些项目展示了它在实际网络场景中的强大功能和灵活性：

### 1. **Cilium**

- **描述**：Cilium 是一个为云原生环境（尤其是 Kubernetes）设计的开源网络、安全和可观测性工具。它利用 XDP 实现高性能的数据包过滤和负载均衡。
- **应用案例**：Cilium 将数据包过滤和安全策略卸载到 XDP，实现高吞吐量和低延迟的容器化环境流量管理，同时不牺牲可扩展性。
- **链接**：[Cilium](https://cilium.io/)

### 2. **Katran**

- **描述**：Katran 是由 Facebook 开发的第 4 层负载均衡器，优化了高可扩展性和性能。它使用 XDP 处理数据包转发，开销极小。
- **应用案例**：Katran 每秒处理数百万个数据包，高效地将流量分配到后端服务器上，利用 XDP 在大规模数据中心中实现低延迟和高性能的负载均衡。
- **链接**：[Katran GitHub](https://github.com/facebookincubator/katran)

### 3. **Cloudflare 的 XDP DDoS 保护**

- **描述**：Cloudflare 已经实现了基于 XDP 的实时 DDoS 缓解。通过在 NIC 级别处理数据包，Cloudflare 能够在恶意流量进入网络栈之前过滤掉攻击流量，最小化 DDoS 攻击对其系统的影响。
- **应用案例**：Cloudflare 利用 XDP 在管道早期丢弃恶意数据包，保护其基础设施免受大规模 DDoS 攻击，同时保持对合法流量的高可用性。
- **链接**：[Cloudflare 博客关于 XDP](https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/)

这些项目展示了 XDP 在不同领域的可扩展和高效的数据包处理能力，从安全和负载均衡到云原生网络。

### 为什么选择 XDP 而不是其他方法？

与传统方法（如 `iptables`、`nftables` 或 `tc`）相比，XDP 提供了几个明显的优势：

- **速度与低开销**：XDP 直接在 NIC 驱动程序中运行，绕过了内核的大部分开销，使数据包处理更快。
  
- **可定制性**：XDP 允许开发人员通过 eBPF 创建自定义的数据包处理程序，提供比传统工具（如 `iptables`）更大的灵活性和细粒度控制。

- **资源效率**：XDP 不需要像 DPDK 等用户空间解决方案那样将整个 CPU 核心专用于数据包处理，因此它是高性能网络的更高效选择。

## 编写 eBPF 程序

```C
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/// @ifindex 1
/// @flags 0
/// @xdpopts {"old_prog_fd":0}
SEC("xdp")
int xdp_pass(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    int pkt_sz = data_end - data;

    bpf_printk("packet size is %d", pkt_sz);
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
```

这是一段 C 语言实现的 eBPF 内核侧代码，它能够通过 xdp 捕获所有经过目标网络设备的数据包，计算其大小并输出到 `trace_pipe` 中。

值得注意的是，在代码中我们使用了以下注释：

```C
/// @ifindex 1
/// @flags 0
/// @xdpopts {"old_prog_fd":0}
```

这是由 eunomia-bpf 提供的功能，我们可以通过这样的注释告知 eunomia-bpf 加载器此 xdp 程序想要挂载的目标网络设备编号，挂载的标志和选项。

这些变量的设计基于 libbpf 提供的 API，可以通过 [patchwork](https://patchwork.kernel.org/project/netdevbpf/patch/20220120061422.2710637-2-andrii@kernel.org/#24705508) 查看接口的详细介绍。

`SEC("xdp")` 宏指出 BPF 程序的类型，`ctx` 是此 BPF 程序执行的上下文，用于包处理流程。

在程序的最后，我们返回了 `XDP_PASS`，这表示我们的 xdp 程序会将经过目标网络设备的包正常交付给内核的网络协议栈。可以通过 [XDP actions](https://prototype-kernel.readthedocs.io/en/latest/networking/XDP/implementation/xdp_actions.html) 了解更多 xdp 的处理动作。

## 编译运行

通过容器编译：

```console
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

或是通过 `ecc` 编译：

```console
$ ecc xdp.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

并通过 `ecli` 运行：

```console
sudo ecli run package.json
```

可以通过如下方式查看程序的输出：

```console
$ sudo cat /sys/kernel/tracing/trace_pipe
            node-1939    [000] d.s11  1601.190413: bpf_trace_printk: packet size is 177
            node-1939    [000] d.s11  1601.190479: bpf_trace_printk: packet size is 66
     ksoftirqd/1-19      [001] d.s.1  1601.237507: bpf_trace_printk: packet size is 66
            node-1939    [000] d.s11  1601.275860: bpf_trace_printk: packet size is 344
```

## 总结

本文介绍了如何使用 xdp 来处理经过特定网络设备的包，基于 eunomia-bpf 提供的通过注释向 libbpf 传递参数的方案，我们可以将自己编写的 xdp BPF 程序以指定选项挂载到目标设备，并在网络包进入内核网络协议栈之前就对其进行处理，从而获取高性能的可编程包处理能力。

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。

## 参考资料

- <http://arthurchiao.art/blog/xdp-paper-acm-2018-zh/>
- <http://arthurchiao.art/blog/linux-net-stack-implementation-rx-zh/>
- <https://github.com/xdp-project/xdp-tutorial/tree/master/basic01-xdp-pass>
