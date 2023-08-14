# eBPF 入门实践教程二十一：使用 xdp 实现可编程包处理

## 背景

xdp（eXpress Data Path）是 Linux 内核中新兴的一种绕过内核的、可编程的包处理方案。相较于 cBPF，xdp 的挂载点非常底层，位于网络设备驱动的软中断处理过程，甚至早于 skb_buff 结构的分配。因此，在 xdp 上挂载 eBPF 程序适用于很多简单但次数极多的包处理操作（如防御 Dos 攻击），可以达到很高的性能（24Mpps/core）。

## XDP 概述

xdp 不是第一个支持可编程包处理的系统，在此之前，以 DPDK（Data Plane Development Kit）为代表的内核旁路方案甚至能够取得更高的性能，其思路为完全绕过内核，由用户态的网络应用接管网络设备，从而避免了用户态和内核态的切换开销。然而，这样的方式具有很多天然的缺陷：

+ 无法与内核中成熟的网络模块集成，而不得不在用户态将其重新实现；
+ 破坏了内核的安全边界，使得内核提供的很多网络工具变得不可用；
+ 在与常规的 socket 交互时，需要从用户态重新将包注入到内核；
+ 需要占用一个或多个单独的 CPU 来进行包处理；

除此之外，利用内核模块和内核网络协议栈中的 hook 点也是一种思路，然而前者对内核的改动大，出错的代价高昂；后者在整套包处理流程中位置偏后，其效率不够理想。

总而言之，xdp + eBPF 为可编程包处理系统提出了一种更为稳健的思路，在某种程度上权衡了上述方案的种种优点和不足，获取较高性能的同时又不会对内核的包处理流程进行过多的改变，同时借助 eBPF 虚拟机的优势将用户定义的包处理过程进行隔离和限制，提高了安全性。

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

+ <http://arthurchiao.art/blog/xdp-paper-acm-2018-zh/>
+ <http://arthurchiao.art/blog/linux-net-stack-implementation-rx-zh/>
+ <https://github.com/xdp-project/xdp-tutorial/tree/master/basic01-xdp-pass>
