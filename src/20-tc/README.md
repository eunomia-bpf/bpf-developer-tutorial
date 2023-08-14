# eBPF 入门实践教程二十：使用 eBPF 进行 tc 流量控制

## 背景

Linux 的流量控制子系统（Traffic Control, tc）在内核中存在了多年，类似于 iptables 和 netfilter 的关系，tc 也包括一个用户态的 tc 程序和内核态的 trafiic control 框架，主要用于从速率、顺序等方面控制数据包的发送和接收。从 Linux 4.1 开始，tc 增加了一些新的挂载点，并支持将 eBPF 程序作为 filter 加载到这些挂载点上。

## tc 概述

从协议栈上看，tc 位于链路层，其所在位置已经完成了 sk_buff 的分配，要晚于 xdp。为了实现对数据包发送和接收的控制，tc 使用队列结构来临时保存并组织数据包，在 tc 子系统中对应的数据结构和算法控制机制被抽象为 qdisc（Queueing discipline），其对外暴露数据包入队和出队的两个回调接口，并在内部隐藏排队算法实现。在 qdisc 中我们可以基于 filter 和 class 实现复杂的树形结构，其中 filter 被挂载到 qdisc 或 class 上用于实现具体的过滤逻辑，返回值决定了该数据包是否属于特定 class。

当数据包到达顶层 qdisc 时，其入队接口被调用，其上挂载的 filter 被依次执行直到一个 filter 匹配成功；此后数据包被送入该 filter 指向的 class，进入该 class 配置的 qdisc 处理流程中。tc 框架提供了所谓 classifier-action 机制，即在数据包匹配到特定 filter 时执行该 filter 所挂载的 action 对数据包进行处理，实现了完整的数据包分类和处理机制。

现有的 tc 为 eBPF 提供了 direct-action 模式，它使得一个作为 filter 加载的 eBPF 程序可以返回像 `TC_ACT_OK` 等 tc action 的返回值，而不是像传统的 filter 那样仅仅返回一个 classid 并把对数据包的处理交给 action 模块。现在，eBPF 程序可以被挂载到特定的 qdisc 上，并完成对数据包的分类和处理动作。

## 编写 eBPF 程序

```c
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */

/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    bpf_printk("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
```

这段代码定义了一个 eBPF 程序，它可以通过 Linux TC（Transmission Control）来捕获数据包并进行处理。在这个程序中，我们限定了只捕获 IPv4 协议的数据包，然后通过 bpf_printk 函数打印出数据包的总长度和 Time-To-Live（TTL）字段的值。

需要注意的是，我们在代码中使用了一些 BPF 库函数，例如 bpf_htons 和 bpf_ntohs 函数，它们用于进行网络字节序和主机字节序之间的转换。此外，我们还使用了一些注释来为 TC 提供附加点和选项信息。例如，在这段代码的开头，我们使用了以下注释：

```c
/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
```

这些注释告诉 TC 将 eBPF 程序附加到网络接口的 ingress 附加点，并指定了 handle 和 priority 选项的值。关于 libbpf 中 tc 相关的 API 可以参考 [patchwork](https://patchwork.kernel.org/project/netdevbpf/patch/20210512103451.989420-3-memxor@gmail.com/) 中的介绍。

总之，这段代码实现了一个简单的 eBPF 程序，用于捕获数据包并打印出它们的信息。

## 编译运行

通过容器编译：

```console
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

或是通过 `ecc` 编译：

```console
$ ecc tc.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

并通过 `ecli` 运行：

```shell
sudo ecli run ./package.json
```

可以通过如下方式查看程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            node-1254811 [007] ..s1 8737831.671074: 0: Got IP packet: tot_len: 79, ttl: 64
            sshd-1254728 [006] ..s1 8737831.674334: 0: Got IP packet: tot_len: 79, ttl: 64
            sshd-1254728 [006] ..s1 8737831.674349: 0: Got IP packet: tot_len: 72, ttl: 64
            node-1254811 [007] ..s1 8737831.674550: 0: Got IP packet: tot_len: 71, ttl: 64
```

## 总结

本文介绍了如何向 TC 流量控制子系统挂载 eBPF 类型的 filter 来实现对链路层数据包的排队处理。基于 eunomia-bpf 提供的通过注释向 libbpf 传递参数的方案，我们可以将自己编写的 tc BPF 程序以指定选项挂载到目标网络设备，并借助内核的 sk_buff 结构对数据包进行过滤处理。

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。

## 参考

+ <http://just4coding.com/2022/08/05/tc/>
+ <https://arthurchiao.art/blog/understanding-tc-da-mode-zh/>
