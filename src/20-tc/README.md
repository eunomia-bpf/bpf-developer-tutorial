# eBPF Tutorial by Example 20: tc Traffic Control

## Background

Linux's Traffic Control (tc) subsystem has been present in the kernel for many years. Similar to the relationship between iptables and netfilter, tc includes a user-space tc program and a kernel-level traffic control framework. It is mainly used to control the sending and receiving of packets in terms of rate, sequence, and other aspects. Starting from Linux 4.1, tc has added some new attachment points and supports loading eBPF programs as filters onto these attachment points.

## Overview of tc

From the protocol stack perspective, tc is located at the link layer. Its position has already completed the allocation of sk_buff and is later than xdp. In order to control the sending and receiving of packets, tc uses a queue structure to temporarily store and organize packets. In the tc subsystem, the corresponding data structure and algorithm control mechanism are abstracted as qdisc (Queueing discipline). It exposes two callback interfaces for enqueuing and dequeuing packets externally, and internally hides the implementation of queuing algorithms. In qdisc, we can implement complex tree structures based on filters and classes. Filters are mounted on qdisc or class to implement specific filtering logic, and the return value determines whether the packet belongs to a specific class.

When a packet reaches the top-level qdisc, its enqueue interface is called, and the mounted filters are executed one by one until a filter matches successfully. Then the packet is sent to the class pointed to by that filter and enters the qdisc processing process configured by that class. The tc framework provides the so-called classifier-action mechanism, that is, when a packet matches a specific filter, the action mounted by that filter is executed to process the packet, implementing a complete packet classification and processing mechanism.

The existing tc provides eBPF with the direct-action mode, which allows an eBPF program loaded as a filter to return values such as `TC_ACT_OK` as tc actions, instead of just returning a classid like traditional filters and handing over the packet processing to the action module. Now, eBPF programs can be mounted on specific qdiscs to perform packet classification and processing actions.

## Writing eBPF Programs

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

This code defines an eBPF program that can capture and process packets through Linux TC (Transmission Control). In this program, we limit it to capture only IPv4 protocol packets, and then print out the total length and Time-To-Live (TTL) value of the packet using the bpf_printk function.

What needs to be noted is that we use some BPF library functions in the code, such as the functions bpf_htons and bpf_ntohs, which are used for conversion between network byte order and host byte order. In addition, we also use some comments to provide additional points and option information for TC. For example, at the beginning of this code, we use the following comments:

```c
/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
```

These comments tell TC to attach the eBPF program to the ingress attachment point of the network interface, and specify the values of the handle and priority options. You can refer to the introduction in [patchwork](https://patchwork.kernel.org/project/netdevbpf/patch/20210512103451.989420-3-memxor@gmail.com/) for tc-related APIs in libbpf.

In summary, this code implements a simple eBPF program that captures packets and prints out their information.

## Compilation and Execution

Compile using a container:

```console
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

Or compile using `ecc`:

```console
$ ecc tc.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

And run using `ecli`:

```shell
sudo ecli run ./package.json
```

You can view the output of the program in the following way:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            node-1254811 [007] ..s1 8737831.671074: 0: Got IP packet: tot_len: 79, ttl: 64
            sshd-1254728 [006] ..s1 8737831.674334: 0: Got IP packet: tot_len: 79, ttl: 64
            sshd-1254728 [006] ..s1 8737831.674349: 0: Got IP packet: tot_len: 72, ttl: 64
            node-1254811 [007] ..s1 8737831.674550: 0: Got IP packet: tot_len: 71, ttl: 64
```

## Summary

This article introduces how to mount eBPF type filters to the TC traffic control subsystem to achieve queuing processing of link layer packets. Based on the solution provided by eunomia-bpf to pass parameters to libbpf through comments, we can mount our own tc BPF program to the target network device with specified options and use the sk_buff structure of the kernel to filter and process packets.

If you want to learn more about eBPF knowledge and practice, you can visit our tutorial code repository <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials.

## References

+ <http://just4coding.com/2022/08/05/tc/>
+ <https://arthurchiao.art/blog/understanding-tc-da-mode-zh/>

> The original link of this article: <https://eunomia.dev/tutorials/20-tc>
