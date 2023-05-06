# eBPF 入门实践教程：编写 eBPF 程序 Tcprtt 测量 TCP 连接的往返时间

## 背景

网络质量在互联网社会中是一个很重要的因素。导致网络质量差的因素有很多，可能是硬件因素导致，也可能是程序
写的不好导致。为了能更好地定位网络问题，`tcprtt` 工具被提出。它可以监测TCP链接的往返时间，从而分析
网络质量，帮助用户定位问题来源。

当有tcp链接建立时，该工具会自动根据当前系统的支持情况，选择合适的执行函数。
在执行函数中，`tcprtt`会收集tcp链接的各项基本信息，包括地址，源端口，目标端口，耗时
等等，并将其更新到直方图的map中。运行结束后通过用户态代码，展现给用户。

## 编写 eBPF 程序

```c
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "tcprtt.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile bool targ_laddr_hist = false;
const volatile bool targ_raddr_hist = false;
const volatile bool targ_show_ext = false;
const volatile __u16 targ_sport = 0;
const volatile __u16 targ_dport = 0;
const volatile __u32 targ_saddr = 0;
const volatile __u32 targ_daddr = 0;
const volatile bool targ_ms = false;

#define MAX_ENTRIES	10240

/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
    const struct inet_sock *inet = (struct inet_sock *)(sk);
    struct tcp_sock *ts;
    struct hist *histp;
    u64 key, slot;
    u32 srtt;

    if (targ_sport && targ_sport != inet->inet_sport)
        return 0;
    if (targ_dport && targ_dport != sk->__sk_common.skc_dport)
        return 0;
    if (targ_saddr && targ_saddr != inet->inet_saddr)
        return 0;
    if (targ_daddr && targ_daddr != sk->__sk_common.skc_daddr)
        return 0;

    if (targ_laddr_hist)
        key = inet->inet_saddr;
    else if (targ_raddr_hist)
        key = inet->sk.__sk_common.skc_daddr;
    else
        key = 0;
    histp = bpf_map_lookup_or_try_init(&hists, &key, &zero);
    if (!histp)
        return 0;
    ts = (struct tcp_sock *)(sk);
    srtt = BPF_CORE_READ(ts, srtt_us) >> 3;
    if (targ_ms)
        srtt /= 1000U;
    slot = log2l(srtt);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;
    __sync_fetch_and_add(&histp->slots[slot], 1);
    if (targ_show_ext) {
        __sync_fetch_and_add(&histp->latency, srtt);
        __sync_fetch_and_add(&histp->cnt, 1);
    }
    return 0;
}

```


这段代码是基于eBPF的网络延迟分析工具，它通过hooking TCP协议栈中的tcp_rcv_established函数来统计TCP连接的RTT分布。下面是这段代码的主要工作原理：

1. 首先定义了一个名为"hists"的eBPF哈希表，用于保存RTT直方图数据。
2. 当tcp_rcv_established函数被调用时，它首先从传入的socket结构体中获取TCP相关信息，包括本地/远程IP地址、本地/远程端口号以及TCP状态信息等。
3. 接下来，代码会检查用户指定的条件是否匹配当前TCP连接。如果匹配失败，则直接返回。
4. 如果匹配成功，则从"hists"哈希表中查找与本地/远程IP地址匹配的直方图数据。如果该IP地址的直方图不存在，则创建一个新的直方图并插入哈希表中。
5. 接下来，代码会从socket结构体中获取当前TCP连接的RTT(srtt)，并根据用户设置的选项来将srtt值进行处理。如果用户设置了"-ms"选项，则将srtt值除以1000。
6. 接着，代码会将srtt值转换为直方图的槽位(slot)，并将该槽位的计数器+1。
7. 如果用户设置了"-show-ext"选项，则还会累加直方图的总延迟(latency)和计数(cnt)。

## 编译运行

eunomia-bpf 是一个结合 Wasm 的开源 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。可以参考 <https://github.com/eunomia-bpf/eunomia-bpf> 下载和安装 ecc 编译工具链和 ecli 运行时。我们使用 eunomia-bpf 编译运行这个例子。

Compile:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

或者

```console
$ ecc runqlat.bpf.c runqlat.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```
Run:
```console
$ sudo ecli run package.json -h
A simple eBPF program


Usage: package.json [OPTIONS]

Options:
      --verbose                  Whether to show libbpf debug information
      --targ_laddr_hist          Set value of `bool` variable targ_laddr_hist
      --targ_raddr_hist          Set value of `bool` variable targ_raddr_hist
      --targ_show_ext            Set value of `bool` variable targ_show_ext
      --targ_sport <targ_sport>  Set value of `__u16` variable targ_sport
      --targ_dport <targ_dport>  Set value of `__u16` variable targ_dport
      --targ_saddr <targ_saddr>  Set value of `__u32` variable targ_saddr
      --targ_daddr <targ_daddr>  Set value of `__u32` variable targ_daddr
      --targ_ms                  Set value of `bool` variable targ_ms
  -h, --help                     Print help
  -V, --version                  Print version

Built with eunomia-bpf framework.
See https://github.com/eunomia-bpf/eunomia-bpf for more information.

$ sudo ecli run package.json
key =  0
latency = 0
cnt = 0

     (unit)              : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 4        |********************                    |
      1024 -> 2047       : 1        |*****                                   |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 8        |****************************************|

key =  0
latency = 0
cnt = 0

     (unit)              : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 11       |***************************             |
      1024 -> 2047       : 1        |**                                      |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 16       |****************************************|
      8192 -> 16383      : 4        |**********                              |
```

## 总结

tcprtt是一个基于eBPF的TCP延迟分析工具。通过hooking TCP协议栈中的tcp_rcv_established函数来统计TCP连接的RTT分布，可以对指定的TCP连接进行RTT分布统计，并将结果保存到eBPF哈希表中。同时，这个工具支持多种条件过滤和RTT分布数据扩展功能，以便用户可以更好地进行网络性能分析和调优。

更多的例子和详细的开发指南，请参考 eunomia-bpf 的官方文档：<https://github.com/eunomia-bpf/eunomia-bpf>

完整的教程和源代码已经全部开源，可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 中查看。
