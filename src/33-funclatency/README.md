# 使用 eBPF 测量函数延迟

在现代软件系统中，了解函数的性能特性，尤其是那些对应用程序运行至关重要的函数的性能特性，是至关重要的。性能分析中的一个关键指标是**函数延迟**，即函数从开始到完成所花费的时间。通过分析函数延迟，开发人员可以识别瓶颈、优化性能，并确保系统在各种条件下高效运行。

本文将深入探讨如何使用 eBPF 这一强大的工具来测量函数延迟，并展示如何在内核和用户空间中进行跟踪和监控。

## 什么是 eBPF？

eBPF（扩展伯克利包过滤器）是一项革命性的技术，它允许开发人员编写小型程序在 Linux 内核中运行。eBPF 最初是为数据包过滤设计的，但它已经发展成为一个多功能工具，用于跟踪、监控和分析系统行为。通过 eBPF，您几乎可以对 Linux 内核或用户空间的任何部分进行插桩，从而收集性能数据、执行安全策略，甚至实时调试系统——这一切都无需修改内核源码或重启系统。

eBPF 程序在内核的沙盒环境中执行，确保了安全性和稳定性。这些程序可以附加到内核中的各种钩子上，如系统调用、网络事件和跟踪点，甚至可以通过 uprobes（用户级探针）附加到用户空间的函数。eBPF 程序收集的数据可以导出到用户空间进行分析，使其成为系统可观测性的重要工具。内核模式 eBPF 运行时的 `Uprobe` 可能会带来较大的性能开销。在这种情况下，你也可以考虑使用用户模式的 eBPF 运行时，例如 [bpftime](https://github.com/eunomia-bpf/bpftime)。

## 为什么函数延迟很重要？

函数延迟是内核和用户空间应用程序性能分析中的一个关键指标。它提供了关于特定函数执行时间的洞察，这对以下方面至关重要：

- **识别性能瓶颈**：高函数延迟可能表明代码中存在需要优化的低效或问题。
- **确保系统响应能力**：在实时系统或对延迟敏感的应用程序中，理解和最小化函数延迟对于保持响应能力至关重要。
- **性能分析和基准测试**：通过测量各种函数的延迟，开发人员可以对系统进行基准测试，并比较不同实现或配置的性能。
- **调试和诊断**：当系统表现出意外行为或性能下降时，测量函数延迟可以帮助定位问题的根源。

内核空间（如系统调用、文件操作）和用户空间（如库函数）中的函数都可以进行延迟分析，从而提供系统性能的全面视图。

## 用于函数延迟的 eBPF 内核代码

以下是一个设计用于测量函数延迟的 eBPF 程序，它通过挂钩函数的入口和出口点来实现。该程序使用 kprobes 和 kretprobes（用于内核函数）或 uprobes 和 uretprobes（用于用户空间函数）来捕获函数执行的开始和结束时间。

```c
// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "funclatency.h"
#include "bits.bpf.h"

const volatile pid_t targ_tgid = 0;
const volatile int units = 0;

/* key: pid.  value: start time */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, u32);
    __type(value, u64);
} starts SEC(".maps");

__u32 hist[MAX_SLOTS] = {};

static void entry(void)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;
    u64 nsec;

    if (targ_tgid && targ_tgid != tgid)
        return;
    nsec = bpf_ktime_get_ns();
    bpf_map_update_elem(&starts, &pid, &nsec, BPF_ANY);
}

SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe)
{
    entry();
    return 0;
}

static void exit(void)
{
    u64 *start;
    u64 nsec = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64 slot, delta;

    start = bpf_map_lookup_elem(&starts, &pid);
    if (!start)
        return;

    delta = nsec - *start;

    switch (units) {
    case USEC:
        delta /= 1000;
        break;
    case MSEC:
        delta /= 1000000;
        break;
    }

    slot = log2l(delta);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;
    __sync_fetch_and_add(&hist[slot], 1);
}

SEC("kretprobe/dummy_kretprobe")
int BPF_KRETPROBE(dummy_kretprobe)
{
    exit();
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 代码解释

1. **头文件**：代码首先包含了必要的头文件，如 `vmlinux.h`（提供内核定义）和 `bpf_helpers.h`（提供 eBPF 程序的辅助函数）。

2. **全局变量**：`targ_tgid` 是目标进程 ID（或线程组 ID），`units` 确定延迟测量的时间单位（如微秒或毫秒）。

3. **BPF 映射**：定义了一个哈希映射（`starts`），用于存储每个进程 ID 的函数执行开始时间。另一个数组（`hist`）用于存储延迟分布。

4. **入口函数**：`entry()` 函数在函数进入时捕获当前时间戳，并将其存储在以进程 ID 为键的 `starts` 映射中。

5. **出口函数**：`exit()` 函数通过将存储的开始时间与当前时间相减来计算延迟。然后将结果分类到直方图槽中，并增加该槽的计数以记录该延迟范围的发生次数。

6. **探针**：`kprobe` 和 `kretprobe` 用于附加到函数的入口和出口点。这些探针触发 `entry()` 和 `exit()` 函数来测量延迟。

7. **许可证**：该程序根据 GPL 许可证发布，以确保符合内核的许可要求。

## 运行函数延迟工具

### 用户空间函数延迟

要跟踪用户空间函数（例如 `libc` 库中的 `read` 函数）的延迟，可以运行以下命令：

```console
# ./funclatency /usr/lib/x86_64-linux-gnu/libc.so.6:read    
tracing /usr/lib/x86_64-linux-gnu/libc.so.6:read...
tracing func read in /usr/lib/x86_64-linux-gnu/libc.so.6...
Tracing /usr/lib/x86_64-linux-gnu/libc.so.6:read.  Hit Ctrl-C to exit
^C
     nsec                : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
       128 -> 255        : 0        |                                        |
       512 -> 1023       : 0        |                                        |
      65536 -> 131071     : 651      |****************************************+|
    131072 -> 262143     : 107      |******                                  |
    262144 -> 524287     : 36       |**                                      |
    524288 -> 1048575    : 8        |                                        |
   8388608 -> 16777215   : 2        |                                        |
Exiting trace of /usr/lib/x86_64-linux-gnu/libc.so.6:read
```

### 内核空间函数延迟

要跟踪内核空间函数（例如 `vfs_read`）的延迟，可以运行以下命令：

```console
# sudo ./funclatency -u vfs_read
Tracing vfs_read.  Hit Ctrl-C to exit
^C
     usec                : count    distribution
         0 -> 1          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 3397     |****************************************|
        32 -> 63         : 2175     |*************************               |
        64 -> 127        : 184      |**                                      |
       1024 -> 2047       : 0        |                                        |
       4096 -> 8191       : 5        |                                        |
   2097152 -> 

4194303    : 2        |                                        |
Exiting trace of vfs_read
```

这些命令会跟踪指定函数（无论是在用户空间还是内核空间）的执行，并打印出观察到的延迟的直方图，显示函数执行时间的分布。

<https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/33-funclatency>

## 结论

使用 eBPF 测量函数延迟可以深入了解用户空间和内核空间代码的性能。通过了解函数延迟，开发人员可以识别性能瓶颈、提高系统响应能力，并确保其应用程序的顺畅运行。

本文介绍了使用 eBPF 跟踪函数延迟的基本知识，包括实现该跟踪功能的 eBPF 内核代码概述。文中提供的示例展示了如何运行工具以跟踪用户空间和内核空间函数的延迟。

如果您有兴趣了解更多关于 eBPF 的知识，包括更多高级示例和教程，请访问我们的[教程代码库](https://github.com/eunomia-bpf/bpf-developer-tutorial)或我们的网站 [Eunomia](https://eunomia.dev/tutorials/)。

如果您正在寻找一个用于函数延迟测量的生产就绪工具，您可能想查看 BCC 仓库中的完整实现：[BCC 仓库](https://github.com/iovisor/bcc/blob/master/libbpf-tools/funclatency.c)。
