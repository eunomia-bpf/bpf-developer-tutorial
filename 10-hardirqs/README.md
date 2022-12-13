# eBPF 入门开发实践指南十：在 eBPF 中使用 kprobe 监测捕获 unlink 系统调用

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践指南的第十篇，在 eBPF 中。

## hardirqs是什么？

hardirqs 是 bcc-tools 工具包的一部分，该工具包是一组用于在 Linux 系统上执行系统跟踪和分析的实用程序。
hardirqs 是一种用于跟踪和分析 Linux 内核中的中断处理程序的工具。它使用 BPF（Berkeley Packet Filter）程序来收集有关中断处理程序的数据，
并可用于识别内核中的性能问题和其他与中断处理相关的问题。

## 使用方法

 sudo hardirqs：该命令会显示有关内核中断处理程序的信息，包括每个处理程序的名称、统计信息和其他相关数据。
 hardirqs 提供了多种选项，您可以根据需要使用它们来控制 hardirqs 的输出。一些常用的选项包括：
 -h：显示帮助信息，包括所有可用选项的描述和示例。
 -p PID：限制输出仅显示指定进程的中断处理程序。
 -t：在输出中显示时间戳，以毫秒为单位。
 -d：以持续的方式运行 hardirqs，并在输出中显示中断处理程序的实时数据。
 -l：在输出中显示中断处理程序的完整路径。

## 实现原理

 在 Linux 内核中，每个中断处理程序都有一个唯一的名称，称为中断向量。hardirqs 通过检查每个中断处理程序的中断向量，来监控内核中的中断处理程序。当内核接收到一个中断时，它会查找与该中断相关的中断处理程序，并执行该程序。hardirqs 通过检查内核中执行的中断处理程序，来监控内核中的中断处理程序。另外，hardirqs 还可以通过注入 BPF 程序到内核中，来捕获内核中的中断处理程序。这样，hardirqs 就可以监控内核中执行的中断处理程序，并收集有关它们的信息。

## 代码实现

```c
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "hardirqs.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES 256

const volatile bool filter_cg = false;
const volatile bool targ_dist = false;
const volatile bool targ_ns = false;
const volatile bool do_count = false;

struct {
 __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
 __type(key, u32);
 __type(value, u32);
 __uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 __uint(max_entries, 1);
 __type(key, u32);
 __type(value, u64);
} start SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, struct irq_key);
 __type(value, struct info);
} infos SEC(".maps");

static struct info zero;

static int handle_entry(int irq, struct irqaction *action)
{
 if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
  return 0;

 if (do_count) {
  struct irq_key key = {};
  struct info *info;

  bpf_probe_read_kernel_str(&key.name, sizeof(key.name), BPF_CORE_READ(action, name));
  info = bpf_map_lookup_or_try_init(&infos, &key, &zero);
  if (!info)
   return 0;
  info->count += 1;
  return 0;
 } else {
  u64 ts = bpf_ktime_get_ns();
  u32 key = 0;

  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
   return 0;

  bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
  return 0;
 }
}

static int handle_exit(int irq, struct irqaction *action)
{
 struct irq_key ikey = {};
 struct info *info;
 u32 key = 0;
 u64 delta;
 u64 *tsp;

 if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
  return 0;

 tsp = bpf_map_lookup_elem(&start, &key);
 if (!tsp)
  return 0;

 delta = bpf_ktime_get_ns() - *tsp;
 if (!targ_ns)
  delta /= 1000U;

 bpf_probe_read_kernel_str(&ikey.name, sizeof(ikey.name), BPF_CORE_READ(action, name));
 info = bpf_map_lookup_or_try_init(&infos, &ikey, &zero);
 if (!info)
  return 0;

 if (!targ_dist) {
  info->count += delta;
 } else {
  u64 slot;

  slot = log2(delta);
  if (slot >= MAX_SLOTS)
   slot = MAX_SLOTS - 1;
  info->slots[slot]++;
 }

 return 0;
}

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(irq_handler_entry_btf, int irq, struct irqaction *action)
{
 return handle_entry(irq, action);
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(irq_handler_exit_btf, int irq, struct irqaction *action)
{
 return handle_exit(irq, action);
}

SEC("raw_tp/irq_handler_entry")
int BPF_PROG(irq_handler_entry, int irq, struct irqaction *action)
{
 return handle_entry(irq, action);
}

SEC("raw_tp/irq_handler_exit")
int BPF_PROG(irq_handler_exit, int irq, struct irqaction *action)
{
 return handle_exit(irq, action);
}

char LICENSE[] SEC("license") = "GPL";
```

这是一个 BPF（Berkeley Packet Filter）程序。BPF 程序是小型程序，可以直接在 Linux 内核中运行，用于过滤和操纵网络流量。这个特定的程序似乎旨在收集内核中中断处理程序的统计信息。它定义了一些地图（可以在 BPF 程序和内核的其他部分之间共享的数据结构）和两个函数：handle_entry 和 handle_exit。当内核进入和退出中断处理程序时，分别执行这些函数。handle_entry 函数用于跟踪中断处理程序被执行的次数，而 handle_exit 则用于测量中断处理程序中花费的时间。

## 运行代码

要编译这个程序，请使用 ecc 工具：

```console
$ ecc kprobe-link.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

然后运行：

```console
sudo ecli package.json
```
