# eBPF 入门开发实践教程十：在 eBPF 中使用 hardirqs 或 softirqs 捕获中断事件

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践教程的第十篇，在 eBPF 中使用 hardirqs 或 softirqs 捕获中断事件。
hardirqs 和 softirqs 是 Linux 内核中两种不同类型的中断处理程序。它们用于处理硬件设备产生的中断请求，以及内核中的异步事件。在 eBPF 中，我们可以使用同名的 eBPF 工具 hardirqs 和 softirqs 来捕获和分析内核中与中断处理相关的信息。

## hardirqs 和 softirqs 是什么？

hardirqs 是硬件中断处理程序。当硬件设备产生一个中断请求时，内核会将该请求映射到一个特定的中断向量，然后执行与之关联的硬件中断处理程序。硬件中断处理程序通常用于处理设备驱动程序中的事件，例如设备数据传输完成或设备错误。

softirqs 是软件中断处理程序。它们是内核中的一种底层异步事件处理机制，用于处理内核中的高优先级任务。softirqs 通常用于处理网络协议栈、磁盘子系统和其他内核组件中的事件。与硬件中断处理程序相比，软件中断处理程序具有更高的灵活性和可配置性。

## 实现原理

在 eBPF 中，我们可以通过挂载特定的 kprobe 或者 tracepoint 来捕获和分析 hardirqs 和 softirqs。为了捕获 hardirqs 和 softirqs，需要在相关的内核函数上放置 eBPF 程序。这些函数包括：

- 对于 hardirqs：irq_handler_entry 和 irq_handler_exit。
- 对于 softirqs：softirq_entry 和 softirq_exit。

当内核处理 hardirqs 或 softirqs 时，这些 eBPF 程序会被执行，从而收集相关信息，如中断向量、中断处理程序的执行时间等。收集到的信息可以用于分析内核中的性能问题和其他与中断处理相关的问题。

为了捕获 hardirqs 和 softirqs，我们需要在 eBPF 程序中定义用于存储中断信息的数据结构和映射，编写 eBPF 程序并将其挂载到相应的内核函数上，收集中断处理程序的相关信息并存储在映射中，最后在用户空间应用程序中读取映射中的数据以分析和展示中断处理信息。通过这种方法，我们可以在 eBPF 中捕获和分析内核中的中断事件，以识别潜在的性能问题。

## hardirqs 代码实现

hardirqs 程序的主要目的是获取中断处理程序的名称、执行次数和执行时间，并以直方图的形式展示执行时间的分布。让我们一步步分析这段代码。

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

这段代码展示了如何使用 eBPF 捕获和分析硬件中断的执行信息。

让我们看看代码的工作原理。程序定义了一些 `const volatile` 全局变量用于配置行为：`filter_cg` 控制是否过滤 cgroup，`targ_dist` 控制是否显示执行时间分布，`do_count` 控制是否只统计计数。程序使用三个映射：cgroup 过滤映射、per-CPU 的开始时间戳映射，以及存储中断处理信息的 hash 映射。

核心逻辑在 `handle_entry` 和 `handle_exit` 两个函数中。在中断入口处，如果启用了计数模式，程序会直接增加中断计数；否则记录当前时间戳。在中断出口处，程序计算执行时间（当前时间减去开始时间），然后根据配置决定是累加总时间还是更新直方图槽位。

程序定义了四个 eBPF 入口点，使用 `tp_btf` 和 `raw_tp` 两种 tracepoint 类型。这种双重实现确保了程序在不同内核版本上的兼容性——较新的内核支持 BTF，较老的内核则使用原始 tracepoint。Softirq 代码也采用类似的模式。

## 运行代码

我们使用 eunomia-bpf 来编译和运行这个示例。你可以从 <https://github.com/eunomia-bpf/eunomia-bpf> 安装它。

要编译这个程序，请使用 ecc 工具：

```console
$ ecc hardirqs.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

然后运行：

```console
sudo ecli run ./package.json
```

## 总结

在本章节中，我们学习了如何使用 eBPF 程序捕获和分析内核中硬件中断处理程序的执行信息。通过在中断处理程序的入口和出口处记录时间戳，我们可以测量中断处理时间，识别内核中的性能问题。

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。
