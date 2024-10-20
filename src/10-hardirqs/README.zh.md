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

为了捕获 hardirqs 和 softirqs，可以遵循以下步骤：

1. 在 eBPF 程序中定义用于存储中断信息的数据结构和映射。
2. 编写 eBPF 程序，将其挂载到相应的内核函数上，以捕获 hardirqs 或 softirqs。
3. 在 eBPF 程序中，收集中断处理程序的相关信息，并将这些信息存储在映射中。
4. 在用户空间应用程序中，读取映射中的数据以分析和展示中断处理信息。

通过上述方法，我们可以在 eBPF 中使用 hardirqs 和 softirqs 捕获和分析内核中的中断事件，以识别潜在的性能问题和与中断处理相关的问题。

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

这段代码是一个 eBPF 程序，用于捕获和分析内核中硬件中断处理程序（hardirqs）的执行信息。程序的主要目的是获取中断处理程序的名称、执行次数和执行时间，并以直方图的形式展示执行时间的分布。让我们一步步分析这段代码。

1. 包含必要的头文件和定义数据结构：

    ```c
    #include <vmlinux.h>
    #include <bpf/bpf_core_read.h>
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_tracing.h>
    #include "hardirqs.h"
    #include "bits.bpf.h"
    #include "maps.bpf.h"
    ```

    该程序包含了 eBPF 开发所需的标准头文件，以及用于定义数据结构和映射的自定义头文件。

2. 定义全局变量和映射：

    ```c

    #define MAX_ENTRIES 256

    const volatile bool filter_cg = false;
    const volatile bool targ_dist = false;
    const volatile bool targ_ns = false;
    const volatile bool do_count = false;

    ...
    ```

    该程序定义了一些全局变量，用于配置程序的行为。例如，`filter_cg` 控制是否过滤 cgroup，`targ_dist` 控制是否显示执行时间的分布等。此外，程序还定义了三个映射，分别用于存储 cgroup 信息、开始时间戳和中断处理程序的信息。

3. 定义两个辅助函数 `handle_entry` 和 `handle_exit`：

    这两个函数分别在中断处理程序的入口和出口处被调用。`handle_entry` 记录开始时间戳或更新中断计数，`handle_exit` 计算中断处理程序的执行时间，并将结果存储到相应的信息映射中。

4. 定义 eBPF 程序的入口点：

    ```c

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
    ```

    这里定义了四个 eBPF 程序入口点，分别用于捕获中断处理程序的入口和出口事件。`tp_btf` 和 `raw_tp` 分别代表使用 BPF Type Format（BTF）和原始 tracepoints 捕获事件。这样可以确保程序在不同内核版本上可以移植和运行。

Softirq 代码也类似，这里就不再赘述了。

## 运行代码

eunomia-bpf 是一个结合 Wasm 的开源 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。可以参考 <https://github.com/eunomia-bpf/eunomia-bpf> 下载和安装 ecc 编译工具链和 ecli 运行时。我们使用 eunomia-bpf 编译运行这个例子。

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

在本章节（eBPF 入门开发实践教程十：在 eBPF 中使用 hardirqs 或 softirqs 捕获中断事件）中，我们学习了如何使用 eBPF 程序捕获和分析内核中硬件中断处理程序（hardirqs）的执行信息。我们详细讲解了示例代码，包括如何定义数据结构、映射以及 eBPF 程序入口点，以及如何在中断处理程序的入口和出口处调用辅助函数来记录执行信息。

通过学习本章节内容，您应该已经掌握了如何在 eBPF 中使用 hardirqs 或 softirqs 捕获中断事件的方法，以及如何分析这些事件以识别内核中的性能问题和其他与中断处理相关的问题。这些技能对于分析和优化 Linux 内核的性能至关重要。

为了更好地理解和实践 eBPF 编程，我们建议您阅读 eunomia-bpf 的官方文档：<https://github.com/eunomia-bpf/eunomia-bpf> 。此外，我们还为您提供了完整的教程和源代码，您可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 中查看和学习。希望本教程能够帮助您顺利入门 eBPF 开发，并为您的进一步学习和实践提供有益的参考。
