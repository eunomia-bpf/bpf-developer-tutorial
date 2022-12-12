## eBPF 入门开发实践指南十：在 eBPF 中使用 kprobe 监测捕获 unlink 系统调用

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践指南的第十篇，在 eBPF 中。
## hardirqs是什么？

```
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "hardirqs.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	256

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
这看起来是一个 BPF（Berkeley Packet Filter）程序。BPF 程序是小型程序，可以直接在 Linux 内核中运行，用于过滤和操纵网络流量。这个特定的程序似乎旨在收集内核中中断处理程序的统计信息。它定义了一些地图（可以在 BPF 程序和内核的其他部分之间共享的数据结构）和两个函数：handle_entry 和 handle_exit。当内核进入和退出中断处理程序时，分别执行这些函数。handle_entry 函数用于跟踪中断处理程序被执行的次数，而 handle_exit 则用于测量中断处理程序中花费的时间。
