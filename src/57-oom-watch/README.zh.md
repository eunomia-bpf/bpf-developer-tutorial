# eBPF 实战教程：在 OOM Kill 之前分析内存回收

你是否遇到过容器或服务突然被 Linux OOM killer 杀掉，只留下一行不明所以的内核日志？内核会告诉你它选择了*哪个*进程作为 victim，但对于导致这一结果的内存压力几乎只字未提。系统尝试了多少次内存回收？每次花了多久？哪些内核路径消耗了这些时间？

本教程构建 `oom-watch`，一个 eBPF 工具，用于捕获 OOM kill *之前*发生的事情。它将每次 memcg 回收尝试记录为延迟直方图和采样的内核调用栈，然后将积累的 profile 附加到 OOM victim 上，并跟踪进程直到它退出。

> 完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/57-oom-watch>

## OOM 调试中缺失的一环

当 memory cgroup 接近其限制时，任何内存分配都可能触发回收。内核会扫描该 cgroup 中可释放的页面。有时几次短暂的尝试就能成功。有时，回收反复运行却进展甚微，直到 OOM killer 最终介入。

如果只观察 `oom/mark_victim` tracepoint，你会丢失所有这些上下文。你看到了 victim，却看不到之前的挣扎过程。运维人员需要这些问题的答案：

- OOM kill 之前发生了多少次回收周期？
- 它们是微秒级的快速扫描，还是毫秒级的长时间停顿？
- 回收是由 cgroup 内部的分配触发的，还是通过 `memory.reclaim` 从外部主动触发的？
- 哪些内核函数占用了回收时间？

`oom-watch` 可以回答所有这些问题。它通过 hook 内核的 vmscan tracepoint 来测量每个回收间隔，采样内核调用栈以展示时间花在了哪里，当 OOM 选择 victim 时，它会将累积的 profile 快照与 victim 信息一起输出。

## 为什么用 eBPF 做内存分析？

传统监控方法在这个场景下有严重的局限性。轮询 `/proc/meminfo` 或 cgroup 统计会错过短暂的回收事件。`perf` 可以捕获调用栈，但需要仔细配置和后处理。两种方法都不容易将回收活动与特定的 OOM 事件关联起来。

eBPF 改变了这一切。程序直接在内核中运行，以纳秒级精度响应事件。Map 在事件之间传递状态，让我们可以构建直方图并关联 begin/end 对。Ring buffer 以最小的开销将事件传递给用户空间。而且因为 eBPF 程序在加载前经过验证，不会有崩溃内核的风险。

对于 `oom-watch`，我们使用几个 tracepoint：

- `mm_vmscan_memcg_reclaim_begin`：当特定 memory cgroup 的回收开始时触发
- `mm_vmscan_memcg_reclaim_end`：当该回收间隔完成时触发
- `oom/mark_victim`：当 OOM killer 选择 victim 时触发
- `sched/sched_process_exit`：当 victim 进程退出时触发

Linux 7.1 添加了一个关键特性：vmscan tracepoint 现在包含被扫描的目标 `mem_cgroup`。这很重要，因为一个 cgroup 中的进程可以通过 `memory.reclaim` 触发另一个 cgroup 的回收。有了 tracepoint 中的目标 cgroup，我们可以正确归因这些工作。

## 架构概述

这个工具有三个主要组件协同工作。

**头文件**定义共享数据结构：包含延迟桶和计数器的 per-cgroup 回收 profile，跟踪采样和时间的 per-stack aggregate，以及 OOM 通知的事件结构。

**BPF 程序**在内核中运行。在回收开始时，它记录开始时间并可选地捕获内核调用栈。在回收结束时，它计算持续时间，更新直方图，并存储 stack aggregate。当 OOM 标记 victim 时，它查找 victim 的 cgroup，将累积的 profile 复制到事件中，并发送给用户空间。它还保存 victim 状态，以便在进程退出时进行报告。

**用户空间程序**加载内核符号用于调用栈符号化，管理可选的 cgroup 过滤器，处理来自 ring buffer 的事件，并包含一个自包含的 demo 模式，可以触发 OOM 来验证一切正常工作。

## Profile 数据结构

共享头文件定义了我们测量的内容：

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OOM_WATCH_H
#define __OOM_WATCH_H

#define OOM_RECLAIM_BUCKETS 20
#define OOM_STACK_DEPTH 127

enum oom_watch_event_type {
	OOM_VICTIM_MARKED = 1,
	OOM_VICTIM_EXITED = 2,
};

struct reclaim_profile {
	unsigned long long begin_count;
	unsigned long long end_count;
	unsigned long long reclaimed_pages;
	unsigned long long cross_cgroup_reclaims;
	unsigned long long last_reclaim_ns;
	unsigned long long total_reclaim_ns;
	unsigned long long maximum_reclaim_ns;
	unsigned long long stack_samples;
	unsigned long long stack_failures;
	unsigned long long latency_slots[OOM_RECLAIM_BUCKETS];
};

struct reclaim_stack_key {
	unsigned long long cgroup_id;
	signed int stack_id;
	unsigned int padding;
};

struct reclaim_stack_profile {
	unsigned long long samples;
	unsigned long long total_ns;
	unsigned long long maximum_ns;
	unsigned long long reclaimed_pages;
};

struct oom_watch_event {
	unsigned long long timestamp_ns;
	unsigned long long cgroup_id;
	struct reclaim_profile profile;
	unsigned long long total_vm_kb;
	unsigned long long anon_rss_kb;
	unsigned long long file_rss_kb;
	unsigned int type;
	unsigned int victim_pid;
	unsigned int victim_tid;
	unsigned int triggering_tgid;
	signed int exit_code;
	char comm[16];
};

#endif /* __OOM_WATCH_H */
```

`latency_slots` 数组是一个 20 个桶的 2 次幂直方图。桶 0 覆盖 0-1 微秒，桶 1 覆盖 2-3 微秒，然后是 4-7 微秒，依此类推。最后一个桶捕获超过半秒的所有内容。这种对数分布可以高效地捕获快速回收周期和罕见的慢速周期。

当 OOM 事件触发时，它会嵌入 cgroup profile 的完整副本。与 victim 一起打印的数字准确显示了选择时的状态。

## BPF 程序

下面是完整的 BPF 代码。我们将在代码之后解释它的工作原理：

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "oom_watch.h"

char LICENSE[] SEC("license") = "GPL";

const volatile __u64 target_cgroup_id;
const volatile __u32 sample_every = 1;

extern struct task_struct *bpf_task_from_pid(__s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *task) __ksym;

struct active_reclaim {
	__u64 started_ns;
	__u64 cgroup_id;
	__s32 stack_id;
	__u32 padding;
};

struct victim_state {
	__u64 cgroup_id;
	__u32 triggering_tgid;
	__u32 victim_tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct reclaim_profile);
} profiles SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct active_reclaim);
} active_reclaims SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, OOM_STACK_DEPTH * sizeof(__u64));
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct reclaim_stack_key);
	__type(value, struct reclaim_stack_profile);
} stack_profiles SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct victim_state);
} victims SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

__u64 dropped_victim_states;
__u64 dropped_reclaim_states;

static __always_inline bool selected_cgroup(__u64 cgroup_id)
{
	return !target_cgroup_id || cgroup_id == target_cgroup_id;
}

static __always_inline __u64 victim_task_info(__u32 victim_pid,
					      __u32 *victim_tgid)
{
	struct task_struct *task;
	__u64 cgroup_id = 0;

	task = bpf_task_from_pid(victim_pid);
	if (!task)
		return 0;
	cgroup_id = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id);
	*victim_tgid = BPF_CORE_READ(task, tgid);
	bpf_task_release(task);
	return cgroup_id;
}

static __always_inline __u64 memcg_cgroup_id(struct mem_cgroup *memcg)
{
	struct cgroup *cgroup;

	cgroup = BPF_CORE_READ(memcg, css.cgroup);
	if (!cgroup)
		return 0;
	return BPF_CORE_READ(cgroup, kn, id);
}

static __always_inline struct reclaim_profile *get_profile(__u64 cgroup_id)
{
	struct reclaim_profile initial = {};
	struct reclaim_profile *profile;

	profile = bpf_map_lookup_elem(&profiles, &cgroup_id);
	if (profile)
		return profile;
	bpf_map_update_elem(&profiles, &cgroup_id, &initial, BPF_NOEXIST);
	return bpf_map_lookup_elem(&profiles, &cgroup_id);
}

static __always_inline __u32 latency_bucket(__u64 duration_ns)
{
	__u64 microseconds = duration_ns / 1000;
	__u32 bucket = 0;

	for (int i = 0; i < OOM_RECLAIM_BUCKETS - 1; i++) {
		if (microseconds < 2)
			break;
		microseconds >>= 1;
		bucket++;
	}
	return bucket;
}

static __always_inline void update_maximum(__u64 *maximum, __u64 value)
{
	__u64 previous = *maximum;

	for (int i = 0; i < 8 && previous < value; i++) {
		__u64 observed = __sync_val_compare_and_swap(maximum, previous,
							 value);

		if (observed == previous)
			break;
		previous = observed;
	}
}

static __always_inline void update_stack_profile(__u64 cgroup_id,
						 __s32 stack_id,
						 __u64 duration_ns,
						 __u64 reclaimed)
{
	struct reclaim_stack_key key = {
		.cgroup_id = cgroup_id,
		.stack_id = stack_id,
	};
	struct reclaim_stack_profile initial = {};
	struct reclaim_stack_profile *profile;

	profile = bpf_map_lookup_elem(&stack_profiles, &key);
	if (!profile) {
		bpf_map_update_elem(&stack_profiles, &key, &initial, BPF_NOEXIST);
		profile = bpf_map_lookup_elem(&stack_profiles, &key);
	}
	if (!profile)
		return;
	__sync_fetch_and_add(&profile->samples, 1);
	__sync_fetch_and_add(&profile->total_ns, duration_ns);
	__sync_fetch_and_add(&profile->reclaimed_pages, reclaimed);
	update_maximum(&profile->maximum_ns, duration_ns);
}

SEC("tp_btf/mm_vmscan_memcg_reclaim_begin")
int BPF_PROG(profile_reclaim_begin, gfp_t gfp_flags, int order,
	     struct mem_cgroup *memcg)
{
	struct active_reclaim active = { .stack_id = -1 };
	struct reclaim_profile *profile;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 cgroup_id = memcg_cgroup_id(memcg);
	__u64 sequence;

	(void)gfp_flags;
	(void)order;
	if (!selected_cgroup(cgroup_id))
		return 0;
	profile = get_profile(cgroup_id);
	if (!profile)
		return 0;
	sequence = __sync_fetch_and_add(&profile->begin_count, 1);
	if (bpf_get_current_cgroup_id() != cgroup_id)
		__sync_fetch_and_add(&profile->cross_cgroup_reclaims, 1);
	profile->last_reclaim_ns = bpf_ktime_get_ns();
	active.started_ns = profile->last_reclaim_ns;
	active.cgroup_id = cgroup_id;
	if (!sample_every || sequence % sample_every == 0) {
		active.stack_id = bpf_get_stackid(ctx, &stack_traces,
						  BPF_F_FAST_STACK_CMP | 2);
		if (active.stack_id >= 0)
			__sync_fetch_and_add(&profile->stack_samples, 1);
		else
			__sync_fetch_and_add(&profile->stack_failures, 1);
	}
	if (bpf_map_update_elem(&active_reclaims, &pid_tgid, &active, BPF_ANY))
		__sync_fetch_and_add(&dropped_reclaim_states, 1);
	return 0;
}

SEC("tp_btf/mm_vmscan_memcg_reclaim_end")
int BPF_PROG(profile_reclaim_end, unsigned long reclaimed,
	     struct mem_cgroup *memcg)
{
	struct active_reclaim *active;
	struct reclaim_profile *profile;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 cgroup_id = memcg_cgroup_id(memcg);
	__u64 duration_ns;
	__s32 stack_id;

	if (!selected_cgroup(cgroup_id))
		return 0;
	active = bpf_map_lookup_elem(&active_reclaims, &pid_tgid);
	if (!active || active->cgroup_id != cgroup_id)
		return 0;
	duration_ns = bpf_ktime_get_ns() - active->started_ns;
	stack_id = active->stack_id;
	profile = get_profile(cgroup_id);
	if (profile) {
		__sync_fetch_and_add(&profile->end_count, 1);
		__sync_fetch_and_add(&profile->reclaimed_pages, reclaimed);
		__sync_fetch_and_add(&profile->total_reclaim_ns, duration_ns);
		__sync_fetch_and_add(&profile->latency_slots[latency_bucket(duration_ns)],
				     1);
		update_maximum(&profile->maximum_reclaim_ns, duration_ns);
		profile->last_reclaim_ns = bpf_ktime_get_ns();
	}
	if (stack_id >= 0)
		update_stack_profile(cgroup_id, stack_id, duration_ns, reclaimed);
	bpf_map_delete_elem(&active_reclaims, &pid_tgid);
	return 0;
}

SEC("tracepoint/oom/mark_victim")
int capture_oom_victim(struct trace_event_raw_mark_victim *ctx)
{
	struct reclaim_profile *profile;
	struct victim_state victim;
	struct oom_watch_event *event;
	__u64 cgroup_id;
	__u32 victim_pid = ctx->pid;
	__u32 victim_tgid = 0;

	cgroup_id = victim_task_info(victim_pid, &victim_tgid);
	if (!victim_tgid || !selected_cgroup(cgroup_id))
		return 0;
	victim.cgroup_id = cgroup_id;
	victim.triggering_tgid = bpf_get_current_pid_tgid() >> 32;
	victim.victim_tgid = victim_tgid;
	if (bpf_map_update_elem(&victims, &victim_pid, &victim, BPF_ANY)) {
		__sync_fetch_and_add(&dropped_victim_states, 1);
		return 0;
	}

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;
	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_ns = bpf_ktime_get_ns();
	event->cgroup_id = cgroup_id;
	event->type = OOM_VICTIM_MARKED;
	event->victim_pid = victim_tgid;
	event->victim_tid = victim_pid;
	event->triggering_tgid = victim.triggering_tgid;
	event->total_vm_kb = ctx->total_vm;
	event->anon_rss_kb = ctx->anon_rss;
	event->file_rss_kb = ctx->file_rss;
	bpf_probe_read_kernel_str(event->comm, sizeof(event->comm),
				  (void *)ctx + (ctx->__data_loc_comm & 0xffff));

	profile = bpf_map_lookup_elem(&profiles, &cgroup_id);
	if (profile)
		__builtin_memcpy(&event->profile, profile, sizeof(event->profile));
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int capture_victim_exit(void *ctx)
{
	struct victim_state *victim;
	struct task_struct *task;
	struct oom_watch_event *event;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;

	(void)ctx;
	victim = bpf_map_lookup_elem(&victims, &tid);
	if (!victim)
		return 0;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		event->timestamp_ns = bpf_ktime_get_ns();
		event->cgroup_id = victim->cgroup_id;
		event->type = OOM_VICTIM_EXITED;
		event->victim_pid = victim->victim_tgid;
		event->victim_tid = tid;
		event->triggering_tgid = victim->triggering_tgid;
		task = (struct task_struct *)bpf_get_current_task_btf();
		event->exit_code = BPF_CORE_READ(task, exit_code);
		bpf_get_current_comm(event->comm, sizeof(event->comm));
		bpf_ringbuf_submit(event, 0);
	}
	bpf_map_delete_elem(&victims, &tid);
	return 0;
}
```

程序使用多个 BPF map 来维护状态。`active_reclaims` map 通过以 `pid_tgid` 为 key 存储开始时间戳来关联 begin 和 end 事件。`profiles` map 累积每个 cgroup 的统计信息。`stack_traces` map 存储去重后的内核调用栈，而 `stack_profiles` 为每个唯一调用栈聚合时间数据。

在回收开始时，我们从 `mem_cgroup` 参数而不是当前 task 的 cgroup 中提取目标 cgroup ID。这个区别对于跨 cgroup 回收很重要。如果有人从外部对某个 cgroup 调用 `memory.reclaim`，我们可以正确地将工作归因到目标。`cross_cgroup_reclaims` 计数器跟踪这种情况发生的频率。

调用栈采样使用 `--sample-every` 设置。默认值为 1 时，我们捕获每个间隔。更大的值可以减少开销，同时仍然在直方图中计算所有间隔。`BPF_F_FAST_STACK_CMP` 标志加速调用栈去重，标志中的 `2` 跳过两个 tracing 帧以获得更清晰的调用栈。

OOM 处理程序必须仔细解析进程身份。tracepoint 给我们一个线程 ID，但我们还需要线程组 ID（用户空间视角的 PID）和 cgroup。我们使用 `bpf_task_from_pid()` 查找 task，读取所需信息，然后释放引用。victim 状态以 TID 为 key，因为 `sched_process_exit` 在该线程的上下文中触发。

## 用户空间：符号化和展示

用户空间代码负责几项工作：加载内核符号用于调用栈符号化，使用任何 cgroup 过滤器设置 BPF 程序，处理来自 ring buffer 的事件，以及按总耗时对调用栈进行排名。它还包含一个 demo 模式，可以创建一个内存受限的 cgroup 并触发 OOM 来验证工具是否正常工作。

完整的用户空间代码相当长，所以我们重点介绍关键部分。启动时，它读取 `/proc/kallsyms`，按地址排序符号，然后使用二分查找解析每个栈帧。当符号地址受限时（在生产系统上很常见），它仍然打印原始地址——测量结果保持准确。

调用栈组按累计回收时间排名。这种排名可以展示频繁调用的路径和罕见的慢速间隔。在 OOM 事件之后，打印前五个调用栈及其时间统计。

demo 模式创建一个 `memory.max=32 MiB`、无 swap、启用分组 OOM 行为的 cgroup。一个 worker 进程首先 fault 24 MiB 然后暂停，让父进程从 cgroup 外部通过 `memory.reclaim` 请求 8 MiB。这会测试跨 cgroup 归因。然后 worker 继续 fault 一个 128 MiB 的映射直到 OOM 杀死它。进程 leader 在第二阶段之前退出，测试我们是否正确地独立处理 TGID 和 victim TID。

## 编译和运行

构建工具：

```bash
cd src/57-oom-watch
make
```

分析一个特定的 cgroup 60 秒，每十个回收间隔采样一次内核调用栈：

```bash
sudo ./oom_watch \
  --cgroup /sys/fs/cgroup/my-service \
  --duration 60 \
  --sample-every 10
```

省略 `--cgroup` 可以观察所有 cgroup。省略 `--duration` 可以持续运行直到中断。内置 demo 会捕获每次回收调用栈：

```bash
sudo ./oom_watch --demo
```

下面是一次真实 demo 运行的输出。PID、cgroup ID、地址和时间在不同运行之间会有变化：

```text
oom-watch tracing cgroup=/sys/fs/cgroup/ebpf-oom-watch-1262 cgroup_id=151
event=oom-victim pid=1263 tid=1264 comm=oom_watch trigger_pid=1263 cgroup_id=151 anon_rss_kb=32064 file_rss_kb=0 total_vm_kb=141844 reclaim_cycles=44 cross_cgroup_reclaims=22 reclaimed_pages=40
reclaim_profile cgroup_id=151 cycles=44 completed=44 total_ms=0.274 max_ms=0.056 reclaimed_pages=40 cross_cgroup=22 stack_samples=44 stack_failures=0
reclaim_latency_us=0-1 count=9
reclaim_latency_us=2-3 count=13
reclaim_latency_us=4-7 count=14
reclaim_latency_us=8-15 count=5
reclaim_latency_us=16-31 count=2
reclaim_latency_us=32-63 count=1
reclaim_stack rank=1 samples=22 total_ms=0.181 max_ms=0.056 reclaimed_pages=40
  #0 try_to_free_mem_cgroup_pages+0x...
  #1 try_charge_memcg+0x...
reclaim_stack rank=2 samples=22 total_ms=0.093 max_ms=0.012 reclaimed_pages=0
  #0 try_to_free_mem_cgroup_pages+0x...
  #1 user_proactive_reclaim+0x...
event=victim-exit pid=1263 tid=1264 cgroup_id=151 exit_code=9
demo workload signaled=1 signal=9
demo result=matched-profile-to-victim
dropped_victim_states=0 dropped_reclaim_states=0
```

看看这告诉我们什么：在 kill 之前完成了 44 个回收周期，其中一半是从目标 cgroup 外部触发的。直方图显示大多数周期很快（不到 8 微秒），但有几个花了更长时间。两个排名的调用栈将分配触发的回收与显式的 `memory.reclaim` 请求区分开来。exit 事件确认 victim 收到了 `SIGKILL`。

## 环境要求

| 要求 | 说明 |
|---|---|
| 内核 | Linux 7.1 或更高版本（需要 target-memcg vmscan tracepoint） |
| 内核配置 | `CONFIG_BPF`、`CONFIG_BPF_SYSCALL`、`CONFIG_BPF_JIT`、`CONFIG_BPF_EVENTS`、`CONFIG_DEBUG_INFO_BTF`、`CONFIG_MEMCG`；`CONFIG_KALLSYMS` 可以改善符号输出 |
| cgroup | 带 memory controller 的 cgroup v2；demo 模式需要 cgroup 管理权限 |
| 权限 | root 或等效的 BPF 和 tracing capability |
| 架构 | 已在 x86-64 上测试；不需要特殊硬件 |

## 实现范围

Profile 从程序附加开始累积直到退出，使用有界的 LRU map：4096 个 cgroup profile、4096 个活动间隔、8192 个调用栈聚合和 1024 个唯一调用栈。每个 `pid_tgid` 保留一个活动间隔，与 begin/end 跟踪模式相匹配。工具捕获内核调用栈而不是用户调用栈，并将符号化视为展示——受限的 `kallsyms` 会将名称变为地址，但不影响测量结果。

## 总结

`oom-watch` 将 OOM kill 之前的混乱变成可以检查的证据。它测量每个 memcg 回收间隔，采样并排名消耗时间的内核路径，正确归因工作到目标 cgroup（即使对于跨 cgroup 回收），并将此 profile 与 victim 选择和退出关联起来。

下次容器死掉有人问"发生了什么？"时，你将不仅仅有一行内核日志可以展示。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [Linux vmscan tracepoint](https://github.com/torvalds/linux/blob/v7.1/include/trace/events/vmscan.h)
- [target-memcg vmscan attribution commit](https://github.com/torvalds/linux/commit/874a0a566ede40f3d6062cae8fe1022e616edd1a)
- [Linux OOM tracepoint](https://github.com/torvalds/linux/blob/v7.1/include/trace/events/oom.h)
- [BPF kfunc 文档](https://docs.kernel.org/bpf/kfuncs.html)
- [Control Group v2 memory interface](https://docs.kernel.org/admin-guide/cgroup-v2.html)
