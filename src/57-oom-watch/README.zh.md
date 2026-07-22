# eBPF 实战教程：在 OOM kill 之前分析 memcg reclaim

一条 OOM 日志回答了内存故障的最后一个问题：内核选择了哪个 task 作为 victim。此前发生的工作却很难从这条记录里看出来，排查时仍然需要知道目标 memory cgroup 进入了多少次 reclaim、每次花了多久、时间主要消耗在哪些内核路径，以及 victim 最终是否退出。

本课构建 `oom-watch` 保存这段缺失的历史。它把 memcg reclaim 聚合为延迟分布和采样内核栈，再把积累得到的 profile 关联到 OOM victim，并继续跟踪这条 victim 记录直到进程退出。

> 完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/57-oom-watch>

## reclaim 是 OOM kill 之前的故事

memory cgroup 接近上限时，一次内存分配可能进入 reclaim，扫描这个 memcg 中可以释放的页面。多次短暂尝试有时只能回收少量内存，也可能几乎没有进展，最终由 OOM killer 选择 victim。只观察 `oom/mark_victim` 会同时丢失这些尝试的延迟分布和调用路径。

eBPF 可以让经过验证器检查的程序运行在内核事件上，再通过 map 连接不同的时刻。Linux 7.1 为 `mm_vmscan_memcg_reclaim_begin` 和 `mm_vmscan_memcg_reclaim_end` tracepoint 加入目标 `mem_cgroup`。这个参数很重要，因为当前 task 可以通过 `memory.reclaim` 回收另一个 cgroup；现在归因可以跟随真正被扫描的 memcg，而不是碰巧触发工作的 task。

另一项依赖来自 victim lookup。`oom/mark_victim` 给出被选中线程的 ID，诊断还需要它的 thread-group ID 和 cgroup。`bpf_task_from_pid()` 在 Linux 6.2 引入，普通 tracepoint program 从 Linux 6.12 开始可以调用这类 tracing kfunc。更新的 vmscan tracepoint signature 最终把完整工具的最低内核版本定在 Linux 7.1。

跟着一次 reclaim interval 走一遍。begin tracepoint 到来时，BPF 程序按当前 `pid_tgid` 保存单调时钟下的开始时间和目标 cgroup，并根据 `--sample-every` 捕获 kernel stack ID。对应的 end tracepoint 计算 duration，增加一个 2 倍区间的微秒直方图 bucket，再累计 reclaimed pages。另一张 map 按 `(cgroup_id, stack_id)` 聚合每条采样路径的样本数、总时间、最长时间和回收页数。

OOM 选中 victim 后，程序把 TID 解析为 TGID 和 cgroup，把这个 cgroup 已积累的 reclaim profile 复制到 ring buffer event，并按 TID 保存 victim state。随后 `sched_process_exit` 消费这份状态并报告 exit code。最终结果会把 kill 之前的回收活动、内核标记的具体线程和之后的进程生命周期连在一起。

## profile 与 event 布局

共享头文件定义 cgroup 级直方图、每 stack aggregate 和携带 OOM snapshot 的事件。

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

`latency_slots` 包含 20 个 base-2 微秒区间。bucket 0 覆盖 0–1 µs，bucket 1 覆盖 2–3 µs，之后依次是 4–7 µs 等范围，最后一个 bucket 收纳所有不小于 524288 µs 的 interval。event 内嵌完整 `reclaim_profile`，因此 victim 旁边打印的数字正是它被选中时的 profile snapshot。

## 分析 reclaim 并跟踪 victim

下面是完整 BPF 程序。

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

`active_reclaims` 按 `pid_tgid` 关联 begin 与 end。begin callback 从 `memcg->css.cgroup->kn->id` 取得目标 cgroup ID，而不是读取当前 task 的 cgroup。两者比较产生 `cross_cgroup_reclaims`，另一个 cgroup 发起的 proactive reclaim 因此可以被直接观察。

stack sampling 发生在 begin，也就是 reclaim 工作开始之前。`sample_every=1` 会捕获每个 interval，设置更大的值可以降低 stack map 与 unwinding 开销，同时 latency histogram 仍会统计所有匹配 interval。flag 低 8 位中的 `2` 会跳过两个 tracing frame，`bpf_get_stackid()` 再把剩余的相同调用栈合并到 `stack_traces`，`stack_profiles` 则为每个 ID 保存 timing 与 reclaimed-page 总计。原子更新让多个 CPU 的 reclaim 可以共同写入同一份 cgroup profile。

`profile_reclaim_end()` 完成统计后删除 active state。它会更新总延迟和最大延迟，选择 histogram bucket，再更新对应的 sampled stack aggregate。active-state 插入失败和 stack-capture 失败都有独立计数，begin 与 end count 的差值也能反映未完成配对的 interval。

OOM 路径需要谨慎处理进程 identity。tracepoint 中的 `ctx->pid` 保留为 `victim_tid`，`bpf_task_from_pid()` 提供 task 的 TGID 与 cgroup ID，`bpf_task_release()` 释放带引用的 task pointer。victim state 继续按 TID 存储，因为 `sched_process_exit` 会在同一个线程上下文中运行。即使多线程进程的 leader 和被选 victim ID 不同，这条关联仍然有效。

## 符号化并展示 profile

用户态程序加载 kernel symbol、排序 stack aggregate、管理可选 cgroup filter，并提供可重复的 OOM demo。

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "oom_watch.h"
#include "oom_watch.skel.h"

struct options {
	const char *cgroup_path;
	unsigned int duration_seconds;
	unsigned int sample_every;
	bool demo;
};

static volatile sig_atomic_t stop;
static int victim_events;
static int exit_events;
static unsigned long long observed_cgroup_id;
static unsigned int observed_victim_pid;
static unsigned int observed_victim_tid;
static unsigned long long observed_reclaims;
static unsigned long long observed_cross_cgroup_reclaims;
static unsigned long long observed_stack_samples;

struct kernel_symbol {
	unsigned long long address;
	char *name;
};

struct kernel_symbols {
	struct kernel_symbol *items;
	size_t count;
	size_t capacity;
};

struct runtime_context {
	int profiles_fd;
	int stack_profiles_fd;
	int stack_traces_fd;
	struct kernel_symbols symbols;
};

struct oom_runtime {
	struct oom_watch_bpf *skel;
	struct ring_buffer *ring;
	struct runtime_context context;
};

struct selected_cgroup {
	char demo_path[256];
	const char *path;
	struct stat metadata;
	bool demo_created;
	bool memory_enabled_by_demo;
};

struct demo_process {
	pid_t child;
	int ready_pipe[2];
	int continue_pipe[2];
	int status;
};

struct ranked_stack {
	struct reclaim_stack_key key;
	struct reclaim_stack_profile profile;
};

struct allocation_context {
	int ready_fd;
	int continue_fd;
};

static struct allocation_context allocation_context;

static void handle_signal(int signal_number)
{
	(void)signal_number;
	stop = 1;
}

static unsigned long long monotonic_ns(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static int write_text(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t length = strlen(text);
	int err = 0;

	if (fd < 0)
		return -1;
	if (write(fd, text, length) != length)
		err = -1;
	close(fd);
	return err;
}

static int memory_controller_enabled(bool *enabled)
{
	char controllers[4096];
	ssize_t length;
	int fd;

	fd = open("/sys/fs/cgroup/cgroup.subtree_control",
		  O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	length = read(fd, controllers, sizeof(controllers) - 1);
	close(fd);
	if (length < 0)
		return -1;
	controllers[length] = '\0';
	*enabled = strstr(controllers, "memory") != NULL;
	return 0;
}

static int compare_symbols(const void *left, const void *right)
{
	const struct kernel_symbol *a = left;
	const struct kernel_symbol *b = right;

	return a->address < b->address ? -1 : a->address > b->address ? 1 : 0;
}

static int load_kernel_symbols(struct kernel_symbols *symbols)
{
	char name[256];
	char type;
	unsigned long long address;
	FILE *file = fopen("/proc/kallsyms", "r");

	if (!file)
		return -1;
	while (fscanf(file, "%llx %c %255s%*[^\n]\n", &address, &type,
		      name) == 3) {
		struct kernel_symbol *item;

		(void)type;
		if (symbols->count == symbols->capacity) {
			size_t capacity = symbols->capacity ? symbols->capacity * 2 : 4096;
			void *items = realloc(symbols->items,
					      capacity * sizeof(*symbols->items));

			if (!items)
				goto error;
			symbols->items = items;
			symbols->capacity = capacity;
		}
		item = &symbols->items[symbols->count++];
		item->address = address;
		item->name = strdup(name);
		if (!item->name)
			goto error;
	}
	fclose(file);
	qsort(symbols->items, symbols->count, sizeof(*symbols->items),
	      compare_symbols);
	return symbols->count ? 0 : -1;

error:
	fclose(file);
	return -1;
}

static void free_kernel_symbols(struct kernel_symbols *symbols)
{
	for (size_t i = 0; i < symbols->count; i++)
		free(symbols->items[i].name);
	free(symbols->items);
}

static const struct kernel_symbol *find_kernel_symbol(
	const struct kernel_symbols *symbols, unsigned long long address)
{
	size_t low = 0, high = symbols->count;

	while (low < high) {
		size_t middle = low + (high - low) / 2;

		if (symbols->items[middle].address <= address)
			low = middle + 1;
		else
			high = middle;
	}
	return low ? &symbols->items[low - 1] : NULL;
}

static void insert_ranked_stack(struct ranked_stack top[5], size_t *count,
				const struct reclaim_stack_key *key,
				const struct reclaim_stack_profile *profile)
{
	size_t position = 0;

	while (position < *count &&
	       top[position].profile.total_ns >= profile->total_ns)
		position++;
	if (position >= 5)
		return;
	if (*count < 5)
		(*count)++;
	for (size_t i = *count - 1; i > position; i--)
		top[i] = top[i - 1];
	top[position].key = *key;
	top[position].profile = *profile;
}

static void print_reclaim_stacks(struct runtime_context *runtime,
				 __u64 cgroup_id)
{
	struct ranked_stack top[5] = {};
	struct reclaim_stack_key previous, next;
	bool have_previous = false;
	size_t count = 0;

	while (!bpf_map_get_next_key(runtime->stack_profiles_fd,
				     have_previous ? &previous : NULL, &next)) {
		struct reclaim_stack_profile profile;

		if (next.cgroup_id == cgroup_id &&
		    !bpf_map_lookup_elem(runtime->stack_profiles_fd, &next,
					 &profile))
			insert_ranked_stack(top, &count, &next, &profile);
		previous = next;
		have_previous = true;
	}

	for (size_t rank = 0; rank < count; rank++) {
		unsigned long long addresses[OOM_STACK_DEPTH] = {};

		printf("reclaim_stack rank=%zu samples=%llu total_ms=%.3f "
		       "max_ms=%.3f reclaimed_pages=%llu\n",
		       rank + 1, top[rank].profile.samples,
		       top[rank].profile.total_ns / 1000000.0,
		       top[rank].profile.maximum_ns / 1000000.0,
		       top[rank].profile.reclaimed_pages);
		if (bpf_map_lookup_elem(runtime->stack_traces_fd,
					&top[rank].key.stack_id, addresses))
			continue;
		for (size_t frame = 0; frame < OOM_STACK_DEPTH && addresses[frame];
		     frame++) {
			const struct kernel_symbol *symbol =
				find_kernel_symbol(&runtime->symbols, addresses[frame]);

			if (symbol && symbol->address)
				printf("  #%zu %s+0x%llx\n", frame, symbol->name,
				       addresses[frame] - symbol->address);
			else
				printf("  #%zu 0x%llx\n", frame, addresses[frame]);
		}
	}
}

static void print_reclaim_profile(struct runtime_context *runtime,
				  __u64 cgroup_id,
				  const struct reclaim_profile *profile)
{
	printf("reclaim_profile cgroup_id=%llu cycles=%llu completed=%llu "
	       "total_ms=%.3f max_ms=%.3f reclaimed_pages=%llu "
	       "cross_cgroup=%llu stack_samples=%llu stack_failures=%llu\n",
	       (unsigned long long)cgroup_id, profile->begin_count,
	       profile->end_count, profile->total_reclaim_ns / 1000000.0,
	       profile->maximum_reclaim_ns / 1000000.0,
	       profile->reclaimed_pages, profile->cross_cgroup_reclaims,
	       profile->stack_samples, profile->stack_failures);
	for (unsigned int bucket = 0; bucket < OOM_RECLAIM_BUCKETS; bucket++) {
		unsigned long long low, high;

		if (!profile->latency_slots[bucket])
			continue;
		low = bucket ? 1ULL << bucket : 0;
		high = (1ULL << (bucket + 1)) - 1;
		if (bucket == OOM_RECLAIM_BUCKETS - 1)
			printf("reclaim_latency_us=>=%llu count=%llu\n", low,
			       profile->latency_slots[bucket]);
		else
			printf("reclaim_latency_us=%llu-%llu count=%llu\n", low,
			       high, profile->latency_slots[bucket]);
	}
	print_reclaim_stacks(runtime, cgroup_id);
}

static void print_live_profiles(struct runtime_context *runtime)
{
	__u64 previous, next;
	bool have_previous = false;

	while (!bpf_map_get_next_key(runtime->profiles_fd,
				     have_previous ? &previous : NULL, &next)) {
		struct reclaim_profile profile;

		if (!bpf_map_lookup_elem(runtime->profiles_fd, &next, &profile))
			print_reclaim_profile(runtime, next, &profile);
		previous = next;
		have_previous = true;
	}
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct oom_watch_event *event = data;
	struct runtime_context *runtime = ctx;

	if (size != sizeof(*event))
		return 0;
	if (event->type == OOM_VICTIM_MARKED) {
		victim_events++;
		observed_cgroup_id = event->cgroup_id;
		observed_victim_pid = event->victim_pid;
		observed_reclaims = event->profile.begin_count;
		observed_victim_tid = event->victim_tid;
		observed_cross_cgroup_reclaims =
			event->profile.cross_cgroup_reclaims;
		observed_stack_samples = event->profile.stack_samples;
		printf("event=oom-victim pid=%u tid=%u comm=%s trigger_pid=%u cgroup_id=%llu "
		       "anon_rss_kb=%llu file_rss_kb=%llu total_vm_kb=%llu "
		       "reclaim_cycles=%llu cross_cgroup_reclaims=%llu "
		       "reclaimed_pages=%llu\n",
		       event->victim_pid, event->victim_tid, event->comm,
		       event->triggering_tgid,
		       (unsigned long long)event->cgroup_id,
		       (unsigned long long)event->anon_rss_kb,
		       (unsigned long long)event->file_rss_kb,
		       (unsigned long long)event->total_vm_kb,
		       (unsigned long long)event->profile.begin_count,
		       (unsigned long long)event->profile.cross_cgroup_reclaims,
		       (unsigned long long)event->profile.reclaimed_pages);
		print_reclaim_profile(runtime, event->cgroup_id, &event->profile);
	} else if (event->type == OOM_VICTIM_EXITED) {
		exit_events++;
		printf("event=victim-exit pid=%u tid=%u cgroup_id=%llu exit_code=%d\n",
		       event->victim_pid, event->victim_tid,
		       (unsigned long long)event->cgroup_id, event->exit_code);
	}
	return 0;
}

static int parse_uint(const char *text, unsigned int maximum,
		      unsigned int *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !*text || *end || !parsed || parsed > maximum)
		return -1;
	*value = parsed;
	return 0;
}

static void usage(const char *program)
{
	printf("Usage: %s [--cgroup PATH] [--duration SEC] [--sample-every N]\n"
	       "       %s --demo [--sample-every N]\n", program, program);
}

static int parse_options(int argc, char **argv, struct options *options)
{
	static const struct option long_options[] = {
		{ "cgroup", required_argument, NULL, 'c' },
		{ "duration", required_argument, NULL, 'd' },
		{ "sample-every", required_argument, NULL, 's' },
		{ "demo", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "c:d:s:Dh", long_options,
				     NULL)) != -1) {
		switch (option) {
		case 'c': options->cgroup_path = optarg; break;
		case 'd':
			if (parse_uint(optarg, 86400, &options->duration_seconds))
				return -1;
			break;
		case 's':
			if (parse_uint(optarg, 1000000, &options->sample_every))
				return -1;
			break;
		case 'D': options->demo = true; break;
		case 'h': usage(argv[0]); exit(0);
		default: return -1;
		}
	}
	return optind == argc && !(options->demo && options->cgroup_path) ? 0 : -1;
}

static void *allocation_worker(void *argument)
{
	struct allocation_context *context = argument;
	size_t first_stage = 24 * 1024 * 1024;
	size_t length = 128 * 1024 * 1024;
	unsigned char *memory;
	char byte = 'x';

	memory = mmap(NULL, length, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (memory == MAP_FAILED)
		_exit(4);
	for (size_t offset = 0; offset < first_stage; offset += 4096)
		memory[offset] = 0xa5;
	if (write(context->ready_fd, &byte, 1) != 1 ||
	    read(context->continue_fd, &byte, 1) != 1)
		_exit(5);
	for (size_t offset = first_stage; offset < length; offset += 4096)
		memory[offset] = 0xa5;
	_exit(6);
}

static void allocate_until_killed(const char *cgroup_path, int ready_fd,
				  int continue_fd)
{
	char procs_path[512];
	char pid_text[32];
	pthread_t worker;

	snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path);
	snprintf(pid_text, sizeof(pid_text), "%d", getpid());
	if (write_text(procs_path, pid_text))
		_exit(3);
	allocation_context.ready_fd = ready_fd;
	allocation_context.continue_fd = continue_fd;
	if (pthread_create(&worker, NULL, allocation_worker,
			   &allocation_context))
		_exit(4);
	pthread_detach(worker);
	pthread_exit(NULL);
}

static int configure_demo_cgroup(const char *path, bool *created,
				 bool *enabled_by_demo)
{
	bool memory_enabled;
	char file[512];

	if (memory_controller_enabled(&memory_enabled))
		return -1;
	if (!memory_enabled) {
		if (write_text("/sys/fs/cgroup/cgroup.subtree_control", "+memory"))
			return -1;
		*enabled_by_demo = true;
	}
	if (mkdir(path, 0755))
		return -1;
	*created = true;
	snprintf(file, sizeof(file), "%s/memory.max", path);
	if (write_text(file, "33554432"))
		return -1;
	snprintf(file, sizeof(file), "%s/memory.swap.max", path);
	if (write_text(file, "0"))
		return -1;
	snprintf(file, sizeof(file), "%s/memory.oom.group", path);
	return write_text(file, "1");
}

static int trigger_cross_cgroup_reclaim(const char *cgroup_path)
{
	char reclaim_path[512];

	snprintf(reclaim_path, sizeof(reclaim_path), "%s/memory.reclaim",
		 cgroup_path);
	if (!write_text(reclaim_path, "8388608") || errno == EAGAIN)
		return 0;
	return -1;
}

static int select_cgroup(const struct options *options,
			 struct selected_cgroup *selected)
{
	if (options->demo) {
		snprintf(selected->demo_path, sizeof(selected->demo_path),
			 "/sys/fs/cgroup/ebpf-oom-watch-%d", getpid());
		if (configure_demo_cgroup(selected->demo_path,
					  &selected->demo_created,
					  &selected->memory_enabled_by_demo)) {
			fprintf(stderr, "failed to configure demo memory cgroup: %s\n",
				strerror(errno));
			return -1;
		}
		selected->path = selected->demo_path;
	} else {
		selected->path = options->cgroup_path;
	}
	if (!selected->path)
		return 0;
	if (!stat(selected->path, &selected->metadata))
		return 0;
	fprintf(stderr, "failed to stat cgroup %s: %s\n", selected->path,
		strerror(errno));
	return -1;
}

static void cleanup_selected_cgroup(struct selected_cgroup *selected,
				    int *result)
{
	if (selected->demo_created && rmdir(selected->demo_path) && !*result)
		*result = 1;
	if (selected->memory_enabled_by_demo &&
	    write_text("/sys/fs/cgroup/cgroup.subtree_control", "-memory") &&
	    !*result)
		*result = 1;
}

static int prepare_runtime(struct oom_runtime *runtime,
			   const struct options *options,
			   const struct selected_cgroup *selected)
{
	runtime->skel = oom_watch_bpf__open();
	if (!runtime->skel)
		return -1;
	runtime->skel->rodata->target_cgroup_id =
		selected->path ? selected->metadata.st_ino : 0;
	runtime->skel->rodata->sample_every = options->sample_every;
	if (oom_watch_bpf__load(runtime->skel) ||
	    oom_watch_bpf__attach(runtime->skel)) {
		fprintf(stderr, "failed to load and attach OOM watcher\n");
		return -1;
	}
	runtime->context.profiles_fd =
		bpf_map__fd(runtime->skel->maps.profiles);
	runtime->context.stack_profiles_fd =
		bpf_map__fd(runtime->skel->maps.stack_profiles);
	runtime->context.stack_traces_fd =
		bpf_map__fd(runtime->skel->maps.stack_traces);
	if (load_kernel_symbols(&runtime->context.symbols))
		fprintf(stderr, "warning: kernel symbols unavailable; printing raw stack addresses\n");
	runtime->ring = ring_buffer__new(
		bpf_map__fd(runtime->skel->maps.events), handle_event,
		&runtime->context, NULL);
	return runtime->ring ? 0 : -1;
}

static void destroy_runtime(struct oom_runtime *runtime)
{
	ring_buffer__free(runtime->ring);
	free_kernel_symbols(&runtime->context.symbols);
	oom_watch_bpf__destroy(runtime->skel);
}

static void init_demo_process(struct demo_process *demo)
{
	memset(demo, 0, sizeof(*demo));
	demo->child = -1;
	demo->ready_pipe[0] = -1;
	demo->ready_pipe[1] = -1;
	demo->continue_pipe[0] = -1;
	demo->continue_pipe[1] = -1;
}

static void close_demo_pipe(int *fd)
{
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}

static void cleanup_demo_process(struct demo_process *demo)
{
	if (demo->child > 0) {
		kill(demo->child, SIGKILL);
		waitpid(demo->child, NULL, 0);
	}
	close_demo_pipe(&demo->ready_pipe[0]);
	close_demo_pipe(&demo->ready_pipe[1]);
	close_demo_pipe(&demo->continue_pipe[0]);
	close_demo_pipe(&demo->continue_pipe[1]);
}

static int start_demo_process(struct demo_process *demo,
			      const char *cgroup_path)
{
	struct pollfd ready = { .events = POLLIN };
	struct timespec leader_exit_delay = { .tv_nsec = 100000000 };
	char byte = 'x';

	if (pipe(demo->ready_pipe) || pipe(demo->continue_pipe))
		return -1;
	demo->child = fork();
	if (demo->child < 0)
		return -1;
	if (!demo->child) {
		close(demo->ready_pipe[0]);
		close(demo->continue_pipe[1]);
		allocate_until_killed(cgroup_path, demo->ready_pipe[1],
				      demo->continue_pipe[0]);
	}
	close_demo_pipe(&demo->ready_pipe[1]);
	close_demo_pipe(&demo->continue_pipe[0]);
	ready.fd = demo->ready_pipe[0];
	if (poll(&ready, 1, 5000) != 1 ||
	    read(demo->ready_pipe[0], &byte, 1) != 1 ||
	    trigger_cross_cgroup_reclaim(cgroup_path))
		return -1;
	nanosleep(&leader_exit_delay, NULL);
	if (write(demo->continue_pipe[1], &byte, 1) != 1)
		return -1;
	close_demo_pipe(&demo->ready_pipe[0]);
	close_demo_pipe(&demo->continue_pipe[1]);
	return 0;
}

static int collect_demo_events(struct demo_process *demo,
			       struct ring_buffer *ring)
{
	for (int i = 0; i < 200; i++) {
		pid_t waited;

		ring_buffer__poll(ring, 50);
		waited = waitpid(demo->child, &demo->status, WNOHANG);
		if (waited == demo->child) {
			demo->child = -1;
			break;
		}
	}
	for (int i = 0; i < 10 && exit_events < 1; i++)
		ring_buffer__poll(ring, 50);
	return demo->child < 0 ? 0 : -1;
}

static bool valid_demo_observation(const struct demo_process *demo,
				   unsigned long long cgroup_id,
				   const struct oom_watch_bpf *skel)
{
	return WIFSIGNALED(demo->status) &&
	       WTERMSIG(demo->status) == SIGKILL && victim_events == 1 &&
	       exit_events == 1 && observed_cgroup_id == cgroup_id &&
	       observed_victim_pid && observed_victim_tid &&
	       observed_victim_pid != observed_victim_tid && observed_reclaims &&
	       observed_cross_cgroup_reclaims && observed_stack_samples &&
	       !skel->bss->dropped_victim_states &&
	       !skel->bss->dropped_reclaim_states;
}

static int run_demo(struct oom_runtime *runtime,
		    const struct selected_cgroup *selected)
{
	struct demo_process demo;
	int result = -1;

	init_demo_process(&demo);
	if (start_demo_process(&demo, selected->path) ||
	    collect_demo_events(&demo, runtime->ring))
		goto cleanup;
	printf("demo workload signaled=%d signal=%d\n",
	       WIFSIGNALED(demo.status),
	       WIFSIGNALED(demo.status) ? WTERMSIG(demo.status) : 0);
	if (!valid_demo_observation(&demo, selected->metadata.st_ino,
				    runtime->skel))
		goto cleanup;
	printf("demo result=matched-profile-to-victim\n");
	result = 0;

cleanup:
	cleanup_demo_process(&demo);
	return result;
}

static int watch_profiles(struct oom_runtime *runtime,
			  unsigned int duration_seconds)
{
	unsigned long long deadline = 0;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	if (duration_seconds)
		deadline = monotonic_ns() +
			   (unsigned long long)duration_seconds * 1000000000ULL;
	while (!stop && (!deadline || monotonic_ns() < deadline)) {
		int result = ring_buffer__poll(runtime->ring, 100);

		if (result < 0 && result != -EINTR) {
			fprintf(stderr, "ring buffer poll failed: %d\n", result);
			return -1;
		}
	}
	print_live_profiles(&runtime->context);
	return 0;
}

int main(int argc, char **argv)
{
	struct options options = { .sample_every = 1 };
	struct selected_cgroup selected = {};
	struct oom_runtime runtime = {};
	int err = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (parse_options(argc, argv, &options)) {
		usage(argv[0]);
		return 2;
	}
	if (select_cgroup(&options, &selected) ||
	    prepare_runtime(&runtime, &options, &selected))
		goto cleanup;

	if (selected.path)
		printf("oom-watch tracing cgroup=%s cgroup_id=%llu\n",
		       selected.path,
		       (unsigned long long)selected.metadata.st_ino);
	else
		printf("oom-watch tracing all cgroups\n");

	if ((options.demo && run_demo(&runtime, &selected)) ||
	    (!options.demo && watch_profiles(&runtime,
					     options.duration_seconds)))
		goto cleanup;
	printf("dropped_victim_states=%llu dropped_reclaim_states=%llu\n",
	       (unsigned long long)runtime.skel->bss->dropped_victim_states,
	       (unsigned long long)runtime.skel->bss->dropped_reclaim_states);
	err = 0;

cleanup:
	destroy_runtime(&runtime);
	cleanup_selected_cgroup(&selected, &err);
	return err;
}
```

启动时，loader 读取 `/proc/kallsyms`，按地址排序，再用二分搜索解析 BPF stack-trace map 中的每个地址。symbol address 被隐藏时，同一份 profile 仍然可以输出 raw address。stack group 按累计 reclaim time 排序，因此调用频繁的路径和一次特别慢的 interval 都能反映在排名中。

普通模式可以观察一个 cgroup，也可以覆盖全部 cgroup。跟踪结束后，程序遍历 profile map，即使没有发生 OOM，也会打印仍然存在的 histogram。OOM event 到来时会立即打印 snapshot，并附上累计时间最高的 5 组调用栈和 frame。

demo 模式创建 `memory.max=32 MiB`、无 swap、启用 grouped OOM behavior 的 cgroup。worker 先 fault 24 MiB 并暂停，让 parent 通过 `memory.reclaim` 请求回收 8 MiB；这次有意制造的 cross-cgroup request 会验证 target-memcg attribution。随后 worker 继续 fault 一段 128 MiB mapping，直到 cgroup OOM killer 选中它。进程 leader 会在第二阶段之前退出，因此测试也会验证 TGID 和 victim TID 的独立处理。清理阶段会恢复启动时观察到的 memory controller 状态。

## 编译和运行

构建 profiler：

```bash
cd src/57-oom-watch
make
```

分析一个 service cgroup 60 秒，每 10 次 reclaim interval 采样一次 kernel stack：

```bash
sudo ./oom_watch \
  --cgroup /sys/fs/cgroup/my-service \
  --duration 60 \
  --sample-every 10
```

省略 `--cgroup` 会观察全部 cgroup，省略 `--duration` 则持续运行到收到中断。内置 demo 会捕获每次 reclaim stack：

```bash
sudo ./oom_watch --demo
```

PID、cgroup ID、地址和延迟会随运行变化。下面是一次真实运行的节选，保留完整 profile 总计，并缩短 stack frame 便于阅读：

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

44 个 completed interval 与 44 个 begin event 一一对应，所有 histogram count 相加也是 44，其中一半由目标 cgroup 之外触发。两条排名路径分别显示 allocation charge reclaim 和显式 `memory.reclaim`，exit event 则确认被标记的 TID 最终收到 `SIGKILL`。

## 环境要求

| 要求 | 说明 |
|---|---|
| 内核 | Linux 7.1 或更高版本，需要携带 target memcg 的 vmscan tracepoint |
| 内核配置 | `CONFIG_BPF`、`CONFIG_BPF_SYSCALL`、`CONFIG_BPF_JIT`、`CONFIG_BPF_EVENTS`、`CONFIG_DEBUG_INFO_BTF`、`CONFIG_MEMCG`，`CONFIG_KALLSYMS` 可以改善符号输出 |
| cgroup | cgroup v2 与 memory controller，demo 模式还需要 cgroup 管理写权限 |
| 权限 | root，或者等价的 BPF、tracing 与 cgroup 管理 capability |
| 架构与硬件 | 当前声明并完成测试的目标是 x86-64，不需要特殊硬件 |

## 实现范围

profile 从程序挂载开始累计到退出，并使用有界 LRU map：4096 份 cgroup profile、4096 条 active interval、8192 组 stack aggregate 和 1024 个 unique stack。每个 `pid_tgid` 保存一个 active interval，与这里观察的 begin/end 路径一致。工具捕获 kernel stack，symbolization 只负责展示，因此受限的 `kallsyms` 会把名称换成地址，并不会改变测量结果。

## 总结

`oom-watch` 把 OOM kill 之前的阶段变成可以检查的证据。它测量每个匹配的 memcg reclaim interval，采样并排序内核路径，把工作归因到目标 cgroup，再将 profile 与 victim selection 和 exit 关联起来。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [Linux vmscan tracepoint](https://github.com/torvalds/linux/blob/v7.1/include/trace/events/vmscan.h)
- [target-memcg vmscan attribution commit](https://github.com/torvalds/linux/commit/874a0a566ede40f3d6062cae8fe1022e616edd1a)
- [Linux OOM tracepoint](https://github.com/torvalds/linux/blob/v7.1/include/trace/events/oom.h)
- [BPF kfunc 文档](https://docs.kernel.org/bpf/kfuncs.html)
- [Control Group v2 memory interface](https://docs.kernel.org/admin-guide/cgroup-v2.html)
