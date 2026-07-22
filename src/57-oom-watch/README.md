# eBPF Tutorial by Example: Profile memcg Reclaim Before an OOM Kill

An OOM log answers the last question in a memory failure: which task did the kernel choose to kill? It says much less about the work that led there. Operators still need to know how often the target memory cgroup entered reclaim, how long those attempts took, which kernel paths consumed the time, and whether the victim actually exited.

This tutorial builds `oom-watch` to preserve that missing history. It profiles memcg reclaim as a latency distribution and a set of sampled kernel stacks, then attaches the accumulated profile to the selected OOM victim and follows that victim to process exit.

> Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/57-oom-watch>

## Reclaim Is the Story Before the Kill

When a memory cgroup approaches its limit, an allocation may enter reclaim and scan that memcg for pages it can free. Several short attempts can succeed partially, or repeated reclaim can make little progress until the OOM killer selects a victim. Looking only at `oom/mark_victim` loses both the time distribution and the call paths of those attempts.

eBPF runs verifier-checked programs at kernel events and uses maps to carry state between them. Linux 7.1 added the target `mem_cgroup` to the `mm_vmscan_memcg_reclaim_begin` and `mm_vmscan_memcg_reclaim_end` tracepoints. That argument matters because the current task can reclaim a different cgroup through `memory.reclaim`; attribution now follows the memcg being scanned instead of the task that triggered the work.

The second dependency is victim lookup. `oom/mark_victim` reports the selected thread ID, while diagnosis also needs its thread-group ID and cgroup. `bpf_task_from_pid()` arrived in Linux 6.2, and regular tracepoint programs gained access to this tracing kfunc class in Linux 6.12. The newer vmscan tracepoint signature therefore sets the complete tool's minimum kernel at Linux 7.1.

Follow one reclaim interval. At the begin tracepoint, the BPF program records the monotonic start time and target cgroup under the current `pid_tgid`. According to `--sample-every`, it also captures a kernel stack ID. The matching end tracepoint computes duration, increments a power-of-two microsecond bucket, and adds reclaimed pages. A second map groups sampled intervals by `(cgroup_id, stack_id)` and accumulates sample count, total time, maximum time, and reclaimed pages for each path.

When OOM selects a victim, the program resolves that TID to its TGID and cgroup, copies the cgroup's reclaim profile into a ring-buffer event, and stores victim state keyed by TID. `sched_process_exit` later consumes that state and reports the exit code. The result connects activity accumulated before the kill with the exact thread the kernel marked and the process lifecycle that followed.

## Profile and Event Layouts

The shared header defines the cgroup-level histogram, per-stack aggregate, and the event that carries an OOM snapshot.

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

`latency_slots` contains 20 base-2 microsecond ranges. Bucket 0 covers 0–1 µs, bucket 1 covers 2–3 µs, then 4–7 µs and so on; the final bucket contains every interval of at least 524288 µs. The event embeds a complete `reclaim_profile`, so the numbers printed with a victim describe the profile as it stood when that victim was selected.

## Profiling Reclaim and Tracking the Victim

Here is the complete BPF program.

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

`active_reclaims` joins begin and end by `pid_tgid`. The begin callback records the target cgroup ID from `memcg->css.cgroup->kn->id`, rather than using the current task's cgroup. Comparing those two IDs produces `cross_cgroup_reclaims`, which makes proactive reclaim from another cgroup visible.

Stack sampling happens at begin, before the reclaim work runs. `sample_every=1` captures every interval; a larger value reduces stack-map and unwinding cost while the latency histogram still counts every matched interval. The value `2` in the low eight flag bits skips two tracing frames, while `bpf_get_stackid()` deduplicates the remaining stack in `stack_traces`. `stack_profiles` attaches timing and reclaimed-page totals to each ID. Atomic updates let reclaim from several CPUs contribute to one cgroup profile.

`profile_reclaim_end()` removes the active state after accounting. It updates total and maximum latency, chooses the histogram bucket, and updates the sampled stack aggregate. Separate counters expose active-state insertion failures and stack-capture failures, while a difference between begin and end counts reveals an interval that could not be paired.

The OOM path handles process identity carefully. The tracepoint's `ctx->pid` is retained as `victim_tid`; `bpf_task_from_pid()` supplies the task's TGID and cgroup ID, and `bpf_task_release()` releases the referenced task pointer. Victim state stays keyed by TID because `sched_process_exit` runs in the context of that exact thread. This also covers a multithreaded process whose leader and selected victim have different IDs.

## Symbolizing and Presenting the Profile

The user-space program loads kernel symbols, ranks stack aggregates, manages the optional cgroup filter, and provides a self-contained OOM demonstration.

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

At startup, the loader reads `/proc/kallsyms`, sorts symbols by address, and uses binary search to resolve each address from the BPF stack-trace map. If symbol addresses are hidden, the same profile is still printed with raw addresses. Stack groups are ranked by cumulative reclaim time, which highlights a path that is called often as well as one unusually slow interval.

Normal mode can trace one cgroup or all cgroups. When tracing stops, it walks the profile map and prints each live histogram even if no OOM happened. An OOM event prints the same profile immediately, followed by the top five stack groups and their frames.

Demo mode creates a cgroup with `memory.max=32 MiB`, no swap, and grouped OOM behavior. A worker first faults 24 MiB, pauses, and lets the parent request 8 MiB through `memory.reclaim`; that deliberate cross-cgroup request exercises target-memcg attribution. The worker then continues faulting a 128 MiB mapping until the cgroup OOM killer selects it. The process leader exits before that second stage, so the test also proves that TGID and victim TID are handled separately. Cleanup restores the memory controller state it found at startup.

## Build and Run

Build the profiler:

```bash
cd src/57-oom-watch
make
```

Profile one service cgroup for 60 seconds and sample one kernel stack for every ten reclaim intervals:

```bash
sudo ./oom_watch \
  --cgroup /sys/fs/cgroup/my-service \
  --duration 60 \
  --sample-every 10
```

Omit `--cgroup` to watch all cgroups. Omit `--duration` to run until interrupted. The built-in demo captures every reclaim stack:

```bash
sudo ./oom_watch --demo
```

The variable PIDs, cgroup ID, addresses, and timings change between runs. The following excerpt comes from a real run; it keeps the complete profile totals and shortens the stack frames for readability:

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

The 44 completed intervals equal the 44 begin events, and all histogram counts sum to 44. Half were triggered from outside the target cgroup. The two ranked paths separate allocation charge reclaim from the explicit `memory.reclaim` request, while the exit event confirms that the marked TID ended with `SIGKILL`.

## Requirements

| Requirement | Details |
|---|---|
| Kernel | Linux 7.1 or newer for target-memcg vmscan tracepoints |
| Kernel config | `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_BPF_EVENTS`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_MEMCG`; `CONFIG_KALLSYMS` improves symbols |
| cgroup | cgroup v2 with the memory controller; demo mode also needs writable cgroup administration |
| Privileges | Root, or equivalent BPF, tracing, and cgroup-management capabilities |
| Architecture and hardware | x86-64 is the declared and tested target; no special hardware |

## Scope

Profiles accumulate from attachment until exit and use bounded LRU maps: 4096 cgroup profiles, 4096 active intervals, 8192 stack aggregates, and 1024 unique stacks. One active interval is retained per `pid_tgid`, which matches the traced begin/end path. The tool captures kernel stacks rather than user stacks and treats symbolization as presentation, so restricted `kallsyms` changes names into addresses without changing the measurements.

## Summary

`oom-watch` turns the period before an OOM kill into evidence that can be inspected. It measures every matched memcg reclaim interval, samples and ranks the kernel paths, attributes work to the target cgroup, then joins that profile to victim selection and exit.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [Linux vmscan tracepoints](https://github.com/torvalds/linux/blob/v7.1/include/trace/events/vmscan.h)
- [Target-memcg vmscan attribution commit](https://github.com/torvalds/linux/commit/874a0a566ede40f3d6062cae8fe1022e616edd1a)
- [Linux OOM tracepoints](https://github.com/torvalds/linux/blob/v7.1/include/trace/events/oom.h)
- [BPF kfunc documentation](https://docs.kernel.org/bpf/kfuncs.html)
- [Control Group v2 memory interface](https://docs.kernel.org/admin-guide/cgroup-v2.html)
