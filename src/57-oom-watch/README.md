# eBPF Tutorial: Profiling Memory Reclaim Before an OOM Kill

Have you ever had a container or service suddenly killed by the Linux OOM killer, leaving you with nothing but a cryptic log message? The kernel tells you *which* process it chose as a victim, but says almost nothing about the memory pressure that led there. How many times did the system try to reclaim memory? How long did each attempt take? Which kernel code paths consumed all that time?

This tutorial builds `oom-watch`, an eBPF tool that captures what happens *before* the kill. It profiles every memcg reclaim attempt as a latency histogram and a set of sampled kernel stacks, then attaches this accumulated profile to the OOM victim and tracks the process until it exits.

> Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/57-oom-watch>

## The Missing Piece in OOM Debugging

When a memory cgroup approaches its limit, any allocation might trigger reclaim. The kernel scans the cgroup for pages it can free. Sometimes a few short attempts succeed. Other times, reclaim keeps running with little progress until the OOM killer finally steps in.

Looking only at the `oom/mark_victim` tracepoint loses all this context. You see the victim, but not the struggle that came before. Operators need answers to questions like:

- How many reclaim cycles happened before the kill?
- Were they quick microsecond scans, or long millisecond stalls?
- Did reclaim come from allocations inside the cgroup, or from external proactive reclaim via `memory.reclaim`?
- Which kernel functions dominated the reclaim time?

`oom-watch` answers all of these. It hooks into the kernel's vmscan tracepoints to measure every reclaim interval, samples kernel stacks to show where time was spent, and when OOM selects a victim, it snapshots the accumulated profile right alongside the victim information.

## Why eBPF for Memory Profiling?

Traditional monitoring approaches have serious limitations for this use case. Polling `/proc/meminfo` or cgroup stats misses short-lived reclaim events. `perf` can capture stack traces but requires careful setup and post-processing. Neither approach easily connects reclaim activity to a specific OOM event.

eBPF changes the game. Programs run directly in the kernel, triggered by events with nanosecond precision. Maps carry state between events, letting us build histograms and correlate begin/end pairs. The ring buffer delivers events to userspace with minimal overhead. And because eBPF programs are verified before loading, there's no risk of crashing the kernel.

For `oom-watch`, we use several tracepoints:

- `mm_vmscan_memcg_reclaim_begin`: Fires when reclaim starts for a specific memory cgroup
- `mm_vmscan_memcg_reclaim_end`: Fires when that reclaim interval completes
- `oom/mark_victim`: Fires when the OOM killer selects a victim
- `sched/sched_process_exit`: Fires when the victim process exits

Linux 7.1 added a crucial feature: the vmscan tracepoints now include the target `mem_cgroup` being scanned. This matters because a process in one cgroup can trigger reclaim in a different cgroup through `memory.reclaim`. With the target cgroup in the tracepoint, we can correctly attribute the work.

## Architecture Overview

The tool has three main components working together.

The **header file** defines shared data structures: a per-cgroup reclaim profile containing latency buckets and counters, a per-stack aggregate tracking samples and timing, and an event structure for OOM notifications.

The **BPF program** runs in the kernel. On reclaim begin, it records the start time and optionally captures a kernel stack. On reclaim end, it computes duration, updates the histogram, and stores the stack aggregate. When OOM marks a victim, it looks up the victim's cgroup, copies the accumulated profile into an event, and sends it to userspace. It also saves victim state so it can report when the process exits.

The **userspace program** loads kernel symbols for stack symbolization, manages the optional cgroup filter, processes events from the ring buffer, and includes a self-contained demo mode that triggers an OOM to verify everything works.

## The Profile Data Structures

The shared header defines what we're measuring:

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

The `latency_slots` array holds a power-of-two histogram with 20 buckets. Bucket 0 covers 0-1 microseconds, bucket 1 covers 2-3 microseconds, then 4-7 microseconds, and so on. The final bucket catches everything over half a second. This logarithmic distribution captures both fast reclaim cycles and rare slow ones efficiently.

When an OOM event fires, it embeds a complete copy of the cgroup's profile. The numbers printed with the victim show exactly how things stood at the moment of selection.

## The BPF Program

Here's the complete BPF code. We'll walk through how it works after the listing:

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

The program uses several BPF maps to maintain state. The `active_reclaims` map joins begin and end events by storing the start timestamp keyed by `pid_tgid`. The `profiles` map accumulates per-cgroup statistics. The `stack_traces` map stores deduplicated kernel stacks, while `stack_profiles` aggregates timing data for each unique stack.

At reclaim begin, we extract the target cgroup ID from the `mem_cgroup` parameter, not from the current task's cgroup. This distinction matters for cross-cgroup reclaim. If someone calls `memory.reclaim` on a cgroup from outside, we correctly attribute the work to the target. The `cross_cgroup_reclaims` counter tracks how often this happens.

Stack sampling uses the `--sample-every` setting. With the default value of 1, we capture every interval. Higher values reduce overhead while still counting all intervals in the histogram. The `BPF_F_FAST_STACK_CMP` flag speeds up stack deduplication, and the `2` in the flags skips two tracing frames to get cleaner stacks.

The OOM handler has to resolve process identity carefully. The tracepoint gives us a thread ID, but we also need the thread group ID (PID from userspace perspective) and the cgroup. We use `bpf_task_from_pid()` to look up the task, read what we need, then release the reference. Victim state is keyed by TID because `sched_process_exit` fires in that thread's context.

## Userspace: Symbols and Presentation

The userspace code handles several jobs: loading kernel symbols for stack symbolization, setting up the BPF program with any cgroup filter, processing events from the ring buffer, and ranking stacks by total time spent. It also includes a demo mode that creates a memory-limited cgroup and triggers an OOM to verify the tool works.

The full userspace code is quite long, so we'll highlight the key parts. On startup, it reads `/proc/kallsyms`, sorts symbols by address, and later uses binary search to resolve each stack frame. When symbol addresses are restricted (common on production systems), it still prints raw addresses - the measurements stay accurate.

Stack groups are ranked by cumulative reclaim time. This ranking surfaces both frequently-called paths and rare slow intervals. After an OOM event, the top five stacks are printed with their timing statistics.

The demo mode creates a cgroup with `memory.max=32 MiB`, no swap, and grouped OOM behavior. A worker process faults 24 MiB then pauses, letting the parent request 8 MiB through `memory.reclaim` from outside the cgroup. This exercises cross-cgroup attribution. The worker then continues faulting a 128 MiB mapping until OOM kills it. The process leader exits before the second stage, testing that we handle TGID and victim TID independently.

## Compilation and Execution

Build the tool:

```bash
cd src/57-oom-watch
make
```

Profile a specific cgroup for 60 seconds, sampling one kernel stack for every ten reclaim intervals:

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

Here's output from a real demo run. PIDs, cgroup IDs, addresses, and timings vary between runs:

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

Look at what this tells us: 44 reclaim cycles completed before the kill, with half triggered from outside the target cgroup. The histogram shows most cycles were fast (under 8 microseconds), but a few took longer. The two ranked stacks separate allocation-triggered reclaim from explicit `memory.reclaim` requests. The exit event confirms the victim received `SIGKILL`.

## Requirements

| Requirement | Details |
|---|---|
| Kernel | Linux 7.1 or newer (needs target-memcg vmscan tracepoints) |
| Kernel config | `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_BPF_EVENTS`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_MEMCG`; `CONFIG_KALLSYMS` improves symbol output |
| cgroup | cgroup v2 with memory controller; demo mode needs cgroup admin access |
| Privileges | Root or equivalent BPF and tracing capabilities |
| Architecture | x86-64 tested; no special hardware needed |

## Implementation Scope

Profiles accumulate from program attach until exit, using bounded LRU maps: 4096 cgroup profiles, 4096 active intervals, 8192 stack aggregates, and 1024 unique stacks. One active interval is retained per `pid_tgid`, matching the begin/end tracing pattern. The tool captures kernel stacks rather than user stacks, and treats symbolization as presentation - restricted `kallsyms` changes names to addresses without affecting measurements.

## Summary

`oom-watch` turns the chaos before an OOM kill into evidence you can examine. It measures every memcg reclaim interval, samples and ranks the kernel paths that consumed time, correctly attributes work to the target cgroup (even for cross-cgroup reclaim), and connects this profile to the victim selection and exit.

The next time a container dies and someone asks "what happened?", you'll have more than a one-line kernel log to show them.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [Linux vmscan tracepoints](https://github.com/torvalds/linux/blob/v7.1/include/trace/events/vmscan.h)
- [Target-memcg vmscan attribution commit](https://github.com/torvalds/linux/commit/874a0a566ede40f3d6062cae8fe1022e616edd1a)
- [Linux OOM tracepoints](https://github.com/torvalds/linux/blob/v7.1/include/trace/events/oom.h)
- [BPF kfunc documentation](https://docs.kernel.org/bpf/kfuncs.html)
- [Control Group v2 memory interface](https://docs.kernel.org/admin-guide/cgroup-v2.html)
