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
