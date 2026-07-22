// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "slow_syscall_index.h"

char LICENSE[] SEC("license") = "GPL";

const volatile __u64 minimum_ns = 10 * 1000 * 1000ULL;
const volatile __u32 target_tgid;
const volatile __u32 ignored_tgid;

struct syscall_state {
	__u64 started_ns;
	__u32 syscall_id;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct syscall_state);
} active_syscalls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

__u64 completed_syscalls;
__u64 slow_syscalls;
__u64 dropped_events;

SEC("tp/raw_syscalls/sys_enter")
int record_syscall_entry(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task;
	struct syscall_state *state;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	if (tgid == ignored_tgid || (target_tgid && tgid != target_tgid))
		return 0;
	task = bpf_get_current_task_btf();
	state = bpf_task_storage_get(&active_syscalls, task, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!state)
		return 0;
	state->started_ns = bpf_ktime_get_ns();
	state->syscall_id = ctx->id;
	return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int report_slow_syscall(struct trace_event_raw_sys_exit *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct slow_syscall_event *event;
	struct syscall_state *state;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 duration_ns;

	state = bpf_task_storage_get(&active_syscalls, task, 0, 0);
	if (!state)
		return 0;
	duration_ns = bpf_ktime_get_ns() - state->started_ns;
	__sync_fetch_and_add(&completed_syscalls, 1);
	if (duration_ns < minimum_ns)
		goto out;

	__sync_fetch_and_add(&slow_syscalls, 1);
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&dropped_events, 1);
		goto out;
	}
	event->timestamp_ns = bpf_ktime_get_ns();
	event->duration_ns = duration_ns;
	event->return_value = ctx->ret;
	event->tgid = pid_tgid >> 32;
	event->tid = (__u32)pid_tgid;
	event->syscall_id = state->syscall_id;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	bpf_ringbuf_submit(event, 0);
out:
	bpf_task_storage_delete(&active_syscalls, task);
	return 0;
}
