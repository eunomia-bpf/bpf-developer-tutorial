// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "execsnoop.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	u64 id;
	pid_t pid, tgid;
	unsigned int ret;
	struct event event;
	struct task_struct *task;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;

	uid_t uid = (u32)bpf_get_current_uid_gid();
	int i;
	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	tgid = id >> 32;

	event.pid = tgid;
	event.uid = uid;
	task = (struct task_struct*)bpf_get_current_task();
	bpf_probe_read_str(&event.comm, sizeof(event.comm), task->comm);
	event.is_exit = false;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
	u64 id;
	pid_t pid;
	int ret;
	struct event event;

	u32 uid = (u32)bpf_get_current_uid_gid();

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;

	ret = ctx->ret;
	event.retval = ret;
	event.pid = pid;
	event.uid = uid;
	event.is_exit = true;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

