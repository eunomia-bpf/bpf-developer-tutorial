// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021~2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "sigsnoop.h"

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct event);
} values SEC(".maps");


static int probe_entry(pid_t tpid, int sig)
{
	struct event event = {};
	__u64 pid_tgid;
	__u32 pid, tid;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	event.pid = pid;
	event.tpid = tpid;
	event.sig = sig;
	bpf_get_current_comm(event.comm, sizeof(event.comm));
	bpf_map_update_elem(&values, &tid, &event, BPF_ANY);
	return 0;
}

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;
	struct event *eventp;

	eventp = bpf_map_lookup_elem(&values, &tid);
	if (!eventp)
		return 0;

	eventp->ret = ret;
	bpf_printk("PID %d (%s) sent signal %d to PID %d, ret = %d",
		   eventp->pid, eventp->comm, eventp->sig, eventp->tpid, eventp->ret);

cleanup:
	bpf_map_delete_elem(&values, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
