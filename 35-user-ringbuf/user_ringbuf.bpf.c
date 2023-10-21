// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "user_ringbuf.h"

char _license[] SEC("license") = "GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024);
} user_ringbuf SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} kernel_ringbuf SEC(".maps");

int read = 0;

static long
do_nothing_cb(struct bpf_dynptr *dynptr, void *context)
{
	struct event *e;
	pid_t pid;
	/* get PID and TID of exiting thread/process */
	pid = bpf_get_current_pid_tgid() >> 32;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&kernel_ringbuf, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = pid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	__sync_fetch_and_add(&read, 1);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
	long num_samples;
	int err = 0;
	
	// receive data from userspace
	num_samples = bpf_user_ringbuf_drain(&user_ringbuf, do_nothing_cb, NULL, 0);

	return 0;
}