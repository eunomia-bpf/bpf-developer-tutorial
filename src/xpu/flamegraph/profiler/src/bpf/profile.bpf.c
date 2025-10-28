// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "profile.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Shared helper to collect stack trace
static __always_inline int collect_stack_trace(void *ctx, u64 cookie)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	int cpu_id = bpf_get_smp_processor_id();
	struct stacktrace_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 1;

	event->pid = pid;
	event->cpu_id = cpu_id;
	event->timestamp = bpf_ktime_get_ns();

	if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
		event->comm[0] = 0;

	// Store probe_id in cpu_id field when in probe mode
	// In perf mode: cpu_id is actual CPU
	// In probe mode: cpu_id is probe_id, actual CPU stored in pid high bits if needed
	if (cookie != 0) {
		event->cpu_id = (u32)cookie;  // probe_id from bpf_get_attach_cookie
	}

	event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

	event->ustack_sz =
		bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("perf_event")
int profile(void *ctx)
{
	return collect_stack_trace(ctx, 0);
}

// Generic kprobe handler
SEC("kprobe")
int kprobe_handler(struct pt_regs *ctx)
{
	u64 probe_id = bpf_get_attach_cookie(ctx);
	return collect_stack_trace(ctx, probe_id);
}

// Generic kretprobe handler
SEC("kretprobe")
int kretprobe_handler(struct pt_regs *ctx)
{
	u64 probe_id = bpf_get_attach_cookie(ctx);
	return collect_stack_trace(ctx, probe_id);
}

// Generic uprobe handler
SEC("uprobe")
int uprobe_handler(struct pt_regs *ctx)
{
	u64 probe_id = bpf_get_attach_cookie(ctx);
	return collect_stack_trace(ctx, probe_id);
}

// Generic uretprobe handler
SEC("uretprobe")
int uretprobe_handler(struct pt_regs *ctx)
{
	u64 probe_id = bpf_get_attach_cookie(ctx);
	return collect_stack_trace(ctx, probe_id);
}
