// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "energy_monitor.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} time_lookup SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} runtime_lookup SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile bool verbose = false;

static inline u64 div_u64_by_1000(u64 n) {
	u64 q, r, t;
	t = (n >> 7) + (n >> 8) + (n >> 12);
	q = (n >> 1) + t + (n >> 15) + (t >> 11) + (t >> 14);
	q = q >> 9;
	r = n - q * 1000;
	return q + ((r + 24) >> 10);
}

static int update_runtime(u32 pid, u64 delta) {
	u64 time_delta_us = div_u64_by_1000(delta);
	u64 *current = bpf_map_lookup_elem(&runtime_lookup, &pid);
	
	if (current) {
		time_delta_us += *current;
	}
	
	return bpf_map_update_elem(&runtime_lookup, &pid, &time_delta_us, BPF_ANY);
}

SEC("tp/sched/sched_switch")
int monitor_energy(struct trace_event_raw_sched_switch *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	u32 cpu = bpf_get_smp_processor_id();
	struct energy_event *e;
	
	u32 prev_pid = ctx->prev_pid;
	u32 next_pid = ctx->next_pid;
	
	// Calculate runtime for the previous process
	u64 *old_ts_ptr = bpf_map_lookup_elem(&time_lookup, &prev_pid);
	if (old_ts_ptr) {
		u64 delta = ts - *old_ts_ptr;
		
		if (verbose) {
			bpf_printk("CPU %d: PID %d ran for %llu ns", cpu, prev_pid, delta);
		}
		
		// Update total runtime
		if (update_runtime(prev_pid, delta) != 0) {
			return 1;
		}
		
		// Send event to userspace
		e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
		if (e) {
			e->ts = ts;
			e->cpu = cpu;
			e->pid = prev_pid;
			e->runtime_ns = delta;
			bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), ctx->prev_comm);
			
			bpf_ringbuf_submit(e, 0);
		}
	}
	
	// Record when the next process starts running
	bpf_map_update_elem(&time_lookup, &next_pid, &ts, BPF_ANY);
	
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	
	// Clean up maps
	bpf_map_delete_elem(&time_lookup, &pid);
	bpf_map_delete_elem(&runtime_lookup, &pid);
	
	return 0;
}