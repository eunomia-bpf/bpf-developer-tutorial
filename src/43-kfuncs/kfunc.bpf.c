/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int pid_t;

extern u64 bpf_kfunc_call_test(u32 a, u64 b, u32 c, u64 d) __ksym;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int handle_kprobe(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	u64 result = bpf_kfunc_call_test(1, 2, 3, 4);
	bpf_printk("BPF triggered do_unlinkat from PID %d. Result: %lld\n", pid, result);
	return 0;
}
