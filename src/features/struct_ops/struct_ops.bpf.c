/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int pid_t;

extern int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz) __ksym;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int handle_kprobe(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	char str[] = "Hello, world!";
	char substr[] = "wor";
	u32 result = bpf_strstr(str, sizeof(str) - 1, substr, sizeof(substr) - 1);
	if (result != -1)
	{
		bpf_printk("'%s' found in '%s' at index %d\n", substr, str, result);
	}
	bpf_printk("Hello, world! (pid: %d) bpf_strstr %d\n", pid, result);
	return 0;
}
