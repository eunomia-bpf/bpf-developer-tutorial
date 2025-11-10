/* SPDX-License-Identifier: GPL-2.0 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "module/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

/* Implement the struct_ops callbacks */
SEC("struct_ops/test_1")
int BPF_PROG(bpf_testmod_test_1)
{
	bpf_printk("BPF test_1 called!\n");
	return 42;
}

SEC("struct_ops/test_2")
int BPF_PROG(bpf_testmod_test_2, int a, int b)
{
	int result = a + b;
	bpf_printk("BPF test_2 called: %d + %d = %d\n", a, b, result);
	return result;
}

SEC("struct_ops/test_3")
void BPF_PROG(bpf_testmod_test_3, const char *buf, int len)
{
	bpf_printk("BPF test_3 called with buffer length %d\n", len);
	if (len > 0) {
		bpf_printk("First char: %c\n", buf[0]);
	}
}

/* Define the struct_ops map */
SEC(".struct_ops")
struct bpf_testmod_ops testmod_ops = {
	.test_1 = (void *)bpf_testmod_test_1,
	.test_2 = (void *)bpf_testmod_test_2,
	.test_3 = (void *)bpf_testmod_test_3,
};
