#define BPF_NO_GLOBAL_DATA
// #define BPF_NO_PRESERVE_ACCESS_INDEX
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

struct data {
        int a;
        int e;
        int d;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif


SEC("uprobe/examples/btf-base:add_test")
int BPF_UPROBE(add_test, struct data *d)
{
	int a = 0, e = 0;
	bpf_probe_read_user(&a, sizeof(a), &d->a);
	bpf_probe_read_user(&e, sizeof(e), &d->e);
	bpf_printk("add_test(&d) %d + %d = %d\n", a, e,  a + e);
	return a + e;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
