#define BPF_NO_GLOBAL_DATA
// #define BPF_NO_PRESERVE_ACCESS_INDEX
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif


struct deep_memory_block {
    int a;
    char b[10];
};

struct inner_memory_block {
    int a;
    char b[10];
    struct deep_memory_block *deep;
};

struct data {
        int a;
        int b;
        int c;
        int d;
        // represent a pointer to a memory block
        struct inner_memory_block *inner;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

SEC("uprobe/examples/btf-base:add_test")
int BPF_UPROBE(add_test, struct data *d)
{
	int inner_deep_a = BPF_CORE_READ_USER(d, inner, deep, a);
	bpf_printk("inner_deep_a = %d\n", inner_deep_a);
	char* inner_deep_b = BPF_CORE_READ_USER(d, inner, deep, b);
	bpf_printk("inner_deep_b[9] = %c\n", inner_deep_b[9]);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
