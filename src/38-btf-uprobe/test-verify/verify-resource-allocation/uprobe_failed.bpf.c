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

extern struct data* my_alloc_data(void) __ksym;
extern void my_free_data(struct data *d) __ksym;

SEC("uprobe/examples/btf-base:add_test")
int BPF_UPROBE(add_test, struct data *d)
{
	struct data *alloced = my_alloc_data();
    if (alloced == NULL) {
        bpf_printk("Failed to allocate data\n");
        return 0;
    }
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
