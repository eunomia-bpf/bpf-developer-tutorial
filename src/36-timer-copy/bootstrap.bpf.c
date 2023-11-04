// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define CLOCK_REALTIME			0
#define CLOCK_MONOTONIC			1

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct map_elem {
    int counter;
    struct bpf_timer timer;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, int);
    __type(value, struct map_elem);
} hmap SEC(".maps");

static int timer_cb(void *map, int *key, struct map_elem *val) {
	bpf_printk("timer_cb\n");
	return 0;
}
/* val points to particular map element that contains bpf_timer. */

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test1, int a)
{
    struct map_elem *val;
    int key = 0;

    val = bpf_map_lookup_elem(&hmap, &key);
    if (val) {
        bpf_timer_init(&val->timer, &hmap, 1);
        bpf_timer_set_callback(&val->timer, timer_cb);
        bpf_timer_start(&val->timer, 1000 /* call timer_cb2 in 1 usec */, CLOCK_MONOTONIC);
    }
	return 0;
}