// SPDX-License-Identifier: GPL-2.0
/* Simple BPF workqueue example */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"

char LICENSE[] SEC("license") = "GPL";

/* Element with embedded workqueue */
struct elem {
	int value;
	struct bpf_wq work;
};

/* Array to store our element */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} array SEC(".maps");

/* Result variables */
__u32 wq_executed = 0;
__u32 main_executed = 0;

/* Workqueue callback - runs asynchronously in workqueue context */
static int wq_callback(void *map, int *key, void *value)
{
	struct elem *val = value;
	/* This runs later in workqueue context */
	wq_executed = 1;
	val->value = 42; /* Modify the value asynchronously */
	return 0;
}

/* Main program - schedules work */
SEC("fentry/do_unlinkat")
int test_workqueue(void *ctx)
{
	struct elem init = {.value = 0}, *val;
	struct bpf_wq *wq;
	int key = 0;

	main_executed = 1;

	/* Initialize element in map */
	bpf_map_update_elem(&array, &key, &init, 0);

	/* Get element from map */
	val = bpf_map_lookup_elem(&array, &key);
	if (!val)
		return 0;

	/* Initialize workqueue */
	wq = &val->work;
	if (bpf_wq_init(wq, &array, 0) != 0)
		return 0;

	/* Set callback function */
	if (bpf_wq_set_callback(wq, wq_callback, 0))
		return 0;

	/* Schedule work to run asynchronously */
	if (bpf_wq_start(wq, 0))
		return 0;

	return 0;
}
