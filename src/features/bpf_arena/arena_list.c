// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bpf_arena_list.h"
#include "arena_list.skel.h"

struct elem {
	struct arena_list_node node;
	uint64_t value;
};

static int list_sum(struct arena_list_head *head)
{
	struct elem __arena *n;
	int sum = 0;

	list_for_each_entry(n, head, node)
		sum += n->value;
	return sum;
}

static void test_arena_list_add_del(int cnt)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct arena_list_bpf *skel;
	int expected_sum = (u_int64_t)cnt * (cnt - 1) / 2;
	int ret, sum;

	skel = arena_list_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return;
	}

	skel->bss->cnt = cnt;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arena_list_add), &opts);
	if (ret != 0) {
		fprintf(stderr, "Failed to run arena_list_add: %d\n", ret);
		goto out;
	}
	if (opts.retval != 0) {
		fprintf(stderr, "arena_list_add returned %d\n", opts.retval);
		goto out;
	}
	if (skel->bss->skip) {
		printf("SKIP: compiler doesn't support arena_cast\n");
		goto out;
	}
	sum = list_sum(skel->bss->list_head);
	printf("Sum of elements: %d (expected: %d)\n", sum, expected_sum);
	printf("Arena sum: %ld (expected: %d)\n", skel->bss->arena_sum, expected_sum);
	printf("Number of elements: %d (expected: %d)\n", skel->data->test_val, cnt + 1);

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arena_list_del), &opts);
	if (ret != 0) {
		fprintf(stderr, "Failed to run arena_list_del: %d\n", ret);
		goto out;
	}
	sum = list_sum(skel->bss->list_head);
	printf("Sum after deletion: %d (expected: 0)\n", sum);
	printf("Sum computed by BPF: %d (expected: %d)\n", skel->bss->list_sum, expected_sum);
	printf("Arena sum after deletion: %ld (expected: %d)\n", skel->bss->arena_sum, expected_sum);

	printf("\nTest passed!\n");
out:
	arena_list_bpf__destroy(skel);
}

int main(int argc, char **argv)
{
	int cnt = 10;

	if (argc > 1) {
		cnt = atoi(argv[1]);
		if (cnt <= 0) {
			fprintf(stderr, "Invalid count: %s\n", argv[1]);
			return 1;
		}
	}

	printf("Testing arena list with %d elements\n", cnt);
	test_arena_list_add_del(cnt);

	return 0;
}
