// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include "uprobe.skel.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct uprobe_bpf *skel;
	int err;
	LIBBPF_OPTS(bpf_object_open_opts , opts,
	);
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	if (argc != 3 && argc != 2) {
		fprintf(stderr, "Usage: %s <example-name> [<external-btf>]\n", argv[0]);
		return 1;
	}
	if (argc == 3)
		opts.btf_custom_path = argv[2];

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = uprobe_bpf__open_opts(&opts);
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = uprobe_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	uprobe_opts.func_name = "add_test";
	skel->links.add_test = bpf_program__attach_uprobe_opts(
		skel->progs.add_test, -1 /* self pid */, argv[1] /* binary path */,
		0 /* offset for function */, &uprobe_opts /* opts */);
	if (!skel->links.add_test) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}
	printf("Successfully started! Press Ctrl+C to stop.\n");
	fflush(stdout);
	while (!exiting) {
		sleep(1);
	}
cleanup:
	/* Clean up */
	uprobe_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
