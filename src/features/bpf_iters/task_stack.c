// SPDX-License-Identifier: GPL-2.0
/* Userspace program for task stack and file iterator */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "task_stack.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void run_iterator(const char *name, struct bpf_program *prog)
{
	struct bpf_link *link;
	int iter_fd, len;
	char buf[8192];

	link = bpf_program__attach_iter(prog, NULL);
	if (!link) {
		fprintf(stderr, "Failed to attach %s iterator\n", name);
		return;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		fprintf(stderr, "Failed to create %s iterator: %d\n", name, iter_fd);
		bpf_link__destroy(link);
		return;
	}

	while ((len = read(iter_fd, buf, sizeof(buf) - 1)) > 0) {
		buf[len] = '\0';
		printf("%s", buf);
	}

	close(iter_fd);
	bpf_link__destroy(link);
}

int main(int argc, char **argv)
{
	struct task_stack_bpf *skel;
	int err;
	int show_files = 0;

	libbpf_set_print(libbpf_print_fn);

	/* Parse arguments */
	if (argc > 1 && strcmp(argv[1], "--files") == 0) {
		show_files = 1;
		argc--;
		argv++;
	}

	/* Open BPF application */
	skel = task_stack_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Configure filter before loading */
	if (argc > 1) {
		strncpy(skel->bss->target_comm, argv[1], sizeof(skel->bss->target_comm) - 1);
		printf("Filtering for tasks matching: %s\n\n", argv[1]);
	} else {
		printf("Usage: %s [--files] [comm]\n", argv[0]);
		printf("  --files    Show open file descriptors instead of stacks\n");
		printf("  comm       Filter by process name\n\n");
	}

	/* Load BPF program */
	err = task_stack_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	if (show_files) {
		printf("=== BPF Task File Descriptor Iterator ===\n\n");
		run_iterator("task_file", skel->progs.dump_task_file);
	} else {
		printf("=== BPF Task Stack Iterator ===\n\n");
		run_iterator("task", skel->progs.dump_task_stack);
	}

cleanup:
	task_stack_bpf__destroy(skel);
	return err;
}
