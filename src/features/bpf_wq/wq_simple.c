// SPDX-License-Identifier: GPL-2.0
/* Userspace test for BPF workqueue */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "wq_simple.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct wq_simple_bpf *skel;
	int err, fd;

	libbpf_set_print(libbpf_print_fn);

	/* Open and load BPF application */
	skel = wq_simple_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = wq_simple_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("BPF workqueue program attached. Triggering unlink syscall...\n");

	/* Create a temporary file to trigger do_unlinkat */
	fd = open("/tmp/wq_test_file", O_CREAT | O_WRONLY, 0644);
	if (fd >= 0) {
		close(fd);
		unlink("/tmp/wq_test_file");
	}

	/* Give workqueue time to execute */
	sleep(1);

	/* Check results */
	printf("\nResults:\n");
	printf("  main_executed = %u (expected: 1)\n", skel->bss->main_executed);
	printf("  wq_executed = %u (expected: 1)\n", skel->bss->wq_executed);

	if (skel->bss->main_executed == 1 && skel->bss->wq_executed == 1) {
		printf("\n✓ Test PASSED!\n");
	} else {
		printf("\n✗ Test FAILED!\n");
		err = 1;
	}

cleanup:
	wq_simple_bpf__destroy(skel);
	return err;
}
