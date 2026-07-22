// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "exec_image_inspector.h"
#include "exec_image_inspector.skel.h"

struct event_context {
	unsigned long long seen;
};

static bool verbose;
static volatile sig_atomic_t exiting;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
		"Usage: %s [--verbose]\n\n"
		"Continuously inspect executable images installed by exec.\n"
		"Press Ctrl-C to stop and print a summary.\n\n"
		"Options:\n"
		"  -v, --verbose             print libbpf diagnostics\n"
		"  -h, --help                show this help\n",
		program);
}

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "+vh", options, NULL)) != -1) {
		switch (option) {
		case 'v':
			verbose = true;
			break;
		case 'h':
			usage(stdout, argv[0]);
			exit(0);
		default:
			return -EINVAL;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "unexpected argument: %s\n", argv[optind]);
		return -EINVAL;
	}
	return 0;
}

static void handle_signal(int signal_number)
{
	(void)signal_number;
	exiting = 1;
}

static int install_signal_handlers(void)
{
	struct sigaction action = {
		.sa_handler = handle_signal,
	};

	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL))
		return -errno;
	return 0;
}

static int drain_events(struct ring_buffer *ring_buffer)
{
	int error;

	for (;;) {
		error = ring_buffer__poll(ring_buffer, 0);
		if (error == -EINTR)
			continue;
		if (error < 0) {
			fprintf(stderr, "ring-buffer drain failed: %s\n",
				strerror(-error));
			return error;
		}
		if (!error)
			return 0;
	}
}

static const char *elf_class_name(unsigned char value)
{
	switch (value) {
	case 1:
		return "ELF32";
	case 2:
		return "ELF64";
	default:
		return "UNKNOWN";
	}
}

static const char *elf_data_name(unsigned char value)
{
	switch (value) {
	case 1:
		return "LSB";
	case 2:
		return "MSB";
	default:
		return "UNKNOWN";
	}
}

static const char *elf_type_name(unsigned short value)
{
	switch (value) {
	case 2:
		return "ET_EXEC";
	case 3:
		return "ET_DYN";
	default:
		return "OTHER";
	}
}

static const char *elf_machine_name(unsigned short value)
{
	switch (value) {
	case 3:
		return "EM_386";
	case 62:
		return "EM_X86_64";
	case 183:
		return "EM_AARCH64";
	default:
		return "OTHER";
	}
}

static int handle_event(void *context, void *data, size_t size)
{
	const struct exec_event *event = data;
	struct event_context *events = context;

	if (size < sizeof(*event)) {
		fprintf(stderr, "short ring-buffer event: %zu bytes\n", size);
		return 0;
	}

	events->seen++;
	printf("EXEC pid=%u tgid=%u comm=%.*s path=%.*s is_elf=%u "
	       "class=%s endian=%s type=%s(%u) machine=%s(%u) "
	       "header_error=%d path_error=%d latency_us=%llu\n",
	       event->pid, event->tgid, EXEC_COMM_LEN, event->comm,
	       EXEC_PATH_LEN, event->path, event->is_elf,
	       elf_class_name(event->elf_class), elf_data_name(event->elf_data),
	       elf_type_name(event->elf_type), event->elf_type,
	       elf_machine_name(event->elf_machine), event->elf_machine,
	       event->header_error, event->path_error,
	       event->latency_ns / 1000);

	fflush(stdout);
	return 0;
}

static int setup_inspector(struct event_context *events,
			   struct exec_image_inspector_bpf **skeleton,
			   struct ring_buffer **ring_buffer)
{
	struct exec_image_inspector_bpf *skel;
	struct ring_buffer *ring;
	int error;

	skel = exec_image_inspector_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return -ENOMEM;
	}
	*skeleton = skel;

	error = exec_image_inspector_bpf__load(skel);
	if (error) {
		fprintf(stderr,
			"failed to load BPF object: %s\n"
			"This monitor requires Linux 6.19+, BTF, BPF JIT, "
			"CONFIG_BPF_LSM=y, and an active bpf LSM.\n"
			"Check the active list with: cat /sys/kernel/security/lsm\n",
			strerror(-error));
		return error;
	}
	error = exec_image_inspector_bpf__attach(skel);
	if (error) {
		fprintf(stderr, "failed to attach bprm_committed_creds LSM hook: %s\n",
			strerror(-error));
		return error;
	}

	ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
				events, NULL);
	if (!ring) {
		fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
		return errno ? -errno : -ENOMEM;
	}
	*ring_buffer = ring;
	return 0;
}

static int monitor_execs(struct ring_buffer *ring_buffer)
{
	int error;

	printf("READY scope=system-wide\n");
	fflush(stdout);
	while (!exiting) {
		error = ring_buffer__poll(ring_buffer, 100);
		if (error == -EINTR)
			continue;
		if (error < 0) {
			fprintf(stderr, "ring-buffer poll failed: %s\n", strerror(-error));
			return error;
		}
	}
	return 0;
}

static int drain_pending_events(struct ring_buffer *ring_buffer,
				const struct exec_image_inspector_bpf *skel)
{
	int attempts, error;

	for (attempts = 0; attempts < 10; attempts++) {
		if (skel->bss->stats.completed >= skel->bss->stats.scheduled)
			return drain_events(ring_buffer);
		error = ring_buffer__poll(ring_buffer, 100);
		if (error == -EINTR)
			continue;
		if (error < 0) {
			fprintf(stderr, "ring-buffer shutdown poll failed: %s\n",
				strerror(-error));
			return error;
		}
	}

	fprintf(stderr, "timed out waiting for %llu scheduled callbacks\n",
		skel->bss->stats.scheduled - skel->bss->stats.completed);
	return -ETIMEDOUT;
}

static void report_result(const struct exec_image_inspector_bpf *skel,
			  const struct event_context *events)
{
	struct inspector_stats final_stats = skel->bss->stats;

	printf("SUMMARY matched=%llu scheduled=%llu schedule_errors=%llu "
	       "callbacks=%llu completed=%llu header_errors=%llu path_errors=%llu "
	       "dropped=%llu cleanup_errors=%llu events=%llu\n",
	       final_stats.matched, final_stats.scheduled,
	       final_stats.schedule_errors, final_stats.callbacks,
	       final_stats.completed, final_stats.header_errors,
	       final_stats.path_errors,
	       final_stats.dropped, final_stats.cleanup_errors, events->seen);
}

int main(int argc, char **argv)
{
	struct exec_image_inspector_bpf *skel = NULL;
	struct event_context events = {};
	struct ring_buffer *ring_buffer = NULL;
	int error, result = 1;

	error = parse_args(argc, argv);
	if (error) {
		usage(stderr, argv[0]);
		return 2;
	}
	error = install_signal_handlers();
	if (error) {
		fprintf(stderr, "failed to install signal handlers: %s\n",
			strerror(-error));
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	error = setup_inspector(&events, &skel, &ring_buffer);
	if (error)
		goto cleanup;
	error = monitor_execs(ring_buffer);
	exec_image_inspector_bpf__detach(skel);
	if (!error)
		error = drain_pending_events(ring_buffer, skel);
	report_result(skel, &events);
	if (!error)
		result = 0;

cleanup:
	ring_buffer__free(ring_buffer);
	exec_image_inspector_bpf__destroy(skel);
	return result;
}
