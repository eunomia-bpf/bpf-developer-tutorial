// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "fsession_latency.h"
#include "fsession_latency.skel.h"

static volatile sig_atomic_t exiting;

static struct env {
	unsigned long long threshold_us;
	unsigned int duration;
	unsigned int pid;
	bool verbose;
} env = {
	.threshold_us = 1000,
	.duration = 10,
};

static unsigned long long events_printed;

static const char *file_type(unsigned int mode)
{
	if (S_ISREG(mode))
		return "regular";
	if (S_ISDIR(mode))
		return "directory";
	if (S_ISCHR(mode))
		return "character";
	if (S_ISBLK(mode))
		return "block";
	if (S_ISFIFO(mode))
		return "fifo";
	if (S_ISLNK(mode))
		return "symlink";
	if (S_ISSOCK(mode))
		return "socket";
	return "unknown";
}

static void handle_signal(int signal)
{
	(void)signal;
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s [--threshold-us USEC] [--duration SEC] [--pid TGID] "
		"[--verbose]\n\n"
		"Report vfs_read calls at or above a latency threshold.\n\n"
		"Options:\n"
		"  -t, --threshold-us USEC  slow-read threshold (default: 1000)\n"
		"  -d, --duration SEC       trace duration, 1-86400 (default: 10)\n"
		"  -p, --pid TGID           trace one process ID (default: all)\n"
		"  -v, --verbose            print libbpf diagnostics\n"
		"  -h, --help               show this help\n",
		program);
}

static int parse_u64(const char *value, unsigned long long maximum,
		     unsigned long long *result)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(value, &end, 10);
	if (errno || end == value || *end || parsed > maximum)
		return -EINVAL;
	*result = parsed;
	return 0;
}

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "threshold-us", required_argument, NULL, 't' },
		{ "duration", required_argument, NULL, 'd' },
		{ "pid", required_argument, NULL, 'p' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	unsigned long long parsed;
	int option;

	while ((option = getopt_long(argc, argv, "t:d:p:vh", options, NULL)) != -1) {
		switch (option) {
		case 't':
			if (parse_u64(optarg, UINT64_MAX / 1000, &env.threshold_us)) {
				fprintf(stderr, "invalid threshold in microseconds: %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'd':
			if (parse_u64(optarg, 86400, &parsed) || parsed == 0) {
				fprintf(stderr, "invalid duration in seconds: %s\n", optarg);
				return -EINVAL;
			}
			env.duration = parsed;
			break;
		case 'p':
			if (parse_u64(optarg, UINT32_MAX, &parsed) || parsed == 0) {
				fprintf(stderr, "invalid process ID: %s\n", optarg);
				return -EINVAL;
			}
			env.pid = parsed;
			break;
		case 'v':
			env.verbose = true;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			return -EINVAL;
		}
	}

	if (optind != argc)
		return -EINVAL;
	return 0;
}

static long long monotonic_milliseconds(void)
{
	struct timespec timestamp;

	if (clock_gettime(CLOCK_MONOTONIC, &timestamp))
		return -errno;
	return timestamp.tv_sec * 1000LL + timestamp.tv_nsec / 1000000;
}

static int handle_event(void *context, void *data, size_t size)
{
	const struct latency_event *event = data;

	(void)context;
	if (size < sizeof(*event))
		return 0;

	printf("EVENT comm=%-16s tgid=%u pid=%u object=%u:%u:%llu type=%s "
	       "requested=%llu result=%lld latency_us=%llu\n",
	       event->comm, event->tgid, event->pid,
	       event->device_major, event->device_minor, event->inode,
	       file_type(event->mode), event->requested, event->result,
	       event->latency_ns / 1000);
	events_printed++;
	return 0;
}

static int poll_until_deadline(struct ring_buffer *ring, long long deadline)
{
	while (!exiting) {
		long long now = monotonic_milliseconds();
		int consumed;

		if (now < 0)
			return (int)now;
		if (now >= deadline)
			break;

		consumed = ring_buffer__poll(ring,
					     deadline - now > 100 ? 100 : deadline - now);
		if (consumed == -EINTR)
			continue;
		if (consumed < 0) {
			fprintf(stderr, "ring buffer poll failed: %s\n",
				strerror(-consumed));
			return consumed;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct fsession_latency_bpf *skel = NULL;
	struct ring_buffer *ring = NULL;
	long long deadline, now;
	int err;

	err = parse_args(argc, argv);
	if (err) {
		usage(argv[0]);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	skel = fsession_latency_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->threshold_ns = env.threshold_us * 1000;
	skel->rodata->target_tgid = env.pid;

	err = fsession_latency_bpf__load(skel);
	if (err) {
		fprintf(stderr,
			"failed to load fsession program: %s\n"
			"This tool requires Linux 7.0+, BTF, BPF JIT, and x86_64 "
			"fsession support.\n",
			strerror(-err));
		goto cleanup;
	}

	err = fsession_latency_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach to vfs_read: %s\n", strerror(-err));
		goto cleanup;
	}

	ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	err = libbpf_get_error(ring);
	if (err) {
		ring = NULL;
		fprintf(stderr, "failed to create ring buffer: %s\n", strerror(-err));
		goto cleanup;
	}

	printf("Tracing vfs_read for %u seconds; threshold=%llu us; pid=%s\n",
	       env.duration, env.threshold_us, env.pid ? "selected" : "all");
	fflush(stdout);

	now = monotonic_milliseconds();
	if (now < 0) {
		err = now;
		goto cleanup;
	}
	deadline = now + env.duration * 1000LL;

	err = poll_until_deadline(ring, deadline);
	if (err)
		goto cleanup;

	fsession_latency_bpf__detach(skel);

	err = ring_buffer__consume(ring);
	if (err < 0) {
		fprintf(stderr, "ring buffer drain failed: %s\n", strerror(-err));
		goto cleanup;
	}
	err = 0;

	printf("SUMMARY calls=%llu slow=%llu errors=%llu dropped=%llu events=%llu\n",
	       skel->bss->stats.calls, skel->bss->stats.slow,
	       skel->bss->stats.errors, skel->bss->stats.dropped, events_printed);

cleanup:
	ring_buffer__free(ring);
	fsession_latency_bpf__destroy(skel);
	return err != 0;
}
