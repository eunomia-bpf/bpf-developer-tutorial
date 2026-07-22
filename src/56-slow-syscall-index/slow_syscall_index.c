// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "slow_syscall_index.h"
#include "slow_syscall_index.skel.h"

#define MAX_STATS 512

struct options {
	unsigned int pid;
	unsigned int minimum_ms;
	unsigned int duration_seconds;
	unsigned int top;
	bool demo;
};

struct syscall_stats {
	unsigned int tgid;
	unsigned int syscall_id;
	unsigned long long count;
	unsigned long long total_ns;
	unsigned long long maximum_ns;
	unsigned long long errors;
	char comm[SLOW_SYSCALL_COMM_LEN];
};

static struct syscall_stats stats[MAX_STATS];
static size_t stats_count;
static volatile sig_atomic_t stop;
static unsigned int received_events;
static unsigned int unaggregated_events;

static void handle_signal(int signal_number)
{
	(void)signal_number;
	stop = 1;
}

static unsigned long long monotonic_ns(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static const char *syscall_name(unsigned int id)
{
	switch (id) {
#ifdef __NR_read
	case __NR_read: return "read";
#endif
#ifdef __NR_write
	case __NR_write: return "write";
#endif
#ifdef __NR_openat
	case __NR_openat: return "openat";
#endif
#ifdef __NR_close
	case __NR_close: return "close";
#endif
#ifdef __NR_fsync
	case __NR_fsync: return "fsync";
#endif
#ifdef __NR_fdatasync
	case __NR_fdatasync: return "fdatasync";
#endif
#ifdef __NR_poll
	case __NR_poll: return "poll";
#endif
#ifdef __NR_ppoll
	case __NR_ppoll: return "ppoll";
#endif
#ifdef __NR_epoll_wait
	case __NR_epoll_wait: return "epoll_wait";
#endif
#ifdef __NR_epoll_pwait
	case __NR_epoll_pwait: return "epoll_pwait";
#endif
#ifdef __NR_futex
	case __NR_futex: return "futex";
#endif
#ifdef __NR_nanosleep
	case __NR_nanosleep: return "nanosleep";
#endif
#ifdef __NR_clock_nanosleep
	case __NR_clock_nanosleep: return "clock_nanosleep";
#endif
#ifdef __NR_connect
	case __NR_connect: return "connect";
#endif
#ifdef __NR_accept
	case __NR_accept: return "accept";
#endif
#ifdef __NR_accept4
	case __NR_accept4: return "accept4";
#endif
#ifdef __NR_recvfrom
	case __NR_recvfrom: return "recvfrom";
#endif
#ifdef __NR_recvmsg
	case __NR_recvmsg: return "recvmsg";
#endif
#ifdef __NR_sendto
	case __NR_sendto: return "sendto";
#endif
#ifdef __NR_sendmsg
	case __NR_sendmsg: return "sendmsg";
#endif
	default: return "unknown";
	}
}

static struct syscall_stats *get_stats(const struct slow_syscall_event *event)
{
	struct syscall_stats *entry;

	for (size_t i = 0; i < stats_count; i++)
		if (stats[i].tgid == event->tgid &&
		    stats[i].syscall_id == event->syscall_id)
			return &stats[i];
	if (stats_count == MAX_STATS)
		return NULL;
	entry = &stats[stats_count++];
	entry->tgid = event->tgid;
	entry->syscall_id = event->syscall_id;
	memcpy(entry->comm, event->comm, sizeof(entry->comm));
	entry->comm[sizeof(entry->comm) - 1] = '\0';
	return entry;
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct slow_syscall_event *event = data;
	struct syscall_stats *entry;

	(void)ctx;
	if (size != sizeof(*event))
		return 0;
	entry = get_stats(event);
	if (entry) {
		entry->count++;
		entry->total_ns += event->duration_ns;
		if (event->duration_ns > entry->maximum_ns)
			entry->maximum_ns = event->duration_ns;
		if (event->return_value < 0)
			entry->errors++;
	} else {
		unaggregated_events++;
	}
	received_events++;
	printf("pid=%u tid=%u comm=%s syscall=%s(%u) latency_ms=%.3f return=%lld\n",
	       event->tgid, event->tid, event->comm,
	       syscall_name(event->syscall_id), event->syscall_id,
	       event->duration_ns / 1000000.0, event->return_value);
	return 0;
}

static int compare_stats(const void *left, const void *right)
{
	const struct syscall_stats *a = left;
	const struct syscall_stats *b = right;

	return a->total_ns < b->total_ns ? 1 : a->total_ns > b->total_ns ? -1 : 0;
}

static void print_summary(unsigned int top)
{
	size_t limit;

	qsort(stats, stats_count, sizeof(stats[0]), compare_stats);
	limit = stats_count < top ? stats_count : top;
	printf("\nSlow syscall index, ranked by total latency:\n");
	printf("%-7s %-16s %-18s %8s %12s %12s %8s\n",
	       "PID", "COMM", "SYSCALL", "COUNT", "TOTAL_MS", "MAX_MS", "ERRORS");
	for (size_t i = 0; i < limit; i++) {
		const struct syscall_stats *entry = &stats[i];

		printf("%-7u %-16s %-12s(%3u) %8llu %12.3f %12.3f %8llu\n",
		       entry->tgid, entry->comm, syscall_name(entry->syscall_id),
		       entry->syscall_id, entry->count,
		       entry->total_ns / 1000000.0,
		       entry->maximum_ns / 1000000.0, entry->errors);
	}
}

static int parse_uint(const char *text, unsigned int maximum,
		      unsigned int *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !*text || *end || parsed > maximum)
		return -1;
	*value = parsed;
	return 0;
}

static void usage(const char *program)
{
	printf("Usage: %s [--pid PID] [--min-ms MS] [--duration SEC] [--top N] [--demo]\n",
	       program);
}

static int parse_options(int argc, char **argv, struct options *options)
{
	static const struct option long_options[] = {
		{ "pid", required_argument, NULL, 'p' },
		{ "min-ms", required_argument, NULL, 'm' },
		{ "duration", required_argument, NULL, 'd' },
		{ "top", required_argument, NULL, 't' },
		{ "demo", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "p:m:d:t:Dh", long_options,
				     NULL)) != -1) {
		switch (option) {
		case 'p':
			if (parse_uint(optarg, 0xffffffffU, &options->pid))
				return -1;
			break;
		case 'm':
			if (parse_uint(optarg, 60000, &options->minimum_ms))
				return -1;
			break;
		case 'd':
			if (parse_uint(optarg, 86400, &options->duration_seconds))
				return -1;
			break;
		case 't':
			if (parse_uint(optarg, MAX_STATS, &options->top))
				return -1;
			break;
		case 'D': options->demo = true; break;
		case 'h': usage(argv[0]); exit(0);
		default: return -1;
		}
	}
	return optind == argc && options->minimum_ms && options->top ? 0 : -1;
}

static pid_t start_demo(int gate[2], int data_pipe[2])
{
	pid_t child = fork();
	char byte;

	if (child)
		return child;
	close(gate[1]);
	close(data_pipe[1]);
	if (read(gate[0], &byte, 1) != 1)
		_exit(2);
	if (read(data_pipe[0], &byte, 1) != 1)
		_exit(3);
	_exit(0);
}

int main(int argc, char **argv)
{
	struct options options = { .minimum_ms = 10, .top = 10 };
	struct slow_syscall_index_bpf *skel = NULL;
	struct ring_buffer *ring = NULL;
	unsigned long long deadline = 0;
	int gate[2] = { -1, -1 }, data_pipe[2] = { -1, -1 };
	pid_t demo_child = -1;
	int demo_status = 0;
	int err = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (parse_options(argc, argv, &options)) {
		usage(argv[0]);
		return 2;
	}
	if (options.demo) {
		if (options.pid) {
			fprintf(stderr, "--demo and --pid cannot be combined\n");
			return 2;
		}
		if (pipe(gate) || pipe(data_pipe)) {
			perror("pipe");
			goto cleanup;
		}
		demo_child = start_demo(gate, data_pipe);
		if (demo_child < 0) {
			perror("fork");
			goto cleanup;
		}
		options.pid = demo_child;
	}

	skel = slow_syscall_index_bpf__open();
	if (!skel)
		goto cleanup;
	skel->rodata->minimum_ns = (unsigned long long)options.minimum_ms * 1000000ULL;
	skel->rodata->target_tgid = options.pid;
	skel->rodata->ignored_tgid = getpid();
	if (slow_syscall_index_bpf__load(skel) ||
	    slow_syscall_index_bpf__attach(skel)) {
		fprintf(stderr, "failed to load and attach slow syscall tracer\n");
		goto cleanup;
	}
	ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
				NULL, NULL);
	if (!ring)
		goto cleanup;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	if (options.pid)
		printf("Tracing PID %u syscalls slower than %u ms. Press Ctrl-C to stop.\n",
		       options.pid, options.minimum_ms);
	else
		printf("Tracing all syscalls slower than %u ms. Press Ctrl-C to stop.\n",
		       options.minimum_ms);
	if (options.duration_seconds)
		deadline = monotonic_ns() +
			   (unsigned long long)options.duration_seconds * 1000000000ULL;

	if (options.demo) {
		char byte = 'x';
		struct timespec delay = {
			.tv_sec = options.minimum_ms / 1000,
			.tv_nsec = (long)(options.minimum_ms % 1000 + 20) * 1000000L,
		};

		if (delay.tv_nsec >= 1000000000L) {
			delay.tv_sec++;
			delay.tv_nsec -= 1000000000L;
		}
		close(gate[0]); gate[0] = -1;
		close(data_pipe[0]); data_pipe[0] = -1;
		write(gate[1], &byte, 1);
		nanosleep(&delay, NULL);
		write(data_pipe[1], &byte, 1);
		waitpid(demo_child, &demo_status, 0);
		demo_child = -1;
		for (int i = 0; i < 20 && !received_events; i++)
			ring_buffer__poll(ring, 50);
	} else {
		while (!stop && (!deadline || monotonic_ns() < deadline)) {
			int poll_result = ring_buffer__poll(ring, 100);

			if (poll_result < 0 && poll_result != -EINTR) {
				fprintf(stderr, "ring buffer poll failed: %d\n", poll_result);
				goto cleanup;
			}
		}
	}

	print_summary(options.top);
	printf("completed=%llu slow=%llu dropped=%llu unaggregated=%u\n",
	       (unsigned long long)skel->bss->completed_syscalls,
	       (unsigned long long)skel->bss->slow_syscalls,
	       (unsigned long long)skel->bss->dropped_events,
	       unaggregated_events);
	if (options.demo && (!WIFEXITED(demo_status) || WEXITSTATUS(demo_status) ||
			     !received_events))
		goto cleanup;
	err = 0;

cleanup:
	if (demo_child > 0) {
		kill(demo_child, SIGKILL);
		waitpid(demo_child, NULL, 0);
	}
	for (size_t i = 0; i < 2; i++) {
		if (gate[i] >= 0) close(gate[i]);
		if (data_pipe[i] >= 0) close(data_pipe[i]);
	}
	ring_buffer__free(ring);
	slow_syscall_index_bpf__destroy(skel);
	return err;
}
