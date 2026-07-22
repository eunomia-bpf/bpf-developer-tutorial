// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <getopt.h>
#include <linux/pkt_sched.h>
#include <net/if.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "egress_pacer.h"
#include "egress_pacer.skel.h"

extern char **environ;

static volatile sig_atomic_t exiting;

static struct env {
	const char *interface;
	unsigned long long rate_kbps;
	unsigned int queue_limit;
	unsigned int duration;
	bool verbose;
} env = {
	.rate_kbps = 1024,
	.queue_limit = 256,
	.duration = 10,
};

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
		"Usage: %s --interface IFACE [--rate-kbps KBPS] "
		"[--queue-limit PACKETS] [--duration SEC] [--verbose]\n\n"
		"Temporarily pace one interface with a bounded BPF qdisc.\n\n"
		"Options:\n"
		"  -i, --interface IFACE       interface to control (required)\n"
		"  -r, --rate-kbps KBPS       egress rate, 8-100000000 "
		"(default: 1024)\n"
		"  -q, --queue-limit PACKETS  queue capacity, 1-65535 "
		"(default: 256)\n"
		"  -d, --duration SEC         control window, 1-86400 "
		"(default: 10)\n"
		"  -v, --verbose              print libbpf diagnostics\n"
		"  -h, --help                 show this help\n",
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

static int parse_rate(const char *value)
{
	unsigned long long parsed;

	if (parse_u64(value, 100000000, &parsed) || parsed < 8) {
		fprintf(stderr, "invalid rate in Kbit/s: %s\n", value);
		return -EINVAL;
	}
	env.rate_kbps = parsed;
	return 0;
}

static int parse_queue_limit(const char *value)
{
	unsigned long long parsed;

	if (parse_u64(value, 65535, &parsed) || parsed == 0) {
		fprintf(stderr, "invalid queue limit: %s\n", value);
		return -EINVAL;
	}
	env.queue_limit = parsed;
	return 0;
}

static int parse_duration(const char *value)
{
	unsigned long long parsed;

	if (parse_u64(value, 86400, &parsed) || parsed == 0) {
		fprintf(stderr, "invalid duration in seconds: %s\n", value);
		return -EINVAL;
	}
	env.duration = parsed;
	return 0;
}

static int parse_option(int option, const char *program)
{
	switch (option) {
	case 'i':
		env.interface = optarg;
		return 0;
	case 'r':
		return parse_rate(optarg);
	case 'q':
		return parse_queue_limit(optarg);
	case 'd':
		return parse_duration(optarg);
	case 'v':
		env.verbose = true;
		return 0;
	case 'h':
		usage(program);
		exit(0);
	default:
		return -EINVAL;
	}
}

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "interface", required_argument, NULL, 'i' },
		{ "rate-kbps", required_argument, NULL, 'r' },
		{ "queue-limit", required_argument, NULL, 'q' },
		{ "duration", required_argument, NULL, 'd' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int error, option;

	while ((option = getopt_long(argc, argv, "i:r:q:d:vh", options, NULL)) != -1) {
		error = parse_option(option, argv[0]);
		if (error)
			return error;
	}

	if (!env.interface) {
		fprintf(stderr, "--interface is required\n");
		return -EINVAL;
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

static int wait_for_duration(void)
{
	struct timespec interval = { .tv_nsec = 100000000 };
	long long deadline, now;

	now = monotonic_milliseconds();
	if (now < 0)
		return (int)now;
	deadline = now + env.duration * 1000LL;

	while (!exiting) {
		now = monotonic_milliseconds();
		if (now < 0)
			return (int)now;
		if (now >= deadline)
			break;
		if (nanosleep(&interval, NULL) && errno != EINTR)
			return -errno;
	}

	return 0;
}

static const char *find_tc_binary(void)
{
	static const char *const candidates[] = {
		"/usr/sbin/tc",
		"/sbin/tc",
	};
	size_t index;

	for (index = 0; index < sizeof(candidates) / sizeof(candidates[0]); index++) {
		if (!access(candidates[index], X_OK))
			return candidates[index];
	}
	return NULL;
}

static void print_qdisc_state(bool all_interfaces)
{
	const char *tc_binary = find_tc_binary();
	char *const all_arguments[] = {
		(char *)"tc", (char *)"qdisc", (char *)"show", NULL,
	};
	char *const interface_arguments[] = {
		(char *)"tc", (char *)"qdisc", (char *)"show", (char *)"dev",
		(char *)env.interface, NULL,
	};
	char *const *arguments = all_interfaces ? all_arguments : interface_arguments;
	posix_spawn_file_actions_t actions;
	pid_t child;
	pid_t waited;
	int error;
	int status;

	fprintf(stderr, "%s:\n",
		all_interfaces ? "qdisc state across interfaces" : "current qdisc state");
	if (!tc_binary) {
		fprintf(stderr, "tc was not found in /usr/sbin or /sbin\n");
		goto manual;
	}

	error = posix_spawn_file_actions_init(&actions);
	if (error)
		goto spawn_failed;
	error = posix_spawn_file_actions_adddup2(&actions, STDERR_FILENO,
						  STDOUT_FILENO);
	if (!error)
		error = posix_spawn(&child, tc_binary, &actions, NULL, arguments,
				    environ);
	posix_spawn_file_actions_destroy(&actions);
	if (error)
		goto spawn_failed;

	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited >= 0 && WIFEXITED(status) && !WEXITSTATUS(status))
		return;
	if (waited < 0)
		error = errno;
	else
		error = EIO;

spawn_failed:
	fprintf(stderr, "failed to run tc: %s\n", strerror(error));
manual:
	if (all_interfaces)
		fprintf(stderr, "run manually: tc qdisc show\n");
	else
		fprintf(stderr, "run manually: tc qdisc show dev %s\n",
			env.interface);
}

static int install_pacer(struct egress_pacer_bpf *skel,
			 struct bpf_tc_hook *hook)
{
	int error;

	error = egress_pacer_bpf__attach(skel);
	if (error) {
		if (error == -EEXIST) {
			fprintf(stderr,
				"bpf_pacer is already registered globally; another interface may own it\n");
			print_qdisc_state(true);
			fprintf(stderr,
				"inspect the bpf_pacer owner above before removing any root qdisc\n");
		} else {
			fprintf(stderr, "failed to register bpf_pacer qdisc: %s\n",
				strerror(-error));
		}
		return error;
	}

	error = bpf_tc_hook_create(hook);
	if (!error)
		return 0;
	if (error == -EEXIST) {
		fprintf(stderr, "refusing to replace the existing root qdisc on %s\n",
			env.interface);
		print_qdisc_state(false);
		fprintf(stderr,
			"if it is stale, recover with: sudo tc qdisc del dev %s root\n",
			env.interface);
	} else {
		fprintf(stderr, "failed to attach bpf_pacer to %s: %s\n",
			env.interface, strerror(-error));
	}
	return error;
}

static int cleanup_pacer(struct egress_pacer_bpf *skel,
			 struct bpf_tc_hook *hook, bool qdisc_created, int error)
{
	struct pacer_stats final_stats = {};
	int cleanup_error;

	if (qdisc_created) {
		cleanup_error = bpf_tc_hook_destroy(hook);
		if (cleanup_error) {
			fprintf(stderr, "failed to remove bpf_pacer from %s: %s\n",
				env.interface, strerror(-cleanup_error));
			if (!error)
				error = cleanup_error;
		}
	}
	if (skel && skel->bss)
		final_stats = skel->bss->stats;
	if (qdisc_created) {
		printf("SUMMARY enqueued=%llu dequeued=%llu policy_dropped=%llu "
		       "cleanup_dropped=%llu bytes_dequeued=%llu max_qlen=%llu\n",
		       final_stats.enqueued, final_stats.dequeued,
		       final_stats.policy_dropped, final_stats.cleanup_dropped,
		       final_stats.bytes_dequeued, final_stats.max_qlen);
	}
	egress_pacer_bpf__destroy(skel);
	return error != 0;
}

int main(int argc, char **argv)
{
	struct egress_pacer_bpf *skel = NULL;
	struct bpf_tc_hook hook = {
		.sz = sizeof(hook),
		.attach_point = BPF_TC_QDISC,
		.parent = TC_H_ROOT,
		.handle = TC_H_MAKE(1 << 16, 0),
		.qdisc = "bpf_pacer",
	};
	bool qdisc_created = false;
	unsigned int ifindex;
	int err;

	err = parse_args(argc, argv);
	if (err) {
		usage(argv[0]);
		return 1;
	}

	ifindex = if_nametoindex(env.interface);
	if (!ifindex) {
		fprintf(stderr, "interface does not exist: %s\n", env.interface);
		return 1;
	}
	hook.ifindex = ifindex;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	skel = egress_pacer_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}
	skel->rodata->rate_kbps = env.rate_kbps;
	skel->rodata->queue_limit = env.queue_limit;

	err = egress_pacer_bpf__load(skel);
	if (err) {
		fprintf(stderr,
			"failed to load BPF qdisc: %s\n"
			"This tool requires Linux 6.16+, CONFIG_NET_SCH_BPF, "
			"BTF, and BPF JIT.\n",
			strerror(-err));
		goto cleanup;
	}

	err = install_pacer(skel, &hook);
	if (err)
		goto cleanup;
	qdisc_created = true;

	printf("READY interface=%s rate_kbps=%llu queue_limit=%u duration=%u\n",
	       env.interface, env.rate_kbps, env.queue_limit, env.duration);
	fflush(stdout);

	err = wait_for_duration();

cleanup:
	return cleanup_pacer(skel, &hook, qdisc_created, err);
}
