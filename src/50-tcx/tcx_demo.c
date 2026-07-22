// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "tcx_demo.skel.h"

static struct env {
	const char *ifname;
	unsigned int duration;
	bool verbose;
} env = {
	.ifname = "lo",
};

static volatile sig_atomic_t exiting;

static void handle_signal(int signal)
{
	(void)signal;
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--interface IFACE] [--duration SEC] [--verbose]\n\n"
		"Monitor a TCX ingress chain until Ctrl-C.\n\n"
		"Options:\n"
		"  -i, --interface IFACE  interface to monitor (default: lo)\n"
		"  -d, --duration SEC     stop after SEC; 0 waits for a signal (default: 0)\n"
		"  -v, --verbose          enable libbpf debug logs\n"
		"  -h, --help             show this help\n",
		prog);
}

static int parse_duration(const char *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(value, &end, 10);
	if (errno || end == value || *end || parsed > 86400) {
		fprintf(stderr, "invalid duration in seconds: %s\n", value);
		return -EINVAL;
	}
	env.duration = parsed;
	return 0;
}

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "interface", required_argument, NULL, 'i' },
		{ "duration", required_argument, NULL, 'd' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int opt;

	while ((opt = getopt_long(argc, argv, "i:d:vh", options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			env.ifname = optarg;
			break;
		case 'd':
			if (parse_duration(optarg))
				return -EINVAL;
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

	return optind == argc ? 0 : -EINVAL;
}

static void print_tcx_chain(int ifindex)
{
	LIBBPF_OPTS(bpf_prog_query_opts, query);
	__u32 prog_ids[8] = {};
	__u32 link_ids[8] = {};
	int err;
	__u32 i;

	query.count = 8;
	query.prog_ids = prog_ids;
	query.link_ids = link_ids;

	err = bpf_prog_query_opts(ifindex, BPF_TCX_INGRESS, &query);
	if (err) {
		fprintf(stderr, "bpf_prog_query_opts failed: %s\n", strerror(errno));
		return;
	}

	printf("TCX ingress chain revision: %llu\n",
	       (unsigned long long)query.revision);
	for (i = 0; i < query.count; i++) {
		printf("  slot %u: prog_id=%u link_id=%u\n",
		       i, prog_ids[i], link_ids[i]);
	}
}

static long long monotonic_milliseconds(void)
{
	struct timespec timestamp;

	if (clock_gettime(CLOCK_MONOTONIC, &timestamp))
		return -errno;
	return timestamp.tv_sec * 1000LL + timestamp.tv_nsec / 1000000;
}

static int wait_until_done(void)
{
	struct timespec interval = { .tv_nsec = 100000000 };
	long long deadline = 0;
	long long now;

	if (env.duration) {
		now = monotonic_milliseconds();
		if (now < 0)
			return (int)now;
		deadline = now + env.duration * 1000LL;
	}

	while (!exiting) {
		if (deadline) {
			now = monotonic_milliseconds();
			if (now < 0)
				return (int)now;
			if (now >= deadline)
				break;
		}
		if (nanosleep(&interval, NULL) && errno != EINTR)
			return -errno;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct tcx_demo_bpf *skel = NULL;
	struct bpf_link *classifier_link = NULL, *stats_link = NULL;
	int ifindex, err;

	err = parse_args(argc, argv);
	if (err) {
		usage(argv[0]);
		return 1;
	}

	ifindex = if_nametoindex(env.ifname);
	if (!ifindex) {
		fprintf(stderr, "unknown interface '%s'\n", env.ifname);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	skel = tcx_demo_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open and load tcx skeleton\n");
		return 1;
	}

	classifier_link = bpf_program__attach_tcx(skel->progs.tcx_classifier,
						 ifindex, NULL);
	err = libbpf_get_error(classifier_link);
	if (err) {
		fprintf(stderr, "failed to attach tcx_classifier: %s\n",
			strerror(-err));
		classifier_link = NULL;
		goto cleanup;
	}

	{
		LIBBPF_OPTS(bpf_tcx_opts, before_opts,
			.flags = BPF_F_BEFORE,
			.relative_fd = bpf_program__fd(skel->progs.tcx_classifier));

		stats_link = bpf_program__attach_tcx(skel->progs.tcx_stats,
						    ifindex, &before_opts);
		err = libbpf_get_error(stats_link);
		if (err) {
			fprintf(stderr, "failed to attach tcx_stats: %s\n",
				strerror(-err));
			stats_link = NULL;
			goto cleanup;
		}
	}

	printf("READY interface=%s ifindex=%d duration=%s\n", env.ifname, ifindex,
	       env.duration ? "limited" : "until-signal");
	fflush(stdout);
	print_tcx_chain(ifindex);

	err = wait_until_done();
	bpf_link__destroy(stats_link);
	stats_link = NULL;
	bpf_link__destroy(classifier_link);
	classifier_link = NULL;

	printf("COUNTERS stats_hits=%llu classifier_hits=%llu last_ifindex=%u "
	       "last_protocol=0x%04x last_len=%u\n",
	       (unsigned long long)skel->bss->stats_hits,
	       (unsigned long long)skel->bss->classifier_hits,
	       skel->bss->last_ifindex, skel->bss->last_protocol,
	       skel->bss->last_len);

cleanup:
	bpf_link__destroy(stats_link);
	bpf_link__destroy(classifier_link);
	tcx_demo_bpf__destroy(skel);
	return err != 0;
}
