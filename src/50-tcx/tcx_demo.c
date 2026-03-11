// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "tcx_demo.skel.h"

static struct env {
	const char *ifname;
	bool verbose;
	bool no_trigger;
} env = {
	.ifname = "lo",
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-i IFACE] [-v] [-n]\n"
		"  -i IFACE  attach TCX programs to interface (default: lo)\n"
		"  -v        enable libbpf debug logs\n"
		"  -n        do not generate loopback traffic automatically\n",
		prog);
}

static int parse_args(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "i:vn")) != -1) {
		switch (opt) {
		case 'i':
			env.ifname = optarg;
			break;
		case 'v':
			env.verbose = true;
			break;
		case 'n':
			env.no_trigger = true;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int generate_loopback_traffic(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(9),
	};
	const char payload[] = "tcx tutorial packet";
	int fd, err = 0;

	if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1)
		return -EINVAL;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	if (sendto(fd, payload, sizeof(payload), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		err = -errno;

	close(fd);
	return err;
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

	printf("Attached TCX programs to %s (ifindex=%d)\n", env.ifname, ifindex);
	print_tcx_chain(ifindex);

	if (!env.no_trigger && strcmp(env.ifname, "lo") == 0) {
		err = generate_loopback_traffic();
		if (err)
			fprintf(stderr, "failed to generate loopback traffic: %s\n",
				strerror(-err));
		usleep(200000);
	} else if (!env.no_trigger) {
		printf("Generate traffic on %s and re-run with -n if you only want attach/query.\n",
		       env.ifname);
	}

	printf("\nCounters:\n");
	printf("  tcx_stats hits      : %llu\n",
	       (unsigned long long)skel->bss->stats_hits);
	printf("  tcx_classifier hits : %llu\n",
	       (unsigned long long)skel->bss->classifier_hits);
	printf("  last ifindex        : %u\n", skel->bss->last_ifindex);
	printf("  last protocol       : 0x%04x\n", skel->bss->last_protocol);
	printf("  last length         : %u\n", skel->bss->last_len);

cleanup:
	bpf_link__destroy(stats_link);
	bpf_link__destroy(classifier_link);
	tcx_demo_bpf__destroy(skel);
	return err != 0;
}
