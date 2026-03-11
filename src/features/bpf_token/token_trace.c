// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "token_trace.skel.h"

struct token_stats {
	__u64 packets;
	__u32 last_ifindex;
};

static struct env {
	const char *token_path;
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
		"Usage: %s [-t TOKEN_BPFFS] [-i IFACE] [-v] [-n]\n"
		"  -t TOKEN_BPFFS  delegated bpffs mount used to derive a BPF token\n"
		"  -i IFACE        interface to attach XDP program to (default: lo)\n"
		"  -v              enable libbpf debug logs\n"
		"  -n              do not generate loopback traffic automatically\n",
		prog);
}

static int parse_args(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "t:i:vn")) != -1) {
		switch (opt) {
		case 't':
			env.token_path = optarg;
			break;
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
	const char payload[] = "bpf token xdp demo";
	int fd, err = 0;

	if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1)
		return -EINVAL;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	if (sendto(fd, payload, sizeof(payload), 0,
		   (struct sockaddr *)&addr, sizeof(addr)) < 0)
		err = -errno;

	close(fd);
	return err;
}

int main(int argc, char **argv)
{
	struct token_trace_bpf *skel = NULL;
	struct bpf_object_open_opts open_opts = {};
	struct token_stats before = {}, after = {};
	struct bpf_link *link = NULL;
	__u32 key = 0;
	int ifindex, map_fd;
	int err = 0;

	err = parse_args(argc, argv);
	if (err) {
		usage(argv[0]);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	libbpf_set_memlock_rlim(0);

	ifindex = if_nametoindex(env.ifname);
	if (!ifindex) {
		fprintf(stderr, "unknown interface '%s'\n", env.ifname);
		return 1;
	}

	open_opts.sz = sizeof(open_opts);
	open_opts.bpf_token_path = env.token_path;

	skel = token_trace_bpf__open_opts(&open_opts);
	if (!skel) {
		fprintf(stderr, "failed to open token_trace skeleton\n");
		return 1;
	}

	err = token_trace_bpf__load(skel);
	if (err) {
		fprintf(stderr,
			"failed to load BPF program: %s\n"
			"hint: if you intended to use a delegated token, pass -t <bpffs-path>\n",
			strerror(-err));
		goto cleanup;
	}

	link = bpf_program__attach_xdp(skel->progs.handle_packet, ifindex);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		fprintf(stderr, "failed to attach XDP program: %s\n", strerror(-err));
		goto cleanup;
	}

	map_fd = bpf_map__fd(skel->maps.stats_map);
	err = bpf_map_lookup_elem(map_fd, &key, &before);
	if (err) {
		err = -errno;
		fprintf(stderr, "failed to read stats before traffic: %s\n",
			strerror(errno));
		goto cleanup;
	}

	if (!env.no_trigger && strcmp(env.ifname, "lo") == 0) {
		err = generate_loopback_traffic();
		if (err) {
			fprintf(stderr, "failed to generate loopback traffic: %s\n",
				strerror(-err));
			goto cleanup;
		}
		usleep(100000);
	} else if (!env.no_trigger) {
		printf("Generate traffic on %s and re-run with -n if you only want attach/query.\n",
		       env.ifname);
	}

	err = bpf_map_lookup_elem(map_fd, &key, &after);
	if (err) {
		err = -errno;
		fprintf(stderr, "failed to read stats after traffic: %s\n",
			strerror(errno));
		goto cleanup;
	}

	printf("token path     : %s\n",
	       env.token_path ? env.token_path :
	       "(none, libbpf may use LIBBPF_BPF_TOKEN_PATH or /sys/fs/bpf)");
	printf("interface      : %s (ifindex=%d)\n", env.ifname, ifindex);
	printf("packets before : %llu\n", (unsigned long long)before.packets);
	printf("packets after  : %llu\n", (unsigned long long)after.packets);
	printf("delta          : %llu\n",
	       (unsigned long long)(after.packets - before.packets));
	printf("last ifindex   : %u\n", after.last_ifindex);

cleanup:
	bpf_link__destroy(link);
	token_trace_bpf__destroy(skel);
	return err != 0;
}
