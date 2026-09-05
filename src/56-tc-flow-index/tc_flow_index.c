// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "tc_flow_index.h"
#include "tc_flow_index.skel.h"

#define MAX_TOP 64

struct options {
	const char *interface;
	unsigned int duration_seconds;
	unsigned int top;
	bool demo;
};

static volatile sig_atomic_t stop;

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

static int parse_uint(const char *text, unsigned int maximum,
		      unsigned int *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !*text || *end || !parsed || parsed > maximum)
		return -1;
	*value = parsed;
	return 0;
}

static void usage(const char *program)
{
	printf("Usage: %s --interface IFACE [--duration SEC] [--top N]\n"
	       "       %s --demo [--top N]\n", program, program);
}

static int parse_options(int argc, char **argv, struct options *options)
{
	static const struct option long_options[] = {
		{ "interface", required_argument, NULL, 'i' },
		{ "duration", required_argument, NULL, 'd' },
		{ "top", required_argument, NULL, 't' },
		{ "demo", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "i:d:t:Dh", long_options,
				     NULL)) != -1) {
		switch (option) {
		case 'i': options->interface = optarg; break;
		case 'd':
			if (parse_uint(optarg, 86400, &options->duration_seconds))
				return -1;
			break;
		case 't':
			if (parse_uint(optarg, MAX_TOP, &options->top))
				return -1;
			break;
		case 'D': options->demo = true; break;
		case 'h': usage(argv[0]); exit(0);
		default: return -1;
		}
	}
	if (options->demo) {
		if (options->interface)
			return -1;
		options->interface = "lo";
	}
	return optind == argc && options->interface ? 0 : -1;
}

static int send_demo_flow(unsigned int datagrams, size_t payload_size)
{
	struct sockaddr_in receiver_address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in sender_address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t address_length = sizeof(receiver_address);
	char payload[1000] = {};
	int receiver = -1, sender = -1;
	int err = -1;

	if (payload_size > sizeof(payload))
		return -1;
	receiver = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	sender = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (receiver < 0 || sender < 0 ||
	    bind(receiver, (struct sockaddr *)&receiver_address,
		 sizeof(receiver_address)) ||
	    getsockname(receiver, (struct sockaddr *)&receiver_address,
			&address_length) ||
	    bind(sender, (struct sockaddr *)&sender_address,
		 sizeof(sender_address)))
		goto cleanup;
	for (unsigned int i = 0; i < datagrams; i++)
		if (sendto(sender, payload, payload_size, 0,
			   (struct sockaddr *)&receiver_address,
			   sizeof(receiver_address)) != (ssize_t)payload_size)
			goto cleanup;
	err = 0;

cleanup:
	if (receiver >= 0) close(receiver);
	if (sender >= 0) close(sender);
	return err;
}

static int run_demo_traffic(void)
{
	return send_demo_flow(2, 100) ||
	       send_demo_flow(4, 300) ||
	       send_demo_flow(6, 700);
}

static int snapshot_next(struct tc_flow_index_bpf *skel,
			 struct flow_snapshot *result)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	if (bpf_prog_test_run_opts(bpf_program__fd(skel->progs.snapshot_next),
				   &opts)) {
		fprintf(stderr, "failed to query BPF flow index: %s\n",
			strerror(errno));
		return -1;
	}
	*result = skel->bss->snapshot_result;
	if (result->found) {
		skel->bss->snapshot_cursor.bytes = result->bytes;
		skel->bss->snapshot_cursor.packets = result->packets;
		skel->bss->snapshot_cursor.key = result->key;
		skel->bss->snapshot_cursor.valid = 1;
	}
	return 0;
}

static int print_flows(struct tc_flow_index_bpf *skel, unsigned int top)
{
	struct flow_snapshot entry;

	memset(&skel->bss->snapshot_cursor, 0,
	       sizeof(skel->bss->snapshot_cursor));
	printf("\nTop egress flows, ranked in the BPF rbtree by bytes:\n");
	printf("%-21s %-21s %-5s %10s %12s %-16s\n",
	       "SOURCE", "DESTINATION", "PROTO", "PACKETS", "BYTES", "COMM");
	for (unsigned int i = 0; i < top; i++) {
		char source_ip[INET_ADDRSTRLEN], destination_ip[INET_ADDRSTRLEN];
		char source[64], destination[64];

		if (snapshot_next(skel, &entry))
			return -1;
		if (!entry.found)
			break;
		inet_ntop(AF_INET, &entry.key.source_ip, source_ip,
			  sizeof(source_ip));
		inet_ntop(AF_INET, &entry.key.destination_ip, destination_ip,
			  sizeof(destination_ip));
		snprintf(source, sizeof(source), "%s:%u", source_ip,
			 ntohs(entry.key.source_port));
		snprintf(destination, sizeof(destination), "%s:%u",
			 destination_ip, ntohs(entry.key.destination_port));
		printf("%-21s %-21s %-5s %10llu %12llu %-16s\n",
		       source, destination,
		       entry.key.protocol == IPPROTO_TCP ? "TCP" : "UDP",
		       entry.packets, entry.bytes, entry.comm);
	}
	return 0;
}

static int attach_tc_program(struct bpf_tc_hook *hook,
			     struct bpf_tc_opts *attach,
			     bool *hook_created, bool *attached)
{
	int err = bpf_tc_hook_create(hook);

	if (!err)
		*hook_created = true;
	else if (err != -EEXIST) {
		fprintf(stderr, "failed to create clsact hook: %s\n", strerror(-err));
		return -1;
	}
	err = bpf_tc_attach(hook, attach);
	if (err) {
		fprintf(stderr, "failed to attach TC program: %s\n", strerror(-err));
		return -1;
	}
	*attached = true;
	return 0;
}

static int capture_traffic(const struct options *options)
{
	unsigned long long deadline;

	if (options->demo)
		return run_demo_traffic();
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	deadline = monotonic_ns() +
		   (unsigned long long)options->duration_seconds * 1000000000ULL;
	while (!stop && monotonic_ns() < deadline) {
		struct timespec pause = { .tv_nsec = 100000000 };

		nanosleep(&pause, NULL);
	}
	return 0;
}

static int detach_tc_program(struct bpf_tc_hook *hook,
			     struct bpf_tc_opts *detach, bool *attached)
{
	int err = bpf_tc_detach(hook, detach);

	if (err) {
		fprintf(stderr, "failed to detach TC program: %s\n", strerror(-err));
		return -1;
	}
	*attached = false;
	return 0;
}

int main(int argc, char **argv)
{
	struct options options = { .duration_seconds = 10, .top = 10 };
	struct tc_flow_index_bpf *skel = NULL;
	LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, attach, .handle = 1, .priority = 1);
	LIBBPF_OPTS(bpf_tc_opts, detach, .handle = 1, .priority = 1);
	bool hook_created = false;
	bool attached = false;
	int err = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (parse_options(argc, argv, &options)) {
		usage(argv[0]);
		return 2;
	}
	hook.ifindex = if_nametoindex(options.interface);
	if (!hook.ifindex) {
		fprintf(stderr, "interface does not exist: %s\n", options.interface);
		return 2;
	}

	skel = tc_flow_index_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to load TC flow index\n");
		goto cleanup;
	}
	attach.prog_fd = bpf_program__fd(skel->progs.index_egress_flow);
	if (attach_tc_program(&hook, &attach, &hook_created, &attached))
		goto cleanup;
	printf("Indexing IPv4 TCP/UDP egress flows on %s for %u seconds.\n",
	       options.interface, options.demo ? 0 : options.duration_seconds);

	if (capture_traffic(&options)) {
		fprintf(stderr, "failed to generate traffic\n");
		goto cleanup;
	}

	if (detach_tc_program(&hook, &detach, &attached))
		goto cleanup;
	if (print_flows(skel, options.top))
		goto cleanup;
	printf("observed_packets=%llu indexed_flows=%llu dropped_new=%llu "
	       "allocation_failures=%llu refcount_failures=%llu rank_update_failures=%llu\n",
	       (unsigned long long)skel->bss->observed_packets,
	       (unsigned long long)skel->bss->indexed_flows,
	       (unsigned long long)skel->bss->dropped_new_flows,
	       (unsigned long long)skel->bss->allocation_failures,
	       (unsigned long long)skel->bss->refcount_failures,
	       (unsigned long long)skel->bss->rank_update_failures);
	if (options.demo &&
	    (skel->bss->indexed_flows != 3 || skel->bss->rank_update_failures))
		goto cleanup;
	err = 0;

cleanup:
	if (attached)
		bpf_tc_detach(&hook, &detach);
	if (hook_created)
		bpf_tc_hook_destroy(&hook);
	tc_flow_index_bpf__destroy(skel);
	return err;
}
