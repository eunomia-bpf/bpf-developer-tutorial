// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "tcp_quarantine.h"
#include "tcp_quarantine.skel.h"

static struct env {
	const char *remote_argument;
	const char *local_argument;
	bool apply;
	bool verbose;
} env;

struct endpoint {
	struct in_addr address;
	unsigned int port;
	char text[INET_ADDRSTRLEN + 7];
};

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
		"Usage: %s [--apply LOCAL_IPV4:PORT] REMOTE_IPV4:PORT [--verbose]\n"
		"\n"
		"List established TCP clients to REMOTE_IPV4:PORT.\n"
		"The default is a dry run. Copy one listed local endpoint into\n"
		"--apply to destroy only that exact IPv4 4-tuple.\n"
		"\n"
		"Options:\n"
		"  -a, --apply IPv4:PORT   local endpoint selected from dry-run output\n"
		"  -v, --verbose           print libbpf diagnostics\n"
		"  -h, --help              show this help\n",
		program);
}

static int parse_port(const char *value, unsigned int *port)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(value, &end, 10);
	if (errno || !end || *end || parsed == 0 || parsed > 65535)
		return -EINVAL;
	*port = parsed;
	return 0;
}

static int parse_endpoint(const char *value, struct endpoint *endpoint)
{
	char address[INET_ADDRSTRLEN];
	const char *separator = strrchr(value, ':');
	size_t address_length;

	if (!separator || separator == value)
		return -EINVAL;
	address_length = separator - value;
	if (address_length >= sizeof(address))
		return -EINVAL;
	memcpy(address, value, address_length);
	address[address_length] = '\0';
	if (inet_pton(AF_INET, address, &endpoint->address) != 1 ||
	    parse_port(separator + 1, &endpoint->port))
		return -EINVAL;
	snprintf(endpoint->text, sizeof(endpoint->text), "%s:%u",
		 address, endpoint->port);
	return 0;
}

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "apply", required_argument, NULL, 'a' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "a:vh", options, NULL)) != -1) {
		switch (option) {
		case 'a':
			env.apply = true;
			env.local_argument = optarg;
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

	if (argc - optind != 1)
		return -EINVAL;
	env.remote_argument = argv[optind];
	return 0;
}

static int run_iterator(struct bpf_program *program)
{
	struct bpf_link *link;
	char buffer[4096];
	int iter_fd, length, err;

	link = bpf_program__attach_iter(program, NULL);
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "failed to attach TCP iterator: %s\n", strerror(-err));
		return err;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		err = iter_fd;
		fprintf(stderr, "failed to create TCP iterator: %s\n", strerror(-err));
		goto cleanup;
	}

	while ((length = read(iter_fd, buffer, sizeof(buffer))) > 0) {
		if (fwrite(buffer, 1, length, stdout) != (size_t)length) {
			err = -EIO;
			fprintf(stderr, "failed to print iterator output\n");
			break;
		}
	}
	if (length < 0) {
		err = -errno;
		fprintf(stderr, "failed while scanning TCP sockets: %s\n", strerror(errno));
	}
	close(iter_fd);

cleanup:
	bpf_link__destroy(link);
	return err;
}

int main(int argc, char **argv)
{
	struct tcp_quarantine_bpf *skel = NULL;
	struct endpoint remote = {};
	struct endpoint local = {};
	int err;

	err = parse_args(argc, argv);
	if (err) {
		usage(argv[0]);
		return 1;
	}
	if (parse_endpoint(env.remote_argument, &remote)) {
		fprintf(stderr, "invalid remote IPv4 endpoint: %s\n",
			env.remote_argument);
		return 1;
	}
	if (env.apply && parse_endpoint(env.local_argument, &local)) {
		fprintf(stderr, "invalid local IPv4 endpoint: %s\n",
			env.local_argument);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	skel = tcp_quarantine_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->target_addr = remote.address.s_addr;
	skel->rodata->target_port = remote.port;
	skel->rodata->target_local_addr = local.address.s_addr;
	skel->rodata->target_local_port = local.port;
	skel->rodata->apply = env.apply;

	err = tcp_quarantine_bpf__load(skel);
	if (err) {
		fprintf(stderr,
			"failed to load TCP quarantine program: %s\n"
			"This tool requires Linux 6.5+ with BTF, TCP BPF iterators, "
			"BPF JIT, and the bpf_sock_destroy kfunc.\n",
			strerror(-err));
		goto cleanup;
	}

	err = run_iterator(skel->progs.quarantine_tcp);
	if (err)
		goto cleanup;

	printf("SUMMARY mode=%s remote=%s%s%s scanned=%llu established=%llu "
	       "matched=%llu destroyed=%llu failed=%llu\n",
	       env.apply ? "apply" : "dry-run", remote.text,
	       env.apply ? " local=" : "", env.apply ? local.text : "",
	       skel->bss->stats.scanned, skel->bss->stats.established,
	       skel->bss->stats.matched, skel->bss->stats.destroyed,
	       skel->bss->stats.failed);
	if (skel->bss->stats.failed)
		err = -EIO;

cleanup:
	tcp_quarantine_bpf__destroy(skel);
	return err != 0;
}
