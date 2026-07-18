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
	const char *destination;
	unsigned int port;
	bool apply;
	bool verbose;
} env;

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
		"Usage: %s --destination IPv4 --port PORT [--apply] [--verbose]\n"
		"\n"
		"Find established TCP client connections to an exact destination.\n"
		"The default is a safe dry run; --apply destroys matching sockets.\n"
		"\n"
		"Options:\n"
		"  -d, --destination IPv4  exact remote IPv4 address\n"
		"  -p, --port PORT         exact remote TCP port (1-65535)\n"
		"  -a, --apply             destroy matching sockets\n"
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

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "destination", required_argument, NULL, 'd' },
		{ "port", required_argument, NULL, 'p' },
		{ "apply", no_argument, NULL, 'a' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "d:p:avh", options, NULL)) != -1) {
		switch (option) {
		case 'd':
			env.destination = optarg;
			break;
		case 'p':
			if (parse_port(optarg, &env.port)) {
				fprintf(stderr, "invalid TCP port: %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'a':
			env.apply = true;
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

	if (!env.destination || !env.port || optind != argc)
		return -EINVAL;
	return 0;
}

static int run_iterator(struct bpf_program *program)
{
	struct bpf_link *link;
	char buffer[256];
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

	while ((length = read(iter_fd, buffer, sizeof(buffer))) > 0)
		;
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
	struct in_addr destination;
	int err;

	err = parse_args(argc, argv);
	if (err) {
		usage(argv[0]);
		return 1;
	}
	if (inet_pton(AF_INET, env.destination, &destination) != 1) {
		fprintf(stderr, "invalid IPv4 destination: %s\n", env.destination);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	skel = tcp_quarantine_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->target_addr = destination.s_addr;
	skel->rodata->target_port = env.port;
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

	printf("mode=%s destination=%s:%u scanned=%llu established=%llu "
	       "matched=%llu destroyed=%llu failed=%llu\n",
	       env.apply ? "apply" : "dry-run", env.destination, env.port,
	       skel->bss->stats.scanned, skel->bss->stats.established,
	       skel->bss->stats.matched, skel->bss->stats.destroyed,
	       skel->bss->stats.failed);
	if (skel->bss->stats.failed)
		err = -EIO;

cleanup:
	tcp_quarantine_bpf__destroy(skel);
	return err != 0;
}
