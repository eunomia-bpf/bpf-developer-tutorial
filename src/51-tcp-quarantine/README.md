# eBPF Tutorial by Example: Targeted TCP Connection Quarantine

Suppose an egress destination has just been added to a policy or threat-intelligence blocklist. A firewall blocks future connects, but `netstat` shows the server already has an active TCP session to that address. You want to preview and close that exact established session while preserving the process and unrelated connections.

This tutorial builds `tcp_quarantine`, a one-shot CLI that matches an exact IPv4 destination address and port, finds all `ESTABLISHED` TCP connections matching that tuple, and counts or destroys them. The default mode is dry-run, which reports matches. The `--apply` flag directs the BPF program to call the kernel's `bpf_sock_destroy` kfunc on each match. The TCP BPF iterator's scan scope is the network namespace of the loading process.

> Complete source: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/51-tcp-quarantine>

## End-to-End Flow

The tool uses a BPF TCP iterator to walk the kernel's TCP socket table. User space first validates the IPv4 address with `inet_pton` and parses the port number, then writes both parameters into the skeleton's read-only data section `.rodata` before loading the BPF program. The `destination.s_addr` stored by `inet_pton` is already in network byte order; the host-order port and apply boolean are written alongside it.

The BPF program attaches as a TCP iterator via `SEC("iter/tcp")`. When user space reads the iterator file descriptor, the kernel invokes the callback once per TCP socket in the loading process's network namespace. The callback first increments `scanned` for each non-null `sk`, then selects `AF_INET` plus `TCP_ESTABLISHED` sockets into `established`. It reads `skc_daddr`, `skc_dport`, `skc_family`, and `skc_state` through `BPF_CORE_READ`, and CO-RE relocations allow the same compiled object to run on kernels with different layouts. Destination-address comparison uses the network-order value from `inet_pton`. Port comparison uses `bpf_htons(target_port)` because `skc_dport` is stored in network byte order.

Exact matches increment `matched`; dry-run mode returns after counting. Apply mode calls `bpf_sock_destroy(sk)`, incrementing `destroyed` on zero return or `failed` on nonzero. `bpf_sock_destroy` is declared as a strong `__ksym`, and the kernel resolves this required kfunc at load time.

The shared `quarantine_stats` object lives in BSS as the result channel. The loader attaches the program with `bpf_program__attach_iter`, creates an iterator fd with `bpf_iter_create`, and reads that fd to EOF to drive traversal; the read buffer serves only to drive traversal, while counters pass through BSS. User space reads the five counters after consuming the iterator. The loader destroys the iterator link and skeleton on cleanup. It returns nonzero when loading or iteration fails, or when any `bpf_sock_destroy` call increments `failed`. The `--verbose` option enables libbpf debug messages.

## The Shared Header

Both the BPF program and user-space loader include this header to ensure the BSS layout of `quarantine_stats` stays consistent.

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCP_QUARANTINE_H
#define __TCP_QUARANTINE_H

struct quarantine_stats {
	unsigned long long scanned;
	unsigned long long established;
	unsigned long long matched;
	unsigned long long destroyed;
	unsigned long long failed;
};

#endif /* __TCP_QUARANTINE_H */
```

The five counters record: total sockets scanned, IPv4 sockets in `ESTABLISHED` state, exact destination-and-port matches, sockets successfully destroyed in apply mode, and `bpf_sock_destroy` calls that returned nonzero. User space reads these counters after iteration completes and prints a single summary line.

## The BPF Program

The complete BPF program source follows.

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "tcp_quarantine.h"

#define AF_INET 2
#define TCP_ESTABLISHED 1

char LICENSE[] SEC("license") = "GPL";

const volatile __u32 target_addr;
const volatile __u16 target_port;
const volatile bool apply;

struct quarantine_stats stats;

extern int bpf_sock_destroy(struct sock_common *sock) __ksym;

SEC("iter/tcp")
int quarantine_tcp(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk = ctx->sk_common;
	__u32 dst_addr;
	__u16 dst_port;
	__u16 family;
	__u8 state;
	int err;

	if (!sk)
		return 0;

	stats.scanned++;
	family = BPF_CORE_READ(sk, skc_family);
	state = BPF_CORE_READ(sk, skc_state);
	if (family != AF_INET || state != TCP_ESTABLISHED)
		return 0;

	stats.established++;
	dst_addr = BPF_CORE_READ(sk, skc_daddr);
	dst_port = BPF_CORE_READ(sk, skc_dport);
	if (dst_addr != target_addr || dst_port != bpf_htons(target_port))
		return 0;

	stats.matched++;
	if (!apply)
		return 0;

	err = bpf_sock_destroy(sk);
	if (err)
		stats.failed++;
	else
		stats.destroyed++;

	return 0;
}
```

The program declares itself as a TCP iterator with `SEC("iter/tcp")`. The iterator context `bpf_iter__tcp` is provided by the kernel, with `sk_common` pointing to successive TCP sockets as the table is traversed. The three `const volatile` variables live in `.rodata`, passing the small fixed configuration directly through read-only global data; user space writes the target address, port, and apply flag after `open()` but before `load()`, and the verifier treats them as compile-time constants.

`bpf_sock_destroy` is declared via `extern ... __ksym` as a strong kfunc symbol. Strong-symbol resolution makes Linux 6.5+ kfunc availability a load-time prerequisite and completes relocation before traversal begins. Load diagnostics report errno plus the prerequisite set. The `BPF_CORE_READ` macro uses BTF to read `sock_common` fields, and CO-RE relocations ensure the same compiled object runs across kernel versions with differing layouts. Port comparison uses `bpf_htons(target_port)` because `skc_dport` is stored in network byte order.

## The User-Space Loader

The complete user-space loader source follows.

```c
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
```

The loader's `main` entry parses command-line arguments. The port must be a decimal number from 1 to 65535, and the address is validated and converted to network byte order with `inet_pton`. After opening the skeleton, the three parameters are written to `.rodata`, and `load` completes BPF program loading. Load diagnostics include the kernel errno plus the prerequisite set: Linux 6.5+, BTF, TCP iterators, JIT, and the kfunc.

The `run_iterator` function attaches the BPF program with `bpf_program__attach_iter` and creates an iterator fd with `bpf_iter_create`. The loop reads that fd until EOF; each `read` drives the kernel to invoke the BPF callback for a batch of TCP sockets. The read buffer serves only to drive traversal, while counters pass through BSS. After iteration, the loader reads `skel->bss->stats` and prints a single summary line. If any `bpf_sock_destroy` call failed, the program exits nonzero.

## Compilation and Execution

Build the tool:

```bash
cd src/51-tcp-quarantine
make clean
make -j2
```

Dry-run mode reports matches; matching connections remain established:

```bash
sudo ./tcp_quarantine --destination 127.0.0.1 --port 42063
```

Apply mode destroys matching sockets:

```bash
sudo ./tcp_quarantine --destination 127.0.0.1 --port 42063 --apply
```

Sample output from the automated test:

```console
mode=dry-run destination=127.0.0.1:42063 scanned=6 established=4 matched=1 destroyed=0 failed=0
mode=apply destination=127.0.0.1:42063 scanned=6 established=4 matched=1 destroyed=1 failed=0
PASS: dry-run preserved both connections; apply destroyed only the target
```

Socket-table counts and ephemeral port values vary by run. The assertions focus on: one exact match, dry-run preservation, targeted destruction, zero destroy failures, and control-connection survival.

Run the test:

```bash
sudo make test
```

This runs `python3 tests/test_tcp_quarantine.py ./tcp_quarantine`. The test creates two loopback TCP connection pairs: a target port and an unrelated control port. It performs request/response round trips before running the tool. The test verifies: invalid destination `not-an-ip` returns nonzero and prints `invalid IPv4 destination`; dry-run output contains `mode=dry-run`, `matched=1`, and `destroyed=0`, and both connections still complete round trips; apply output contains `mode=apply`, `matched=1`, `destroyed=1`, and `failed=0`; the target client's `send()` or `getsockopt(SO_ERROR)` returns `ECONNABORTED`, `ECONNRESET`, or `EPIPE`; and the control connection continues to survive.

Runtime behavior was functionally tested on x86_64 with Linux 7.0.0-rc2+.

## Network Namespace

The TCP BPF iterator scans the network namespace of the process that loads the BPF program. To quarantine connections inside a container or another network namespace, enter that namespace first with `nsenter`:

```bash
sudo nsenter --net=/proc/<target-pid>/ns/net -- ./tcp_quarantine \
  --destination 203.0.113.99 --port 443 --apply
```

`<target-pid>` is any process in the target network namespace. `nsenter --net` changes only the network namespace; the caller's mount namespace is retained, so the binary and working directory remain reachable. Namespace-boundary validation found `matched=0` from the caller namespace and `matched=1` after entering the isolated target namespace.

## Requirements

| Requirement | Detail |
|---|---|
| Kernel | Linux 6.5+ (where `bpf_sock_destroy` first appeared) |
| BTF | Required (`CONFIG_DEBUG_INFO_BTF=y`) |
| Kernel configs | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_INET=y`, `CONFIG_PROC_FS=y` |
| BPF JIT | Must be enabled at runtime. Programs calling kfuncs use the JIT path; `CONFIG_BPF_JIT_ALWAYS_ON` kernels may omit the sysctl because JIT is permanently active. |
| Architecture | Tested on x86_64 |
| Privileges | Tested as root |
| Hardware | None |

Load diagnostics report the kernel errno plus the prerequisite set: Linux 6.5+, BTF, TCP BPF iterators, BPF JIT, and the kfunc.

## bpf_sock_destroy Semantics

The `bpf_sock_destroy` kfunc was introduced in Linux commit `4ddbcb886268af8d12a23e6640b39d1d9c652b1b` to let BPF programs forcibly close a socket from an iterator context. The kernel invokes the protocol-specific destroy path, and the error the application sees depends on which endpoint is destroyed and what operation it attempts next. The upstream TCP selftest expects `ECONNABORTED` on the client side and `ECONNRESET` on the server side; this lesson's test also accepts `EPIPE` as a send-side result.

## Scope and Extensions

This example performs one pass through the caller-selected network namespace, handling every established connection that matches one exact IPv4 destination tuple. Extensions can add IPv6, continuous policy input, process/cgroup attribution, multi-namespace orchestration, authorization, and audit records.

## Summary

After completing this tutorial, you can terminate all TCP connections matching a destination tuple while preserving the process and unrelated traffic. Dry-run mode previews the impact; apply mode destroys the matches. You understand how BPF iterators traverse the kernel's socket table, how kfuncs expose kernel functionality to BPF programs, and how CO-RE ensures cross-kernel compatibility. For more eBPF tutorials and examples, see <https://github.com/eunomia-bpf/bpf-developer-tutorial>.

## References

- `bpf_sock_destroy` kernel commit: <https://github.com/torvalds/linux/commit/4ddbcb886268af8d12a23e6640b39d1d9c652b1b>
- Upstream sock_destroy selftest (BPF program): <https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/sock_destroy_prog.c>
- Upstream sock_destroy selftest (userspace test): <https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/sock_destroy.c>
