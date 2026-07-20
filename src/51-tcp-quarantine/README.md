# eBPF Tutorial: Precisely Isolating Established TCP Connections

Suppose an outbound destination address has just been added to a threat-intelligence blocklist. The firewall has updated its rules to block future connections. However, `netstat` shows that a server already has an active TCP session to that address -- you need to close that exact connection while preserving the process and all unrelated traffic.

This tutorial demonstrates how to achieve this using a BPF iterator and the `bpf_sock_destroy` kfunc. The tool traverses the kernel's TCP socket table, finds established connections that exactly match an IPv4 destination address and port, reports match counts in dry-run mode, and destroys the selected sockets in `--apply` mode.

> Complete source: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/51-tcp-quarantine>

## Why Kernel-Level Connection Isolation Is Needed

Traditional approaches to terminating connections all have significant limitations.

**Killing the process** is the most direct approach, but a single process often maintains multiple connections. Killing it disrupts all business traffic, and the process may immediately reconnect to the same destination after restart.

**Firewall rules** can block new connections but are powerless against already-established ones. The `-m state --state ESTABLISHED` rule in `iptables` or `nftables` can only match state -- it cannot actively sever existing sessions.

**User-space tools** such as `ss --kill` or `tcpkill` rely on traversing `/proc/net/tcp` and injecting RST packets. This approach has a race condition: between reading the socket list and sending the RST, the socket state may have already changed. Furthermore, injecting RST requires the correct sequence number and may be ineffective against encrypted connections or certain protocol stack configurations.

**A kernel-level approach** is needed to truly solve this problem. BPF iterators can traverse the kernel's socket table while holding appropriate locks. The `bpf_sock_destroy` kfunc directly invokes the kernel's socket destruction path. The entire process is atomic with no race window. This is the significance of Linux 6.5 introducing `bpf_sock_destroy`: it allows BPF programs to forcibly close sockets from an iterator context without relying on user-space RST injection.

## BPF Iterator and bpf_sock_destroy

A BPF TCP iterator is a special type of BPF program that drives typed callbacks for each TCP socket in the loading process's network namespace. User space triggers the traversal by reading the iterator file descriptor, and the kernel invokes the BPF callback once per socket during traversal.

The `bpf_sock_destroy` kfunc was introduced in Linux 6.5 (commit `4ddbcb886268af8d12a23e6640b39d1d9c652b1b`), allowing BPF programs to forcibly close sockets from an iterator context. The kernel executes the protocol-specific destroy path. This is a synchronous operation -- the socket is destroyed by the time the call returns.

The `tcp_quarantine` tool combines these two capabilities. The user specifies a target IPv4 address and port, and the BPF program traverses the socket table, filtering for `ESTABLISHED` connections with an exact destination match. Dry-run mode only counts matches; apply mode calls `bpf_sock_destroy` to destroy matching sockets. The entire process completes in kernel space. User space only needs to read the iterator file descriptor to drive the traversal, then read the statistics counters from the BSS section afterward.

## Code Implementation

This tool consists of three files: a shared header defining the statistics structure, a BPF program that traverses the socket table and performs destruction, and a user-space loader that manages the lifecycle and prints results.

### Shared Header

`tcp_quarantine.h` defines the statistics structure shared between BPF and user space, residing in the BSS section as a result channel carrying five counters.

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

The five counters record: total sockets scanned, IPv4 sockets in `ESTABLISHED` state, sockets with exact destination address and port matches, sockets successfully destroyed in apply mode, and `bpf_sock_destroy` calls that returned nonzero.

### BPF Program

`tcp_quarantine.bpf.c` uses `SEC("iter/tcp")` to declare itself as a TCP iterator type. When user space reads the iterator file descriptor, the kernel calls the callback once for each TCP socket in the loading process's network namespace.

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

The program structure is straightforward. Three `const volatile` variables reside in the `.rodata` section. User space writes the target address, port, and apply flag after `open()` but before `load()`, and the verifier treats them as compile-time constants. `bpf_sock_destroy` is declared via `extern ... __ksym` as a strong kfunc symbol, which the kernel resolves at load time.

The callback logic uses three-level filtering. First, for each non-null `sk`, it increments the `scanned` counter, then selects sockets that are `AF_INET` and in `TCP_ESTABLISHED` state for the `established` count. The `BPF_CORE_READ` macro uses BTF information to read `sock_common` structure fields. CO-RE relocations ensure the same compiled artifact runs across different kernel versions and field layouts.

The second filter checks destination address and port. The destination address is compared directly in network byte order (the result stored by `inet_pton` is already in network byte order). Port comparison uses `bpf_htons(target_port)` because `skc_dport` is stored in network byte order.

Matching sockets increment `matched`. Dry-run mode returns at this point. Apply mode calls `bpf_sock_destroy(sk)`, incrementing `destroyed` on success or `failed` on nonzero return.

### User-Space Loader

`tcp_quarantine.c` parses command-line arguments, configures BPF constants, runs the iterator, and prints results.

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

The loader follows a standard flow. After parsing command-line arguments, it validates the IPv4 address with `inet_pton` and converts it to network byte order. After opening the skeleton, it writes three parameters to the `.rodata` section, then calls `load` to complete BPF program loading. The load failure diagnostic provides both the kernel errno and a prerequisite checklist to help users troubleshoot.

The `run_iterator` function is the core driver for traversal. It first attaches the BPF program with `bpf_program__attach_iter`, then creates an iterator file descriptor with `bpf_iter_create`. The loop reads that fd until EOF, with each `read` driving the kernel to invoke the BPF callback for a batch of TCP sockets. The content of the read buffer is irrelevant in this scenario -- it only serves to drive traversal. The actual results are conveyed through the BSS section counters. After iteration completes, the loader reads counters from `skel->bss->stats` and prints a single-line summary.

## Network Namespaces

The TCP BPF iterator scans the network namespace of the process that loads the BPF program. This is an important boundary: the tool can only see and operate on connections within its own network namespace.

To isolate connections inside a container or another network namespace, first enter the target namespace with `nsenter`:

```bash
sudo nsenter --net=/proc/<target-pid>/ns/net -- ./tcp_quarantine \
  --destination 203.0.113.99 --port 443 --apply
```

`<target-pid>` is the PID of any process in the target network namespace. `nsenter --net` changes only the network namespace; the caller's mount namespace is retained, so the binary and working directory remain accessible.

## bpf_sock_destroy Semantics

`bpf_sock_destroy` directly invokes the kernel's socket destruction path, which is fundamentally different from user-space RST packet injection. The kernel executes protocol-specific cleanup logic, removes the socket from hash tables, and releases associated resources.

The error seen by the application depends on which endpoint is destroyed and what operation it attempts next. The upstream TCP selftest expects `ECONNABORTED` on the client side and `ECONNRESET` on the server side. This tutorial's test also accepts `EPIPE` on the send side, as the exact error code may vary depending on operation order and kernel version.

## Compilation and Execution

Build from source:

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

Command-line options:

```text
Usage: ./tcp_quarantine --destination IPv4 --port PORT [--apply] [--verbose]

Options:
  -d, --destination IPv4  exact remote IPv4 address
  -p, --port PORT         exact remote TCP port (1-65535)
  -a, --apply             destroy matching sockets
  -v, --verbose           print libbpf diagnostics
  -h, --help              show this help
```

The following output was captured on an x86_64 environment running kernel `7.0.0-rc2+`. The automated test creates two loopback TCP connection pairs: one target port and one unrelated control port. It performs request/response round trips before running the tool to verify behavior:

```console
mode=dry-run destination=127.0.0.1:42063 scanned=6 established=4 matched=1 destroyed=0 failed=0
mode=apply destination=127.0.0.1:42063 scanned=6 established=4 matched=1 destroyed=1 failed=0
PASS: dry-run preserved both connections; apply destroyed only the target
```

Socket table counts and ephemeral port numbers vary with each run. The test assertions focus on: match count is 1, dry-run preserves connections, apply destroys the target, destroy failures are 0, and the control connection survives.

Run the test:

```bash
sudo make test
```

### Environment Requirements

| Requirement | Details |
|---|---|
| Kernel | Linux 6.5+ (when `bpf_sock_destroy` was first introduced) |
| BTF | Required (`CONFIG_DEBUG_INFO_BTF=y`) |
| Kernel configs | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_INET=y`, `CONFIG_PROC_FS=y` |
| BPF JIT | Must be enabled at runtime. Programs calling kfuncs use the JIT path; `CONFIG_BPF_JIT_ALWAYS_ON` kernels require no sysctl setting. |
| Architecture | Tested on x86_64 |
| Privileges | root |

## Summary

This tutorial demonstrated how to use a BPF iterator and the `bpf_sock_destroy` kfunc to implement precise TCP connection isolation. Compared to killing processes, firewall rules, or user-space RST injection, this kernel-level approach is atomic with no race window and no dependency on correct sequence numbers.

The tool is designed for single-pass traversal with exact matching on one IPv4 destination tuple. Future extensions could add IPv6 support, continuous policy input, process/cgroup attribution, multi-namespace orchestration, authorization controls, and audit logging.

> To learn more about eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [bpf_sock_destroy kernel commit](https://github.com/torvalds/linux/commit/4ddbcb886268af8d12a23e6640b39d1d9c652b1b)
- [Upstream sock_destroy selftest (BPF program)](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/sock_destroy_prog.c)
- [Upstream sock_destroy selftest (userspace test)](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/sock_destroy.c)
