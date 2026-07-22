# eBPF Tutorial: Precisely Isolating Established TCP Connections

## The Problem

An outbound IP address has just been added to a threat-intelligence blocklist. Your firewall now rejects new connections to that address. But when you check `netstat`, you find a server already has an active TCP session to the same destination. You need to close that exact connection immediately, without killing the process, disrupting unrelated traffic, or waiting for the session to time out.

This seemingly simple requirement is surprisingly difficult to achieve with traditional tools:

- **Killing the process** disrupts all its connections, not just the problematic one. Worse, the process may immediately reconnect to the same destination after restarting.

- **Firewall rules** block new connections but have no effect on sessions that are already established. Even `iptables -m state --state ESTABLISHED` can only match existing connections for filtering future packets; it cannot tear down an active session.

- **User-space tools** like `ss --kill` or `tcpkill` work by reading `/proc/net/tcp` and then injecting TCP RST packets. This approach suffers from a race condition: the socket state can change between reading the list and sending the RST. RST injection also requires guessing the correct sequence number and may fail against encrypted tunnels or certain network configurations.

What we need is a kernel-level mechanism that can identify and destroy specific sockets atomically, with no race window. This is exactly what Linux 6.5 introduced with the `bpf_sock_destroy` kernel function (kfunc).

This tutorial builds a command-line tool that uses a BPF iterator to walk the kernel's TCP socket table, find established connections matching a specific IPv4 address and port, and destroy them on demand. You will learn how BPF iterators provide safe, locked traversal of kernel data structures, and how kfuncs like `bpf_sock_destroy` expose kernel operations to BPF programs.

> Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/51-tcp-quarantine>

## Background: BPF Iterators and Kfuncs

Before diving into the code, let's understand the two kernel features that make this tool possible.

### BPF Iterators

A BPF iterator is a special type of BPF program that the kernel invokes repeatedly, once for each element in some kernel data structure. Unlike tracepoints or kprobes that fire when specific events occur, iterators let you actively scan kernel state on demand.

The TCP iterator (`SEC("iter/tcp")`) iterates over all TCP sockets in the network namespace of the process that triggers it. User space initiates a scan by reading from an iterator file descriptor. Each `read()` call causes the kernel to invoke your BPF callback for a batch of sockets. When `read()` returns zero (EOF), the traversal is complete.

Because the kernel controls the iteration and holds appropriate locks while invoking your callback, there's no race condition between reading socket state and acting on it.

### Kfuncs

Kfuncs (kernel functions) are a mechanism for BPF programs to call specific kernel functions directly. Unlike the older BPF helper functions which have a fixed ABI, kfuncs are regular kernel functions that are explicitly marked as callable from BPF. They can do things that helpers cannot, including operations that modify kernel state in complex ways.

The `bpf_sock_destroy` kfunc, introduced in Linux 6.5 (commit `4ddbcb886268af8d12a23e6640b39d1d9c652b1b`), allows a BPF program running in an iterator context to forcibly close a socket. The kernel executes the full protocol-specific teardown: removing the socket from hash tables, sending FIN/RST as appropriate, and releasing resources. This happens synchronously: by the time the call returns, the socket is destroyed.

## How the Tool Works

The `tcp_quarantine` tool combines these two features into a practical workflow:

1. User space specifies a remote IPv4 address and port. By default this is a dry run; apply mode also requires one local IPv4 address and port copied from the dry-run output.
2. The BPF program is loaded with these parameters baked into its read-only data section.
3. User space opens an iterator file descriptor and reads from it, triggering the kernel to invoke the BPF callback for each TCP socket.
4. For each socket, the BPF callback checks: Is this an IPv4 socket? Is it in the ESTABLISHED state? Does its remote endpoint match? In apply mode, does its local endpoint also match?
5. Matching sockets are printed and counted. Only an apply scan with all four endpoint fields equal calls `bpf_sock_destroy`.
6. After traversal completes, user space reads statistics from the BPF program's BSS section and reports results.

The final match and destroy happen in one iterator callback on the same socket. Dry-run and apply are separate scans, so a connection can disappear between them; in that case apply safely reports `matched=0`.

## Code Walkthrough

The implementation has three source files: a shared header defining the statistics structure, the BPF program that performs the actual iteration and destruction, and a user-space loader that orchestrates everything.

### Statistics Structure

`tcp_quarantine.h` defines counters that the BPF program updates during iteration and user space reads afterward:

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

These five counters track: total sockets examined, how many were IPv4 and ESTABLISHED, how many matched the active selector, how many were successfully destroyed (apply mode only), and how many `bpf_sock_destroy` calls failed.

### BPF Iterator Program

`tcp_quarantine.bpf.c` is the kernel-side code. The `SEC("iter/tcp")` annotation tells the loader this is a TCP iterator program:

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
const volatile __u32 target_local_addr;
const volatile __u16 target_local_port;
const volatile bool apply;

struct quarantine_stats stats;

extern int bpf_sock_destroy(struct sock_common *sock) __ksym;

SEC("iter/tcp")
int quarantine_tcp(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk = ctx->sk_common;
	struct seq_file *seq = ctx->meta->seq;
	__u32 dst_addr, local_addr;
	__u32 dst_host, local_host;
	__u16 dst_port;
	__u16 local_port;
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
	local_addr = BPF_CORE_READ(sk, skc_rcv_saddr);
	local_port = BPF_CORE_READ(sk, skc_num);
	if (apply && (local_addr != target_local_addr ||
		      local_port != target_local_port))
		return 0;

	stats.matched++;
	local_host = bpf_ntohl(local_addr);
	dst_host = bpf_ntohl(dst_addr);
	BPF_SEQ_PRINTF(seq,
		       "MATCH local=%u.%u.%u.%u:%u remote=%u.%u.%u.%u:%u\n",
		       local_host >> 24, (local_host >> 16) & 0xff,
		       (local_host >> 8) & 0xff, local_host & 0xff, local_port,
		       dst_host >> 24, (dst_host >> 16) & 0xff,
		       (dst_host >> 8) & 0xff, dst_host & 0xff, target_port);
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

Let's break down the key elements:

**Configuration variables**: The five `const volatile` variables hold the remote endpoint, optional local endpoint, and apply mode in the BPF program's read-only data section (`.rodata`). User space writes them after opening the skeleton but before loading the program. The verifier can eliminate the local-match and destruction path when `apply` is false.

**Kfunc declaration**: The line `extern int bpf_sock_destroy(struct sock_common *sock) __ksym;` declares `bpf_sock_destroy` as an external kernel symbol. The `__ksym` annotation tells the loader to resolve this at load time by looking up the kernel function.

**CO-RE field access**: `BPF_CORE_READ(sk, skc_family)` reads the `skc_family` field from the socket structure using BTF (BPF Type Format) information. This is part of CO-RE (Compile Once, Run Everywhere): the compiled BPF program contains relocation records that the loader patches based on the running kernel's BTF data. A program compiled on one kernel version will work on others even if structure field offsets differ.

**Byte order handling**: Remote and local addresses match the network byte order produced by `inet_pton`. The remote `skc_dport` is in network byte order and is compared with `bpf_htons(target_port)`; local `skc_num` is already in host byte order.

**Progressive filtering**: The callback first counts all sockets (`scanned`), then IPv4 ESTABLISHED sockets (`established`), then remote matches. Dry-run prints every candidate as `MATCH local=... remote=...`. Apply mode rechecks the selected local endpoint before incrementing `matched` or destroying anything. There is deliberately no option that destroys every remote match.

### User-Space Loader

`tcp_quarantine.c` handles argument parsing, BPF lifecycle management, and result reporting:

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
```

The key workflow:

1. **Open the skeleton**: `tcp_quarantine_bpf__open()` parses the embedded BPF object but doesn't load it yet.

2. **Configure parameters**: We write the parsed remote endpoint, optional local endpoint, and apply flag to `skel->rodata->*` before `load()`.

3. **Load the program**: `tcp_quarantine_bpf__load()` loads the BPF program into the kernel. The verifier runs, BTF relocations are applied, and kfuncs are resolved.

4. **Run the iterator**: `run_iterator()` attaches the program, creates an iterator file descriptor, and reads from it until EOF. The read loop drives the kernel to invoke our BPF callback for every TCP socket.

5. **Read results**: After iteration, we read statistics from `skel->bss->stats`. The BSS section is automatically memory-mapped, so these reads just access shared memory.

The iterator callback writes each candidate with `BPF_SEQ_PRINTF`. The `read()` loop copies that iterator output to stdout, making the dry run actionable; aggregate results still come from BSS statistics.

## Network Namespace Boundary

The TCP BPF iterator scans sockets in the network namespace of the process that triggers it. This is a critical boundary to understand: the tool can only see and operate on connections within its own network namespace.

If you need to close a connection inside a container or another namespace, first enter that namespace using `nsenter`:

```bash
sudo nsenter --net=/proc/<target-pid>/ns/net -- ./tcp_quarantine \
  203.0.113.99:443
```

Here `<target-pid>` is the PID of any process in the target network namespace. The `--net` flag changes only the network namespace while keeping the mount namespace intact, so the tool binary remains accessible.

## What Applications See

When `bpf_sock_destroy` tears down a socket, the kernel executes the protocol's shutdown path. The specific error an application sees depends on which end of the connection is destroyed and what operation it next attempts:

- The upstream TCP selftest expects `ECONNABORTED` for the client and `ECONNRESET` for the server.
- Writes may produce `EPIPE` with a `SIGPIPE` signal.
- The exact behavior varies by kernel version and the timing of operations.

Treat any of these outcomes as application-visible evidence that the connection was torn down; confirm the exact behavior expected by your application and kernel version.

## Building and Running

Build the tool:

```bash
cd src/51-tcp-quarantine
make clean
make -j2
```

**Dry-run mode** (the default) scans for matches but doesn't destroy anything:

```bash
sudo ./tcp_quarantine 127.0.0.1:42063
```

Copy one `MATCH` line's local endpoint into apply mode. This destroys only that complete 4-tuple:

```bash
sudo ./tcp_quarantine --apply 127.0.0.1:55490 127.0.0.1:42063
```

Command-line reference:

```text
Usage: ./tcp_quarantine [--apply LOCAL_IPV4:PORT] REMOTE_IPV4:PORT [--verbose]

Options:
  -a, --apply IPv4:PORT   local endpoint selected from dry-run output
  -v, --verbose           print libbpf diagnostics
  -h, --help              show this help
```

### Example Session

Suppose a service has two established connections to the same remote listener. A normal dry-run lists both candidates; copying one local endpoint into the apply command selects only that connection:

```console
MATCH local=127.0.0.1:55490 remote=127.0.0.1:42063
MATCH local=127.0.0.1:55494 remote=127.0.0.1:42063
SUMMARY mode=dry-run remote=127.0.0.1:42063 scanned=8 established=6 matched=2 destroyed=0 failed=0
MATCH local=127.0.0.1:55490 remote=127.0.0.1:42063
SUMMARY mode=apply remote=127.0.0.1:42063 local=127.0.0.1:55490 scanned=7 established=5 matched=1 destroyed=1 failed=0
```

Socket counts and ports vary. What matters is that dry-run lists both remote matches without changing them, while apply reports `matched=1 destroyed=1` for the copied 4-tuple and leaves the other socket intact.

### Requirements

| Requirement | Details |
|---|---|
| Kernel | Linux 6.5+ (when `bpf_sock_destroy` was introduced) |
| BTF | Required (`CONFIG_DEBUG_INFO_BTF=y`) |
| Kernel configs | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_INET=y`, `CONFIG_PROC_FS=y` |
| BPF JIT | Must be enabled. Kfuncs require the JIT. Kernels built with `CONFIG_BPF_JIT_ALWAYS_ON` require no runtime configuration. |
| Architecture | Tested on x86_64 |
| Privileges | Root required |

If loading fails, the tool prints both the kernel error and a checklist of prerequisites to help you diagnose the problem.

## Summary

This tutorial demonstrated how to use BPF iterators and the `bpf_sock_destroy` kfunc to surgically terminate one selected TCP connection. Unlike process killing, firewall rules, or user-space RST injection, this approach:

- Works atomically with no race window between inspection and action
- Does not require guessing TCP sequence numbers
- Does not disrupt unrelated connections on the same process
- Is not affected by encryption or unusual network configurations

The tool uses the complete IPv4 4-tuple as its smallest safe destructive selector. Possible extensions include IPv6 support, process/cgroup attribution, multi-namespace orchestration, and integration with threat-intelligence feeds; broad wildcard destruction is intentionally outside this tutorial.

> To learn more about eBPF, visit our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or our website at <https://eunomia.dev/tutorials/>.

## References

- [bpf_sock_destroy kernel commit](https://github.com/torvalds/linux/commit/4ddbcb886268af8d12a23e6640b39d1d9c652b1b)
- [Upstream sock_destroy selftest (BPF program)](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/sock_destroy_prog.c)
- [Upstream sock_destroy selftest (userspace test)](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/sock_destroy.c)
