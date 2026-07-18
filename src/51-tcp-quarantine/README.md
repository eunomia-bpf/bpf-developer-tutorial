# eBPF Tutorial by Example: Quarantine an Established TCP Connection

Your threat-intel feed just flagged `203.0.113.99` as a command-and-control server. Firewall rules and iptables block new connections immediately, but `netstat` shows three production workers already holding established TCP sessions to that address. Those sessions will keep exfiltrating data until the process closes them or the machine reboots. You need to sever the active connections right now, without restarting services, without killing processes, and without dropping unrelated traffic.

This tutorial builds a small eBPF tool that scans every TCP socket on the host, finds established IPv4 connections to an exact remote address and port, and destroys them with `bpf_sock_destroy`. A dry-run mode lets you verify what would be killed before you pull the trigger.

> Complete source: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/51-tcp-quarantine>

## Quick demo

Build the tool and run it against a target destination:

```bash
cd src/51-tcp-quarantine
make clean
make -j2
```

Dry-run (safe, nothing is destroyed):

```bash
sudo ./tcp_quarantine --destination 127.0.0.1 --port 42063
```

Apply (destroys matching sockets):

```bash
sudo ./tcp_quarantine --destination 127.0.0.1 --port 42063 --apply
```

Real output from the test environment:

```console
mode=dry-run destination=127.0.0.1:42063 scanned=6 established=4 matched=1 destroyed=0 failed=0
mode=apply destination=127.0.0.1:42063 scanned=6 established=4 matched=1 destroyed=1 failed=0
PASS: dry-run preserved both connections; apply destroyed only the target
```

Substitute your own destination IP and port. The tool exits after one scan; it does not run continuously.

## How it works: end-to-end flow

The tool uses a BPF TCP iterator to walk the kernel's socket table. Here is the flow:

1. **User space parses the target.** The loader validates the IPv4 address with `inet_pton`, converts the port, and stores both into the BPF program's read-only data section before loading.

2. **BPF program loads and attaches as a TCP iterator.** The kernel calls the iterator callback once per socket in the TCP hash table.

3. **The iterator filters.** For each socket it increments `scanned`, skips anything that isn't `AF_INET` + `TCP_ESTABLISHED`, then compares `skc_daddr` and `skc_dport` against the target.

4. **Dry-run vs. apply.** If `apply` is false (the default), matched sockets are counted but left alone. If true, the program calls `bpf_sock_destroy` on each match.

5. **User space reads statistics.** After consuming the iterator to completion, the loader reads counters from BSS and prints the single summary line.

## The BPF program

The complete BPF side fits in under 60 lines:

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

extern int bpf_sock_destroy(struct sock_common *sock) __weak __ksym;

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

Key points:

- **`const volatile` for parameters.** These variables live in the `.rodata` section. User space sets them after `open()` but before `load()`, so the verifier sees them as constants. This avoids maps for simple configuration.

- **`bpf_sock_destroy` as a kfunc.** Declared with `__weak __ksym`, the kernel resolves this at load time. If the kfunc is unavailable (kernel too old), loading fails with a clear error rather than silently doing nothing.

- **`BPF_CORE_READ` for portability.** CO-RE relocations let the same compiled object run on kernels with different `sock_common` layouts, as long as BTF is available.

- **Network byte order for the port.** `skc_dport` is stored in network order, so the comparison uses `bpf_htons(target_port)`.

## The user-space loader

The loader handles argument parsing, BPF lifecycle, and iterator execution. The critical section:

```c
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
        "and the bpf_sock_destroy kfunc.\n",
        strerror(-err));
    goto cleanup;
}
```

After loading, the iterator is attached and consumed:

```c
link = bpf_program__attach_iter(program, NULL);
iter_fd = bpf_iter_create(bpf_link__fd(link));
while ((length = read(iter_fd, buffer, sizeof(buffer))) > 0)
    ;
```

Reading the iterator fd to EOF drives the kernel to call the BPF callback for every TCP socket. The read buffer content is unused here because the program communicates results through BSS counters rather than seq_file output.

## The shared header

```c
struct quarantine_stats {
    unsigned long long scanned;
    unsigned long long established;
    unsigned long long matched;
    unsigned long long destroyed;
    unsigned long long failed;
};
```

Both the BPF program and user-space loader include this header so the BSS layout is consistent.

## Running the automated test

The Python test (`tests/test_tcp_quarantine.py`) exercises four scenarios:

1. Invalid IPv4 address is rejected.
2. Dry-run finds and reports the target but leaves it alive.
3. Apply mode destroys the target socket (verified by `send()` failing with `ECONNABORTED`, `ECONNRESET`, or `EPIPE`, matching `BROKEN_ERRORS` in the test).
4. A control connection to a different port survives both runs.

```bash
sudo make test
```

This runs `python3 tests/test_tcp_quarantine.py ./tcp_quarantine` which creates ephemeral loopback connections, exercises the tool, and asserts the expected behavior.

## Requirements

| Requirement | Detail |
|---|---|
| Kernel | Linux 6.5+ (where `bpf_sock_destroy` first appeared) |
| BTF | Required (`CONFIG_DEBUG_INFO_BTF=y`) |
| Kernel configs | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_INET=y` |
| Architecture | Tested on x86_64 |
| Privileges | Tested as root. A least-privilege deployment must determine the required capabilities and LSM policy for its kernel version and environment. |

If loading fails, the loader prints the kernel errno followed by the kernel/BTF/iterator/kfunc requirement so you can identify which prerequisite is missing.

## Limitations

This is a teaching tool, not a production agent. Specifically:

- **IPv4 only.** There is no IPv6 path.
- **One-shot scan.** The tool exits after a single pass. It does not monitor for new connections.
- **No process attribution.** You cannot see which process owns the matched sockets.
- **No cgroup scoping.** The scan covers all sockets on the host, not a specific container or service.
- **No authorization or audit log.** A production version would gate destruction behind policy approval and record an audit trail.
- **No UDP or packet inspection.** Only TCP established sockets are considered.

A real deployment would source targets from threat intelligence or policy, add RBAC controls, and integrate with an incident management system.

## How bpf_sock_destroy works

The `bpf_sock_destroy` kfunc was introduced in Linux 6.5 to give BPF programs the ability to forcibly close a socket from within an iterator context. The original motivation was allowing network policy enforcement to terminate connections that violate updated rules without requiring cooperation from user space.

When called on a TCP socket, the kernel invokes the protocol-specific destroy path. The exact error the owning application sees depends on which endpoint is destroyed and what operation it attempts next. The upstream TCP selftest expects `ECONNABORTED` on the client side and `ECONNRESET` on the server side; this lesson's test also accepts `EPIPE` as a send-side result. Do not assume a specific TCP state transition or packet-level behavior from these observations alone.

The kernel commit introducing this functionality: <https://github.com/torvalds/linux/commit/4ddbcb886268af8d12a23e6640b39d1d9c652b1b>

Upstream BPF selftests provide additional reference:
- BPF program: <https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/sock_destroy_prog.c>
- Userspace test: <https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/sock_destroy.c>

## What you can do now

After completing this tutorial, you can:

- Identify and terminate specific TCP connections by destination without killing processes.
- Safely preview the blast radius with dry-run before taking action.
- Understand how BPF iterators walk kernel data structures and how kfuncs extend BPF capabilities.
- Build on this pattern to create policy-driven connection enforcement tools.

## References

- Tutorial repository: <https://github.com/eunomia-bpf/bpf-developer-tutorial>
- Tutorial website: <https://eunomia.dev/tutorials/>
- `bpf_sock_destroy` kernel commit: <https://github.com/torvalds/linux/commit/4ddbcb886268af8d12a23e6640b39d1d9c652b1b>
- Upstream sock_destroy selftest (BPF): <https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/sock_destroy_prog.c>
- Upstream sock_destroy selftest (userspace): <https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/sock_destroy.c>
