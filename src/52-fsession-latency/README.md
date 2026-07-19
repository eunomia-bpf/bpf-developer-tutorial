# eBPF Tutorial by Example: Trace Slow vfs_read Calls with fsession

Suppose a file-backed service shows read-latency spikes. Application timing tells you that requests slowed down, but it cannot distinguish a blocked kernel read path from user-space work. The useful question is: which thread made the read, how many bytes did it request, what did the call return, and how long did that one `vfs_read` invocation take?

This tutorial demonstrates `fsession_latency`, which attaches a single BPF program at `SEC("fsession/vfs_read")`. The program timestamps entry, computes latency at return, and reports only calls that reach or exceed a threshold. Linux 7.0 fsession runs that same BPF program once at function entry and once at function return, providing an 8-byte per-invocation scratch slot via `bpf_session_cookie(ctx)` that replaces the per-thread hash-map insert, lookup, and cleanup commonly used by a separate fentry/fexit pair.

> Complete source: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/52-fsession-latency>

## Build and Run

Build from source (libbpf 1.7.0 and bpftool v7.7.0 are vendored in this repository):

```bash
cd src/52-fsession-latency
make clean
make -j2
```

Trace a specific service process for 30 seconds, reporting reads that take 10 ms or longer:

```bash
SERVICE_PID=$(pgrep -n my-service)
sudo ./fsession_latency --pid "$SERVICE_PID" --threshold-us 10000 --duration 30
```

`--pid` compares against the TGID returned by `bpf_get_current_pid_tgid()`, which is the TGID in the host (initial) PID namespace. The `pgrep` example above works for a process running directly on the host, and a target inside a container or nested PID namespace needs its host-visible TGID.

CLI arguments:

```text
Usage: ./fsession_latency [--threshold-us USEC] [--duration SEC] [--pid TGID] [--verbose]
```

Defaults are threshold 1000 microseconds, duration 10 seconds, and all processes. `--duration` accepts 1 through 86400 seconds, `--pid` accepts 1 through `UINT32_MAX`, and `--threshold-us` accepts 0 through `UINT64_MAX / 1000` microseconds because user space converts the value to nanoseconds before load. Empty values and trailing characters are rejected by `parse_u64`.

## Example Output

The following output was captured on x86_64 with kernel `7.0.0-rc2+`. The integration test performs 64 ordinary file reads plus one pipe read delayed by 50 ms. The pipe read crosses the 10 ms threshold and appears in the event stream:

```console
Tracing vfs_read for 1 seconds; threshold=10000 us; pid=selected
EVENT comm=python3          tgid=1257 pid=1257 requested=1 result=1 latency_us=50160
SUMMARY calls=66 slow=1 errors=0 dropped=0 events=1
TEST-SUMMARY miss_calls=0 high_threshold_calls=66 high_threshold_slow=0 threshold_calls=66 threshold_slow=1 events=1 dropped=0
PASS: PID filtering, threshold miss, and slow-read reporting behaved as expected
```

Exact call counts, PID values, and latency vary by run.

## Implementation

The tool consists of three files: a shared header defining the event and statistics structures, a BPF program that measures latency and submits events, and a user-space loader that manages the lifecycle and prints results.

### Shared Header

`fsession_latency.h` defines the event and statistics structures shared between BPF and user space. `latency_event` contains 32-bit PID and TGID, 64-bit requested bytes, signed 64-bit result, nanosecond latency, and the command name. `latency_stats` contains `calls` (total invocations), `slow` (invocations at or above threshold), `errors` (negative return values), and `dropped` (ring-buffer reservation failures).

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FSESSION_LATENCY_H
#define __FSESSION_LATENCY_H

#define FSESSION_COMM_LEN 16

struct latency_event {
	unsigned int pid;
	unsigned int tgid;
	unsigned long long requested;
	long long result;
	unsigned long long latency_ns;
	char comm[FSESSION_COMM_LEN];
};

struct latency_stats {
	unsigned long long calls;
	unsigned long long slow;
	unsigned long long errors;
	unsigned long long dropped;
};

#endif /* __FSESSION_LATENCY_H */
```

`FSESSION_COMM_LEN` is 16 to match the kernel's `TASK_COMM_LEN`.

### BPF Program

`fsession_latency.bpf.c` attaches a program at `SEC("fsession/vfs_read")`. Linux 7.0 fsession runs this program once at `vfs_read` entry and once at return. The program uses `bpf_session_is_return(ctx)` to distinguish the two phases and `bpf_session_cookie(ctx)` to obtain an 8-byte per-invocation scratch slot that persists from entry to return, replacing an external hash map.

```c
// SPDX-License-Identifier: GPL-2.0
#define bpf_session_is_return bpf_session_is_return_vmlinux_snapshot
#define bpf_session_cookie bpf_session_cookie_vmlinux_snapshot
#include "vmlinux.h"
#undef bpf_session_is_return
#undef bpf_session_cookie
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "fsession_latency.h"

char LICENSE[] SEC("license") = "GPL";

const volatile __u64 threshold_ns;
const volatile __u32 target_tgid;

struct latency_stats stats;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * The repository vmlinux.h snapshot predates the ctx argument on these
 * kfunc prototypes. Rename those stale declarations while including the
 * snapshot, then provide the Linux 7.0 signatures below.
 */
extern bool bpf_session_is_return(void *ctx) __ksym;
extern __u64 *bpf_session_cookie(void *ctx) __ksym;

SEC("fsession/vfs_read")
int BPF_PROG(measure_vfs_read, struct file *file, char *buf, size_t count,
	     loff_t *pos, ssize_t ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 *started = bpf_session_cookie(ctx);
	struct latency_event *event;
	__u64 latency;

	if (!bpf_session_is_return(ctx)) {
		if (target_tgid && pid_tgid >> 32 != target_tgid) {
			*started = 0;
			return 0;
		}
		*started = bpf_ktime_get_ns();
		return 0;
	}

	if (!*started)
		return 0;

	latency = bpf_ktime_get_ns() - *started;
	__sync_fetch_and_add(&stats.calls, 1);
	if (ret < 0)
		__sync_fetch_and_add(&stats.errors, 1);
	if (latency < threshold_ns)
		return 0;

	__sync_fetch_and_add(&stats.slow, 1);
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&stats.dropped, 1);
		return 0;
	}

	event->pid = (__u32)pid_tgid;
	event->tgid = pid_tgid >> 32;
	event->requested = count;
	event->result = ret;
	event->latency_ns = latency;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	bpf_ringbuf_submit(event, 0);
	return 0;
}
```

At entry, `bpf_get_current_pid_tgid()` provides PID and TGID. If `target_tgid` is set and the call belongs to a different TGID, the program writes zero to the cookie so the return phase can skip that invocation. A matching call stores the `bpf_ktime_get_ns()` timestamp.

At return, a zero cookie identifies a filtered call. Otherwise the program subtracts the saved timestamp from the current monotonic nanosecond timestamp, increments `calls`, and increments `errors` when `ret < 0`. Calls below `threshold_ns` remain in aggregate counters. Calls at or above the threshold increment `slow`, reserve a fixed-size ring-buffer record, fill PID, TGID, requested bytes, result, latency, and command name, then submit. A failed reservation increments `dropped`, so the final accounting exposes pressure in the event path. The return-side fsession context includes the original function arguments and return value, which is why `count` and `ret` are available without saving them in a map.

The macros at the top handle the older `bpf_session_is_return` and `bpf_session_cookie` declarations in the repository's `vmlinux.h` snapshot. This is a local compatibility bridge around generated-header age, and a freshly generated 7.0+ `vmlinux.h` can carry the current signatures directly.

### User-Space Loader

`fsession_latency.c` parses CLI arguments, configures BPF constants, manages the observation window, and prints results.

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "fsession_latency.h"
#include "fsession_latency.skel.h"

static volatile sig_atomic_t exiting;

static struct env {
	unsigned long long threshold_us;
	unsigned int duration;
	unsigned int pid;
	bool verbose;
} env = {
	.threshold_us = 1000,
	.duration = 10,
};

static unsigned long long events_printed;

static void handle_signal(int signal)
{
	(void)signal;
	exiting = 1;
}

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
		"Usage: %s [--threshold-us USEC] [--duration SEC] [--pid TGID] "
		"[--verbose]\n\n"
		"Report vfs_read calls at or above a latency threshold.\n\n"
		"Options:\n"
		"  -t, --threshold-us USEC  slow-read threshold (default: 1000)\n"
		"  -d, --duration SEC       trace duration, 1-86400 (default: 10)\n"
		"  -p, --pid TGID           trace one process ID (default: all)\n"
		"  -v, --verbose            print libbpf diagnostics\n"
		"  -h, --help               show this help\n",
		program);
}

static int parse_u64(const char *value, unsigned long long maximum,
		     unsigned long long *result)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(value, &end, 10);
	if (errno || end == value || *end || parsed > maximum)
		return -EINVAL;
	*result = parsed;
	return 0;
}

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "threshold-us", required_argument, NULL, 't' },
		{ "duration", required_argument, NULL, 'd' },
		{ "pid", required_argument, NULL, 'p' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	unsigned long long parsed;
	int option;

	while ((option = getopt_long(argc, argv, "t:d:p:vh", options, NULL)) != -1) {
		switch (option) {
		case 't':
			if (parse_u64(optarg, UINT64_MAX / 1000, &env.threshold_us)) {
				fprintf(stderr, "invalid threshold in microseconds: %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'd':
			if (parse_u64(optarg, 86400, &parsed) || parsed == 0) {
				fprintf(stderr, "invalid duration in seconds: %s\n", optarg);
				return -EINVAL;
			}
			env.duration = parsed;
			break;
		case 'p':
			if (parse_u64(optarg, UINT32_MAX, &parsed) || parsed == 0) {
				fprintf(stderr, "invalid process ID: %s\n", optarg);
				return -EINVAL;
			}
			env.pid = parsed;
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

	if (optind != argc)
		return -EINVAL;
	return 0;
}

static long long monotonic_milliseconds(void)
{
	struct timespec timestamp;

	if (clock_gettime(CLOCK_MONOTONIC, &timestamp))
		return -errno;
	return timestamp.tv_sec * 1000LL + timestamp.tv_nsec / 1000000;
}

static int handle_event(void *context, void *data, size_t size)
{
	const struct latency_event *event = data;

	(void)context;
	if (size < sizeof(*event))
		return 0;

	printf("EVENT comm=%-16s tgid=%u pid=%u requested=%llu result=%lld "
	       "latency_us=%llu\n",
	       event->comm, event->tgid, event->pid, event->requested,
	       event->result, event->latency_ns / 1000);
	events_printed++;
	return 0;
}

static int poll_until_deadline(struct ring_buffer *ring, long long deadline)
{
	while (!exiting) {
		long long now = monotonic_milliseconds();
		int consumed;

		if (now < 0)
			return (int)now;
		if (now >= deadline)
			break;

		consumed = ring_buffer__poll(ring,
					     deadline - now > 100 ? 100 : deadline - now);
		if (consumed == -EINTR)
			continue;
		if (consumed < 0) {
			fprintf(stderr, "ring buffer poll failed: %s\n",
				strerror(-consumed));
			return consumed;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct fsession_latency_bpf *skel = NULL;
	struct ring_buffer *ring = NULL;
	long long deadline, now;
	int err;

	err = parse_args(argc, argv);
	if (err) {
		usage(argv[0]);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	skel = fsession_latency_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->threshold_ns = env.threshold_us * 1000;
	skel->rodata->target_tgid = env.pid;

	err = fsession_latency_bpf__load(skel);
	if (err) {
		fprintf(stderr,
			"failed to load fsession program: %s\n"
			"This tool requires Linux 7.0+, BTF, BPF JIT, and x86_64 "
			"fsession support.\n",
			strerror(-err));
		goto cleanup;
	}

	err = fsession_latency_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach to vfs_read: %s\n", strerror(-err));
		goto cleanup;
	}

	ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	err = libbpf_get_error(ring);
	if (err) {
		ring = NULL;
		fprintf(stderr, "failed to create ring buffer: %s\n", strerror(-err));
		goto cleanup;
	}

	printf("Tracing vfs_read for %u seconds; threshold=%llu us; pid=%s\n",
	       env.duration, env.threshold_us, env.pid ? "selected" : "all");
	fflush(stdout);

	now = monotonic_milliseconds();
	if (now < 0) {
		err = now;
		goto cleanup;
	}
	deadline = now + env.duration * 1000LL;

	err = poll_until_deadline(ring, deadline);
	if (err)
		goto cleanup;

	fsession_latency_bpf__detach(skel);

	err = ring_buffer__consume(ring);
	if (err < 0) {
		fprintf(stderr, "ring buffer drain failed: %s\n", strerror(-err));
		goto cleanup;
	}
	err = 0;

	printf("SUMMARY calls=%llu slow=%llu errors=%llu dropped=%llu events=%llu\n",
	       skel->bss->stats.calls, skel->bss->stats.slow,
	       skel->bss->stats.errors, skel->bss->stats.dropped, events_printed);

cleanup:
	ring_buffer__free(ring);
	fsession_latency_bpf__destroy(skel);
	return err != 0;
}
```

Before load, user space writes `threshold_ns` and `target_tgid` into read-only BPF configuration. It opens, loads, and attaches the skeleton, creates the ring-buffer consumer, calculates a monotonic deadline, and polls for at most 100 ms per iteration until the deadline or SIGINT/SIGTERM. Each event prints comm, TGID, PID, requested bytes, result, and latency in microseconds.

After polling, the loader detaches the fsession program first so aggregate counters stop changing, calls `ring_buffer__consume()` to deliver records submitted before detach, and only then prints stable `SUMMARY` counters. This ordering is part of correctness at the observation-window boundary. The loader frees the ring buffer and destroys the skeleton on exit.

The repository uses bpftool v7.7.0 with nested libbpf v1.7.0. libbpf 1.7.0 recognizes `fsession/` section names through the released public interface.

## Running the Tests

The integration test runs four scenarios plus CLI parsing tests against the built binary:

```bash
sudo make test
```

The test validates four runtime paths:

1. Target TGID `UINT32_MAX` yields zero calls and events.
2. A 10,000,000-microsecond threshold allows ordinary reads to complete while producing zero slow events.
3. 64 ordinary file reads followed by one pipe read delayed by 50 ms, under a 10,000-microsecond threshold, produces a slow-read event and verifies its TGID, PID, request size, result, and latency.
4. Threshold 0 with continuous reads through the one-second deadline verifies successful exit and `slow == events + dropped`, proving that every threshold-matching call at the boundary is either delivered or explicitly accounted as a ring-buffer reservation drop.

CLI tests cover invalid duration, empty duration, empty threshold, and empty PID.

## Requirements

| Requirement | Value |
|---|---|
| Kernel | Linux 7.0 |
| libbpf | 1.7.0 |
| Architecture | x86_64 (current tested setup) |
| BTF | Required |
| Privilege | root |
| Kernel configs | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y` |
| Runtime | BPF JIT enabled and `vfs_read` present in kernel BTF and traceable |

Runtime behavior was tested on x86_64 with kernel `7.0.0-rc2+`. The upstream merge commit is `f17b474e36647c23801ef8fdaf2255ab66dd2973`.

## Scope

The tool measures time inside `vfs_read`, covering read paths that reach that function and selecting an exact host-visible TGID. A broader tracer can add cgroup, path, inode, mount, stack, or long-running metrics dimensions while keeping the same fsession correlation pattern, and the existing `dropped` count remains the event-loss signal under load.

## Summary

One `fsession/vfs_read` program sees both entry and return, and the 8-byte per-invocation session cookie replaces an external correlation map for carrying the timestamp while TGID filtering and thresholding select useful events and aggregate counters retain totals for calls, threshold matches, errors, and dropped events within that scope. Detaching, draining, and then reading the summary closes the observation window cleanly, and if you want to dive deeper into eBPF, check out the tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial>.

## References

- [Linux fsession merge commit](https://github.com/torvalds/linux/commit/f17b474e36647c23801ef8fdaf2255ab66dd2973)
- [Upstream fsession program selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/fsession_test.c)
- [Upstream fsession runner selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/fsession_test.c)
- [libbpf 1.7.0](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
- [bpftool v7.7.0](https://github.com/libbpf/bpftool/releases/tag/v7.7.0)
