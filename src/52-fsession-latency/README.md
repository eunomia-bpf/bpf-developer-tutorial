# eBPF Tutorial: Tracing Slow vfs_read Calls with fsession

Suppose a file-backed service shows read-latency spikes. Application-level timing tells you that requests slowed down, but it cannot distinguish whether the kernel read path blocked or user-space logic took too long. The useful questions are: which thread issued the read, how many bytes did it request, what did the call return, and how long did that single `vfs_read` invocation take?

This tutorial demonstrates how to measure `vfs_read` call latency using the fsession mechanism introduced in Linux 7.0. The tool timestamps function entry, computes latency at return, filters by TGID and threshold, and reports slow-read events.

> Complete source: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/52-fsession-latency>

## Why fsession Is Needed

Traditional approaches to measuring function latency all have notable limitations.

**Separate fentry and fexit programs** are the most common approach. You write two BPF programs: one attached to function entry, one to function return. The two programs pass timestamps through a per-thread hash map: entry stores a mapping from `bpf_get_current_pid_tgid()` to timestamp, and return looks up and deletes the entry. This pattern has several problems. First, you must maintain an extra hash map, incurring lookup and deletion overhead on every call. Second, if a thread dies between entry and return (for example, if it is killed), the hash-map entry leaks. Third, the two programs have no intrinsic relationship; state passing depends entirely on an external data structure.

**kprobe and kretprobe** also require two separate programs and an external hash map. Compared to fentry/fexit, kprobes have higher overhead because they work through a breakpoint mechanism, whereas fentry hooks directly into the function prologue using JIT-optimized call sequences on x86_64.

**User-space sampling** such as `perf record` or periodic stack sampling with `bpftrace` provides only a statistical profile and cannot precisely measure the latency of each call. For scenarios that need to capture tail-latency events, sampling may completely miss critical slow calls.

**The fsession mechanism** solves this problem fundamentally. Linux 7.0 introduced fsession, which executes the same BPF program once at function entry and once at return, providing an 8-byte per-invocation scratch area through `bpf_session_cookie(ctx)`. This cookie persists from entry to return, completely replacing external hash maps. The program uses `bpf_session_is_return(ctx)` to distinguish the two phases and handles all logic within a single program.

## How fsession Works

fsession is a special ftracing program type. When you declare a program with `SEC("fsession/vfs_read")`, the kernel calls your BPF program once at `vfs_read` entry and once at return.

`bpf_session_is_return(ctx)` returns false during the entry phase and true during the return phase. The program uses this helper to determine which phase it is in and execute the appropriate logic.

`bpf_session_cookie(ctx)` returns a pointer to an 8-byte scratch area. This scratch area is unique to each invocation and persists from entry to return. You can write data (such as a timestamp) during entry and read it during return.

The return-phase context includes not only the original function arguments but also the function's return value. For `vfs_read`, you can see the `file`, `buf`, `count`, and `pos` arguments at entry; at return you can also see the `ret` return value. This means you do not need to store arguments in a map - the return phase can access them directly.

The `fsession_latency` tool leverages these capabilities for latency measurement. At entry, it checks whether the TGID matches the target process; matching calls store a `bpf_ktime_get_ns()` timestamp in the cookie. At return, it reads the timestamp from the cookie to compute latency, increments aggregate counters, and reports detailed events through a ring buffer for calls exceeding the threshold.

## Code Implementation

This tool consists of three files: a shared header defining event and statistics structures, a BPF program that measures latency and submits events, and a user-space loader that manages the lifecycle and prints results.

### Shared Header

`fsession_latency.h` defines the event and statistics structures shared between BPF and user space. `latency_event` contains a 32-bit PID and TGID, 64-bit requested bytes, a signed 64-bit return value, nanosecond-precision latency, and the process name. `latency_stats` contains four counters for aggregate statistics.

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

The four counters record: `calls` for total invocations, `slow` for calls reaching the threshold, `errors` for calls returning negative values, and `dropped` for ring-buffer reservation failures. `FSESSION_COMM_LEN` is set to 16 to match the kernel's `TASK_COMM_LEN`.

### BPF Program

`fsession_latency.bpf.c` uses `SEC("fsession/vfs_read")` to declare itself as an fsession type. The kernel calls this program once at `vfs_read` entry and once at return.

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

The program is structured into entry and return phases. The two `const volatile` variables reside in the `.rodata` section; user space writes the threshold and target TGID after `open()` but before `load()`, and the verifier treats them as compile-time constants. `bpf_session_is_return` and `bpf_session_cookie` are declared as kfunc symbols via `extern ... __ksym`, resolved by the kernel at load time.

At entry, the program calls `bpf_get_current_pid_tgid()` to obtain the caller's PID and TGID. If `target_tgid` is set and the call comes from a different process, the program writes 0 to the cookie to indicate this invocation should be skipped. Matching calls store the monotonic timestamp returned by `bpf_ktime_get_ns()`.

At return, the program first checks whether the cookie is 0. A zero cookie indicates the entry phase already filtered this call, so it returns immediately. Otherwise it computes latency as the current timestamp minus the saved entry timestamp, then increments the `calls` counter. If `ret < 0`, indicating the read operation returned an error, it increments the `errors` counter. Calls with latency below `threshold_ns` stop here, updating only aggregate counters without reporting events.

Calls reaching the threshold increment the `slow` counter, then attempt to reserve a fixed-size record in the ring buffer. A failed reservation increments the `dropped` counter, allowing the final statistics to expose pressure in the event path. On successful reservation, the record is filled with PID, TGID, requested bytes, return value, latency, and process name, then submitted to the ring buffer.

The macros at the beginning of the file provide a local compatibility bridge. The repository's `vmlinux.h` snapshot has `bpf_session_is_return` and `bpf_session_cookie` declarations that predate the `ctx` argument added in Linux 7.0. The macros rename the old declarations, include the snapshot, undef, then redeclare with the correct Linux 7.0 signatures. A freshly regenerated `vmlinux.h` from kernel 7.0 or later can be used directly without this bridge.

### User-Space Loader

`fsession_latency.c` parses the command line, configures BPF constants, manages the observation window, and prints results.

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

The loader follows a standard flow. After parsing the command line, it opens the skeleton and writes `threshold_ns` and `target_tgid` to the read-only BPF configuration. The user-provided threshold is in microseconds; it is multiplied by 1000 to convert to nanoseconds before writing. Calling `load` completes BPF program loading, then attaches to `vfs_read`. The failure diagnostic provides both the kernel errno and a prerequisite list to help users troubleshoot.

`ring_buffer__new` creates the ring-buffer consumer and registers the `handle_event` callback to process each event. The callback prints comm, TGID, PID, requested bytes, result, and latency in microseconds, incrementing `events_printed`.

The `poll_until_deadline` function drives the event consumption loop. It calculates a monotonic deadline and polls for up to 100 ms per iteration until the deadline or SIGINT/SIGTERM. A `-EINTR` return continues the loop; other negative values indicate errors.

After polling ends, the loader first calls `fsession_latency_bpf__detach` to detach the fsession program, stopping changes to aggregate counters. It then calls `ring_buffer__consume` to deliver records submitted before detach but not yet consumed. This ordering is part of observation-window boundary correctness: stop new event production first, drain existing events, then read stable counters. On exit, it frees the ring buffer and destroys the skeleton.

## Compilation and Execution

Build from source (the repository vendors libbpf 1.7.0 and bpftool v7.7.0):

```bash
cd src/52-fsession-latency
make clean
make -j2
```

Trace a specific service process for 30 seconds, reporting reads of 10 ms or longer:

```bash
SERVICE_PID=$(pgrep -n my-service)
sudo ./fsession_latency --pid "$SERVICE_PID" --threshold-us 10000 --duration 30
```

`--pid` compares against the TGID returned by `bpf_get_current_pid_tgid()`, which is the TGID in the host (initial) PID namespace. The `pgrep` example above works for processes running directly on the host; targets inside containers or nested PID namespaces need their host-visible TGID resolved and passed in.

Command-line arguments:

```text
Usage: ./fsession_latency [--threshold-us USEC] [--duration SEC] [--pid TGID] [--verbose]

Options:
  -t, --threshold-us USEC  slow-read threshold (default: 1000 microseconds)
  -d, --duration SEC       trace duration, 1-86400 (default: 10 seconds)
  -p, --pid TGID           trace a specific process ID (default: all processes)
  -v, --verbose            print libbpf diagnostics
  -h, --help               show this help
```

Defaults are 1000 microsecond threshold, 10 second duration, and all processes. `--duration` accepts 1 through 86400 seconds, `--pid` accepts 1 through 2^32-1, and `--threshold-us` accepts 0 through `UINT64_MAX / 1000` microseconds (user space converts to nanoseconds before load). Empty values and trailing characters are rejected by `parse_u64`.

The following output was captured on x86_64 with kernel `7.0.0-rc2+`. The integration test performs 64 ordinary file reads plus one pipe read delayed by 50 ms; the pipe read exceeds the 10 ms threshold and appears in the event stream:

```console
Tracing vfs_read for 1 seconds; threshold=10000 us; pid=selected
EVENT comm=python3          tgid=1257 pid=1257 requested=1 result=1 latency_us=50160
SUMMARY calls=66 slow=1 errors=0 dropped=0 events=1
TEST-SUMMARY miss_calls=0 high_threshold_calls=66 high_threshold_slow=0 threshold_calls=66 threshold_slow=1 events=1 dropped=0
PASS: PID filtering, threshold miss, and slow-read reporting behaved as expected
```

Exact call counts, PID values, and latency numbers vary by run.

Running the tests:

```bash
sudo make test
```

The integration test validates four runtime paths: target TGID of `UINT32_MAX` produces zero calls and events; a 10,000,000 microsecond threshold causes ordinary reads to produce zero slow events; 64 ordinary file reads plus one 50 ms delayed pipe read under a 10,000 microsecond threshold produces a slow event; and threshold 0 verifies `slow == events + dropped`, proving every threshold-matching call is either delivered or accounted as a ring-buffer reservation failure. CLI tests cover invalid duration, empty duration, empty threshold, and empty PID.

### Environment Requirements

| Requirement | Details |
|---|---|
| Kernel version | Linux 7.0+ (fsession first introduced) |
| BTF | Must be enabled (`CONFIG_DEBUG_INFO_BTF=y`) |
| Kernel config | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y` |
| BPF JIT | Must be enabled at runtime |
| Architecture | Tested on x86_64 |
| Privilege | root |

Runtime behavior was tested on x86_64 with kernel `7.0.0-rc2+`. The upstream merge commit is `f17b474e36647c23801ef8fdaf2255ab66dd2973`.

## Observation Scope

This tool measures time inside `vfs_read`, covering read paths that reach that function and filtering by exact host-visible TGID. A more comprehensive tracer could add cgroup, path, inode, mount, stack, or long-running metrics dimensions while keeping the same fsession correlation pattern; the existing `dropped` counter remains the event-loss signal under load.

## Summary

This tutorial demonstrated how to measure kernel function latency using the fsession mechanism in Linux 7.0. Compared to the traditional approach of two fentry/fexit programs with a hash map, fsession handles both entry and return in a single program. The 8-byte per-invocation session cookie replaces the external correlation map for carrying timestamps, resulting in cleaner code, no state-leak risk, and lower performance overhead.

The tool's design demonstrates the core fsession pattern: use `bpf_session_is_return` to distinguish phases, use `bpf_session_cookie` to pass per-invocation state, and access function arguments and return values directly in the return phase. This pattern applies to any scenario requiring correlation between function entry and return.

> To learn more about eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit <https://eunomia.dev/tutorials/>.

## References

- [Linux fsession merge commit](https://github.com/torvalds/linux/commit/f17b474e36647c23801ef8fdaf2255ab66dd2973)
- [Upstream fsession program selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/fsession_test.c)
- [Upstream fsession runner selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/fsession_test.c)
- [libbpf 1.7.0](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
- [bpftool v7.7.0](https://github.com/libbpf/bpftool/releases/tag/v7.7.0)
