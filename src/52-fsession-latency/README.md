# eBPF Tutorial by Example: Trace Slow vfs_read Calls with fsession

A file-backed service shows read-latency spikes in its application metrics, but the metrics cannot distinguish a blocked kernel read from work above the syscall boundary. The operator needs to answer: which specific `vfs_read` invocations are slow, for which threads, and by how much?

`fsession_latency` attaches a single BPF program to `vfs_read` that timestamps entry, measures return latency, and reports only calls at or above a configurable threshold. It uses the Linux 7.0 fsession mechanism, which eliminates the hash-map correlation that traditional fentry/fexit pairs require.

> Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/52-fsession-latency>

## Quick Start

Build the tool from source (requires libbpf 1.7.0 and bpftool v7.7.0, both vendored in this repository):

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

`--pid` compares against the TGID returned by `bpf_get_current_pid_tgid()`, which is always the TGID in the host (initial) PID namespace. The `pgrep` example above works for a process running directly on the host. For a process inside a container or nested PID namespace, you must resolve and pass its host-namespace TGID; a namespace-local PID will silently match nothing.

CLI usage:

```text
Usage: ./fsession_latency [--threshold-us USEC] [--duration SEC] [--pid TGID] [--verbose]
```

Defaults: threshold 1000 microseconds, duration 10 seconds, all processes.

## Verified Test Output

The integration test performs 64 ordinary file reads plus one pipe read delayed by 50 ms. The pipe read crosses the 10 ms threshold and appears as an event. This output was captured on a KVM guest running kernel `7.0.0-rc2+`:

```console
Tracing vfs_read for 1 seconds; threshold=10000 us; pid=selected
EVENT comm=python3          tgid=1257 pid=1257 requested=1 result=1 latency_us=50160
SUMMARY calls=66 slow=1 errors=0 dropped=0 events=1
TEST-SUMMARY miss_calls=0 high_threshold_calls=66 high_threshold_slow=0 threshold_calls=66 threshold_slow=1 events=1 dropped=0
PASS: PID filtering, threshold miss, and slow-read reporting behaved as expected
```

The exact counts and latency are specific to that test environment; your numbers will differ.

## How It Works

### The fsession Mechanism

Traditional fentry/fexit tracing attaches two separate BPF programs. Correlating entry and return requires a per-thread hash map lookup on both sides. The fsession program type, introduced in Linux 7.0, runs one BPF program at both entry and return of a traced function. Two kfuncs make this work:

- `bpf_session_cookie(ctx)` returns a pointer to an 8-byte scratch space that persists from entry to return of one function invocation. No map allocation, no lookup, no cleanup.
- `bpf_session_is_return(ctx)` returns true on the return invocation.

On return, the program receives the original function arguments plus the return value. This means the tool can report `count` (requested bytes) and `ret` (actual result or error) without storing them in a map.

### BPF Program

The entire BPF program is a single function in `fsession_latency.bpf.c`:

```c
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

The flow works like this:

1. On entry, check the TGID filter. If the process does not match, store zero in the session cookie so the return side skips it. Otherwise, store the current nanosecond timestamp.
2. On return, if the cookie is zero the call was filtered out. Otherwise compute latency from the stored timestamp.
3. Increment the atomic `calls` counter. If the return value is negative, increment `errors`.
4. If latency is below the threshold, stop. Otherwise increment `slow`, reserve a ring-buffer slot, populate the event, and submit.

### Shared Structures

The header `fsession_latency.h` defines the event and stats structures shared between BPF and user space:

```c
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
```

### User-Space Loader

The user-space program in `fsession_latency.c` performs these steps:

1. Parse CLI arguments (threshold, duration, PID filter).
2. Open the BPF skeleton and set `rodata` constants (`threshold_ns`, `target_tgid`) before loading.
3. Load and attach the fsession program to `vfs_read`.
4. Create a ring buffer and poll it with a 100 ms timeout until the duration expires or a signal arrives. Print each event as it arrives (comm, tgid, pid, requested bytes, result, latency in microseconds).
5. Detach the fsession program so BPF statistics stop changing.
6. Call `ring_buffer__consume()` to drain events already submitted to the ring buffer before detach.
7. Print the summary line with stable aggregate counters from BSS.

The summary line exposes ring-buffer drops so the operator knows if events were lost under load.

### vmlinux.h Compatibility

The repository's `vmlinux.h` snapshot predates the ctx argument on `bpf_session_is_return` and `bpf_session_cookie`. The BPF source works around this by renaming those stale declarations during the include, then declaring the correct Linux 7.0 signatures:

```c
#define bpf_session_is_return bpf_session_is_return_vmlinux_snapshot
#define bpf_session_cookie bpf_session_cookie_vmlinux_snapshot
#include "vmlinux.h"
#undef bpf_session_is_return
#undef bpf_session_cookie

extern bool bpf_session_is_return(void *ctx) __ksym;
extern __u64 *bpf_session_cookie(void *ctx) __ksym;
```

This avoids hand-editing the generated header. A regenerated `vmlinux.h` from a 7.0+ kernel would not need the workaround.

### libbpf Section Recognition

The repository uses bpftool v7.7.0, whose nested libbpf is v1.7.0. libbpf 1.7.0 recognizes `fsession/` as a valid program section, so no private numeric attach-type workaround is needed.

## Running the Tests

The integration test runs four scenarios against the built binary:

```bash
sudo make test
```

The test validates:

1. An unmatched PID (2^32 - 1) produces zero calls, proving the TGID filter works.
2. A 10-second threshold (10,000,000 us) produces no slow events even though reads complete, proving the threshold comparison works.
3. A 10 ms threshold with a pipe read delayed by 50 ms produces at least one slow event, proving the end-to-end reporting path works.
4. Threshold 0 with continuous target-TGID reads through the one-second deadline produces calls and events, and the CLI still exits successfully. The test also asserts `slow == events + dropped`, so every slow call at the window boundary is either delivered or explicitly counted as a ring-buffer reservation drop.

## Requirements

| Requirement | Value |
|---|---|
| Minimum kernel | Linux 7.0 |
| Minimum libbpf | 1.7.0 |
| Architecture | x86_64 (tested) |
| BTF | Required |
| Privilege | root |
| Kernel configs | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y` |
| Runtime | BPF JIT enabled; `vfs_read` present in kernel BTF and traceable |

## Limitations

- Measures time inside `vfs_read` only. This is not full request latency, storage-device service time, or application p99.
- Covers only paths that invoke `vfs_read`. mmap and other paths that bypass it are invisible.
- Exact TGID filter only. No cgroup, process-tree, path, inode, mount, PID-namespace, or container selector. The filter operates on the host-namespace TGID; there is no way to pass a namespace-local PID or select by container runtime.
- One-shot duration. Not a daemon, alerting system, or metrics exporter.
- Ring buffer can drop matching events under load. The `dropped` counter exposes that condition; other counters remain aggregate observations.
- Command names can repeat and PID reuse is possible outside the bounded tracing window.
- No user/kernel stack capture and no filename/path resolution.

## References

- [Linux fsession merge commit](https://github.com/torvalds/linux/commit/f17b474e36647c23801ef8fdaf2255ab66dd2973)
- [Upstream fsession BPF selftest (prog)](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/fsession_test.c)
- [Upstream fsession BPF selftest (runner)](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/fsession_test.c)
- [libbpf 1.7.0 release](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)

## More eBPF Tutorials

- Tutorial repository: <https://github.com/eunomia-bpf/bpf-developer-tutorial>
- Tutorial site: <https://eunomia.dev/tutorials/>
