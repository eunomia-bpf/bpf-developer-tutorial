# eBPF Tutorial: Tracing Slow vfs_read Calls with fsession

When a file-backed service shows read-latency spikes, application-level timing tells you that requests slowed down, but it cannot distinguish whether the kernel blocked on I/O or user-space logic took too long. The useful questions are: which thread issued the read, how many bytes did it request, what did the call return, and how long did that single `vfs_read` invocation take?

This tutorial demonstrates how to measure `vfs_read` call latency using the **fsession** mechanism introduced in Linux 7.0. fsession is a new eBPF program type that runs once at function entry and once at return, with built-in per-invocation storage for correlating the two phases. The tool we build timestamps function entry, computes latency at return, filters by process and threshold, and reports slow-read events through a ring buffer.

> Complete source: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/52-fsession-latency>

## The Problem: Correlating Function Entry and Return

To measure how long a kernel function takes, you need to record a timestamp when it starts and compute the difference when it returns. This sounds simple, but the traditional approaches in eBPF all have drawbacks.

### Traditional Approach: Two Programs with a Hash Map

The most common pattern uses two separate BPF programs - one attached to function entry (fentry), one to function return (fexit). The entry program records the timestamp in a hash map keyed by thread ID; the return program looks up the timestamp, computes latency, and deletes the entry:

```
Entry program:                          Return program:
1. Get thread ID                        1. Get thread ID
2. Get timestamp                        2. Look up timestamp from map
3. Store timestamp in hash map          3. Compute latency
                                        4. Delete entry from map
                                        5. Report event
```

This works, but has several problems:

- **Map overhead**: Every function call requires a hash map insertion at entry and a lookup plus deletion at return. For high-frequency functions like `vfs_read`, this overhead adds up.
- **State leaks**: If a thread is killed between entry and return (e.g., `kill -9`), the hash map entry is never deleted and leaks memory.
- **No intrinsic relationship**: The two programs are completely independent. The only thing connecting them is the external hash map - there's no guarantee they're actually tracking the same function invocation.

### kprobe/kretprobe: Same Pattern, Higher Overhead

The kprobe mechanism has the same two-program structure and requires the same external hash map for correlation. Additionally, kprobes work through a software breakpoint mechanism (replacing the first instruction with an interrupt), which has higher overhead than fentry hooks that use the kernel's ftrace infrastructure and JIT-optimized call sequences.

### User-Space Sampling: Statistical, Not Precise

Tools like `perf record` sample stack traces periodically and can build statistical profiles of where time is spent. However, sampling cannot measure the latency of individual function calls. If you need to capture tail-latency events - the occasional 100ms read that causes a timeout - statistical sampling may miss them entirely.

## The fsession Solution

Linux 7.0 introduced **fsession**, which solves the correlation problem at the kernel level. When you declare a BPF program with `SEC("fsession/vfs_read")`, the kernel:

1. Calls your program once when `vfs_read` enters
2. Allocates an 8-byte scratch area (the "session cookie") tied to this specific invocation
3. Calls your program again when `vfs_read` returns
4. Deallocates the session cookie

The key insight is that the session cookie is automatically managed and scoped to exactly one function invocation. Your program distinguishes entry from return using `bpf_session_is_return(ctx)`, and reads or writes the cookie using `bpf_session_cookie(ctx)`.

### What the Session Cookie Replaces

In the traditional approach, you'd use a hash map like this:

```c
// Traditional: hash map keyed by thread ID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);    // pid_tgid
    __type(value, u64);  // timestamp
} start SEC(".maps");
```

With fsession, this entire map disappears. The timestamp lives in the session cookie:

```c
// fsession: per-invocation cookie, no map needed
__u64 *started = bpf_session_cookie(ctx);
*started = bpf_ktime_get_ns();
```

The cookie persists from entry to return and is automatically cleaned up afterward - no leaks possible.

### Return-Phase Context Includes Function Arguments

Another fsession advantage: the return-phase context includes both the original function arguments and the return value. In the traditional approach, if you need access to function arguments at return time (e.g., to include the requested byte count in your event), you must store them in the hash map at entry. With fsession, arguments are directly available:

```c
SEC("fsession/vfs_read")
int BPF_PROG(measure_vfs_read, struct file *file, char *buf, size_t count,
             loff_t *pos, ssize_t ret)
{
    // At return, 'count' and 'ret' are both available
    // No need to store 'count' anywhere at entry
}
```

## Code Implementation

This tool consists of three files:
- `fsession_latency.h`: Shared data structures for BPF and user space
- `fsession_latency.bpf.c`: The BPF program that measures latency
- `fsession_latency.c`: User-space loader that manages the BPF lifecycle and prints results

### Shared Header

`fsession_latency.h` defines the event structure sent through the ring buffer and the aggregate statistics structure:

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
	unsigned int device_major;
	unsigned int device_minor;
	unsigned long long inode;
	unsigned int mode;
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

The four counters track:
- `calls`: Total `vfs_read` invocations observed
- `slow`: Calls that met or exceeded the latency threshold
- `errors`: Calls where `vfs_read` returned a negative error code
- `dropped`: Events that couldn't be submitted because the ring buffer was full

`FSESSION_COMM_LEN` is 16 to match the kernel's `TASK_COMM_LEN`.

Each event also carries `device_major`, `device_minor`, `inode`, and `mode`. The BPF program splits the kernel's raw `s_dev` encoding into its 12-bit major and 20-bit minor fields. Combined with `i_ino`, this gives a stable VFS object identity; `i_mode` lets user space print `regular`, `fifo`, `character`, and other object types.

### BPF Program

`fsession_latency.bpf.c` is the core of the tool. Here is the complete kernel-side program:

```c
// SPDX-License-Identifier: GPL-2.0
#define bpf_session_is_return bpf_session_is_return_vmlinux_snapshot
#define bpf_session_cookie bpf_session_cookie_vmlinux_snapshot
#include "vmlinux.h"
#undef bpf_session_is_return
#undef bpf_session_cookie
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "fsession_latency.h"

#define KERNEL_MINOR_BITS 20
#define KERNEL_MINOR_MASK ((1U << KERNEL_MINOR_BITS) - 1)

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
	struct inode *inode;
	__u32 device;
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

	__builtin_memset(event, 0, sizeof(*event));
	event->pid = (__u32)pid_tgid;
	event->tgid = pid_tgid >> 32;
	event->requested = count;
	event->result = ret;
	event->latency_ns = latency;
	inode = BPF_CORE_READ(file, f_inode);
	if (inode) {
		device = BPF_CORE_READ(inode, i_sb, s_dev);
		event->device_major = device >> KERNEL_MINOR_BITS;
		event->device_minor = device & KERNEL_MINOR_MASK;
		event->inode = BPF_CORE_READ(inode, i_ino);
		event->mode = BPF_CORE_READ(inode, i_mode);
	}
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	bpf_ringbuf_submit(event, 0);
	return 0;
}
```

The walkthrough below explains the same program section by section.

```c
// SPDX-License-Identifier: GPL-2.0
#define bpf_session_is_return bpf_session_is_return_vmlinux_snapshot
#define bpf_session_cookie bpf_session_cookie_vmlinux_snapshot
#include "vmlinux.h"
#undef bpf_session_is_return
#undef bpf_session_cookie
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "fsession_latency.h"

#define KERNEL_MINOR_BITS 20
#define KERNEL_MINOR_MASK ((1U << KERNEL_MINOR_BITS) - 1)

char LICENSE[] SEC("license") = "GPL";
```

The macro dance at the top is a compatibility workaround. The repository's `vmlinux.h` snapshot was generated before Linux 7.0 added a `ctx` argument to `bpf_session_is_return` and `bpf_session_cookie`. The macros rename the old declarations during the include, then we provide the correct signatures below. A `vmlinux.h` regenerated from kernel 7.0+ wouldn't need this.

```c
const volatile __u64 threshold_ns;
const volatile __u32 target_tgid;

struct latency_stats stats;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");
```

`const volatile` variables in BPF programs have special semantics. They're placed in the `.rodata` section and can be set by user space after opening the skeleton but before loading. Once loaded, the verifier treats them as compile-time constants, enabling optimizations like dead-code elimination when `target_tgid` is 0.

`stats` is a global variable in the `.bss` section, directly readable from user space after the program runs.

The ring buffer (`events`) is sized at 256 KB - enough for thousands of events before overflow.

```c
/*
 * The repository vmlinux.h snapshot predates the ctx argument on these
 * kfunc prototypes. Rename those stale declarations while including the
 * snapshot, then provide the Linux 7.0 signatures below.
 */
extern bool bpf_session_is_return(void *ctx) __ksym;
extern __u64 *bpf_session_cookie(void *ctx) __ksym;
```

These are **kfunc** declarations - kernel functions exported for BPF programs to call. The `__ksym` attribute tells the verifier to resolve these symbols from the running kernel at load time, rather than expecting them to be defined in the BPF object.

```c
SEC("fsession/vfs_read")
int BPF_PROG(measure_vfs_read, struct file *file, char *buf, size_t count,
	     loff_t *pos, ssize_t ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 *started = bpf_session_cookie(ctx);
	struct latency_event *event;
	struct inode *inode;
	__u32 device;
	__u64 latency;
```

The `SEC("fsession/vfs_read")` tells the kernel this is an fsession program attached to `vfs_read`. The `BPF_PROG` macro expands to set up the standard tracing context; `ctx` is implicitly available for passing to kfuncs.

The function signature lists `vfs_read`'s parameters followed by its return value. At entry, `ret` is undefined; at return, all parameters and the return value are valid.

```c
	if (!bpf_session_is_return(ctx)) {
		if (target_tgid && pid_tgid >> 32 != target_tgid) {
			*started = 0;
			return 0;
		}
		*started = bpf_ktime_get_ns();
		return 0;
	}
```

**Entry phase**: First, check if we should filter this call. If `target_tgid` is set (non-zero) and the current process's TGID doesn't match, write 0 to the cookie to mark this invocation as "skip" and return. Otherwise, write the current monotonic timestamp to the cookie.

The TGID is in the upper 32 bits of `bpf_get_current_pid_tgid()`'s return value; the lower 32 bits are the thread ID (PID in kernel terms).

```c
	if (!*started)
		return 0;

	latency = bpf_ktime_get_ns() - *started;
	__sync_fetch_and_add(&stats.calls, 1);
	if (ret < 0)
		__sync_fetch_and_add(&stats.errors, 1);
	if (latency < threshold_ns)
		return 0;
```

**Return phase**: If the cookie is 0, the entry phase filtered this call - return immediately. Otherwise, compute latency and update the aggregate counters. The `__sync_fetch_and_add` provides atomic updates since multiple CPUs may execute this program concurrently.

If the latency is below the threshold, we're done - the call is counted but no event is emitted. This keeps the ring buffer focused on slow calls.

```c
	__sync_fetch_and_add(&stats.slow, 1);
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&stats.dropped, 1);
		return 0;
	}

	__builtin_memset(event, 0, sizeof(*event));
	event->pid = (__u32)pid_tgid;
	event->tgid = pid_tgid >> 32;
	event->requested = count;
	event->result = ret;
	event->latency_ns = latency;
	inode = BPF_CORE_READ(file, f_inode);
	if (inode) {
		device = BPF_CORE_READ(inode, i_sb, s_dev);
		event->device_major = device >> KERNEL_MINOR_BITS;
		event->device_minor = device & KERNEL_MINOR_MASK;
		event->inode = BPF_CORE_READ(inode, i_ino);
		event->mode = BPF_CORE_READ(inode, i_mode);
	}
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	bpf_ringbuf_submit(event, 0);
	return 0;
}
```

For slow calls, increment the `slow` counter and try to reserve space in the ring buffer. If the reservation fails (buffer full), increment `dropped` so the user knows events were lost. On success, zero the event, copy call fields, and read object identity from `file->f_inode` before submitting it.

Note that both `count` and `file` are available directly - no need to store either at entry. This is the fsession advantage: function arguments persist to the return phase. The tool intentionally does not resolve a path; paths can be renamed or have multiple aliases. For a regular file, use the device to identify the mount and search it by inode, for example `find /mount -xdev -inum INODE -print`.

### User-Space Loader

`fsession_latency.c` handles command-line parsing, BPF lifecycle management, and event consumption. The key sections:

**Configuration via read-only data**:
```c
skel->rodata->threshold_ns = env.threshold_us * 1000;
skel->rodata->target_tgid = env.pid;
```

After opening the skeleton but before loading, user space writes the threshold (converted from microseconds to nanoseconds) and target TGID to the `.rodata` section. These become constants in the BPF program.

**Ring buffer consumption**:
```c
static int handle_event(void *context, void *data, size_t size)
{
	const struct latency_event *event = data;

	printf("EVENT comm=%-16s tgid=%u pid=%u object=%u:%u:%llu type=%s "
	       "requested=%llu result=%lld latency_us=%llu\n",
	       event->comm, event->tgid, event->pid,
	       event->device_major, event->device_minor, event->inode,
	       file_type(event->mode), event->requested, event->result,
	       event->latency_ns / 1000);
	events_printed++;
	return 0;
}
```

Each event is printed with the process name, IDs, VFS identity and type, requested bytes, return value, and latency in microseconds.

**Clean shutdown sequence**:
```c
fsession_latency_bpf__detach(skel);

err = ring_buffer__consume(ring);
// ... error handling ...

printf("SUMMARY calls=%llu slow=%llu errors=%llu dropped=%llu events=%llu\n",
       skel->bss->stats.calls, skel->bss->stats.slow,
       skel->bss->stats.errors, skel->bss->stats.dropped, events_printed);
```

The shutdown order matters for correctness:
1. Detach the BPF program (stops new events from being generated)
2. Drain remaining events from the ring buffer
3. Read the final counter values (now stable since the program is detached)

This ensures `events_printed` matches the events actually delivered through the ring buffer.

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

**Note about PID namespaces**: The `--pid` option compares against the TGID in the host (initial) PID namespace. If your target runs in a container with its own PID namespace, you need to find its host-visible TGID. Inside the container the process might be PID 1, but from the host it could be PID 12345. Use `pgrep` on the host or inspect `/proc/<pid>/status` for the `NSpid` line.

### Command-Line Options

```text
Usage: ./fsession_latency [--threshold-us USEC] [--duration SEC] [--pid TGID] [--verbose]

Options:
  -t, --threshold-us USEC  slow-read threshold (default: 1000 microseconds)
  -d, --duration SEC       trace duration, 1-86400 (default: 10 seconds)
  -p, --pid TGID           trace a specific process ID (default: all processes)
  -v, --verbose            print libbpf diagnostics
  -h, --help               show this help
```

### Example Output

For example, a Python service waiting on a FIFO can produce this output when the writer responds after 50 ms:

```console
Tracing vfs_read for 1 seconds; threshold=10000 us; pid=selected
EVENT comm=python3          tgid=1245 pid=1245 object=0:16:784 type=fifo requested=1 result=1 latency_us=50246
SUMMARY calls=66 slow=1 errors=0 dropped=0 events=1
```

The `SUMMARY` line shows:
- 66 total `vfs_read` calls were observed
- 1 was slow (met the threshold)
- 0 returned errors
- 0 events were dropped
- 1 event was printed

## Environment Requirements

| Requirement | Details |
|---|---|
| Kernel version | Linux 7.0+ (fsession first introduced) |
| BTF | Must be enabled (`CONFIG_DEBUG_INFO_BTF=y`) |
| Kernel config | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y` |
| BPF JIT | Must be enabled at runtime |
| Architecture | Tested on x86_64 |
| Privilege | root |

The upstream merge commit is `f17b474e36647c23801ef8fdaf2255ab66dd2973`.

## Extending This Tool

The fsession pattern demonstrated here applies to any kernel function where you need to correlate entry and return. Some directions for extension:

- **Additional functions**: Attach to `vfs_write`, `vfs_fsync`, or other VFS operations
- **File path filtering**: Use `file->f_path` to filter by specific files or mount points
- **Stack traces**: Add `bpf_get_stackid()` to capture kernel and/or user stack traces for slow calls
- **Histograms**: Replace per-event reporting with latency histograms using `BPF_MAP_TYPE_ARRAY`
- **cgroup filtering**: Add cgroup ID checks for container-aware tracing

The `dropped` counter remains the signal for ring buffer pressure - if it's growing, either increase the buffer size or raise the threshold to reduce event volume.

## Summary

This tutorial demonstrated how to measure kernel function latency using the fsession mechanism in Linux 7.0. The key advantages over the traditional fentry/fexit with hash map approach:

1. **Single program**: One BPF program handles both entry and return, with `bpf_session_is_return()` distinguishing the phases
2. **Built-in correlation**: The 8-byte session cookie replaces the external hash map for passing data between phases
3. **No state leaks**: The kernel manages cookie lifecycle - no cleanup required, no leaks possible
4. **Arguments available at return**: Function parameters persist to the return phase without explicit storage

For this `vfs_read` example, that last property also lets the return phase report the VFS object's device, inode, and type. Treat the result as generic VFS-call latency; use the object identity for follow-up rather than assuming every slow event is a disk problem.

The pattern is simple: check `bpf_session_is_return()`, use `bpf_session_cookie()` for per-invocation state, and access arguments/return value directly. This applies wherever you need to correlate function entry and exit.

> To learn more about eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit <https://eunomia.dev/tutorials/>.

## References

- [Linux fsession merge commit](https://github.com/torvalds/linux/commit/f17b474e36647c23801ef8fdaf2255ab66dd2973)
- [Upstream fsession program selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/fsession_test.c)
- [Upstream fsession runner selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/fsession_test.c)
- [libbpf 1.7.0](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
- [bpftool v7.7.0](https://github.com/libbpf/bpftool/releases/tag/v7.7.0)
