# eBPF Tutorial by Example 32: Wall Clock Profiling with Combined On-CPU and Off-CPU Analysis

Performance bottlenecks can hide in two very different places. Your code might be burning CPU cycles in hot loops, or it might be sitting idle waiting for I/O, network responses, or lock contention. Traditional profilers often focus on just one side of this story. But what if you could see both at once?

This tutorial introduces a complete wall clock profiling solution that combines on-CPU and off-CPU analysis using eBPF. We'll show you how to capture the full picture of where your application spends its time, using two complementary eBPF programs that work together to account for every microsecond of execution. Whether your performance problems come from computation or waiting, you'll be able to spot them in a unified flame graph view.

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/32-wallclock-profiler>

## Understanding Wall Clock Profiling

Wall clock time is the actual elapsed time from start to finish, like checking a stopwatch. For any running process, this time gets divided into two categories. On-CPU time is when your code actively executes on a processor, doing real work. Off-CPU time is when your process exists but isn't running, waiting for something like disk I/O, network packets, or acquiring a lock.

Traditional CPU profilers only show you the on-CPU story. They sample the stack at regular intervals when your code runs, building a picture of which functions consume CPU cycles. But these profilers are blind to off-CPU time. When your thread blocks on a system call or waits for a mutex, the profiler stops seeing it. This creates a massive blind spot for applications that spend significant time waiting.

Off-CPU profilers flip the problem around. They track when threads go to sleep and wake up, measuring blocked time and capturing stack traces at blocking points. This reveals I/O bottlenecks and lock contention. But they miss pure computation problems.

The tools in this tutorial solve both problems by running two eBPF programs simultaneously. The `oncputime` tool samples on-CPU execution using perf events. The `offcputime` tool hooks into the kernel scheduler to catch blocking operations. A Python script combines the results, normalizing the time scales so you can see CPU-intensive code paths (marked red) and blocking operations (marked blue) in the same flame graph. This complete view shows where every microsecond goes.

Here's an example flame graph showing combined on-CPU and off-CPU profiling results:

![Combined Wall Clock Flame Graph Example](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/32-wallclock-profiler/tests/example.svg)

In this visualization, you can clearly see the distinction between CPU-intensive work (shown in red/warm colors marked with `_[c]`) and blocking operations (shown in blue/cool colors marked with `_[o]`). The relative widths immediately reveal where your application spends its wall clock time.

## The Tools: oncputime and offcputime

This tutorial provides two complementary profiling tools. The `oncputime` tool samples your process at regular intervals using perf events, capturing stack traces when code actively runs on the CPU. At a default rate of 49 Hz, it wakes up roughly every 20 milliseconds to record where your program is executing. Higher sample counts in the output indicate more CPU time spent in those code paths.

The `offcputime` tool takes a different approach. It hooks into the kernel scheduler's context switch mechanism, specifically the `sched_switch` tracepoint. When your thread goes off-CPU, the tool records a timestamp and captures the stack trace showing why it blocked. When the thread returns to running, it calculates how long the thread was sleeping. This directly measures I/O waits, lock contention, and other blocking operations in microseconds.

Both tools use BPF stack maps to efficiently capture kernel and user space call chains with minimal overhead. They aggregate results by unique stack traces, so repeated execution of the same code path gets summed together. The tools can filter by process ID, thread ID, and various other criteria to focus analysis on specific parts of your application.

## Implementation: Kernel-Space eBPF Programs

Let's examine how these tools work at the eBPF level. We'll start with the on-CPU profiler, then look at the off-CPU profiler, and see how they complement each other.

### On-CPU Profiling with oncputime

The on-CPU profiler uses perf events to sample execution at regular time intervals. Here's the complete eBPF program:

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "oncputime.h"

const volatile bool kernel_stacks_only = false;
const volatile bool user_stacks_only = false;
const volatile bool include_idle = false;
const volatile bool filter_by_pid = false;
const volatile bool filter_by_tid = false;

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_PID_NR);
} pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_TID_NR);
} tids SEC(".maps");

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
	u64 *valp;
	static const u64 zero;
	struct key_t key = {};
	u64 id;
	u32 pid;
	u32 tid;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = id;

	if (!include_idle && tid == 0)
		return 0;

	if (filter_by_pid && !bpf_map_lookup_elem(&pids, &pid))
		return 0;

	if (filter_by_tid && !bpf_map_lookup_elem(&tids, &tid))
		return 0;

	key.pid = pid;
	bpf_get_current_comm(&key.name, sizeof(key.name));

	if (user_stacks_only)
		key.kern_stack_id = -1;
	else
		key.kern_stack_id = bpf_get_stackid(&ctx->regs, &stackmap, 0);

	if (kernel_stacks_only)
		key.user_stack_id = -1;
	else
		key.user_stack_id = bpf_get_stackid(&ctx->regs, &stackmap,
						    BPF_F_USER_STACK);

	valp = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (valp)
		__sync_fetch_and_add(valp, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

The program starts by defining several BPF maps. The `stackmap` is a special map type for storing stack traces. When you call `bpf_get_stackid()`, the kernel walks the stack and stores the instruction pointers in this map, returning an ID you can use to look it up later. The `counts` map aggregates samples by a composite key that includes both the process ID and the stack IDs. The `pids` and `tids` maps act as filters, letting you restrict profiling to specific processes or threads.

The main logic lives in the `do_perf_event()` function, which runs every time a perf event fires. The user space program sets up these perf events at a specific frequency (default 49 Hz), one per CPU core. When a CPU triggers its timer, this function executes on whatever process happens to be running at that moment. It first extracts the process and thread IDs from the current task, then applies any configured filters. If the current thread should be sampled, it builds a key structure that includes the process name and stack traces.

The two calls to `bpf_get_stackid()` capture different pieces of the execution context. The first call without flags gets the kernel stack, showing what kernel functions were active. The second call with `BPF_F_USER_STACK` gets the user space stack, showing your application's function calls. These stack IDs go into the key, and the program increments a counter for that unique combination. Over time, hot code paths get sampled more frequently, building up higher counts.

### Off-CPU Profiling with offcputime

The off-CPU profiler hooks into the scheduler to measure blocking time. Here's the complete eBPF program:

```c
// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "offcputime.h"

#define PF_KTHREAD		0x00200000

const volatile bool kernel_threads_only = false;
const volatile bool user_threads_only = false;
const volatile __u64 max_block_ns = -1;
const volatile __u64 min_block_ns = 0;
const volatile bool filter_by_tgid = false;
const volatile bool filter_by_pid = false;
const volatile long state = -1;

struct internal_key {
	u64 start_ts;
	struct key_t key;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct internal_key);
	__uint(max_entries, MAX_ENTRIES);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, struct val_t);
	__uint(max_entries, MAX_ENTRIES);
} info SEC(".maps");

static bool allow_record(struct task_struct *t)
{
	u32 tgid = BPF_CORE_READ(t, tgid);
	u32 pid = BPF_CORE_READ(t, pid);

	if (filter_by_tgid && !bpf_map_lookup_elem(&tgids, &tgid))
		return false;
	if (filter_by_pid && !bpf_map_lookup_elem(&pids, &pid))
		return false;
	if (user_threads_only && (BPF_CORE_READ(t, flags) & PF_KTHREAD))
		return false;
	else if (kernel_threads_only && !(BPF_CORE_READ(t, flags) & PF_KTHREAD))
		return false;
	if (state != -1 && get_task_state(t) != state)
		return false;
	return true;
}

static int handle_sched_switch(void *ctx, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	struct internal_key *i_keyp, i_key;
	struct val_t *valp, val;
	s64 delta;
	u32 pid;

	if (allow_record(prev)) {
		pid = BPF_CORE_READ(prev, pid);
		if (!pid)
			pid = bpf_get_smp_processor_id();
		i_key.key.pid = pid;
		i_key.key.tgid = BPF_CORE_READ(prev, tgid);
		i_key.start_ts = bpf_ktime_get_ns();

		if (BPF_CORE_READ(prev, flags) & PF_KTHREAD)
			i_key.key.user_stack_id = -1;
		else
			i_key.key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
		i_key.key.kern_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
		bpf_map_update_elem(&start, &pid, &i_key, 0);
		bpf_probe_read_kernel_str(&val.comm, sizeof(prev->comm), BPF_CORE_READ(prev, comm));
		val.delta = 0;
		bpf_map_update_elem(&info, &i_key.key, &val, BPF_NOEXIST);
	}

	pid = BPF_CORE_READ(next, pid);
	i_keyp = bpf_map_lookup_elem(&start, &pid);
	if (!i_keyp)
		return 0;
	delta = (s64)(bpf_ktime_get_ns() - i_keyp->start_ts);
	if (delta < 0)
		goto cleanup;
	if (delta < min_block_ns || delta > max_block_ns)
		goto cleanup;
	delta /= 1000U;
	valp = bpf_map_lookup_elem(&info, &i_keyp->key);
	if (!valp)
		goto cleanup;
	__sync_fetch_and_add(&valp->delta, delta);

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_sched_switch(ctx, preempt, prev, next);
}

char LICENSE[] SEC("license") = "GPL";
```

The off-CPU profiler is more complex because it needs to track timing across multiple events. The `start` map stores timestamps and stack information for threads that go off-CPU. When a thread blocks, we record when it happened and why (the stack trace). When that same thread returns to running, we calculate how long it was blocked.

The scheduler switch happens many times per second on a busy system, so performance matters. The `allow_record()` function quickly filters out threads we don't care about before doing expensive operations. If a thread passes the filter, the program captures the current timestamp using `bpf_ktime_get_ns()` and records the stack traces showing where the thread blocked.

The key insight is in the two-stage approach. The `prev` task (the thread going off-CPU) gets its blocking point recorded with a timestamp. When the scheduler later switches to the `next` task (a thread waking up), we look up whether we previously recorded this thread going to sleep. If we find a record, we calculate the delta between now and when it went to sleep. This delta is the off-CPU time in nanoseconds, which we convert to microseconds and add to the accumulated total for that stack trace.

### User-Space Programs: Loading and Processing

Both tools follow a similar pattern in user space. They use libbpf to load the compiled eBPF object file and attach it to the appropriate event. For `oncputime`, this means setting up perf events at the desired sampling frequency. For `offcputime`, it means attaching to the scheduler tracepoint. The user space programs then periodically read the BPF maps, resolve the stack IDs to actual function names using symbol tables, and format the output.

The symbol resolution is handled by the blazesym library, which parses DWARF debug information from binaries. When you see a stack trace with function names and line numbers, that's blazesym converting raw instruction pointer addresses into human-readable form. The user space programs output in "folded" format, where each line contains a semicolon-separated stack trace followed by a count or time value. This format feeds directly into flame graph generation tools.

## Combining On-CPU and Off-CPU Profiles

The real power comes from running both tools together and merging their results. The `wallclock_profiler.py` script orchestrates this process. It launches both profilers simultaneously on the target process, waits for them to complete, and then combines their outputs.

The challenge is that the two tools measure different things in different units. The on-CPU profiler counts samples (49 per second by default), while the off-CPU profiler measures microseconds. To create a unified view, the script normalizes the off-CPU time to equivalent sample counts. If sampling at 49 Hz, each sample represents about 20,408 microseconds of potential execution time. The script divides off-CPU microseconds by this value to get equivalent samples.

After normalization, the script adds annotations to distinguish the two types of time. On-CPU stack traces get a `_[c]` suffix (for compute), while off-CPU stacks get `_[o]` (for off-CPU or blocking). A custom color palette in the flame graph tool renders these different colors, red for CPU time and blue for blocking time. The result is a single flame graph where you can see both types of activity and their relative magnitudes.

The script also handles multi-threaded applications by profiling each thread separately. It detects threads at startup, launches parallel profiling sessions for each one, and generates individual flame graphs showing per-thread behavior. This helps identify which threads are busy versus idle, and whether your parallelism is effective.

## Compilation and Execution

Building the tools requires a standard eBPF development environment. The tutorial repository includes all dependencies in the `src/third_party/` directory. To build:

```bash
cd src/32-wallclock-profiler
make
```

The Makefile compiles the eBPF C code with clang, generates skeletons with bpftool, builds the blazesym symbol resolver, and links everything with libbpf to create the final executables.

To use the individual tools:

```bash
# Profile on-CPU execution for 30 seconds
sudo ./oncputime -p <PID> -F 99 30

# Profile off-CPU blocking for 30 seconds
sudo ./offcputime -p <PID> -m 1000 30

# Use the combined profiler (recommended)
sudo python3 wallclock_profiler.py <PID> -d 30 -f 99
```

Let's try profiling a test program that does both CPU work and blocking I/O:

```bash
# Build and run the test program
cd tests
make
./test_combined &
TEST_PID=$!

# Profile it with the combined profiler
cd ..
sudo python3 wallclock_profiler.py $TEST_PID -d 30

# This generates:
# - combined_profile_pid<PID>_<timestamp>.folded (raw data)
# - combined_profile_pid<PID>_<timestamp>.svg (flame graph)
# - combined_profile_pid<PID>_<timestamp>_single_thread_analysis.txt (time breakdown)
```

The output flame graph will show red frames for the `cpu_work()` function consuming CPU time, and blue frames for the `blocking_work()` function spending time in sleep. The relative widths show how much wall clock time each consumes.

For multi-threaded applications, the profiler creates a directory with per-thread results:

```bash
# Profile a multi-threaded application
sudo python3 wallclock_profiler.py <PID> -d 30

# Output in multithread_combined_profile_pid<PID>_<timestamp>/
# - thread_<TID>_main.svg (main thread flame graph)
# - thread_<TID>_<role>.svg (worker thread flame graphs)
# - *_thread_analysis.txt (time analysis for all threads)
```

The analysis files show time accounting, letting you verify that on-CPU plus off-CPU time adds up correctly to the wall clock profiling duration. Coverage percentages help identify if threads are mostly idle or if you're missing data.

## Interpreting the Results

When you open the flame graph SVG in a browser, each horizontal box represents a function in a stack trace. The width shows how much time was spent there. Boxes stacked vertically show the call chain, with lower boxes calling higher ones. Red boxes indicate on-CPU time, blue boxes show off-CPU time.

Look for wide red sections to find CPU bottlenecks. These are functions burning through cycles in tight loops or expensive algorithms. Wide blue sections indicate blocking operations. Common patterns include file I/O (read/write system calls), network operations (recv/send), and lock contention (futex calls).

The flame graph is interactive. Click any box to zoom in and see details about that subtree. The search function lets you highlight all frames matching a pattern, useful for finding specific functions or libraries. Hovering shows the full function name and exact sample count or time value.

Pay attention to the relative proportions. An application that's 90% blue is I/O bound and probably won't benefit much from CPU optimization. One that's mostly red is CPU bound. Applications split evenly between red and blue might benefit from overlapping computation and I/O, such as using asynchronous I/O or threading.

For multi-threaded profiles, compare the per-thread flame graphs. Ideally, worker threads should show similar patterns if the workload is balanced. If one thread is mostly red while others are mostly blue, you might have load imbalance. If all threads show lots of blue time in futex waits with similar stacks, that's lock contention.

## Summary

Wall clock profiling with eBPF gives you complete visibility into application performance by combining on-CPU and off-CPU analysis. The on-CPU profiler samples execution to find hot code paths that consume CPU cycles. The off-CPU profiler hooks into the scheduler to measure blocking time and identify I/O bottlenecks or lock contention. Together, they account for every microsecond of wall clock time, showing where your application actually spends its life.

The tools use eBPF's low-overhead instrumentation to collect this data with minimal impact on the target application. Stack trace capture and aggregation happen in the kernel, avoiding expensive context switches. The user space programs only need to periodically read accumulated results and resolve symbols, making the overhead negligible even for production use.

By visualizing both types of time in a single flame graph with color coding, you can quickly identify whether problems are computational or blocking in nature. This guides optimization efforts more effectively than traditional profiling approaches that only show one side of the picture. Multi-threaded profiling support reveals parallelism issues and thread-level bottlenecks.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## Reference

- BCC libbpf-tools offcputime: <https://github.com/iovisor/bcc/tree/master/libbpf-tools>
- BCC libbpf-tools profile: <https://github.com/iovisor/bcc/tree/master/libbpf-tools>
- Blazesym symbol resolution: <https://github.com/libbpf/blazesym>
- FlameGraph visualization: <https://github.com/brendangregg/FlameGraph>
- "Off-CPU Analysis" by Brendan Gregg: <http://www.brendangregg.com/offcpuanalysis.html>

> The original link of this article: <https://eunomia.dev/tutorials/32-wallclock-profiler>
