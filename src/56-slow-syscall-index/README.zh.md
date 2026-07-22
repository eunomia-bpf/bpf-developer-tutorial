# eBPF 实战教程：慢系统调用延迟索引

应用程序中哪些系统调用耗时最长？本教程构建一个工具，使用 BPF 任务本地存储跟踪每个进程的系统调用延迟，按 TGID 和系统调用号聚合结果，并按总延迟排名，最终找出哪些慢系统调用占据了最多的观测延迟。

> 完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/56-slow-syscall-index>

## eBPF 与系统调用跟踪

eBPF 让经过验证器检查的程序运行在 Linux 内核 hook 上，并把选出的状态发送到用户态。本教程使用 `raw_syscalls/sys_enter` 和 `raw_syscalls/sys_exit` 跟踪点，它们在系统范围内每次系统调用进入和退出时触发。为了关联进入和退出，我们使用 Linux 5.11 引入的 BPF 任务本地存储，把状态直接附加到 task 结构上，并由内核在任务退出时清理。这里测量的是系统调用从进入到退出的挂钟延迟，而不是只统计调度器阻塞时间，因此本例需要 Linux 5.11 或更高版本。

## 实现原理

该工具附加到原始系统调用进入和退出跟踪点。在进入时，它在任务本地存储中记录开始时间戳和系统调用 ID。在退出时，它计算持续时间并报告超过配置阈值的事件。用户空间按 TGID 和系统调用聚合事件，跟踪计数、总延迟、最大延迟和错误计数。

## 头文件

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SLOW_SYSCALL_INDEX_H
#define __SLOW_SYSCALL_INDEX_H

#define SLOW_SYSCALL_COMM_LEN 16

struct slow_syscall_event {
	unsigned long long timestamp_ns;
	unsigned long long duration_ns;
	long long return_value;
	unsigned int tgid;
	unsigned int tid;
	unsigned int syscall_id;
	char comm[SLOW_SYSCALL_COMM_LEN];
};

#endif /* __SLOW_SYSCALL_INDEX_H */
```

头文件定义了通过 ring buffer 发送到用户空间的事件结构。每个事件包括时间戳、持续时间、返回值、TGID、TID、系统调用号和进程名。

## BPF 程序

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "slow_syscall_index.h"

char LICENSE[] SEC("license") = "GPL";

const volatile __u64 minimum_ns = 10 * 1000 * 1000ULL;
const volatile __u32 target_tgid;
const volatile __u32 ignored_tgid;

struct syscall_state {
	__u64 started_ns;
	__u32 syscall_id;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct syscall_state);
} active_syscalls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

__u64 completed_syscalls;
__u64 slow_syscalls;
__u64 dropped_events;

SEC("tp/raw_syscalls/sys_enter")
int record_syscall_entry(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task;
	struct syscall_state *state;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	if (tgid == ignored_tgid || (target_tgid && tgid != target_tgid))
		return 0;
	task = bpf_get_current_task_btf();
	state = bpf_task_storage_get(&active_syscalls, task, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!state)
		return 0;
	state->started_ns = bpf_ktime_get_ns();
	state->syscall_id = ctx->id;
	return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int report_slow_syscall(struct trace_event_raw_sys_exit *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct slow_syscall_event *event;
	struct syscall_state *state;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 duration_ns;

	state = bpf_task_storage_get(&active_syscalls, task, 0, 0);
	if (!state)
		return 0;
	duration_ns = bpf_ktime_get_ns() - state->started_ns;
	__sync_fetch_and_add(&completed_syscalls, 1);
	if (duration_ns < minimum_ns)
		goto out;

	__sync_fetch_and_add(&slow_syscalls, 1);
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&dropped_events, 1);
		goto out;
	}
	event->timestamp_ns = bpf_ktime_get_ns();
	event->duration_ns = duration_ns;
	event->return_value = ctx->ret;
	event->tgid = pid_tgid >> 32;
	event->tid = (__u32)pid_tgid;
	event->syscall_id = state->syscall_id;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	bpf_ringbuf_submit(event, 0);
out:
	bpf_task_storage_delete(&active_syscalls, task);
	return 0;
}
```

BPF 程序使用 `BPF_MAP_TYPE_TASK_STORAGE` 存储每个任务的系统调用状态。这种映射类型在 Linux 5.11 中引入，提供在任务退出时自动清理的存储。

`record_syscall_entry` 函数在系统调用进入时运行，存储开始时间戳和系统调用 ID。它按目标 TGID 过滤并忽略跟踪器进程本身。

`report_slow_syscall` 函数在系统调用退出时运行。它通过从当前时间减去开始时间戳来计算持续时间。如果持续时间超过阈值，它在 ring buffer 中预留空间，填写事件并提交。每次系统调用后删除任务存储以保持内存使用有界。

程序跟踪三个全局计数器：`completed_syscalls` 计数所有跟踪的系统调用，`slow_syscalls` 计数超过阈值的调用，`dropped_events` 计数 ring buffer 分配失败。

## 用户空间程序

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "slow_syscall_index.h"
#include "slow_syscall_index.skel.h"

#define MAX_STATS 512

struct options {
	unsigned int pid;
	unsigned int minimum_ms;
	unsigned int duration_seconds;
	unsigned int top;
	bool demo;
};

struct syscall_stats {
	unsigned int tgid;
	unsigned int syscall_id;
	unsigned long long count;
	unsigned long long total_ns;
	unsigned long long maximum_ns;
	unsigned long long errors;
	char comm[SLOW_SYSCALL_COMM_LEN];
};

static struct syscall_stats stats[MAX_STATS];
static size_t stats_count;
static volatile sig_atomic_t stop;
static unsigned int received_events;
static unsigned int unaggregated_events;

static void handle_signal(int signal_number)
{
	(void)signal_number;
	stop = 1;
}

static unsigned long long monotonic_ns(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static const char *syscall_name(unsigned int id)
{
	switch (id) {
#ifdef __NR_read
	case __NR_read: return "read";
#endif
#ifdef __NR_write
	case __NR_write: return "write";
#endif
#ifdef __NR_openat
	case __NR_openat: return "openat";
#endif
#ifdef __NR_close
	case __NR_close: return "close";
#endif
#ifdef __NR_fsync
	case __NR_fsync: return "fsync";
#endif
#ifdef __NR_fdatasync
	case __NR_fdatasync: return "fdatasync";
#endif
#ifdef __NR_poll
	case __NR_poll: return "poll";
#endif
#ifdef __NR_ppoll
	case __NR_ppoll: return "ppoll";
#endif
#ifdef __NR_epoll_wait
	case __NR_epoll_wait: return "epoll_wait";
#endif
#ifdef __NR_epoll_pwait
	case __NR_epoll_pwait: return "epoll_pwait";
#endif
#ifdef __NR_futex
	case __NR_futex: return "futex";
#endif
#ifdef __NR_nanosleep
	case __NR_nanosleep: return "nanosleep";
#endif
#ifdef __NR_clock_nanosleep
	case __NR_clock_nanosleep: return "clock_nanosleep";
#endif
#ifdef __NR_connect
	case __NR_connect: return "connect";
#endif
#ifdef __NR_accept
	case __NR_accept: return "accept";
#endif
#ifdef __NR_accept4
	case __NR_accept4: return "accept4";
#endif
#ifdef __NR_recvfrom
	case __NR_recvfrom: return "recvfrom";
#endif
#ifdef __NR_recvmsg
	case __NR_recvmsg: return "recvmsg";
#endif
#ifdef __NR_sendto
	case __NR_sendto: return "sendto";
#endif
#ifdef __NR_sendmsg
	case __NR_sendmsg: return "sendmsg";
#endif
	default: return "unknown";
	}
}

static struct syscall_stats *get_stats(const struct slow_syscall_event *event)
{
	struct syscall_stats *entry;

	for (size_t i = 0; i < stats_count; i++)
		if (stats[i].tgid == event->tgid &&
		    stats[i].syscall_id == event->syscall_id)
			return &stats[i];
	if (stats_count == MAX_STATS)
		return NULL;
	entry = &stats[stats_count++];
	entry->tgid = event->tgid;
	entry->syscall_id = event->syscall_id;
	memcpy(entry->comm, event->comm, sizeof(entry->comm));
	entry->comm[sizeof(entry->comm) - 1] = '\0';
	return entry;
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct slow_syscall_event *event = data;
	struct syscall_stats *entry;

	(void)ctx;
	if (size != sizeof(*event))
		return 0;
	entry = get_stats(event);
	if (entry) {
		entry->count++;
		entry->total_ns += event->duration_ns;
		if (event->duration_ns > entry->maximum_ns)
			entry->maximum_ns = event->duration_ns;
		if (event->return_value < 0)
			entry->errors++;
	} else {
		unaggregated_events++;
	}
	received_events++;
	printf("pid=%u tid=%u comm=%s syscall=%s(%u) latency_ms=%.3f return=%lld\n",
	       event->tgid, event->tid, event->comm,
	       syscall_name(event->syscall_id), event->syscall_id,
	       event->duration_ns / 1000000.0, event->return_value);
	return 0;
}

static int compare_stats(const void *left, const void *right)
{
	const struct syscall_stats *a = left;
	const struct syscall_stats *b = right;

	return a->total_ns < b->total_ns ? 1 : a->total_ns > b->total_ns ? -1 : 0;
}

static void print_summary(unsigned int top)
{
	size_t limit;

	qsort(stats, stats_count, sizeof(stats[0]), compare_stats);
	limit = stats_count < top ? stats_count : top;
	printf("\nSlow syscall index, ranked by total latency:\n");
	printf("%-7s %-16s %-18s %8s %12s %12s %8s\n",
	       "PID", "COMM", "SYSCALL", "COUNT", "TOTAL_MS", "MAX_MS", "ERRORS");
	for (size_t i = 0; i < limit; i++) {
		const struct syscall_stats *entry = &stats[i];

		printf("%-7u %-16s %-12s(%3u) %8llu %12.3f %12.3f %8llu\n",
		       entry->tgid, entry->comm, syscall_name(entry->syscall_id),
		       entry->syscall_id, entry->count,
		       entry->total_ns / 1000000.0,
		       entry->maximum_ns / 1000000.0, entry->errors);
	}
}

static int parse_uint(const char *text, unsigned int maximum,
		      unsigned int *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !*text || *end || parsed > maximum)
		return -1;
	*value = parsed;
	return 0;
}

static void usage(const char *program)
{
	printf("Usage: %s [--pid PID] [--min-ms MS] [--duration SEC] [--top N] [--demo]\n",
	       program);
}

static int parse_options(int argc, char **argv, struct options *options)
{
	static const struct option long_options[] = {
		{ "pid", required_argument, NULL, 'p' },
		{ "min-ms", required_argument, NULL, 'm' },
		{ "duration", required_argument, NULL, 'd' },
		{ "top", required_argument, NULL, 't' },
		{ "demo", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "p:m:d:t:Dh", long_options,
				     NULL)) != -1) {
		switch (option) {
		case 'p':
			if (parse_uint(optarg, 0xffffffffU, &options->pid))
				return -1;
			break;
		case 'm':
			if (parse_uint(optarg, 60000, &options->minimum_ms))
				return -1;
			break;
		case 'd':
			if (parse_uint(optarg, 86400, &options->duration_seconds))
				return -1;
			break;
		case 't':
			if (parse_uint(optarg, MAX_STATS, &options->top))
				return -1;
			break;
		case 'D': options->demo = true; break;
		case 'h': usage(argv[0]); exit(0);
		default: return -1;
		}
	}
	return optind == argc && options->minimum_ms && options->top ? 0 : -1;
}

static pid_t start_demo(int gate[2], int data_pipe[2])
{
	pid_t child = fork();
	char byte;

	if (child)
		return child;
	close(gate[1]);
	close(data_pipe[1]);
	if (read(gate[0], &byte, 1) != 1)
		_exit(2);
	if (read(data_pipe[0], &byte, 1) != 1)
		_exit(3);
	_exit(0);
}

int main(int argc, char **argv)
{
	struct options options = { .minimum_ms = 10, .top = 10 };
	struct slow_syscall_index_bpf *skel = NULL;
	struct ring_buffer *ring = NULL;
	unsigned long long deadline = 0;
	int gate[2] = { -1, -1 }, data_pipe[2] = { -1, -1 };
	pid_t demo_child = -1;
	int demo_status = 0;
	int err = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (parse_options(argc, argv, &options)) {
		usage(argv[0]);
		return 2;
	}
	if (options.demo) {
		if (options.pid) {
			fprintf(stderr, "--demo and --pid cannot be combined\n");
			return 2;
		}
		if (pipe(gate) || pipe(data_pipe)) {
			perror("pipe");
			goto cleanup;
		}
		demo_child = start_demo(gate, data_pipe);
		if (demo_child < 0) {
			perror("fork");
			goto cleanup;
		}
		options.pid = demo_child;
	}

	skel = slow_syscall_index_bpf__open();
	if (!skel)
		goto cleanup;
	skel->rodata->minimum_ns = (unsigned long long)options.minimum_ms * 1000000ULL;
	skel->rodata->target_tgid = options.pid;
	skel->rodata->ignored_tgid = getpid();
	if (slow_syscall_index_bpf__load(skel) ||
	    slow_syscall_index_bpf__attach(skel)) {
		fprintf(stderr, "failed to load and attach slow syscall tracer\n");
		goto cleanup;
	}
	ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
				NULL, NULL);
	if (!ring)
		goto cleanup;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	if (options.pid)
		printf("Tracing PID %u syscalls slower than %u ms. Press Ctrl-C to stop.\n",
		       options.pid, options.minimum_ms);
	else
		printf("Tracing all syscalls slower than %u ms. Press Ctrl-C to stop.\n",
		       options.minimum_ms);
	if (options.duration_seconds)
		deadline = monotonic_ns() +
			   (unsigned long long)options.duration_seconds * 1000000000ULL;

	if (options.demo) {
		char byte = 'x';
		struct timespec delay = {
			.tv_sec = options.minimum_ms / 1000,
			.tv_nsec = (long)(options.minimum_ms % 1000 + 20) * 1000000L,
		};

		if (delay.tv_nsec >= 1000000000L) {
			delay.tv_sec++;
			delay.tv_nsec -= 1000000000L;
		}
		close(gate[0]); gate[0] = -1;
		close(data_pipe[0]); data_pipe[0] = -1;
		write(gate[1], &byte, 1);
		nanosleep(&delay, NULL);
		write(data_pipe[1], &byte, 1);
		waitpid(demo_child, &demo_status, 0);
		demo_child = -1;
		for (int i = 0; i < 20 && !received_events; i++)
			ring_buffer__poll(ring, 50);
	} else {
		while (!stop && (!deadline || monotonic_ns() < deadline)) {
			int poll_result = ring_buffer__poll(ring, 100);

			if (poll_result < 0 && poll_result != -EINTR) {
				fprintf(stderr, "ring buffer poll failed: %d\n", poll_result);
				goto cleanup;
			}
		}
	}

	print_summary(options.top);
	printf("completed=%llu slow=%llu dropped=%llu unaggregated=%u\n",
	       (unsigned long long)skel->bss->completed_syscalls,
	       (unsigned long long)skel->bss->slow_syscalls,
	       (unsigned long long)skel->bss->dropped_events,
	       unaggregated_events);
	if (options.demo && (!WIFEXITED(demo_status) || WEXITSTATUS(demo_status) ||
			     !received_events))
		goto cleanup;
	err = 0;

cleanup:
	if (demo_child > 0) {
		kill(demo_child, SIGKILL);
		waitpid(demo_child, NULL, 0);
	}
	for (size_t i = 0; i < 2; i++) {
		if (gate[i] >= 0) close(gate[i]);
		if (data_pipe[i] >= 0) close(data_pipe[i]);
	}
	ring_buffer__free(ring);
	slow_syscall_index_bpf__destroy(skel);
	return err;
}
```

用户空间程序按 TGID 和系统调用号聚合事件。每个事件更新该组合的计数、总延迟、最大延迟和错误计数。在退出时，它按总延迟排序结果并打印前 N 个条目。

演示模式 fork 一个子进程，该进程阻塞在管道读取上。父进程延迟足够长的时间以超过阈值，然后写入以解除子进程阻塞。这会创建一个有保证的慢系统调用用于测试。

## 编译和执行

构建工具：

```bash
cd src/56-slow-syscall-index
make
```

使用选项运行：

```bash
sudo ./slow_syscall_index --pid 1234 --min-ms 10 --duration 60 --top 20
```

或运行内置演示：

```bash
sudo ./slow_syscall_index --demo --min-ms 10 --top 10
```

示例输出：

```text
Tracing PID 1255 syscalls slower than 10 ms. Press Ctrl-C to stop.
pid=1255 tid=1255 comm=slow_syscall_in syscall=read(0) latency_ms=30.080 return=1

Slow syscall index, ranked by total latency:
PID     COMM             SYSCALL               COUNT     TOTAL_MS       MAX_MS   ERRORS
1255    slow_syscall_in  read        (  0)        1       30.080       30.080        0
completed=1 slow=1 dropped=0 unaggregated=0
```

## 环境要求

| 要求 | 详情 |
|------|------|
| 内核 | Linux 5.11+（BPF 任务本地存储） |
| 配置 | `CONFIG_BPF_SYSCALL`、`CONFIG_DEBUG_INFO_BTF` |
| 权限 | Root |

## 理解输出

索引显示：

- **PID**：线程组 ID，也就是事件中携带的进程 ID
- **COMM**：进程名
- **SYSCALL**：系统调用名和号
- **COUNT**：慢调用次数
- **TOTAL_MS**：所有慢系统调用持续时间之和
- **MAX_MS**：单次最长调用
- **ERRORS**：返回负值的调用次数

`completed` 计数器显示所有跟踪的系统调用，`slow` 显示超过阈值的调用，`dropped` 显示 ring buffer 分配失败。用户态最多保存 512 个 `(TGID, syscall)` 分组，超过表容量的事件仍会被接收，并计入 `unaggregated`。

## 总结

任务本地存储把每次系统调用退出与对应的入口关联起来，无需在用户态维护 PID 映射。内核中的阈值过滤让事件流保持集中，用户态聚合再把慢调用整理成延迟排名。这里得到的是系统调用的挂钟延迟，如果还需要区分 off-CPU 时间，可以继续关联调度器事件。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [BPF 任务本地存储文档](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_TASK_STORAGE/)
- [BPF ring buffer 文档](https://docs.kernel.org/6.6/bpf/ringbuf.html)
- [raw_syscalls 跟踪点](https://github.com/torvalds/linux/blob/master/include/trace/events/syscalls.h)
- [任务本地存储 commit](https://github.com/torvalds/linux/commit/4cf1bc1f1045)
