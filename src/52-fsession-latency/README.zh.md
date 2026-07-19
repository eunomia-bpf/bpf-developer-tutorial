# eBPF 实践教程：使用 fsession 追踪慢速 vfs_read 调用

假设一个文件服务出现了读延迟尖峰，应用层计时只能告诉你请求变慢了，却无法区分是内核读路径阻塞还是用户态逻辑耗时。有用的问题是：哪个线程发起了读操作、请求了多少字节、调用返回了什么、这一次 `vfs_read` 花了多长时间。

本教程属于 eBPF Tutorial by Example 系列。用户空间将经过验证器检查的追踪程序加载并附加到内核函数上，BPF 侧测量内核执行过程并将选中的事件发送回用户空间。

当一个追踪场景需要同时观察函数进入和返回时，传统做法是编写独立的 fentry 和 fexit 程序，用一个按线程索引的 map 将时间戳从进入传递到返回。Linux 7.0 引入了 fsession，它让同一个 BPF 程序在被追踪函数的进入和返回阶段各执行一次，并通过 `bpf_session_cookie(ctx)` 提供一个 8 字节的调用级暂存区。本教程的 `fsession_latency` 利用这一能力，在 `vfs_read` 进入时记录时间戳、返回时计算延迟，按 TGID 和阈值过滤后上报慢读事件。

> 完整源码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/52-fsession-latency>

## 构建与运行

从源码构建（仓库内置 libbpf 1.7.0 和 bpftool v7.7.0）：

```bash
cd src/52-fsession-latency
make clean
make -j2
```

追踪指定服务进程 30 秒，上报 10 ms 及以上的读操作：

```bash
SERVICE_PID=$(pgrep -n my-service)
sudo ./fsession_latency --pid "$SERVICE_PID" --threshold-us 10000 --duration 30
```

`--pid` 比较的是 `bpf_get_current_pid_tgid()` 返回的 TGID，即宿主机（初始）PID 命名空间中的 TGID。上面的 `pgrep` 适用于直接在宿主机上运行的进程，容器或嵌套 PID 命名空间内的目标需要解析并传入其宿主机可见的 TGID。

命令行参数：

```text
Usage: ./fsession_latency [--threshold-us USEC] [--duration SEC] [--pid TGID] [--verbose]
```

默认阈值 1000 微秒、持续 10 秒、追踪所有进程。`--duration` 接受 1 到 86400 秒，`--pid` 接受 1 到 2^32−1，`--threshold-us` 接受 0 到 `UINT64_MAX / 1000` 微秒（用户空间在加载前转换为纳秒）。空值和尾随字符都会被 `parse_u64` 拒绝。

## 示例输出

以下输出在运行内核 `7.0.0-rc2+` 的 x86_64 环境中采集。集成测试执行 64 次普通文件读取加一次延迟 50 ms 的管道读取，管道读超过 10 ms 阈值后出现在事件流中：

```console
Tracing vfs_read for 1 seconds; threshold=10000 us; pid=selected
EVENT comm=python3          tgid=1257 pid=1257 requested=1 result=1 latency_us=50160
SUMMARY calls=66 slow=1 errors=0 dropped=0 events=1
TEST-SUMMARY miss_calls=0 high_threshold_calls=66 high_threshold_slow=0 threshold_calls=66 threshold_slow=1 events=1 dropped=0
PASS: PID filtering, threshold miss, and slow-read reporting behaved as expected
```

具体调用次数、PID 值和延迟数值因运行环境而异。

## 实现详解

本工具由三个文件组成：共享头文件定义事件和统计结构、BPF 程序测量延迟并提交事件、用户空间加载器管理生命周期并打印结果。

### 共享头文件

`fsession_latency.h` 定义了 BPF 和用户空间共享的事件与统计结构。`latency_event` 包含 32 位 PID 和 TGID、64 位请求字节数、有符号 64 位返回值、纳秒精度延迟和进程名。`latency_stats` 包含 `calls`（总调用数）、`slow`（达到阈值的调用数）、`errors`（返回负值的调用数）和 `dropped`（ring buffer 预留失败计数）。

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

`FSESSION_COMM_LEN` 设为 16，与内核 `TASK_COMM_LEN` 一致。

### BPF 程序

`fsession_latency.bpf.c` 附加一个程序到 `SEC("fsession/vfs_read")`。Linux 7.0 的 fsession 让这个程序在 `vfs_read` 的进入和返回阶段各执行一次。程序用 `bpf_session_is_return(ctx)` 区分两个阶段，用 `bpf_session_cookie(ctx)` 获取一个 8 字节的调用级暂存区，从进入到返回期间持续有效，替代了外部哈希表。

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

进入阶段，`bpf_get_current_pid_tgid()` 提供 PID 和 TGID。如果设置了 `target_tgid` 且调用来自其他 TGID，程序在 cookie 中写入 0 以便返回阶段跳过，匹配的调用则存入 `bpf_ktime_get_ns()` 时间戳。

返回阶段，cookie 为 0 表示已过滤的调用。否则程序用当前单调纳秒时间戳减去保存的时间戳计算延迟，递增 `calls`，如果 `ret < 0` 递增 `errors`。延迟低于 `threshold_ns` 的调用只更新聚合计数器，达到阈值的调用递增 `slow`，预留固定大小的 ring buffer 记录，填入 PID、TGID、请求字节数、返回值、延迟和进程名后提交。预留失败时递增 `dropped`，使最终统计暴露事件路径的压力。返回阶段的 fsession 上下文包含原始函数参数和返回值，因此 `count` 和 `ret` 无需保存到 map。

文件开头的宏处理仓库 `vmlinux.h` 快照中旧版本的 `bpf_session_is_return` 和 `bpf_session_cookie` 声明。这是一个本地兼容桥接，用于绕过生成头文件的版本差异，从 7.0 以上内核重新生成的 `vmlinux.h` 可以直接携带当前签名。

### 用户空间加载器

`fsession_latency.c` 解析命令行、配置 BPF 常量、管理观察窗口并打印结果。

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

加载前，用户空间将 `threshold_ns` 和 `target_tgid` 写入只读 BPF 配置。它打开、加载并附加 skeleton，创建 ring buffer 消费者，计算单调时间截止点，每次迭代最多轮询 100 ms 直到截止或收到 SIGINT/SIGTERM。每个事件打印 comm、TGID、PID、请求字节数、结果和延迟微秒数。

轮询结束后，加载器先解除 fsession 程序的附加以使聚合计数器停止变化，再调用 `ring_buffer__consume()` 投递解除附加前已提交的记录，最后打印稳定的 `SUMMARY` 计数器。这个顺序是观察窗口边界正确性的一部分。退出时释放 ring buffer 并销毁 skeleton。

仓库使用 bpftool v7.7.0，其内置 libbpf v1.7.0。libbpf 1.7.0 通过公开接口识别 `fsession/` 段名。

## 运行测试

集成测试对构建产物运行四个场景加上 CLI 解析测试：

```bash
sudo make test
```

测试验证四个运行时路径：

1. 目标 TGID 为 `UINT32_MAX` 产生零调用和事件。
2. 10,000,000 微秒阈值使普通读完成后仍产生零慢事件。
3. 64 次普通文件读加一次延迟 50 ms 的管道读、阈值 10,000 微秒时产生慢事件并验证其 TGID、PID、请求大小、结果和延迟。
4. 阈值为 0 时持续读到一秒截止后成功退出，且 `slow == events + dropped`，证明窗口边界的每个阈值匹配调用要么被投递要么被明确计入 ring buffer 预留失败。

CLI 测试覆盖无效 duration、空 duration、空 threshold 和空 PID。

## 环境要求

| 要求 | 值 |
|---|---|
| 内核 | Linux 7.0 |
| libbpf | 1.7.0 |
| 架构 | x86_64（当前已测试配置） |
| BTF | 必须 |
| 权限 | root |
| 内核配置 | `CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`、`CONFIG_BPF_JIT=y`、`CONFIG_BPF_EVENTS=y`、`CONFIG_DEBUG_INFO_BTF=y`、`CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y` |
| 运行时 | BPF JIT 已启用、`vfs_read` 在内核 BTF 中存在且可追踪 |

运行时行为在 x86_64 内核 `7.0.0-rc2+` 上测试。上游合并提交为 `f17b474e36647c23801ef8fdaf2255ab66dd2973`。

## 观察范围

本工具测量 `vfs_read` 内部的时间，覆盖到达该函数的读路径并按精确的宿主机可见 TGID 筛选。更完整的追踪器可以在保持相同 fsession 关联模式的基础上加入 cgroup、路径、inode、挂载点、栈或长时运行指标维度，现有的 `dropped` 计数器在负载下仍是事件丢失信号。

## 总结

一个 `fsession/vfs_read` 程序同时看到进入和返回，8 字节的调用级 session cookie 替代外部关联 map 携带时间戳，TGID 过滤和阈值筛选出有用事件，聚合计数器在选定范围内保留调用数、阈值匹配数、错误数和丢弃数，解除附加、排空 ring buffer 再读取汇总的顺序干净地关闭观察窗口。如果想深入了解 eBPF，请查看教程仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial>。

## 参考资料

- [Linux fsession 合并提交](https://github.com/torvalds/linux/commit/f17b474e36647c23801ef8fdaf2255ab66dd2973)
- [上游 fsession 程序自测试](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/fsession_test.c)
- [上游 fsession 运行器自测试](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/fsession_test.c)
- [libbpf 1.7.0](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
- [bpftool v7.7.0](https://github.com/libbpf/bpftool/releases/tag/v7.7.0)
