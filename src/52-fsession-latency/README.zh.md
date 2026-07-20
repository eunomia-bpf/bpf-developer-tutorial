# eBPF 教程：使用 fsession 追踪慢速 vfs_read 调用

假设一个文件服务出现了读延迟尖峰，应用层计时只能告诉你请求变慢了，却无法区分是内核读路径阻塞还是用户态逻辑耗时。有用的问题是：哪个线程发起了读操作、请求了多少字节、调用返回了什么、这一次 `vfs_read` 花了多长时间。

本教程展示如何使用 Linux 7.0 引入的 fsession 机制测量 `vfs_read` 调用延迟。工具在函数进入时记录时间戳、返回时计算延迟，按 TGID 和阈值过滤后上报慢读事件。

> 完整源码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/52-fsession-latency>

## 为什么需要 fsession

传统的函数延迟测量方案都有明显的局限性。

**独立的 fentry 和 fexit 程序**是最常见的做法。你需要编写两个 BPF 程序，一个附加到函数入口，一个附加到函数返回。两个程序之间需要通过一个按线程索引的哈希表来传递时间戳：进入时存入 `bpf_get_current_pid_tgid()` 到时间戳的映射，返回时查找并删除。这个模式有几个问题：首先需要维护额外的哈希表，每次调用都有查找和删除的开销；其次如果进入后没有正常返回（比如线程被杀死），哈希表中的条目会泄漏；最后两个程序之间没有天然的关联，状态传递完全依赖外部数据结构。

**kprobe 和 kretprobe**同样需要两个独立的程序和外部哈希表。相比 fentry/fexit，kprobe 的开销更大，因为它通过断点机制工作，而 fentry 直接挂钩到函数序言，在 x86_64 上使用 JIT 优化的调用序列。

**用户态采样**如 `perf record` 或 `bpftrace` 的周期性堆栈采样只能提供统计概貌，无法精确测量每次调用的延迟。对于需要捕获尾部延迟事件的场景，采样可能完全错过关键的慢调用。

**fsession 机制**从根本上解决了这个问题。Linux 7.0 引入了 fsession，它让同一个 BPF 程序在被追踪函数的进入和返回阶段各执行一次，并通过 `bpf_session_cookie(ctx)` 提供一个 8 字节的调用级暂存区。这个 cookie 从进入到返回期间持续有效，完全替代了外部哈希表。程序用 `bpf_session_is_return(ctx)` 区分两个阶段，在同一个程序内处理所有逻辑。

## fsession 的工作原理

fsession 是一种特殊的 ftracing 程序类型。当你用 `SEC("fsession/vfs_read")` 声明一个程序时，内核会在 `vfs_read` 的进入和返回阶段各调用一次你的 BPF 程序。

`bpf_session_is_return(ctx)` 返回 false 表示进入阶段，返回 true 表示返回阶段。程序可以用这个 helper 函数区分当前处于哪个阶段，执行相应的逻辑。

`bpf_session_cookie(ctx)` 返回一个指向 8 字节暂存区的指针。这个暂存区是每次调用独立的，从进入阶段到返回阶段持续有效。你可以在进入阶段写入数据（比如时间戳），在返回阶段读取并使用它。

返回阶段的上下文不仅包含原始函数参数，还包含函数的返回值。对于 `vfs_read`，进入时能看到 `file`、`buf`、`count`、`pos` 四个参数，返回时还能看到 `ret` 返回值。这意味着你不需要把参数存到 map 里，返回阶段可以直接访问。

`fsession_latency` 工具利用这些能力实现延迟测量。进入阶段，它检查 TGID 是否匹配目标进程，匹配的调用在 cookie 中存入 `bpf_ktime_get_ns()` 时间戳。返回阶段，它从 cookie 读取时间戳计算延迟，递增聚合计数器，超过阈值的调用通过 ring buffer 上报详细事件。

## 代码实现

本工具由三个文件组成：共享头文件定义事件和统计结构、BPF 程序测量延迟并提交事件、用户空间加载器管理生命周期并打印结果。

### 共享头文件

`fsession_latency.h` 定义了 BPF 和用户空间共享的事件与统计结构。`latency_event` 包含 32 位 PID 和 TGID、64 位请求字节数、有符号 64 位返回值、纳秒精度延迟和进程名。`latency_stats` 包含四个计数器用于聚合统计。

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

四个计数器分别记录：`calls` 是总调用数、`slow` 是达到阈值的调用数、`errors` 是返回负值的调用数、`dropped` 是 ring buffer 预留失败的计数。`FSESSION_COMM_LEN` 设为 16，与内核 `TASK_COMM_LEN` 一致。

### BPF 程序

`fsession_latency.bpf.c` 使用 `SEC("fsession/vfs_read")` 声明为 fsession 类型。内核会在 `vfs_read` 的进入和返回阶段各调用一次这个程序。

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

程序结构分为进入阶段和返回阶段两部分。两个 `const volatile` 变量位于 `.rodata` 段，用户态在 `open()` 之后、`load()` 之前写入阈值和目标 TGID，验证器将它们视为编译期常量。`bpf_session_is_return` 和 `bpf_session_cookie` 通过 `extern ... __ksym` 声明为 kfunc 符号，内核在加载时解析。

进入阶段，程序调用 `bpf_get_current_pid_tgid()` 获取调用者的 PID 和 TGID。如果设置了 `target_tgid` 且调用来自其他进程，程序在 cookie 中写入 0 表示这次调用应该被跳过。匹配的调用则存入 `bpf_ktime_get_ns()` 返回的单调时间戳。

返回阶段，程序首先检查 cookie 是否为 0。cookie 为 0 表示进入阶段已经过滤了这次调用，直接返回。否则计算延迟为当前时间戳减去保存的进入时间戳，然后递增 `calls` 计数器。如果 `ret < 0` 表示读操作返回错误，递增 `errors` 计数器。延迟低于 `threshold_ns` 的调用到此为止，只更新聚合计数器不上报事件。

达到阈值的调用递增 `slow` 计数器，然后尝试在 ring buffer 中预留固定大小的记录。预留失败时递增 `dropped` 计数器，这让最终统计能够暴露事件路径的压力。预留成功后填入 PID、TGID、请求字节数、返回值、延迟和进程名，最后提交到 ring buffer。

文件开头的宏处理是一个本地兼容桥接。仓库的 `vmlinux.h` 快照中 `bpf_session_is_return` 和 `bpf_session_cookie` 的声明早于 Linux 7.0 添加的 `ctx` 参数。宏先把旧声明重命名，include 之后再 undef，然后用正确的 Linux 7.0 签名重新声明。从 7.0 以上内核重新生成的 `vmlinux.h` 可以直接使用，不需要这个桥接。

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

加载器的流程比较标准。解析命令行后，打开 skeleton 并把 `threshold_ns` 和 `target_tgid` 写入只读 BPF 配置。用户输入的阈值是微秒单位，乘以 1000 转换为纳秒后写入。调用 `load` 完成 BPF 程序加载，然后附加到 `vfs_read`。加载失败时的诊断同时给出内核 errno 和前置条件列表，方便用户排查问题。

`ring_buffer__new` 创建 ring buffer 消费者，注册 `handle_event` 回调处理每个事件。回调打印 comm、TGID、PID、请求字节数、结果和延迟微秒数，并递增 `events_printed` 计数。

`poll_until_deadline` 函数驱动事件消费循环。它计算单调时间截止点，每次迭代最多轮询 100 ms 直到截止或收到 SIGINT/SIGTERM。轮询返回 `-EINTR` 时继续循环，其他负值表示错误。

轮询结束后，加载器先调用 `fsession_latency_bpf__detach` 解除 fsession 程序的附加，使聚合计数器停止变化。然后调用 `ring_buffer__consume` 投递解除附加前已提交但尚未消费的记录。这个顺序是观察窗口边界正确性的一部分：先停止新事件产生，再排空已有事件，最后读取稳定的计数器。退出时释放 ring buffer 并销毁 skeleton。

## 编译与运行

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

Options:
  -t, --threshold-us USEC  慢读阈值（默认：1000 微秒）
  -d, --duration SEC       追踪时长，1-86400（默认：10 秒）
  -p, --pid TGID           追踪指定进程 ID（默认：所有进程）
  -v, --verbose            打印 libbpf 诊断信息
  -h, --help               显示帮助
```

默认阈值 1000 微秒、持续 10 秒、追踪所有进程。`--duration` 接受 1 到 86400 秒，`--pid` 接受 1 到 2^32-1，`--threshold-us` 接受 0 到 `UINT64_MAX / 1000` 微秒（用户空间在加载前转换为纳秒）。空值和尾随字符都会被 `parse_u64` 拒绝。

以下输出在运行内核 `7.0.0-rc2+` 的 x86_64 环境中采集。集成测试执行 64 次普通文件读取加一次延迟 50 ms 的管道读取，管道读超过 10 ms 阈值后出现在事件流中：

```console
Tracing vfs_read for 1 seconds; threshold=10000 us; pid=selected
EVENT comm=python3          tgid=1257 pid=1257 requested=1 result=1 latency_us=50160
SUMMARY calls=66 slow=1 errors=0 dropped=0 events=1
TEST-SUMMARY miss_calls=0 high_threshold_calls=66 high_threshold_slow=0 threshold_calls=66 threshold_slow=1 events=1 dropped=0
PASS: PID filtering, threshold miss, and slow-read reporting behaved as expected
```

具体调用次数、PID 值和延迟数值因运行环境而异。

运行测试：

```bash
sudo make test
```

集成测试验证四个运行时路径：目标 TGID 为 `UINT32_MAX` 产生零调用和事件、10,000,000 微秒阈值使普通读产生零慢事件、64 次普通文件读加一次延迟 50 ms 的管道读在 10,000 微秒阈值下产生慢事件、阈值为 0 时 `slow == events + dropped` 证明每个阈值匹配调用要么被投递要么被计入 ring buffer 预留失败。CLI 测试覆盖无效 duration、空 duration、空 threshold 和空 PID。

### 环境要求

| 要求 | 详情 |
|---|---|
| 内核版本 | Linux 7.0+（fsession 首次引入） |
| BTF | 必须启用 (`CONFIG_DEBUG_INFO_BTF=y`) |
| 内核配置 | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y` |
| BPF JIT | 运行时必须启用 |
| 架构 | 已在 x86_64 上测试 |
| 权限 | root |

运行时行为在 x86_64 内核 `7.0.0-rc2+` 上测试。上游合并提交为 `f17b474e36647c23801ef8fdaf2255ab66dd2973`。

## 观察范围

本工具测量 `vfs_read` 内部的时间，覆盖到达该函数的读路径并按精确的宿主机可见 TGID 筛选。更完整的追踪器可以在保持相同 fsession 关联模式的基础上加入 cgroup、路径、inode、挂载点、栈或长时运行指标维度，现有的 `dropped` 计数器在负载下仍是事件丢失信号。

## 总结

本教程展示了如何使用 Linux 7.0 的 fsession 机制测量内核函数延迟。相比传统的 fentry/fexit 两程序配合哈希表的方案，fsession 用一个程序同时处理进入和返回，8 字节的调用级 session cookie 替代外部关联 map 携带时间戳，代码更简洁、无状态泄漏风险、性能开销更低。

工具的设计演示了 fsession 的核心模式：用 `bpf_session_is_return` 区分阶段，用 `bpf_session_cookie` 传递调用级状态，返回阶段直接访问函数参数和返回值。这个模式适用于任何需要关联函数进入和返回的场景。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [Linux fsession 合并提交](https://github.com/torvalds/linux/commit/f17b474e36647c23801ef8fdaf2255ab66dd2973)
- [上游 fsession 程序自测试](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/fsession_test.c)
- [上游 fsession 运行器自测试](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/fsession_test.c)
- [libbpf 1.7.0](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
- [bpftool v7.7.0](https://github.com/libbpf/bpftool/releases/tag/v7.7.0)
