# eBPF 教程：使用 fsession 追踪慢速 vfs_read 调用

当一个文件服务出现读延迟尖峰时，应用层计时只能告诉你请求变慢了，却无法区分是内核在 I/O 上阻塞还是用户态逻辑耗时。真正有用的问题是：哪个线程发起了读操作、请求了多少字节、调用返回了什么、这一次 `vfs_read` 花了多长时间？

本教程展示如何使用 Linux 7.0 引入的 **fsession** 机制测量 `vfs_read` 调用延迟。fsession 是一种新的 eBPF 程序类型，它在函数进入时执行一次、返回时再执行一次，并提供内置的调用级存储来关联这两个阶段。我们构建的工具会在函数进入时记录时间戳、返回时计算延迟，按进程和阈值过滤后，通过 ring buffer 上报慢读事件。

> 完整源码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/52-fsession-latency>

## 问题：如何关联函数的进入和返回

要测量一个内核函数的执行时间，需要在它开始时记录时间戳，在它返回时计算差值。这听起来很简单，但 eBPF 中的传统方案都有各自的缺陷。

### 传统方案：两个程序配合哈希表

最常见的做法是使用两个独立的 BPF 程序，一个附加到函数进入（fentry），一个附加到函数返回（fexit）。进入程序把时间戳存入一个以线程 ID 为键的哈希表；返回程序查找时间戳、计算延迟、删除条目：

```
进入程序：                              返回程序：
1. 获取线程 ID                         1. 获取线程 ID
2. 获取时间戳                          2. 从哈希表查找时间戳
3. 存入哈希表                          3. 计算延迟
                                       4. 删除哈希表条目
                                       5. 上报事件
```

这个方案能工作，但有几个问题：

- **哈希表开销**：每次函数调用都需要在进入时插入、在返回时查找并删除。对于像 `vfs_read` 这样的高频函数，开销会累积。
- **状态泄漏**：如果线程在进入后、返回前被杀死（比如 `kill -9`），哈希表条目永远不会被删除，造成内存泄漏。
- **没有内在关联**：两个程序完全独立，唯一的联系是外部哈希表，没有任何保证它们追踪的是同一次函数调用。

### kprobe/kretprobe：相同模式，更高开销

kprobe 机制也是两个程序的结构，同样需要外部哈希表来关联。此外，kprobe 通过软件断点机制工作（用中断指令替换第一条指令），开销比 fentry 更大，后者使用内核的 ftrace 基础设施和 JIT 优化的调用序列。

### 用户态采样：统计性的，不是精确的

像 `perf record` 这样的工具周期性采样堆栈，可以构建时间花在哪里的统计概貌。然而，采样无法测量单次函数调用的延迟。如果你需要捕获尾部延迟事件（偶尔出现的 100ms 读操作导致超时），统计采样可能完全错过它们。

## fsession 的解决方案

Linux 7.0 引入了 **fsession**，在内核层面解决了关联问题。当你用 `SEC("fsession/vfs_read")` 声明一个 BPF 程序时，内核会：

1. 在 `vfs_read` 进入时调用你的程序
2. 分配一个 8 字节的暂存区（"session cookie"），绑定到这次特定的调用
3. 在 `vfs_read` 返回时再次调用你的程序
4. 释放 session cookie

关键在于 session cookie 是自动管理的，作用域精确到一次函数调用。程序用 `bpf_session_is_return(ctx)` 区分进入和返回，用 `bpf_session_cookie(ctx)` 读写 cookie。

### Session Cookie 替代了什么

在传统方案中，你需要一个这样的哈希表：

```c
// 传统方案：以线程 ID 为键的哈希表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);    // pid_tgid
    __type(value, u64);  // timestamp
} start SEC(".maps");
```

用了 fsession，整个哈希表都不需要了。时间戳直接存在 session cookie 里：

```c
// fsession：调用级 cookie，不需要 map
__u64 *started = bpf_session_cookie(ctx);
*started = bpf_ktime_get_ns();
```

cookie 从进入到返回一直存在，之后自动清理，不可能泄漏。

### 返回阶段可以访问函数参数

fsession 的另一个优势：返回阶段的上下文同时包含原始函数参数和返回值。在传统方案中，如果你需要在返回时访问函数参数（比如在事件中包含请求的字节数），必须在进入时把它们存到哈希表里。用 fsession，参数直接可用：

```c
SEC("fsession/vfs_read")
int BPF_PROG(measure_vfs_read, struct file *file, char *buf, size_t count,
             loff_t *pos, ssize_t ret)
{
    // 返回时，'count' 和 'ret' 都可以直接访问
    // 不需要在进入时存储 'count'
}
```

## 代码实现

本工具由三个文件组成：
- `fsession_latency.h`：BPF 和用户空间共享的数据结构
- `fsession_latency.bpf.c`：测量延迟的 BPF 程序
- `fsession_latency.c`：管理 BPF 生命周期并打印结果的用户空间加载器

### 共享头文件

`fsession_latency.h` 定义了通过 ring buffer 发送的事件结构和聚合统计结构：

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

四个计数器分别记录：
- `calls`：观察到的 `vfs_read` 调用总数
- `slow`：达到或超过延迟阈值的调用数
- `errors`：`vfs_read` 返回负数错误码的调用数
- `dropped`：因 ring buffer 满而无法提交的事件数

`FSESSION_COMM_LEN` 设为 16，与内核的 `TASK_COMM_LEN` 一致。

### BPF 程序

`fsession_latency.bpf.c` 是工具的核心。我们逐段分析。

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
```

开头的宏处理是一个兼容性变通。仓库的 `vmlinux.h` 快照是在 Linux 7.0 给 `bpf_session_is_return` 和 `bpf_session_cookie` 加上 `ctx` 参数之前生成的。宏在 include 时重命名旧声明，然后我们在下面提供正确的签名。从 7.0 以上内核重新生成的 `vmlinux.h` 不需要这个处理。

```c
const volatile __u64 threshold_ns;
const volatile __u32 target_tgid;

struct latency_stats stats;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");
```

BPF 程序中的 `const volatile` 变量有特殊语义。它们被放在 `.rodata` 段，用户空间可以在打开 skeleton 之后、加载之前设置。一旦加载，验证器把它们当作编译期常量，可以做死代码消除等优化（比如当 `target_tgid` 为 0 时）。

`stats` 是 `.bss` 段的全局变量，程序运行后用户空间可以直接读取。

ring buffer（`events`）大小是 256 KB，足够容纳数千个事件才会溢出。

```c
/*
 * The repository vmlinux.h snapshot predates the ctx argument on these
 * kfunc prototypes. Rename those stale declarations while including the
 * snapshot, then provide the Linux 7.0 signatures below.
 */
extern bool bpf_session_is_return(void *ctx) __ksym;
extern __u64 *bpf_session_cookie(void *ctx) __ksym;
```

这是 **kfunc** 声明，导出给 BPF 程序调用的内核函数。`__ksym` 属性告诉验证器在加载时从运行中的内核解析这些符号，而不是期望它们在 BPF 对象中定义。

```c
SEC("fsession/vfs_read")
int BPF_PROG(measure_vfs_read, struct file *file, char *buf, size_t count,
	     loff_t *pos, ssize_t ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 *started = bpf_session_cookie(ctx);
	struct latency_event *event;
	__u64 latency;
```

`SEC("fsession/vfs_read")` 告诉内核这是一个附加到 `vfs_read` 的 fsession 程序。`BPF_PROG` 宏展开后设置标准的追踪上下文；`ctx` 隐式可用，可以传给 kfunc。

函数签名列出 `vfs_read` 的参数，最后是返回值。进入时，`ret` 是未定义的；返回时，所有参数和返回值都有效。

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

**进入阶段**：首先检查是否应该过滤这次调用。如果设置了 `target_tgid`（非零）且当前进程的 TGID 不匹配，在 cookie 中写入 0 表示"跳过"，然后返回。否则，把当前单调时间戳写入 cookie。

TGID 在 `bpf_get_current_pid_tgid()` 返回值的高 32 位；低 32 位是线程 ID（内核术语中的 PID）。

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

**返回阶段**：如果 cookie 是 0，说明进入阶段已经过滤了这次调用，直接返回。否则计算延迟并更新聚合计数器。`__sync_fetch_and_add` 提供原子更新，因为多个 CPU 可能同时执行这个程序。

如果延迟低于阈值，到此为止，调用被计数但不产生事件。这让 ring buffer 只关注慢调用。

```c
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

对于慢调用，递增 `slow` 计数器并尝试在 ring buffer 中预留空间。如果预留失败（缓冲区满），递增 `dropped` 让用户知道有事件丢失。成功后填入各字段并提交。

注意 `count`（请求的字节数）可以直接访问，不需要在进入时存储。这就是 fsession 的优势：函数参数在返回阶段仍然可用。

### 用户空间加载器

`fsession_latency.c` 处理命令行解析、BPF 生命周期管理和事件消费。关键部分：

**通过只读数据配置**：
```c
skel->rodata->threshold_ns = env.threshold_us * 1000;
skel->rodata->target_tgid = env.pid;
```

打开 skeleton 之后、加载之前，用户空间把阈值（从微秒转换为纳秒）和目标 TGID 写入 `.rodata` 段。这些在 BPF 程序中成为常量。

**Ring buffer 消费**：
```c
static int handle_event(void *context, void *data, size_t size)
{
	const struct latency_event *event = data;

	printf("EVENT comm=%-16s tgid=%u pid=%u requested=%llu result=%lld "
	       "latency_us=%llu\n",
	       event->comm, event->tgid, event->pid, event->requested,
	       event->result, event->latency_ns / 1000);
	events_printed++;
	return 0;
}
```

每个事件打印进程名、ID、请求字节数、返回值和延迟（微秒）。

**干净关闭序列**：
```c
fsession_latency_bpf__detach(skel);

err = ring_buffer__consume(ring);
// ... 错误处理 ...

printf("SUMMARY calls=%llu slow=%llu errors=%llu dropped=%llu events=%llu\n",
       skel->bss->stats.calls, skel->bss->stats.slow,
       skel->bss->stats.errors, skel->bss->stats.dropped, events_printed);
```

关闭顺序对正确性很重要：
1. 解除 BPF 程序的附加（停止产生新事件）
2. 排空 ring buffer 中剩余的事件
3. 读取最终的计数器值（现在稳定了，因为程序已解除附加）

这确保 `events_printed` 与实际通过 ring buffer 投递的事件数一致。

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

**关于 PID 命名空间**：`--pid` 选项比较的是宿主机（初始）PID 命名空间中的 TGID。如果目标运行在有自己 PID 命名空间的容器中，你需要找到它在宿主机可见的 TGID。在容器内进程可能是 PID 1，但从宿主机看可能是 PID 12345。在宿主机上使用 `pgrep` 或检查 `/proc/<pid>/status` 中的 `NSpid` 行。

### 命令行选项

```text
Usage: ./fsession_latency [--threshold-us USEC] [--duration SEC] [--pid TGID] [--verbose]

选项：
  -t, --threshold-us USEC  慢读阈值（默认：1000 微秒）
  -d, --duration SEC       追踪时长，1-86400（默认：10 秒）
  -p, --pid TGID           追踪指定进程 ID（默认：所有进程）
  -v, --verbose            打印 libbpf 诊断信息
  -h, --help               显示帮助
```

### 输出示例

以下输出在运行内核 `7.0.0-rc2+` 的 x86_64 环境中采集。集成测试执行 64 次普通文件读取加一次延迟 50 ms 的管道读取。管道读超过 10 ms 阈值后出现在事件流中：

```console
Tracing vfs_read for 1 seconds; threshold=10000 us; pid=selected
EVENT comm=python3          tgid=1257 pid=1257 requested=1 result=1 latency_us=50160
SUMMARY calls=66 slow=1 errors=0 dropped=0 events=1
TEST-SUMMARY miss_calls=0 high_threshold_calls=66 high_threshold_slow=0 threshold_calls=66 threshold_slow=1 events=1 dropped=0
PASS: PID filtering, threshold miss, and slow-read reporting behaved as expected
```

`SUMMARY` 行显示：
- 观察到 66 次 `vfs_read` 调用
- 1 次是慢的（达到阈值）
- 0 次返回错误
- 0 个事件被丢弃
- 1 个事件被打印

### 运行测试

```bash
sudo make test
```

集成测试验证：
- **PID 过滤**：针对不存在的 TGID 产生零调用
- **阈值过滤**：很高的阈值（10 秒）使快速读取产生零慢事件
- **事件上报**：故意延迟的管道读取（50ms）在 10ms 阈值下触发事件
- **计数不变式**：阈值为 0 时，`slow == events + dropped`（每个达到阈值的调用要么被投递要么被计入丢弃）

## 环境要求

| 要求 | 详情 |
|---|---|
| 内核版本 | Linux 7.0+（fsession 首次引入） |
| BTF | 必须启用（`CONFIG_DEBUG_INFO_BTF=y`） |
| 内核配置 | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y` |
| BPF JIT | 运行时必须启用 |
| 架构 | 已在 x86_64 上测试 |
| 权限 | root |

运行时行为在 x86_64 内核 `7.0.0-rc2+` 上测试。上游合并提交为 `f17b474e36647c23801ef8fdaf2255ab66dd2973`。

## 扩展方向

这里展示的 fsession 模式适用于任何需要关联进入和返回的内核函数。一些扩展方向：

- **其他函数**：附加到 `vfs_write`、`vfs_fsync` 或其他 VFS 操作
- **文件路径过滤**：使用 `file->f_path` 按特定文件或挂载点过滤
- **堆栈追踪**：添加 `bpf_get_stackid()` 捕获慢调用的内核和/或用户态堆栈
- **直方图**：用 `BPF_MAP_TYPE_ARRAY` 的延迟直方图替代逐事件上报
- **cgroup 过滤**：添加 cgroup ID 检查实现容器感知的追踪

`dropped` 计数器仍然是 ring buffer 压力的信号。如果它在增长，要么增大缓冲区大小，要么提高阈值减少事件量。

## 总结

本教程展示了如何使用 Linux 7.0 的 fsession 机制测量内核函数延迟。相比传统的 fentry/fexit 配合哈希表的方案，主要优势：

1. **单个程序**：一个 BPF 程序处理进入和返回，用 `bpf_session_is_return()` 区分阶段
2. **内置关联**：8 字节的 session cookie 替代外部哈希表在两个阶段间传递数据
3. **无状态泄漏**：内核管理 cookie 生命周期，不需要清理，不可能泄漏
4. **返回时可访问参数**：函数参数在返回阶段仍然可用，无需显式存储

模式很简单：检查 `bpf_session_is_return()`，用 `bpf_session_cookie()` 管理调用级状态，直接访问参数和返回值。这个模式适用于任何需要关联函数进入和退出的场景。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [Linux fsession 合并提交](https://github.com/torvalds/linux/commit/f17b474e36647c23801ef8fdaf2255ab66dd2973)
- [上游 fsession 程序自测试](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/fsession_test.c)
- [上游 fsession 运行器自测试](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/fsession_test.c)
- [libbpf 1.7.0](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
- [bpftool v7.7.0](https://github.com/libbpf/bpftool/releases/tag/v7.7.0)
