# eBPF 实践教程: 使用 fsession 追踪慢速 vfs_read 调用

一个文件服务出现了读延迟尖峰，但应用层指标无法区分是内核读操作阻塞还是系统调用之上的业务逻辑耗时。运维人员需要确定：哪些具体的 `vfs_read` 调用慢了、发生在哪个线程、慢了多少。

`fsession_latency` 将一个 BPF 程序附加到 `vfs_read`，在进入时记录时间戳、返回时计算延迟，只上报达到或超过阈值的调用。它使用 Linux 7.0 引入的 fsession 机制，免去了传统 fentry/fexit 需要的哈希表关联。

> 完整源代码: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/52-fsession-latency>

## 快速开始

从源码构建（需要 libbpf 1.7.0 和 bpftool v7.7.0，均已在仓库中内置）：

```bash
cd src/52-fsession-latency
make clean
make -j2
```

追踪指定服务进程 30 秒，上报 10 ms 以上的读操作：

```bash
SERVICE_PID=$(pgrep -n my-service)
sudo ./fsession_latency --pid "$SERVICE_PID" --threshold-us 10000 --duration 30
```

`--pid` 比较的是 `bpf_get_current_pid_tgid()` 返回的 TGID，即宿主机（初始）PID 命名空间中的 TGID。上面的 `pgrep` 示例适用于直接运行在宿主机上的进程。如果目标进程位于容器或嵌套 PID 命名空间内，必须解析并传入其宿主机命名空间的 TGID；传入命名空间内部的 PID 会静默匹配不到任何进程。

命令行用法：

```text
Usage: ./fsession_latency [--threshold-us USEC] [--duration SEC] [--pid TGID] [--verbose]
```

默认值：阈值 1000 微秒，持续时间 10 秒，追踪所有进程。

## 验证测试输出

集成测试执行 64 次普通文件读取加一次延迟 50 ms 的管道读取。管道读超过 10 ms 阈值，出现在事件输出中。此输出在运行内核 `7.0.0-rc2+` 的 KVM 虚拟机中采集：

```console
Tracing vfs_read for 1 seconds; threshold=10000 us; pid=selected
EVENT comm=python3          tgid=1257 pid=1257 requested=1 result=1 latency_us=50160
SUMMARY calls=66 slow=1 errors=0 dropped=0 events=1
TEST-SUMMARY miss_calls=0 high_threshold_calls=66 high_threshold_slow=0 threshold_calls=66 threshold_slow=1 events=1 dropped=0
PASS: PID filtering, threshold miss, and slow-read reporting behaved as expected
```

具体的调用次数和延迟数值取决于测试环境，你的结果会有所不同。

## 工作原理

### fsession 机制

传统的 fentry/fexit 追踪需要附加两个独立的 BPF 程序，通过每线程哈希表在进入和返回之间关联数据。fsession 程序类型（Linux 7.0 引入）让同一个 BPF 程序在被追踪函数的进入和返回阶段都执行，通过两个 kfunc 实现：

- `bpf_session_cookie(ctx)` 返回一个 8 字节暂存区的指针，从函数进入到返回期间持续有效。无需分配 map、无需查找、无需清理。
- `bpf_session_is_return(ctx)` 在返回阶段返回 true。

返回时，程序接收到原始函数参数加上返回值。因此工具可以直接报告 `count`（请求字节数）和 `ret`（实际结果或错误），不需要将它们存入 map。

### BPF 程序

整个 BPF 程序在 `fsession_latency.bpf.c` 中是一个函数：

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

执行流程：

1. 进入时检查 TGID 过滤器。如果不匹配，在 session cookie 中存 0，返回时跳过。匹配则存入当前纳秒时间戳。
2. 返回时，如果 cookie 为 0 则表示该调用已被过滤。否则用当前时间减去存储的时间戳得到延迟。
3. 原子递增 `calls` 计数器。如果返回值为负数，递增 `errors`。
4. 如果延迟低于阈值，结束。否则递增 `slow`，在 ring buffer 中预留空间，填充事件并提交。

### 共享数据结构

头文件 `fsession_latency.h` 定义了 BPF 和用户空间共享的事件和统计结构：

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

### 用户空间加载器

`fsession_latency.c` 中的用户空间程序执行以下步骤：

1. 解析命令行参数（阈值、持续时间、PID 过滤器）。
2. 打开 BPF skeleton，在加载前设置 `rodata` 常量（`threshold_ns`、`target_tgid`）。
3. 加载并附加 fsession 程序到 `vfs_read`。
4. 创建 ring buffer，以 100 ms 超时轮询，直到持续时间到期或收到信号。每收到一个事件立即打印（comm、tgid、pid、请求字节数、结果、延迟微秒数）。
5. 解除 fsession 程序的附加，使 BPF 统计计数器不再变化。
6. 调用 `ring_buffer__consume()` 排空解除附加前已提交到 ring buffer 的事件。
7. 打印汇总行，此时聚合计数器已稳定。

汇总行中的 `dropped` 字段暴露 ring buffer 丢失事件的情况，让运维人员知道是否有数据丢失。

### vmlinux.h 兼容性处理

仓库的 `vmlinux.h` 快照中 `bpf_session_is_return` 和 `bpf_session_cookie` 的声明早于 ctx 参数版本。BPF 源码通过在 include 时重命名这些旧声明来解决，然后声明正确的 Linux 7.0 签名：

```c
#define bpf_session_is_return bpf_session_is_return_vmlinux_snapshot
#define bpf_session_cookie bpf_session_cookie_vmlinux_snapshot
#include "vmlinux.h"
#undef bpf_session_is_return
#undef bpf_session_cookie

extern bool bpf_session_is_return(void *ctx) __ksym;
extern __u64 *bpf_session_cookie(void *ctx) __ksym;
```

这样避免了手动编辑生成的头文件。如果从 7.0+ 内核重新生成 `vmlinux.h`，则不需要这个处理。

### libbpf 段名识别

仓库使用 bpftool v7.7.0，其内置的 libbpf 版本为 v1.7.0。libbpf 1.7.0 能识别 `fsession/` 作为有效的程序段名，因此不需要私有的数字 attach-type 变通方案。

## 运行测试

集成测试对构建产物运行四个场景：

```bash
sudo make test
```

测试验证：

1. 不匹配的 PID (2^32 - 1) 产生零次调用，证明 TGID 过滤器有效。
2. 10 秒阈值 (10,000,000 us) 即使有读操作完成也不产生慢事件，证明阈值比较逻辑正确。
3. 10 ms 阈值加上延迟 50 ms 的管道读产生至少一个慢事件，证明端到端上报路径正常工作。
4. 阈值为 0 时，持续对目标 TGID 执行读操作直到一秒截止时间结束，产生调用和事件，且 CLI 仍然成功退出。该场景还断言 `slow == events + dropped`，确保窗口边界的每一个慢调用要么被投递为事件，要么被明确计入 ring buffer 预留失败。

## 环境要求

| 要求 | 值 |
|---|---|
| 最低内核版本 | Linux 7.0 |
| 最低 libbpf | 1.7.0 |
| 架构 | x86_64（已测试） |
| BTF | 必须 |
| 权限 | root |
| 内核配置 | `CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`、`CONFIG_BPF_JIT=y`、`CONFIG_BPF_EVENTS=y`、`CONFIG_DEBUG_INFO_BTF=y`、`CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y` |
| 运行时 | BPF JIT 已启用；`vfs_read` 在内核 BTF 中存在且可追踪 |

## 局限性

- 仅测量 `vfs_read` 内部的时间，不等于完整请求延迟、存储设备服务时间或应用 p99。
- 仅覆盖调用 `vfs_read` 的路径。mmap 和其他绕过 `vfs_read` 的路径不可见。
- 仅支持精确 TGID 过滤，不支持 cgroup、进程树、路径、inode、挂载点、PID 命名空间或容器选择器。过滤器在宿主机命名空间 TGID 上工作，无法传入命名空间内部的 PID 或按容器运行时选择。
- 单次运行，不是守护进程、告警系统或指标导出器。
- Ring buffer 在高负载下可能丢失匹配事件。`dropped` 计数器暴露该情况，其他计数器为聚合观察值。
- 命令名称可能重复，PID 在有界追踪窗口外可能被复用。
- 不采集用户/内核栈，不解析文件名或路径。

## 参考资料

- [Linux fsession 合并提交](https://github.com/torvalds/linux/commit/f17b474e36647c23801ef8fdaf2255ab66dd2973)
- [上游 fsession BPF 自测试 (prog)](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/fsession_test.c)
- [上游 fsession BPF 自测试 (runner)](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/fsession_test.c)
- [libbpf 1.7.0 发布](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)

## 更多 eBPF 教程

- 教程仓库: <https://github.com/eunomia-bpf/bpf-developer-tutorial>
- 教程网站: <https://eunomia.dev/tutorials/>
