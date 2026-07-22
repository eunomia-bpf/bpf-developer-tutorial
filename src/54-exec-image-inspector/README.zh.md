# eBPF 教程：检查 exec 后实际安装的可执行镜像

当进程调用 `execve` 时，内核会用新的可执行镜像替换它的内存映像。但具体是哪个可执行文件？如果命令行显示 `/usr/bin/wrapper.sh --config /etc/app.conf`，实际运行的代码可能是三层包装脚本深处的 Python 解释器或编译好的二进制。安全工具、容器运行时、故障排查工具都需要知道内核 *实际* 安装的是什么，而不仅仅是用户输入的命令行。

本教程构建一个在内核层面捕获这些信息的工具。它在 exec 提交凭据后挂载钩子，安排一个延迟回调，然后读取已安装可执行文件的 ELF 头部，报告其架构、字节序和文件类型。过程中会演示两个较新的内核特性（BPF task work 和 file dynptr），它们组合起来可以解决传统 eBPF 方案无法处理的问题。

> 完整源码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/54-exec-image-inspector>

## 问题：从 eBPF 读取文件内容的困难

为什么安全工具需要读取可执行文件的内容，而不仅仅是路径？因为路径本身并不能确定将要运行什么代码。对可执行文件内容的哈希可以验证它是否与已知的可信二进制匹配。嵌入的签名或证书可以证明来源。特定偏移处的特定字节模式可以识别加壳、混淆或篡改。这些信息都无法从路径获取，必须读取文件的字节。在 eBPF 中、在 exec 的精确时刻读取，消除了困扰用户态方案的竞态窗口。

最直接的可执行文件检查方法是读取 `/proc/<pid>/exe`，但这要求进程仍然存活。短命进程在你读取之前就已退出。即使抓住了时机，`/proc` 文件系统是从用户态访问的，与内核的 exec 事件之间存在竞态窗口：等你读到符号链接时，进程可能已经再次调用了 `execve`。

Tracepoint 和 kprobe 可以钩住 `sched_process_exec` 同步观察 exec 事件，但这些钩子运行在内核所谓的**不可睡眠上下文**中。为什么这很重要？这涉及到 Linux 如何管理内存中的文件数据。

当你读取文件时，内核首先检查请求的字节是否已经在**页缓存**（page cache）中，这是一块缓存最近访问过的文件数据的内存区域。如果在，读取立即完成。如果不在（即**冷页**），内核必须向存储设备发起 I/O 请求，调用上下文必须**睡眠**等待 I/O 完成。

挂载在 tracepoint 和 kprobe 上的 BPF 程序不能睡眠。它们运行时可能中断被禁用、持有锁；如果睡眠会导致系统死锁。当 BPF 程序尝试读取文件内容遇到冷页时，读取会以 `-EFAULT` 失败，而不是等待 I/O。

这就形成了根本性的限制：你可以观察 exec 事件，但无法可靠地读取可执行文件的内容来验证其 ELF 头部或检查嵌入的元数据。

## 解决方案：BPF task work 与 file dynptr

Linux 6.18 引入了 **BPF task work**，这是一种让 BPF 程序安排回调稍后在安全的可睡眠上下文中执行的机制。回调会在目标任务返回用户态之前、内核允许睡眠的时刻执行。

Linux 6.19 引入了 **file dynptr**，提供验证器跟踪的文件数据访问。dynptr（动态指针）是一种 BPF 抽象，在验证时追踪指针的边界；file 变体封装了文件 I/O 操作，让验证器能确保内存安全。

结合这两个特性，设计变成：

1. 在 `bprm_committed_creds` 挂载 LSM 钩子，它在 exec 安装新凭据后触发
2. 在钩子中（不可睡眠）识别目标进程并安排 task work 回调
3. 回调在可睡眠上下文中执行，可以访问已安装的可执行文件、读取任意偏移的内容（包括冷页）、然后把结果发送给用户态

这种分离（在不可睡眠的钩子中识别目标，在可睡眠的回调中完成重活）是关键思路。

## BPF task work 的工作机制

调用 `bpf_task_work_schedule_signal(task, work, map, callback)` 时，内核把你的回调关联到指定的任务。回调不会立即执行；它会稍后在该任务返回用户态之前的某个安全点执行。

`struct bpf_task_work` 是一个不透明结构，内核用它来追踪已安排的回调。BPF 程序只需为它分配存储空间，不解释其内容。本工具使用单元素 ARRAY map 保存 `struct exec_work`，其中包含 `bpf_task_work` 存储以及时间戳和中间结果字段。

回调签名是 `int callback(struct bpf_map *map, void *key, void *value)`。`value` 参数指向包含你的 `bpf_task_work` 的 map 元素，所以你可以通过周围的字段从调度钩子向回调传递数据。

## file dynptr 的工作机制

dynptr 用边界信息包装指针，BPF 验证器可以追踪这些边界。对于 file dynptr：

- `bpf_dynptr_from_file(file, flags, dynptr)` 从文件创建 dynptr
- `bpf_dynptr_read(dst, len, dynptr, offset, flags)` 读取指定偏移处的内容
- `bpf_dynptr_file_discard(dynptr)` 释放 dynptr 的内部状态

每条创建 dynptr 的路径（包括错误路径）都必须调用 `bpf_dynptr_file_discard` 来释放它。忘记释放会泄漏内部资源。

在不可睡眠上下文中，`bpf_dynptr_read` 只有在目标字节已经在页缓存中时才会成功。访问冷页返回 `-EFAULT`。在可睡眠上下文中，同样的调用可以触发缺页处理并等待 I/O，即使对冷页也能成功。这个差异就是 task work 的价值所在：回调运行在可睡眠上下文中，文件读取能可靠完成。

## 工具架构

用户态程序 fork 出一个子进程，但在子进程调用 `execvp` 之前用管道阻塞它。这给父进程时间去：

1. 记录子进程的 PID（它会成为 TGID，线程组 ID）
2. 打开 BPF skeleton 并把目标 TGID 写入只读数据段
3. 加载并挂载 BPF 程序
4. 创建 ring buffer reader

只有这些都完成后，父进程才通过写管道来释放子进程。这个握手消除了竞态条件：没有它的话，快速退出的命令可能在 BPF 程序挂载之前就结束了。

当子进程调用 `execvp` 时，`lsm/bprm_committed_creds` 钩子触发。BPF 程序比较当前 TGID 与配置的目标；如果匹配，它记录时间戳并安排 task work 回调。

回调 `inspect_executable` 在子进程的可睡眠上下文中执行。它：

1. 调用 `bpf_get_task_exe_file` 获取已安装的可执行文件（返回一个带引用的 `struct file`，必须用 `bpf_put_file` 释放）
2. 用 `bpf_path_d_path` 解析路径
3. 创建 file dynptr 并读取 64 字节 ELF 头部
4. 解析 ELF 字段：魔数、class（32/64 位）、data（字节序）、type（可执行文件 vs 共享对象）、machine（架构）
5. 通过 ring buffer 发送事件

用户态一边轮询 ring buffer 一边检查子进程是否已退出。单个子进程可能多次 exec（例如 `/bin/sh -c 'exec /bin/true'` 先 exec shell，然后 exec `/bin/true`），所以在子进程退出后，工具会取尽 ring buffer 中的剩余事件。

![exec 镜像检查器数据流](https://github.com/eunomia-bpf/bpf-developer-tutorial/raw/main/src/54-exec-image-inspector/exec-image-flow.png)

## 代码详解

实现分布在四个文件中：共享头文件、新内核接口的兼容性头文件、BPF 程序、用户态加载器。

### 共享头文件

`exec_image_inspector.h` 定义 BPF 和用户态共享的结构：

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EXEC_IMAGE_INSPECTOR_H
#define __EXEC_IMAGE_INSPECTOR_H

#define EXEC_COMM_LEN 16
#define EXEC_PATH_LEN 256
#define EXEC_PROBE_LEN 8

struct exec_event {
	unsigned int pid;
	unsigned int tgid;
	unsigned char is_elf;
	unsigned char elf_class;
	unsigned char elf_data;
	unsigned char reserved;
	unsigned short elf_type;
	unsigned short elf_machine;
	int header_error;
	int path_error;
	int direct_probe_error;
	int deferred_probe_error;
	unsigned long long latency_ns;
	unsigned long long probe_offset;
	char comm[EXEC_COMM_LEN];
	char path[EXEC_PATH_LEN];
	unsigned char probe_bytes[EXEC_PROBE_LEN];
};

struct inspector_stats {
	unsigned long long matched;
	unsigned long long scheduled;
	unsigned long long schedule_errors;
	unsigned long long callbacks;
	unsigned long long header_errors;
	unsigned long long path_errors;
	unsigned long long direct_probes;
	unsigned long long direct_probe_errors;
	unsigned long long deferred_probes;
	unsigned long long deferred_probe_errors;
	unsigned long long dropped;
};

#endif /* __EXEC_IMAGE_INSPECTOR_H */
```

`exec_event` 携带报告一次 exec 所需的全部信息：进程标识符、解析后的路径、ELF 元数据、错误码。`inspector_stats` 累计各种计数器，用户态在退出时从 BSS 段读取并报告成功和失败率。

### 兼容性头文件

仓库的 vendored vmlinux 头文件早于 Linux 6.18/6.19，所以 `bpf_experimental.h` 在本地声明新接口：

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EXEC_IMAGE_INSPECTOR_BPF_EXPERIMENTAL_H
#define __EXEC_IMAGE_INSPECTOR_BPF_EXPERIMENTAL_H

/*
 * These Linux 6.18/6.19 declarations are not present in the repository's
 * older generated UAPI and vmlinux headers. Keep them local until those
 * vendored headers are regenerated.
 */
struct bpf_task_work {
	__u64 opaque;
} __attribute__((aligned(8)));

typedef int (*bpf_task_work_callback_t)(struct bpf_map *map, void *key,
					void *value);

extern int bpf_task_work_schedule_signal(struct task_struct *task,
					 struct bpf_task_work *work,
					 void *map__map,
					 bpf_task_work_callback_t callback) __ksym;
extern struct file *bpf_get_task_exe_file(struct task_struct *task) __ksym;
extern void bpf_put_file(struct file *file) __ksym;
extern int bpf_path_d_path(const struct path *path, char *buf,
			   __u64 buf__sz) __ksym;
extern int bpf_dynptr_from_file(struct file *file, __u32 flags,
				struct bpf_dynptr *ptr__uninit) __ksym;
extern int bpf_dynptr_file_discard(struct bpf_dynptr *dynptr) __ksym;

#endif /* __EXEC_IMAGE_INSPECTOR_BPF_EXPERIMENTAL_H */
```

这些声明用 `__ksym` 标记为在加载时解析的内核符号。等仓库的 vmlinux 头文件从 6.19+ 内核重新生成后，这个文件可以移除。

### BPF 程序

`exec_image_inspector.bpf.c` 实现 LSM 钩子和 task work 回调：

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"
#include "exec_image_inspector.h"

char LICENSE[] SEC("license") = "GPL";

#define ENOENT 2

#define EI_CLASS 4
#define EI_DATA 5
#define ELFCLASS32 1
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

const volatile __u32 target_tgid;
const volatile __u32 probe_offset;

struct inspector_stats stats;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct exec_work {
	__u64 scheduled_ns;
	int direct_probe_error;
	struct bpf_task_work work;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_work);
} pending SEC(".maps");

static __u16 read_elf_u16(const unsigned char *header, int offset, __u8 data)
{
	if (data == ELFDATA2MSB)
		return ((__u16)header[offset] << 8) | header[offset + 1];
	return header[offset] | ((__u16)header[offset + 1] << 8);
}

static int probe_file_without_sleep(struct file *file)
{
	unsigned char sample[EXEC_PROBE_LEN];
	struct bpf_dynptr dynptr;
	int err;

	if (!probe_offset)
		return 0;

	__sync_fetch_and_add(&stats.direct_probes, 1);
	if (!file) {
		err = -ENOENT;
		goto record;
	}

	err = bpf_dynptr_from_file(file, 0, &dynptr);
	if (err) {
		bpf_dynptr_file_discard(&dynptr);
		goto record;
	}

	err = bpf_dynptr_read(sample, sizeof(sample), &dynptr, probe_offset, 0);
	bpf_dynptr_file_discard(&dynptr);

record:
	if (err)
		__sync_fetch_and_add(&stats.direct_probe_errors, 1);
	return err;
}

static int inspect_executable(struct bpf_map *map, void *key, void *value)
{
	unsigned char header[64] = {};
	struct exec_work *work = value;
	struct exec_event event = {};
	struct task_struct *task;
	struct bpf_dynptr dynptr;
	struct file *file;
	__u64 pid_tgid;
	int err;

	(void)map;
	(void)key;
	__sync_fetch_and_add(&stats.callbacks, 1);

	pid_tgid = bpf_get_current_pid_tgid();
	event.pid = (__u32)pid_tgid;
	event.tgid = pid_tgid >> 32;
	event.latency_ns = bpf_ktime_get_ns() - work->scheduled_ns;
	event.direct_probe_error = work->direct_probe_error;
	event.probe_offset = probe_offset;
	bpf_get_current_comm(event.comm, sizeof(event.comm));

	task = bpf_get_current_task_btf();
	file = bpf_get_task_exe_file(task);
	if (!file) {
		event.header_error = -ENOENT;
		__sync_fetch_and_add(&stats.header_errors, 1);
		if (probe_offset) {
			event.deferred_probe_error = -ENOENT;
			__sync_fetch_and_add(&stats.deferred_probes, 1);
			__sync_fetch_and_add(&stats.deferred_probe_errors, 1);
		}
		goto emit;
	}

	err = bpf_path_d_path(&file->f_path, event.path, sizeof(event.path));
	if (err < 0) {
		event.path_error = err;
		__sync_fetch_and_add(&stats.path_errors, 1);
	}

	err = bpf_dynptr_from_file(file, 0, &dynptr);
	if (err) {
		bpf_dynptr_file_discard(&dynptr);
		event.header_error = err;
		__sync_fetch_and_add(&stats.header_errors, 1);
		if (probe_offset) {
			event.deferred_probe_error = err;
			__sync_fetch_and_add(&stats.deferred_probes, 1);
			__sync_fetch_and_add(&stats.deferred_probe_errors, 1);
		}
		goto put_file;
	}

	err = bpf_dynptr_read(header, sizeof(header), &dynptr, 0, 0);
	if (err) {
		event.header_error = err;
		__sync_fetch_and_add(&stats.header_errors, 1);
	}

	if (probe_offset) {
		__sync_fetch_and_add(&stats.deferred_probes, 1);
		err = bpf_dynptr_read(event.probe_bytes, sizeof(event.probe_bytes),
				      &dynptr, probe_offset, 0);
		event.deferred_probe_error = err;
		if (err)
			__sync_fetch_and_add(&stats.deferred_probe_errors, 1);
	}
	bpf_dynptr_file_discard(&dynptr);

	if (!event.header_error && header[0] == 0x7f && header[1] == 'E' &&
	    header[2] == 'L' && header[3] == 'F') {
		event.is_elf = 1;
		event.elf_class = header[EI_CLASS];
		event.elf_data = header[EI_DATA];
		event.elf_type = read_elf_u16(header, 16, event.elf_data);
		event.elf_machine = read_elf_u16(header, 18, event.elf_data);
	}

put_file:
	bpf_put_file(file);
emit:
	if (bpf_ringbuf_output(&events, &event, sizeof(event), 0))
		__sync_fetch_and_add(&stats.dropped, 1);
	return 0;
}

SEC("lsm/bprm_committed_creds")
void BPF_PROG(schedule_exec_inspection, struct linux_binprm *bprm)
{
	struct task_struct *task;
	struct exec_work *work;
	__u64 pid_tgid;
	__u32 key = 0, tgid;
	int err;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = pid_tgid >> 32;
	if (target_tgid && tgid != target_tgid)
		return;

	__sync_fetch_and_add(&stats.matched, 1);
	work = bpf_map_lookup_elem(&pending, &key);
	if (!work) {
		__sync_fetch_and_add(&stats.schedule_errors, 1);
		return;
	}

	work->scheduled_ns = bpf_ktime_get_ns();
	work->direct_probe_error = probe_file_without_sleep(bprm->file);
	task = bpf_get_current_task_btf();
	err = bpf_task_work_schedule_signal(task, &work->work, &pending,
					    inspect_executable);
	if (err) {
		__sync_fetch_and_add(&stats.schedule_errors, 1);
		return;
	}
	__sync_fetch_and_add(&stats.scheduled, 1);
}
```

入口点是用 `SEC("lsm/bprm_committed_creds")` 声明的 `schedule_exec_inspection`。这个 LSM 钩子在新可执行文件的凭据安装后触发，此时 `bprm->file` 指向正在被执行的文件。钩子本身不可睡眠，但可以识别目标并安排延迟工作。

两个 `const volatile` 变量（`target_tgid` 和 `probe_offset`）位于 `.rodata` 段。用户态在 `open()` 和 `load()` 之间写入值，验证器把它们当作编译期常量来优化。

当目标匹配时，程序从单元素 `pending` ARRAY map 查找 `struct exec_work`。这个结构保存 `bpf_task_work` 存储以及时间戳和可选的直接探测结果。单个槽位就够了，因为本工具每次调用只观察一个子进程。

可选的 `--probe-offset` 标志让工具通过 `probe_file_without_sleep` 在不可睡眠的钩子中尝试直接读取。测试套件用这个来验证：读取冷页在不可睡眠上下文中以 `-EFAULT` 失败，但在可睡眠回调中成功。

保存时间戳和直接探测结果后，钩子调用 `bpf_task_work_schedule_signal`。内核持有稍后执行回调所需的引用。

回调 `inspect_executable` 计算延迟用于诊断，然后用 `bpf_get_task_exe_file` 获取可执行文件。这返回一个带引用的 `struct file`，必须用 `bpf_put_file` 释放。回调解析路径、创建 file dynptr、读取 64 字节 ELF 头部并解析它。`read_elf_u16` 辅助函数处理字节序：ELF 文件在头部声明其字节序，多字节字段必须相应地读取。

每条创建 dynptr 的路径（无论成功还是失败）都必须调用 `bpf_dynptr_file_discard`。最后，`bpf_ringbuf_output` 把事件发送给用户态。

### 用户态加载器

`exec_image_inspector.c` 协调子进程、加载 BPF、接收事件、报告结果：

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "exec_image_inspector.h"
#include "exec_image_inspector.skel.h"

struct environment {
	unsigned long long probe_offset;
	unsigned int timeout_ms;
	bool verbose;
	char **command;
};

struct child_process {
	pid_t pid;
	int release_fd;
	bool released;
	bool reaped;
	int status;
};

struct event_context {
	unsigned int seen;
};

static struct environment env = {
	.timeout_ms = 5000,
};

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
		"Usage: %s [--probe-offset BYTES] [--timeout-ms MS] [--verbose] "
		"-- COMMAND [ARG...]\n\n"
		"Inspect the executable image installed by one command.\n\n"
		"Options:\n"
		"  -p, --probe-offset BYTES  also compare direct/deferred file reads\n"
		"  -t, --timeout-ms MS       bound the command, 100-60000 "
		"(default: 5000)\n"
		"  -v, --verbose             print libbpf diagnostics\n"
		"  -h, --help                show this help\n",
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

static int parse_probe_offset(const char *value)
{
	unsigned long long parsed;

	if (parse_u64(value, UINT_MAX - EXEC_PROBE_LEN, &parsed)) {
		fprintf(stderr, "invalid probe offset: %s\n", value);
		return -EINVAL;
	}
	env.probe_offset = parsed;
	return 0;
}

static int parse_timeout(const char *value)
{
	unsigned long long parsed;

	if (parse_u64(value, 60000, &parsed) || parsed < 100) {
		fprintf(stderr, "invalid timeout in milliseconds: %s\n", value);
		return -EINVAL;
	}
	env.timeout_ms = parsed;
	return 0;
}

static int parse_option(int option, const char *program)
{
	switch (option) {
	case 'p':
		return parse_probe_offset(optarg);
	case 't':
		return parse_timeout(optarg);
	case 'v':
		env.verbose = true;
		return 0;
	case 'h':
		usage(program);
		exit(0);
	default:
		return -EINVAL;
	}
}

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "probe-offset", required_argument, NULL, 'p' },
		{ "timeout-ms", required_argument, NULL, 't' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int error, option;

	while ((option = getopt_long(argc, argv, "+p:t:vh", options, NULL)) != -1) {
		error = parse_option(option, argv[0]);
		if (error)
			return error;
	}

	if (optind == argc) {
		fprintf(stderr, "COMMAND is required\n");
		return -EINVAL;
	}
	env.command = &argv[optind];
	return 0;
}

static long long monotonic_milliseconds(void)
{
	struct timespec timestamp;

	if (clock_gettime(CLOCK_MONOTONIC, &timestamp))
		return -errno;
	return timestamp.tv_sec * 1000LL + timestamp.tv_nsec / 1000000;
}

static int start_blocked_child(struct child_process *child)
{
	int pipe_fds[2];
	pid_t pid;

	if (pipe(pipe_fds))
		return -errno;

	pid = fork();
	if (pid < 0) {
		int error = -errno;

		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return error;
	}

	if (pid == 0) {
		char release;
		ssize_t count;

		close(pipe_fds[1]);
		do {
			count = read(pipe_fds[0], &release, sizeof(release));
		} while (count < 0 && errno == EINTR);
		close(pipe_fds[0]);
		if (count != sizeof(release))
			_exit(126);

		/* Intentional argv execution; no shell parses the supplied arguments. */
		execvp(env.command[0], env.command); /* Flawfinder: ignore */
		fprintf(stderr, "failed to execute %s: %s\n", env.command[0],
			strerror(errno));
		_exit(127);
	}

	close(pipe_fds[0]);
	child->pid = pid;
	child->release_fd = pipe_fds[1];
	return 0;
}

static int release_child(struct child_process *child)
{
	char release = 1;
	ssize_t count;

	do {
		count = write(child->release_fd, &release, sizeof(release));
	} while (count < 0 && errno == EINTR);
	close(child->release_fd);
	child->release_fd = -1;
	if (count != sizeof(release))
		return count < 0 ? -errno : -EIO;
	child->released = true;
	return 0;
}

static int child_exit_code(int status)
{
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);
	return 125;
}

static int reap_child(struct child_process *child, int options)
{
	pid_t result;

	if (child->reaped)
		return 1;
	do {
		result = waitpid(child->pid, &child->status, options);
	} while (result < 0 && errno == EINTR);
	if (result < 0)
		return -errno;
	if (result == 0)
		return 0;
	child->reaped = true;
	return 1;
}

static int drain_events(struct ring_buffer *ring_buffer)
{
	int error;

	for (;;) {
		error = ring_buffer__poll(ring_buffer, 0);
		if (error == -EINTR)
			continue;
		if (error < 0) {
			fprintf(stderr, "ring-buffer drain failed: %s\n",
				strerror(-error));
			return error;
		}
		if (!error)
			return 0;
	}
}

static const char *elf_class_name(unsigned char value)
{
	switch (value) {
	case 1:
		return "ELF32";
	case 2:
		return "ELF64";
	default:
		return "UNKNOWN";
	}
}

static const char *elf_data_name(unsigned char value)
{
	switch (value) {
	case 1:
		return "LSB";
	case 2:
		return "MSB";
	default:
		return "UNKNOWN";
	}
}

static const char *elf_type_name(unsigned short value)
{
	switch (value) {
	case 2:
		return "ET_EXEC";
	case 3:
		return "ET_DYN";
	default:
		return "OTHER";
	}
}

static const char *elf_machine_name(unsigned short value)
{
	switch (value) {
	case 3:
		return "EM_386";
	case 62:
		return "EM_X86_64";
	case 183:
		return "EM_AARCH64";
	default:
		return "OTHER";
	}
}

static int handle_event(void *context, void *data, size_t size)
{
	const struct exec_event *event = data;
	struct event_context *events = context;
	unsigned int index;

	if (size < sizeof(*event)) {
		fprintf(stderr, "short ring-buffer event: %zu bytes\n", size);
		return 0;
	}

	events->seen++;
	printf("EXEC pid=%u tgid=%u comm=%.*s path=%.*s is_elf=%u "
	       "class=%s endian=%s type=%s(%u) machine=%s(%u) "
	       "header_error=%d path_error=%d latency_us=%llu\n",
	       event->pid, event->tgid, EXEC_COMM_LEN, event->comm,
	       EXEC_PATH_LEN, event->path, event->is_elf,
	       elf_class_name(event->elf_class), elf_data_name(event->elf_data),
	       elf_type_name(event->elf_type), event->elf_type,
	       elf_machine_name(event->elf_machine), event->elf_machine,
	       event->header_error, event->path_error,
	       event->latency_ns / 1000);

	if (event->probe_offset) {
		printf("PROBE offset=%llu direct_error=%d deferred_error=%d bytes=",
		       event->probe_offset, event->direct_probe_error,
		       event->deferred_probe_error);
		for (index = 0; index < EXEC_PROBE_LEN; index++)
			printf("%02x", event->probe_bytes[index]);
		putchar('\n');
	}
	fflush(stdout);
	return 0;
}

static void stop_child(struct child_process *child)
{
	if (child->reaped || child->pid <= 0)
		return;
	if (!child->released && child->release_fd >= 0) {
		close(child->release_fd);
		child->release_fd = -1;
	} else {
		kill(child->pid, SIGKILL);
	}
	(void)reap_child(child, 0);
}

static int setup_inspector(const struct child_process *child,
			   struct event_context *events,
			   struct exec_image_inspector_bpf **skeleton,
			   struct ring_buffer **ring_buffer)
{
	struct exec_image_inspector_bpf *skel;
	struct ring_buffer *ring;
	int error;

	skel = exec_image_inspector_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return -ENOMEM;
	}
	*skeleton = skel;
	skel->rodata->target_tgid = child->pid;
	skel->rodata->probe_offset = env.probe_offset;

	error = exec_image_inspector_bpf__load(skel);
	if (error) {
		fprintf(stderr, "failed to load BPF object: %s\n", strerror(-error));
		return error;
	}
	error = exec_image_inspector_bpf__attach(skel);
	if (error) {
		fprintf(stderr, "failed to attach bprm_committed_creds LSM hook: %s\n",
			strerror(-error));
		return error;
	}

	ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
				events, NULL);
	if (!ring) {
		fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
		return errno ? -errno : -ENOMEM;
	}
	*ring_buffer = ring;
	return 0;
}

static int reap_timed_out_child(struct child_process *child)
{
	int error;

	if (child->reaped)
		return 0;

	fprintf(stderr, "command exceeded timeout; sending SIGKILL\n");
	kill(child->pid, SIGKILL);
	error = reap_child(child, 0);
	if (error < 0) {
		fprintf(stderr, "waitpid after timeout failed: %s\n",
			strerror(-error));
		return error;
	}
	return 0;
}

static int wait_for_command(struct ring_buffer *ring_buffer,
			    struct child_process *child,
			    const struct event_context *events)
{
	long long deadline, now;
	int error;

	printf("READY target_tgid=%d probe_offset=%llu timeout_ms=%u command=%s\n",
	       child->pid, env.probe_offset, env.timeout_ms, env.command[0]);
	fflush(stdout);
	error = release_child(child);
	if (error) {
		fprintf(stderr, "failed to release command process: %s\n",
			strerror(-error));
		return error;
	}

	now = monotonic_milliseconds();
	if (now < 0) {
		fprintf(stderr, "failed to read monotonic clock: %s\n",
			strerror((int)-now));
		return (int)now;
	}
	deadline = now + env.timeout_ms;

	for (;;) {
		error = ring_buffer__poll(ring_buffer, 50);
		if (error == -EINTR)
			continue;
		if (error < 0) {
			fprintf(stderr, "ring-buffer poll failed: %s\n", strerror(-error));
			return error;
		}

		error = reap_child(child, WNOHANG);
		if (error < 0) {
			fprintf(stderr, "waitpid failed: %s\n", strerror(-error));
			return error;
		}
		if (child->reaped && events->seen)
			break;

		now = monotonic_milliseconds();
		if (now < 0)
			return (int)now;
		if (now >= deadline)
			break;
		if (child->reaped && !events->seen)
			continue;
	}

	error = reap_timed_out_child(child);
	if (error)
		return error;
	error = drain_events(ring_buffer);
	if (error)
		return error;
	return child_exit_code(child->status);
}

static int report_result(const struct exec_image_inspector_bpf *skel,
			 const struct event_context *events, int command_exit)
{
	struct inspector_stats final_stats = skel->bss->stats;

	printf("SUMMARY matched=%llu scheduled=%llu schedule_errors=%llu "
	       "callbacks=%llu header_errors=%llu path_errors=%llu "
	       "direct_probes=%llu direct_probe_errors=%llu "
	       "deferred_probes=%llu deferred_probe_errors=%llu dropped=%llu "
	       "events=%u command_exit=%d\n",
	       final_stats.matched, final_stats.scheduled,
	       final_stats.schedule_errors, final_stats.callbacks,
	       final_stats.header_errors, final_stats.path_errors,
	       final_stats.direct_probes, final_stats.direct_probe_errors,
	       final_stats.deferred_probes, final_stats.deferred_probe_errors,
	       final_stats.dropped, events->seen, command_exit);

	if (!events->seen) {
		fprintf(stderr, "no executable image event was observed\n");
		return 1;
	}
	if (command_exit) {
		fprintf(stderr, "command exited with status %d\n", command_exit);
		return command_exit;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct exec_image_inspector_bpf *skel = NULL;
	struct child_process child = { .release_fd = -1 };
	struct event_context events = {};
	struct ring_buffer *ring_buffer = NULL;
	int command_exit, error, result = 1;

	error = parse_args(argc, argv);
	if (error) {
		usage(argv[0]);
		return 2;
	}

	libbpf_set_print(libbpf_print_fn);
	error = start_blocked_child(&child);
	if (error) {
		fprintf(stderr, "failed to create command process: %s\n",
			strerror(-error));
		return 1;
	}

	error = setup_inspector(&child, &events, &skel, &ring_buffer);
	if (error)
		goto cleanup;
	command_exit = wait_for_command(ring_buffer, &child, &events);
	if (command_exit < 0)
		goto cleanup;
	result = report_result(skel, &events, command_exit);

cleanup:
	stop_child(&child);
	ring_buffer__free(ring_buffer);
	exec_image_inspector_bpf__destroy(skel);
	return result;
}
```

核心技术是阻塞子进程握手。`start_blocked_child` 在 BPF 设置前 fork，但子进程阻塞在 pipe 读取上。父进程记录子进程 PID、打开 skeleton、写入 `target_tgid`、加载并挂载、创建 ring buffer，然后才调用 `release_child` 写管道让子进程继续执行 `execvp`。

`wait_for_command` 是主循环。它打印 `READY` 行、释放子进程，然后交替轮询 ring buffer 和检查子进程是否退出。当子进程被回收且至少收到一条事件时循环结束，或者超时时结束。超时后，`reap_timed_out_child` 发送 SIGKILL 并等待。

单次 exec 可能触发多条事件，如果命令本身也调用 exec（例如 `/bin/sh -c 'exec /bin/true'`）。子进程退出后，`drain_events` 用零超时 poll 取尽剩余事件。

`handle_event` 格式化输出，把数字 ELF 值转换为可读名称，同时保留原始值供脚本使用。

## 构建与运行

从源码构建：

```bash
git submodule update --init --recursive
make -C src/54-exec-image-inspector clean
make -C src/54-exec-image-inspector -j2
```

测试套件要求 Linux 6.19 或更新版本，且 BPF LSM 处于活动状态。检查 `bpf` 是否出现在 LSM 列表中：

```bash
cat /sys/kernel/security/lsm
```

如果缺少 `bpf`，在内核命令行中添加它：把引导加载器配置中的 `lsm=<existing-list>` 改为 `lsm=<existing-list>,bpf`。

运行测试：

```bash
cd src/54-exec-image-inspector
sudo make test
```

仓库 CI 只编译本课。运行时行为在 x86_64 上通过功能测试，内核版本 `7.0.0-rc2+`。示例输出：

```text
TEST-MISSING matched=0 events=0 command_exit=127
TEST-TIMEOUT matched=1 callbacks=1 events=1 command_exit=137
TEST-REEXEC matched=2 callbacks=2 events=2 command_exit=0 final_path=/usr/bin/true
READY target_tgid=1265 probe_offset=4214784 timeout_ms=3000 command=/tmp/exec-image-inspector-sxm3lumw/exec_fixture_image
EXEC pid=1265 tgid=1265 comm=exec_fixture_im path=/tmp/exec-image-inspector-sxm3lumw/exec_fixture_image is_elf=1 class=ELF64 endian=LSB type=ET_DYN(3) machine=EM_X86_64(62) header_error=0 path_error=0 latency_us=37
PROBE offset=4214784 direct_error=-14 deferred_error=0 bytes=454950524f424521
exec fixture completed
SUMMARY matched=1 scheduled=1 schedule_errors=0 callbacks=1 header_errors=0 path_errors=0 direct_probes=1 direct_probe_errors=1 deferred_probes=1 deferred_probe_errors=0 dropped=0 events=1 command_exit=0
PASS: missing-command, timeout cleanup, re-exec drain, ELF decode, and deferred file read succeeded
```

前三行测试覆盖边界条件：

- **TEST-MISSING**：不存在的命令以状态 127 退出。LSM 钩子从未触发，因为 exec 在凭据提交前就失败了，所以 `matched=0` 且 `events=0`。
- **TEST-TIMEOUT**：命令运行太久，被 SIGKILL 终止，以状态 137（128 + 9）回收。观察到一条 exec 事件。
- **TEST-REEXEC**：内部使用 `exec` 的 shell 命令产生两条事件，最终路径是 `/usr/bin/true`。

`EXEC` 行显示已安装的镜像和解析的 ELF 字段。`PROBE` 行展示了可睡眠上下文的差异：测试向一个页面写入标记（`EIPROBE!`），刷新并从页缓存驱逐它，然后 exec。不可睡眠钩子中的直接读取返回 `-EFAULT`（`-14`），因为页是冷的。可睡眠回调中的延迟读取成功，返回标记字节的十六进制表示（`454950524f424521`）。

检查简单命令：

```bash
sudo ./exec_image_inspector --timeout-ms 3000 -- /bin/true
```

命令行格式：

```text
exec_image_inspector [--probe-offset BYTES] [--timeout-ms MS] [--verbose] -- COMMAND [ARG...]
```

- `--timeout-ms`：100 到 60000 毫秒（默认 5000）。超过此期限后工具会终止并回收命令。
- `--probe-offset`：在钩子中（直接）和回调中（延迟）分别读取此偏移处的 8 字节，以验证冷页差异。
- `--verbose`：打印 libbpf 诊断信息。
- `--`：分隔 inspector 选项和要运行的命令。

### 环境要求

| 要求 | 详情 |
|---|---|
| 内核版本 | Linux 6.19+（BPF task work 在 6.18 引入，file dynptr 在 6.19 引入） |
| 内核配置 | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_LSM=y`, `CONFIG_SECURITY=y`, `CONFIG_DEBUG_INFO_BTF=y` |
| 活动 LSM | `/sys/kernel/security/lsm` 必须包含 `bpf` |
| 架构 | 已在 x86_64 上测试 |
| 权限 | root |

## 局限性与扩展

本工具每次调用观察一个直接子进程，使用单个 map 槽位。对于并发服务场景，需要按任务分配状态、实现准入限制、处理回调回收。超时清理只向子进程发送 SIGKILL；需要进程组管理或外部信号处理的调用方需自行添加这些功能。

## 总结

本教程展示了如何结合 BPF task work 和 file dynptr 来检查 exec 实际安装的可执行镜像。关键思路是分离两个时刻：识别目标（在不可睡眠的 LSM 钩子中）和读取文件内容（在可睡眠的 task work 回调中）。这让 eBPF 程序能可靠地读取文件数据，即使目标字节不在页缓存中也能完成。

阻塞子进程握手消除了 attach 竞态，有界执行确保清理完整，最终 drain 捕获所有事件。这些技术组合产生一个可复现的单命令工具，同时为扩展留出空间。

> 要深入了解 eBPF，请访问我们的教程仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或 <https://eunomia.dev/tutorials/>。

## 参考资料

- [BPF task-work 基础实现](https://github.com/torvalds/linux/commit/5c8fd7e2b5b0a527cf88740da122166695382a78)
- [bpf_task_work_schedule_signal kfunc](https://github.com/torvalds/linux/commit/38aa7003e369802f81a078f6673d10d97013f04f)
- [File-backed dynptr 基础实现](https://github.com/torvalds/linux/commit/8d8771dc03e48300e80b43744dd3c320ccaf746a)
- [File dynptr kfunc 与 helper](https://github.com/torvalds/linux/commit/e3e36edb1b8f0e6975c68acd2e1202ec0397fd75)
- [可睡眠 file-dynptr dispatch](https://github.com/torvalds/linux/commit/2c52e8943a437af6093d8b0f0920f1764f0e5f64)
- [Kernel kfunc 文档](https://github.com/torvalds/linux/blob/v7.1/Documentation/bpf/kfuncs.rst)
- [File-reader BPF selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/file_reader.c)
- [BPF task-work selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/task_work.c)
