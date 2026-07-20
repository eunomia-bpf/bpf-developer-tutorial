# eBPF 教程：检查 exec 后真正安装的可执行镜像

假设某个容器中运行着一系列嵌套的包装脚本，你从 `ps` 或 `/proc` 看到的命令行是 `/usr/bin/wrapper.sh --config /etc/app.conf`，但实际执行业务逻辑的可能是三层深处的 Python 解释器或某个动态链接的二进制。排查故障时你需要知道内核最终安装的是哪个可执行镜像、它是什么架构、用什么字节序，而不只是命令行参数。

本教程展示如何使用 BPF task work 和 file-backed dynptr 实现这一目标。工具挂载 LSM hook 观察 `bprm_committed_creds` 时刻，在凭据提交后为目标进程安排 task work 回调，回调在可睡眠上下文中重新获取已安装的可执行文件、解析路径、读取 ELF 头部，并把结果通过 ring buffer 发送给用户态。

> 完整源码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/54-exec-image-inspector>

## 为什么需要 BPF task work 和 file dynptr

传统的可执行文件检查方案都有明显的局限性。

最直接的想法是读取 `/proc/<pid>/exe` 符号链接，但这需要在进程存活期间完成，短命进程可能在你读取之前就已经退出。而且 `/proc` 访问发生在用户态，与内核的 exec 事件之间存在竞态窗口，同一进程可能已经执行了多次 `execve`。

使用 tracepoint 或 kprobe 观察 `sched_process_exec` 可以捕获 exec 事件，但这些 hook 运行在不可睡眠上下文中。你可以获取文件路径，但如果需要读取文件内容来验证 ELF 头部或检查嵌入的元数据，问题就来了：file-backed dynptr 的 `bpf_dynptr_read` 在目标字节位于冷页时会触发缺页操作，而缺页需要睡眠才能完成。不可睡眠上下文中的 BPF 程序无法等待 I/O。

BPF task work 才能真正解决这个问题。Linux 6.18 引入了 `bpf_task_work_schedule_signal` kfunc，允许 BPF 程序为目标 task 安排回调，内核会在安全的可睡眠上下文中执行这个回调。Linux 6.19 引入了 file-backed dynptr，提供验证器跟踪的文件数据访问方式。把这两个功能组合起来，你可以在 LSM hook 中识别目标进程、记录时间戳，然后安排 task work；回调在可睡眠上下文中执行，可以重新获取 task 已安装的可执行文件、通过 dynptr 读取任意位置的内容（包括冷页），最后把完整的检查结果发送给用户态。

这就是 `exec_image_inspector` 的设计思路：LSM hook 选定子进程并调度 task work，可睡眠回调完成实际的文件读取和解析工作。

## BPF task work 与 file dynptr 的工作原理

BPF task work 是一种延迟执行机制。当你在 BPF 程序中调用 `bpf_task_work_schedule_signal(task, work, map, callback)` 时，内核会把回调关联到指定的 task。回调不会立即执行，而是在该 task 返回用户态前的某个安全点执行，此时上下文允许睡眠。

`struct bpf_task_work` 是一个不透明的 64 字节结构，BPF 程序只需要为它分配存储空间，内核负责管理其内部状态。本工具使用单元素 ARRAY map 存储 `struct exec_work`，其中包含 `bpf_task_work` 存储、调度时间戳和直接探测结果。

File-backed dynptr 则提供了验证器跟踪的文件数据访问接口。`bpf_dynptr_from_file(file, flags, dynptr)` 从文件创建 dynptr，`bpf_dynptr_read(dst, len, dynptr, offset, flags)` 读取指定偏移处的内容。dynptr 持有内部状态，因此所有创建 dynptr 的路径都必须调用 `bpf_dynptr_file_discard` 来释放，包括失败分支。

在不可睡眠上下文中，dynptr 只能读取已经在页缓存中的内容，访问冷页会返回 `-EFAULT`。在可睡眠上下文中，dynptr 可以触发缺页操作并等待 I/O 完成。这正是 task work 回调的价值所在。

## 工具的整体流程

用户态启动后先 fork 目标命令，但子进程会在 pipe 上阻塞等待释放信号。这样父进程就能在子进程执行 `execvp` 之前知道它的 PID（也是 TGID），可以把这个值写入 BPF 程序的只读数据段作为过滤条件。阻塞子进程消除了短命命令带来的 attach 竞态，让整个示例保持自包含。

父进程打开 BPF skeleton、设置 `target_tgid` 和可选的 `probe_offset`、加载并挂载 LSM 程序、创建 ring buffer reader，随后向 pipe 写入释放字节让子进程执行 `execvp`。

子进程执行 exec 后，凭据提交时 `lsm/bprm_committed_creds` hook 触发。BPF 程序比较当前 TGID 与 `target_tgid`，不匹配则直接返回。命中目标后程序记录调度时间戳，如果设置了 `--probe-offset` 则先尝试在当前上下文直接读取（用于验证冷页场景），然后调用 `bpf_task_work_schedule_signal` 安排回调。

回调 `inspect_executable` 在该 task 的可睡眠上下文中执行。它调用 `bpf_get_task_exe_file` 获取 task 当前安装的可执行文件（返回带引用的 `struct file`，必须用 `bpf_put_file` 释放），用 `bpf_path_d_path` 解析路径，用 file dynptr 读取 64 字节 ELF 头部和可选的标记位置。读取成功后解析 ELF 魔数、class、data、type 和 machine 字段。最后把所有信息打包成 ring buffer 事件发送给用户态。

用户态边轮询 ring buffer 边用 `waitpid(WNOHANG)` 检查子进程状态。子进程回收且至少收到一条事件时结束循环，或者等到超时。同一子进程可能连续安装多个镜像（例如 `/bin/sh -c 'exec /bin/true'`），子进程回收后还要执行 `drain_events` 取尽 ring buffer 中的剩余事件。

![exec 镜像检查器数据流](https://github.com/eunomia-bpf/bpf-developer-tutorial/raw/main/src/54-exec-image-inspector/exec-image-flow.png)

## 代码实现

本工具由四个文件组成：共享头文件定义事件和统计结构、兼容性头文件声明新内核 kfunc、BPF 程序实现 hook 和回调、用户空间加载器管理生命周期。

### 共享头文件

`exec_image_inspector.h` 定义了 BPF 和用户空间共享的 ring buffer 事件结构和统计结构。

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

`exec_event` 包含了检查一次 exec 所需的全部信息：PID、TGID、进程名、路径、ELF 解析结果、探测结果、回调延迟和各类错误代码。`inspector_stats` 累计匹配、调度、回调、错误和丢弃计数，用户态在结束时读取 BSS 段并报告。

### 兼容性声明

Linux 6.18 引入 BPF task work，6.19 引入 file-backed dynptr。仓库当前生成的 UAPI 与 BTF 头文件早于这些功能，因此本工具把缺失声明放在局部头文件 `bpf_experimental.h` 中。

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

这个文件声明了 `bpf_task_work_schedule_signal`、`bpf_get_task_exe_file`、`bpf_put_file`、`bpf_path_d_path`、`bpf_dynptr_from_file` 和 `bpf_dynptr_file_discard` 等 kfunc。等仓库集成的 vmlinux 头文件包含这些声明后即可移除此文件。

### BPF 程序

`exec_image_inspector.bpf.c` 实现了 LSM hook 和 task work 回调。

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

程序的入口是 `SEC("lsm/bprm_committed_creds")` 声明的 `schedule_exec_inspection` 函数。`bprm_committed_creds` hook 在新可执行文件的凭据提交后运行，此时 `bprm->file` 指向本次 exec 涉及的镜像。这个 hook 本身不可睡眠，但我们可以在这里识别目标进程并安排 task work。

两个 `const volatile` 变量 `target_tgid` 和 `probe_offset` 位于 `.rodata` 段，用户态在 `open()` 之后、`load()` 之前写入值，验证器将它们视为编译期常量。程序首先比较当前 TGID 与 `target_tgid`，不匹配则直接返回，避免观察无关进程的 exec。

命中目标后程序从单元素 `pending` ARRAY map 查找 key 0 得到 `struct exec_work`。这个结构保存调度时间戳、直接探测结果和 `struct bpf_task_work` 存储。本工具一次调用只观察一个子进程，一个槽位已经足够。设置 `--probe-offset` 时，`probe_file_without_sleep` 在当前不可睡眠上下文中尝试从 `bprm->file` 读取指定位置的 8 字节。测试程序会把标记放到冷页位置，验证此时直接读取返回 `-EFAULT`。

hook 保存时间戳和直接读取结果后调用 `bpf_task_work_schedule_signal`，传入当前 task、work 存储、map 指针与 `inspect_executable` 回调函数指针。内核持有回调执行所需的引用，回调会在该 task 返回用户态前的可睡眠上下文中执行。

`inspect_executable` 是 task work 回调函数，签名为 `int callback(struct bpf_map *map, void *key, void *value)`。它首先计算回调延迟（当前时间减去调度时间戳）用于诊断，填充 PID、TGID、进程名和直接探测结果到事件结构。然后调用 `bpf_get_task_exe_file` 获取 task 已安装的可执行文件。这个 kfunc 返回带引用的 `struct file`，每次成功获取都必须用 `bpf_put_file` 释放。

回调先用 `bpf_path_d_path` 解析文件路径，再用 `bpf_dynptr_from_file` 创建 dynptr。因为现在处于可睡眠上下文，`bpf_dynptr_read` 可以触发缺页操作并等待 I/O 完成。回调只读取 64 字节 ELF 头部和可选的 8 字节标记。头部读取成功后程序检查 4 字节 ELF 魔数 `\x7fELF`，再解析 `EI_CLASS`（32 位或 64 位）、`EI_DATA`（小端或大端）、`e_type`（可执行文件或共享对象）和 `e_machine`（架构）。`read_elf_u16` 辅助函数根据字节序正确解析 16 位字段。

所有创建 dynptr 的路径都必须调用 `bpf_dynptr_file_discard` 释放其内部状态，包括 helper 失败的分支。最后 `bpf_ringbuf_output` 把事件发送给用户态，发送失败时递增 `dropped` 计数器。

### 用户空间加载器

`exec_image_inspector.c` 负责解析命令行、协调阻塞子进程、加载 BPF、格式化事件并清理资源。

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

加载器的流程围绕阻塞子进程握手展开。`start_blocked_child` 在 BPF 设置完成前 fork，但子进程会阻塞在 pipe 读取上。父进程此时已经知道子进程 PID，可以在打开 skeleton 后把它写入 `rodata->target_tgid`。挂载完成后 `release_child` 向 pipe 写入一个字节让子进程继续执行 `execvp`。这个握手消除了短命命令带来的 attach 竞态。

`setup_inspector` 函数打开 skeleton、设置只读数据、加载并挂载 BPF 程序、创建 ring buffer reader。加载失败时的错误信息会指出可能的原因，帮助用户排查内核版本或配置问题。

`wait_for_command` 是主循环。它先打印 `READY` 行表示工具已就绪，然后释放子进程、设置超时 deadline、进入 poll 循环。循环中交替调用 `ring_buffer__poll` 接收事件和 `waitpid(WNOHANG)` 检查子进程状态。子进程回收且至少收到一条事件时结束循环，或者等到超时。超时后 `reap_timed_out_child` 向子进程发送 SIGKILL 并等待其退出。

同一子进程可能连续安装多个镜像。例如运行 `/bin/sh -c 'exec /bin/true'` 时，shell 先 exec 自身，然后 exec `/bin/true`。子进程回收后 `drain_events` 用零超时 poll 取尽 ring buffer 中的剩余事件，确保最后一条镜像事件也能到达用户态。

`handle_event` 解析 ring buffer 事件并打印格式化输出。它把 ELF 数值转换成可读名称如 `ELF64`、`LSB`、`ET_DYN`、`EM_X86_64`，同时保留原始数值。设置 `--probe-offset` 时还会打印 `PROBE` 行显示探测结果。

## 编译与运行

从源码构建：

```bash
git submodule update --init --recursive
make -C src/54-exec-image-inspector clean
make -C src/54-exec-image-inspector -j2
```

集成测试需要 Linux 6.19 或更新版本，执行前请先确认活动 LSM 列表中包含 `bpf`：

```bash
cat /sys/kernel/security/lsm
```

要添加 `bpf`，请在内核启动参数中把 `lsm=<existing-list>` 改成 `lsm=<existing-list>,bpf`。

运行测试：

```bash
cd src/54-exec-image-inspector
sudo make test
```

仓库 CI 只编译本课。运行时行为在 x86_64 上通过功能测试，内核版本 `7.0.0-rc2+`。下面的会话记录给出测试框架和工具输出：

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

前三条测试记录覆盖重要边界：缺失命令以状态 127 退出，此时 committed-exec hook 尚未触发，因此 `matched=0`、`events=0`；超时用例产生 exec 事件后超过测试时限，由 SIGKILL 终止并以状态 137 回收；连续 exec 用例取尽两条镜像事件，确认 `/usr/bin/true` 最后出现。

`EXEC` 行给出已安装镜像和 ELF 头部解析结果。测试程序在 exec 前刷新并驱逐标记所在页面，hook 中直接读取返回 `-EFAULT`（`-14`），而 task-work 回调成功返回 `454950524f424521`（`EIPROBE!` 的十六进制字节）。这验证了不可睡眠上下文无法读取冷页，而可睡眠上下文可以。

检查其他命令时可省略测试程序专用的探测偏移：

```bash
sudo ./exec_image_inspector --timeout-ms 3000 -- /bin/true
```

命令行格式如下：

```text
exec_image_inspector [--probe-offset BYTES] [--timeout-ms MS] [--verbose] -- COMMAND [ARG...]
```

`--timeout-ms` 接受 100 至 60000 毫秒，默认值为 5000 毫秒，超过时限后加载器会终止并回收命令。`--probe-offset` 比较指定位置的 8 字节直接读取与延迟读取，用于验证冷页场景。`--verbose` 输出 libbpf 诊断，便于排查 load 或 attach 问题。`--` 明确结束 inspector 选项解析，后面的参数全部属于被观察命令。

### 环境要求

| 要求 | 详情 |
|---|---|
| 内核版本 | Linux 6.19+（BPF task work 在 6.18 引入，file-backed dynptr 在 6.19 引入） |
| 内核配置 | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_LSM=y`, `CONFIG_SECURITY=y`, `CONFIG_DEBUG_INFO_BTF=y` |
| 活动 LSM | `/sys/kernel/security/lsm` 中包含 `bpf` |
| 架构 | 已在 x86_64 上测试 |
| 权限 | root |

## 适用范围

本工具观察自身创建的一个直接子进程，单个 map 槽位适合这种 CLI 场景。如果要扩展到并发服务，可以改为按 task 分配状态、设置准入上限并回收待处理回调。超时清理向该子进程发送 SIGKILL，调用方可以添加进程组管理和外部信号处理来覆盖更复杂的场景。

## 总结

本教程展示了如何使用 BPF task work 和 file-backed dynptr 检查 exec 后真正安装的可执行镜像。相比读取 `/proc/<pid>/exe` 或在 tracepoint 中获取路径，这种方案可以在可睡眠上下文中读取文件内容，即使目标字节位于冷页也能完成。

工具的核心思路是把识别目标进程的时刻（不可睡眠的 LSM hook）与读取文件内容的时刻（可睡眠的 task work 回调）分开。阻塞子进程握手消除了 attach 竞态，有界命令运行和最终 drain 确保所有事件都能到达用户态，显式资源释放保证清理完整。这些内核功能组合成了一个可复现的单命令工具，同时为并发场景留出扩展空间。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [BPF task-work 基础实现](https://github.com/torvalds/linux/commit/5c8fd7e2b5b0a527cf88740da122166695382a78)
- [bpf_task_work_schedule_signal kfunc](https://github.com/torvalds/linux/commit/38aa7003e369802f81a078f6673d10d97013f04f)
- [File-backed dynptr 基础实现](https://github.com/torvalds/linux/commit/8d8771dc03e48300e80b43744dd3c320ccaf746a)
- [File dynptr kfunc 与 helper](https://github.com/torvalds/linux/commit/e3e36edb1b8f0e6975c68acd2e1202ec0397fd75)
- [可睡眠 file-dynptr dispatch](https://github.com/torvalds/linux/commit/2c52e8943a437af6093d8b0f0920f1764f0e5f64)
- [Kernel kfunc 文档](https://github.com/torvalds/linux/blob/v7.1/Documentation/bpf/kfuncs.rst)
- [File-reader BPF selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/file_reader.c)
- [BPF task-work selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/task_work.c)
