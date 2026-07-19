# eBPF 教程：在 exec 后检查真正安装的可执行镜像

一个包装脚本启动另一个包装脚本，最终启动解释器加载真正的业务逻辑。排查故障时你只知道命令行，却想知道内核最后安装的是哪个可执行镜像。

本课实现 `exec_image_inspector`，在 `bprm_committed_creds` LSM hook 上观察一个子进程，报告最终安装的可执行文件路径，并解析 ELF 类别、字节序、类型和机器架构。示例同时展示为什么可能触发缺页的文件读取要放到 BPF task work 回调中执行：LSM hook 本身不可睡眠，但 task-work 回调可以进入可睡眠上下文，通过 file-backed dynptr 读取文件页。学完本课后，你可以把这套把小规模文件检查从不可睡眠 hook 转移到可睡眠回调的做法用于类似场景。

完整实现位于 [`exec_image_inspector.h`](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/54-exec-image-inspector/exec_image_inspector.h)、[`bpf_experimental.h`](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/54-exec-image-inspector/bpf_experimental.h)、[`exec_image_inspector.bpf.c`](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/54-exec-image-inspector/exec_image_inspector.bpf.c) 和 [`exec_image_inspector.c`](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/54-exec-image-inspector/exec_image_inspector.c)。本课的 [`Makefile`](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/54-exec-image-inspector/Makefile)、[exec 测试程序](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/54-exec-image-inspector/tests/exec_fixture.c)和[集成测试](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/54-exec-image-inspector/tests/test_exec_image_inspector.py)提供了构建流程与可复现的冷页用例。

## 为什么文件读取需要可睡眠上下文

`bprm_committed_creds` 在新可执行文件的凭据提交后运行，此时 `bprm->file` 指向本次 exec 涉及的镜像，可以观察 task 实际安装的内容。这个 hook 本身不可睡眠，file-backed dynptr 可以读取缓存中的页面，但目标字节恰好在冷页中时触发的缺页操作需要睡眠才能完成。测试程序会主动驱逐标记所在页面，让这条边界稳定复现。

BPF task work 提供了可睡眠分支。`bpf_task_work_schedule_signal()` 把回调关联到当前 task，回调在安全的可睡眠上下文中执行，通过 `bpf_get_task_exe_file()` 取得 task 当前安装的可执行文件，再调用 file dynptr 辅助函数完成读取。

工具只观察自身创建的一个子进程，让加载器在挂载前就能确定目标 TGID，单个 task-work 槽位也足够支撑本例。

## 一次 exec 如何变成用户态事件

用户态 fork 目标命令后让子进程在 pipe 上阻塞，父进程把子进程 TGID 和可选的 probe offset 写入 BPF 只读数据，加载 skeleton、挂载 LSM 程序、创建 ring-buffer reader，随后释放 pipe 让子进程执行 `execvp`。

凭据提交后 `lsm/bprm_committed_creds` 匹配选定的 TGID，hook 可以先在当前上下文中尝试直接文件读取，保存结果后通过 `bpf_task_work_schedule_signal` 安排 `inspect_executable` 回调。回调在可睡眠上下文重新取得 task 已安装的可执行文件、解析路径、通过 file dynptr 读取 ELF 头部和可选标记，最后发送一条 ring buffer 事件。

用户态边 poll 边 `waitpid(WNOHANG)` 检查子进程状态，子进程回收且至少收到一条事件时结束循环，或者等到时限。子进程回收后 `drain_events` 取尽 ring buffer，确保同一子进程后续 exec 的事件也能到达用户态，随后加载器释放 ring buffer 并销毁 BPF skeleton。

让子进程先阻塞可以消除短命命令带来的 attach 竞态，pipe 握手让整个示例保持自包含。

![exec 镜像检查器数据流](https://github.com/eunomia-bpf/bpf-developer-tutorial/raw/main/src/54-exec-image-inspector/exec-image-flow.png)

蓝色节点覆盖用户态的阻塞子进程握手、目标 TGID 与 probe offset 配置、attach、释放 exec、poll/waitpid 循环以及最终 drain，橙色节点跟踪不可睡眠的 `bprm_committed_creds` 路径及其可选的直接探测和 `pending[0]` 调度状态。紫色节点从调度 task work 开始，可睡眠回调重新获取可执行文件、解析路径、通过 file-backed dynptr 读取内容并释放 dynptr 和文件状态，绿色 ring-buffer 事件把路径、ELF 字段、探测结果和回调延迟返回用户态。同一子进程后续每次 committed exec 都走相同的 hook 到事件路径，加载器因此执行最终 drain。

## 共享事件与统计结构

共享头文件定义了内核态与用户态共同使用的 ring buffer 事件和最终统计。

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

`exec_event` 包含 PID、TGID、ELF 解析结果、路径、命令名、回调延迟、探测结果和各类错误代码。`inspector_stats` 累计匹配、调度、回调、错误和丢弃计数，用户态在结束时读取 BSS 区并报告。

## 兼容性声明

Linux 6.18 引入 BPF task work，6.19 引入 file-backed dynptr。仓库当前生成的 UAPI 与 BTF 头文件早于这些功能，因此本课把缺失声明放在局部头文件 `bpf_experimental.h` 中。

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

这个文件声明了 `bpf_task_work_schedule_signal`、`bpf_get_task_exe_file`、`bpf_put_file`、`bpf_path_d_path`、`bpf_dynptr_from_file` 和 `bpf_dynptr_file_discard` 等 kfunc，仓库集成的 vmlinux 头文件包含这些声明后即可移除。

## BPF 程序

内核态程序过滤一个 TGID，在 `lsm/bprm_committed_creds` hook 中匹配目标进程后安排 task work，回调读取已安装镜像并解析 ELF 头部，最后发送 ring buffer 事件。
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

`schedule_exec_inspection` 先比较当前 TGID 与 `target_tgid`，加载器在 BPF object 加载前设置这个只读值，其他进程的 exec 直接返回。命中目标后程序增加 `matched`，从单元素 `pending` ARRAY map 查找 key 0 得到 `struct exec_work`。这个结构保存 `scheduled_ns`、直接探测结果和 `struct bpf_task_work` 存储，一次工具调用只观察一个子进程，一个槽位已经足够。

设置 `--probe-offset` 后，`probe_file_without_sleep` 从 `bprm->file` 创建 file-backed dynptr 并尝试读取 8 字节。测试程序中的 `create_probe_image()` 把 `EIPROBE!` 放到超过 4 MiB 的位置，再驱逐标记所在页面，验证运行时直接读取返回 `-EFAULT`。hook 保存时间戳和直接读取结果后调用 `bpf_task_work_schedule_signal`，传入当前 task、work storage、map 与 `inspect_executable`，内核持有回调所需引用。

`inspect_executable` 在该 task 的可睡眠上下文中执行。它记录回调延迟用于诊断，填充 PID、TGID、进程名与直接探测结果，调用 `bpf_get_task_exe_file()` 取得 task 已安装的镜像。这个 kfunc 返回带引用的 `struct file`，每次成功获取都必须用 `bpf_put_file()` 释放。回调先通过 `bpf_path_d_path` 解析路径，再用 `bpf_dynptr_from_file` 创建 dynptr，这个 file dynptr 持有内部状态，因此所有创建分支都要调用 `bpf_dynptr_file_discard()`，包括 helper 失败分支。

回调只读取 64 字节 ELF 头部和可选的 8 字节标记。头部读取成功后程序检查 4 字节 ELF 魔数，再解析 `EI_CLASS`、`EI_DATA`、`e_type` 与 `e_machine`，`read_elf_u16` 同时处理大端和小端的 16 位字段。头部、路径、直接探测和延迟探测的错误都保留在事件中。

## 用户态加载器

用户态程序负责解析命令、协调阻塞子进程、加载 BPF、格式化事件、执行超时策略并清理资源。
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

`start_blocked_child` 在 BPF 设置前 fork，但子进程先等待 pipe 中的一个字节。父进程此时已经知道 child PID（在本例中也是 TGID），可以在加载 object 前设置 `target_tgid`。挂载完成后 `release_child` 才允许 `execvp` 运行，程序把 `argv` 参数向量直接传入这个函数。`wait_for_command()` 轮询 ring buffer、调用 `waitpid(WNOHANG)`，在子进程已回收且至少收到一条事件时结束，或者等到时限。

同一子进程可能连续安装多个镜像，集成用例运行 `/bin/sh -c 'exec /bin/true'` 先收到 shell 的事件再收到 `/bin/true` 的事件。子进程回收后 `drain_events` 取尽 ring buffer，确保最后一条镜像事件到达用户态。命令超过 `--timeout-ms` 后 `reap_timed_out_child` 发送 SIGKILL 并等待其退出，正常完成与已处理错误路径都会释放 ring buffer、销毁 skeleton 并由此卸载 LSM link。用户态把常见 ELF 值转换成 `ELF64`、`LSB`、`ET_DYN` 和 `EM_X86_64` 等名称，同时保留原始数值，检查错误也保留在事件字段中。

## 编译和运行

完成干净构建：

```bash
git submodule update --init --recursive
make -C src/54-exec-image-inspector clean
make -C src/54-exec-image-inspector -j2
```

集成测试需要 Linux 6.19 或更新版本的一次性测试客户机，执行前请先满足下文的运行要求并确认活动 LSM 列表中包含 `bpf`。`make test` 与直接运行工具都会挂载 BPF LSM 程序。

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

PID、TGID、临时路径、回调延迟和探测偏移在重新构建或运行后会变化，延迟只用于诊断。`EXEC` 行给出已安装镜像和 ELF 头部，测试程序在 exec 前刷新并驱逐标记所在页面，hook 中直接读取返回 `-EFAULT`（`-14`），task-work 回调返回 `454950524f424521`（`EIPROBE!` 的十六进制字节）。

`READY` 前三条测试记录覆盖重要边界：缺失命令以状态 127 退出，此时 committed-exec hook 尚未触发，因此 `matched=0`、`events=0`；超时用例产生 exec 事件后超过 200 ms 测试时限，由 SIGKILL 终止并以状态 137 回收；连续 exec 用例取尽两条镜像事件，确认 `/usr/bin/true` 最后出现。

检查其他命令时可省略测试程序专用的探测偏移：

```bash
sudo ./exec_image_inspector --timeout-ms 3000 -- /bin/true
```

命令行格式如下：

```text
exec_image_inspector [--probe-offset BYTES] [--timeout-ms MS] [--verbose] -- COMMAND [ARG...]
```

- `--timeout-ms` 接受 100 至 60000 ms，默认值为 5000 ms。超过时限后，加载器会终止并回收命令。
- `--probe-offset` 比较指定位置的 8 字节直接读取与延迟读取，用于测试程序验证直接读取与延迟读取的差异；测试程序会计算有效的标记偏移并创建冷页条件。
- `--verbose` 输出 libbpf 诊断，便于排查 load 或 attach 问题。
- `--` 明确结束 inspector 选项解析，后面的参数全部属于被观察命令。

普通运行会打印 `READY`、一条或多条 `EXEC` 与 `SUMMARY`，设置 `--probe-offset` 时还会输出 `PROBE` 行。

## 运行要求

| 要求 | 值 | 原因 |
| --- | --- | --- |
| Linux 内核 | 6.19 或更新版本 | BPF task work 在 6.18 引入，file-backed dynptr 在 6.19 引入 |
| 内核配置 | `CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`、`CONFIG_BPF_JIT=y`、`CONFIG_BPF_LSM=y`、`CONFIG_SECURITY=y`、`CONFIG_DEBUG_INFO_BTF=y` | 加载带 BTF 的 BPF LSM 程序 |
| 活动 LSM 列表 | `/sys/kernel/security/lsm` 中包含 `bpf` | 启动时激活 BPF LSM 还需要在 `lsm=` 参数中包含 `bpf` |
| 权限 | root | 加载并挂载 BPF LSM 程序 |
| 已测试架构 | x86_64 | 确定性 ELF 断言当前按 x86-64 编写 |
| 已测试工具链 | 仓库固定的 bpftool `3be8ac3` 与嵌套 libbpf `fc064eb` | 构建本课使用的 BPF object 与生成 skeleton |
| 硬件 | 无 | 测试程序无需加速器或特殊设备 |

采集输出时内核源码工作树在 commit `a03114efd0720dff230388f7e160e427e54ea31b` 上保持干净，内核镜像 SHA-256 为 `760150dd317a5c05e58d35928bd70c399f41838f3be3ac643f3f3a3af4340b88`，配置文件 SHA-256 为 `82f63944a9ddd0bc3b0a60c3e6ebbe3e9900f2eefad7d3872793bb98b3cc68fe`。

在测试客户机中执行下面的命令，检查活动 LSM 列表：

```bash
cat /sys/kernel/security/lsm
```

要添加 `bpf`，请保留现有的逗号分隔 LSM 条目，在 kernel command-line 中把 `lsm=<existing-list>` 改成 `lsm=<existing-list>,bpf`，这样可以在一次性测试客户机中启用 attach。

## 适用范围

本工具观察自身创建的一个直接子进程，单个 map 槽位适合这种 CLI，并发服务可以扩展为按 task 分配状态、设置准入上限并回收待处理回调。超时清理向该子进程发送 SIGKILL，调用方可以添加进程组管理和外部信号处理。

## 总结

本例把 LSM hook 识别已提交 exec 的时刻与可睡眠回调读取文件页的时刻分开。阻塞子进程握手、有界命令运行、最终取尽 ring buffer 和显式资源释放把这些内核功能组合成了可复现的单命令工具，同时为并发服务留出扩展空间。

> 如果你想继续深入学习 eBPF，可以查看我们的教程仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial>。

## 参考资料

- [BPF task-work 基础实现](https://github.com/torvalds/linux/commit/5c8fd7e2b5b0a527cf88740da122166695382a78)
- [bpf_task_work_schedule_signal kfunc](https://github.com/torvalds/linux/commit/38aa7003e369802f81a078f6673d10d97013f04f)
- [File-backed dynptr 基础实现](https://github.com/torvalds/linux/commit/8d8771dc03e48300e80b43744dd3c320ccaf746a)
- [File dynptr kfunc 与 helper](https://github.com/torvalds/linux/commit/e3e36edb1b8f0e6975c68acd2e1202ec0397fd75)
- [可睡眠 file-dynptr dispatch](https://github.com/torvalds/linux/commit/2c52e8943a437af6093d8b0f0920f1764f0e5f64)
- [Kernel kfunc 文档](https://github.com/torvalds/linux/blob/v7.1/Documentation/bpf/kfuncs.rst)
- [File-reader BPF selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/file_reader.c)
- [BPF task-work selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/task_work.c)
