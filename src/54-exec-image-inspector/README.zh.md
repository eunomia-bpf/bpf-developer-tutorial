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
2. 在钩子中（不可睡眠）创建每次 exec 独立的状态并安排 task work 回调
3. 回调在可睡眠上下文中执行，可以访问已安装的可执行文件、读取任意偏移的内容（包括冷页）、然后把结果发送给用户态

这种分离（在不可睡眠钩子中安排工作，在可睡眠回调中读取文件）是关键思路。

## BPF task work 的工作机制

调用 `bpf_task_work_schedule_signal(task, work, map, callback)` 时，内核把你的回调关联到指定的任务。回调不会立即执行；它会稍后在该任务返回用户态之前的某个安全点执行。

`struct bpf_task_work` 是一个不透明结构，内核用它来追踪已安排的回调。BPF 程序只需为它分配存储空间，不解释其内容。本工具使用以 `pid_tgid` 为键的 HASH map；每个 `struct exec_work` 值包含 `bpf_task_work` 存储以及时间戳和中间结果字段。不同 key 让并发 exec 互不干扰。

回调签名是 `int callback(struct bpf_map *map, void *key, void *value)`。`value` 参数指向包含你的 `bpf_task_work` 的 map 元素，所以你可以通过周围的字段从调度钩子向回调传递数据。

## file dynptr 的工作机制

dynptr 用边界信息包装指针，BPF 验证器可以追踪这些边界。对于 file dynptr：

- `bpf_dynptr_from_file(file, flags, dynptr)` 从文件创建 dynptr
- `bpf_dynptr_read(dst, len, dynptr, offset, flags)` 读取指定偏移处的内容
- `bpf_dynptr_file_discard(dynptr)` 释放 dynptr 的内部状态

每条创建 dynptr 的路径（包括错误路径）都必须调用 `bpf_dynptr_file_discard` 来释放它。忘记释放会泄漏内部资源。

在不可睡眠上下文中，`bpf_dynptr_read` 只有在目标字节已经在页缓存中时才会成功。访问冷页返回 `-EFAULT`。在可睡眠上下文中，同样的调用可以触发缺页处理并等待 I/O，即使对冷页也能成功。这个差异就是 task work 的价值所在：回调运行在可睡眠上下文中，文件读取能可靠完成。

## 工具架构

用户态程序加载并挂载 BPF 程序，创建 ring buffer reader，然后打印 `READY scope=system-wide`。之后它会持续运行到收到 SIGINT 或 SIGTERM，期间 workload 可以正常运行。

`READY` 之后每次成功 exec 都会触发 `lsm/bprm_committed_creds`。钩子以当前 `pid_tgid` 为键向 `pending` HASH map 插入一个 `exec_work`，记录时间戳并安排 task work 回调。插入或调度失败都会被计数并清理对应 map 条目。

回调 `inspect_executable` 稍后在执行 exec 的任务的可睡眠上下文中运行。它：

1. 调用 `bpf_get_task_exe_file` 获取已安装的可执行文件（返回一个带引用的 `struct file`，必须用 `bpf_put_file` 释放）
2. 用 `bpf_path_d_path` 解析路径
3. 创建 file dynptr 并读取 64 字节 ELF 头部
4. 解析 ELF 字段：魔数、class（32/64 位）、data（字节序）、type（可执行文件 vs 共享对象）、machine（架构）
5. 通过 ring buffer 发送事件

用户态轮询 ring buffer，直到收到信号。关闭时先解除 LSM 挂载，再等待 `completed >= scheduled`，排空剩余事件并打印计数，最后销毁 skeleton。

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
	unsigned long long latency_ns;
	char comm[EXEC_COMM_LEN];
	char path[EXEC_PATH_LEN];
};

struct inspector_stats {
	unsigned long long matched;
	unsigned long long scheduled;
	unsigned long long schedule_errors;
	unsigned long long callbacks;
	unsigned long long completed;
	unsigned long long header_errors;
	unsigned long long path_errors;
	unsigned long long dropped;
	unsigned long long cleanup_errors;
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

struct inspector_stats stats;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct exec_work {
	__u64 scheduled_ns;
	struct bpf_task_work work;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct exec_work);
} pending SEC(".maps");

static __u16 read_elf_u16(const unsigned char *header, int offset, __u8 data)
{
	if (data == ELFDATA2MSB)
		return ((__u16)header[offset] << 8) | header[offset + 1];
	return header[offset] | ((__u16)header[offset + 1] << 8);
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

	__sync_fetch_and_add(&stats.callbacks, 1);
	pid_tgid = bpf_get_current_pid_tgid();
	event.pid = (__u32)pid_tgid;
	event.tgid = pid_tgid >> 32;
	event.latency_ns = bpf_ktime_get_ns() - work->scheduled_ns;
	bpf_get_current_comm(event.comm, sizeof(event.comm));

	task = bpf_get_current_task_btf();
	file = bpf_get_task_exe_file(task);
	if (!file) {
		event.header_error = -ENOENT;
		__sync_fetch_and_add(&stats.header_errors, 1);
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
		goto put_file;
	}

	err = bpf_dynptr_read(header, sizeof(header), &dynptr, 0, 0);
	if (err) {
		event.header_error = err;
		__sync_fetch_and_add(&stats.header_errors, 1);
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
	if (bpf_map_delete_elem(map, key))
		__sync_fetch_and_add(&stats.cleanup_errors, 1);
	__sync_fetch_and_add(&stats.completed, 1);
	return 0;
}

SEC("lsm/bprm_committed_creds")
void BPF_PROG(schedule_exec_inspection, struct linux_binprm *bprm)
{
	struct task_struct *task;
	struct exec_work empty_work = {};
	struct exec_work *work;
	__u64 pid_tgid;
	__u64 key;
	int err;

	(void)bprm;
	pid_tgid = bpf_get_current_pid_tgid();
	key = pid_tgid;
	__sync_fetch_and_add(&stats.matched, 1);
	err = bpf_map_update_elem(&pending, &key, &empty_work, BPF_NOEXIST);
	if (err) {
		__sync_fetch_and_add(&stats.schedule_errors, 1);
		return;
	}
	work = bpf_map_lookup_elem(&pending, &key);
	if (!work) {
		__sync_fetch_and_add(&stats.schedule_errors, 1);
		if (bpf_map_delete_elem(&pending, &key))
			__sync_fetch_and_add(&stats.cleanup_errors, 1);
		return;
	}

	work->scheduled_ns = bpf_ktime_get_ns();
	task = bpf_get_current_task_btf();
	err = bpf_task_work_schedule_signal(task, &work->work, &pending,
					    inspect_executable);
	if (err) {
		__sync_fetch_and_add(&stats.schedule_errors, 1);
		if (bpf_map_delete_elem(&pending, &key))
			__sync_fetch_and_add(&stats.cleanup_errors, 1);
		return;
	}
	__sync_fetch_and_add(&stats.scheduled, 1);
}
```

入口点是用 `SEC("lsm/bprm_committed_creds")` 声明的 `schedule_exec_inspection`。这个 LSM 钩子在新可执行文件的凭据安装后触发。钩子本身不可睡眠，因此它创建每次 exec 独立的状态并安排延迟工作。

每次 exec 都会用 `BPF_NOEXIST` 向 `pending` HASH map 插入清零的 `struct exec_work`，key 是 `pid_tgid`，然后记录时间戳。回调删除同一个 key，因此并发 exec 不会共享一个 task-work 槽位。

保存时间戳后，钩子调用 `bpf_task_work_schedule_signal`。内核持有稍后执行回调所需的引用。插入、查找或调度失败都会被计数；任何已经创建 pending 状态的失败路径都会删除它。

回调 `inspect_executable` 计算延迟用于诊断，然后用 `bpf_get_task_exe_file` 获取可执行文件。这返回一个带引用的 `struct file`，必须用 `bpf_put_file` 释放。回调解析路径、创建 file dynptr、读取 64 字节 ELF 头部并解析它。`read_elf_u16` 辅助函数处理字节序：ELF 文件在头部声明其字节序，多字节字段必须相应地读取。

每条创建 dynptr 的路径（无论成功还是失败）都必须调用 `bpf_dynptr_file_discard`。最后，`bpf_ringbuf_output` 把事件发送给用户态，回调删除 pending 条目并增加 `completed`，使关闭流程等待真正完成的工作，而不只是已调度的工作。

### 用户态加载器

完整加载器可从教程开头的源码链接查看。它的主生命周期如下：

```c
int main(int argc, char **argv)
{
	struct exec_image_inspector_bpf *skel = NULL;
	struct event_context events = {};
	struct ring_buffer *ring_buffer = NULL;
	int error, result = 1;

	error = parse_args(argc, argv);
	if (error) {
		usage(stderr, argv[0]);
		return 2;
	}
	error = install_signal_handlers();
	if (error) {
		fprintf(stderr, "failed to install signal handlers: %s\n",
			strerror(-error));
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	error = setup_inspector(&events, &skel, &ring_buffer);
	if (error)
		goto cleanup;
	error = monitor_execs(ring_buffer);
	exec_image_inspector_bpf__detach(skel);
	if (!error)
		error = drain_pending_events(ring_buffer, skel);
	report_result(skel, &events);
	if (!error)
		result = 0;

cleanup:
	ring_buffer__free(ring_buffer);
	exec_image_inspector_bpf__destroy(skel);
	return result;
}
```

`setup_inspector` 打开、加载并挂载 skeleton，然后创建 ring buffer。`monitor_execs` 打印 `READY`，并轮询到 SIGINT 或 SIGTERM。

关闭时 `main` 先 detach。`drain_pending_events` 再用有界的 100 ms poll 等待 `completed` 追上 `scheduled`，排空 ring buffer，并在销毁资源前报告全部计数。

`handle_event` 格式化输出，把数字 ELF 值转换为可读名称，同时保留原始值供脚本使用。

## 构建与运行

从源码构建：

```bash
git submodule update --init --recursive
make -C src/54-exec-image-inspector clean
make -C src/54-exec-image-inspector -j2
```

运行前，检查 `bpf` 是否出现在活动 LSM 列表中：

```bash
cat /sys/kernel/security/lsm
```

如果缺少 `bpf`，在内核命令行中添加它：把引导加载器配置中的 `lsm=<existing-list>` 改为 `lsm=<existing-list>,bpf`。

启动监控器：

```bash
sudo ./src/54-exec-image-inspector/exec_image_inspector
```

程序打印 `READY scope=system-wide` 后，会为每次成功 exec 输出一行 `EXEC`，其中包含进程 ID、命令名、解析后的可执行文件路径、ELF 元数据和回调延迟。按 Ctrl-C 停止；最后的 `SUMMARY` 会显示调度、回调、错误、丢弃和事件计数。

需要查看 libbpf 诊断信息时使用 `--verbose`：

```bash
sudo ./src/54-exec-image-inspector/exec_image_inspector --verbose
```

### 环境要求

| 要求 | 详情 |
|---|---|
| 内核版本 | Linux 6.19+（BPF task work 在 6.18 引入，file dynptr 在 6.19 引入） |
| 内核配置 | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_LSM=y`, `CONFIG_SECURITY=y`, `CONFIG_DEBUG_INFO_BTF=y` |
| 活动 LSM | `/sys/kernel/security/lsm` 必须包含 `bpf` |
| 架构 | 已在 x86_64 上测试 |
| 权限 | root |

## 局限性与扩展

本工具在 `READY` 后观察系统级成功 exec。pending HASH map 最多支持 4096 个并发 `pid_tgid` key，插入或调度压力会反映在 `schedule_errors`。关闭时会等待回调约一秒，超时则返回错误。

## 总结

本教程展示了如何结合 BPF task work 和 file dynptr 来检查 exec 实际安装的可执行镜像。LSM 钩子为每次 exec 安排工作，task work 回调则在可睡眠上下文中读取文件。这让 eBPF 程序能可靠地读取文件数据，即使目标字节不在页缓存中也能完成。

持续监控器为独立 workload 提供自然的 `READY` 边界。先 detach 再 drain 的关闭顺序、每次 exec 独立的 pending 状态和完成计数，在保留原有 task-work 与 file-dynptr 教学内容的同时保证并发回调安全。

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
