# eBPF 教程：BPF 迭代器用于内核数据导出

你是否曾经尝试监控数百个进程，却不得不解析数千个 `/proc` 文件，只为找到你关心的几个进程？或者需要自定义格式的内核数据，但不想修改内核本身？传统的 `/proc` 文件系统访问速度慢、不灵活，即使你只需要一小部分过滤后的数据，也会强制你在用户空间处理大量数据。

这正是 **BPF 迭代器**要解决的问题。在 Linux 内核 5.8 中引入，迭代器让你可以直接从 BPF 程序遍历内核数据结构，在内核中应用过滤器，并以你想要的任何格式输出你需要的确切数据。在本教程中，我们将构建一个双模式迭代器，它显示进程的内核堆栈跟踪和打开的文件描述符，并通过进程名称进行内核内过滤 - 比解析 `/proc` 快得多。

## BPF 迭代器简介：/proc 的替代品

### 问题：/proc 缓慢且僵化

传统的 Linux 监控围绕着 `/proc` 文件系统展开。需要查看进程在做什么？读取 `/proc/*/stack`。想要打开的文件？解析 `/proc/*/fd/*`。这样可以工作，但当你在大规模监控系统或需要内核数据的特定过滤视图时，效率非常低下。

性能问题是系统性的。每次 `/proc` 访问都需要一个系统调用、内核模式转换、文本格式化、数据复制到用户空间，然后你将文本解析回结构。如果你想要 1000 个进程中所有 "bash" 进程的堆栈跟踪，你仍然需要读取所有 1000 个 `/proc/*/stack` 文件并在用户空间过滤。这就是 1000 次系统调用、1000 次文本解析操作，以及传输的数兆字节数据，只是为了找到少数几个匹配项。

格式不灵活性加剧了问题。内核选择显示什么数据以及如何格式化。想要带有自定义注释的堆栈跟踪？抱歉，你只能得到内核的固定格式。需要跨进程聚合数据？在用户空间解析所有内容。`/proc` 接口是为人类使用而设计的，而不是为程序化过滤和分析设计的。

传统监控是这样的：

```bash
# 查找所有 bash 进程的堆栈跟踪
for pid in $(pgrep bash); do
  echo "=== PID $pid ==="
  cat /proc/$pid/stack
done
```

这会生成 `pgrep` 作为子进程，对每个匹配的 PID 进行一次系统调用以读取堆栈文件，解析文本输出，并在用户空间进行所有过滤。编写简单，但性能糟糕。

### 解决方案：可编程的内核内迭代

BPF 迭代器翻转了这个模型。与其将所有数据拉到用户空间进行处理，不如将处理逻辑推送到数据所在的内核中。迭代器是一个附加到内核数据结构遍历的 BPF 程序，它会为每个元素调用。内核遍历任务、文件或套接字，用每个元素的上下文调用你的 BPF 程序，你的代码决定输出什么以及如何格式化。

架构很优雅。你编写一个标记为 `SEC("iter/task")` 或 `SEC("iter/task_file")` 的 BPF 程序，在迭代期间接收每个任务或文件。在这个程序中，你可以直接访问内核结构字段，可以使用普通的 C 逻辑根据任何条件进行过滤，并使用 `BPF_SEQ_PRINTF()` 按需格式化输出。内核处理迭代机制，而你的代码纯粹专注于过滤和格式化。

当用户空间从迭代器文件描述符读取时，魔法完全发生在内核中。内核遍历任务列表，为每个任务调用你的 BPF 程序并传递 task_struct 指针。你的程序检查任务名称是否匹配你的过滤器 - 如果不匹配，它立即返回 0 且不输出。如果匹配，你的程序提取堆栈跟踪并将其格式化到 seq_file。所有这些都发生在内核上下文中，然后数据才会跨越到用户空间。

好处是变革性的。**内核内过滤**意味着只有相关数据跨越内核边界，消除了浪费的工作。**自定义格式**让你可以输出二进制、JSON、CSV，无论你的工具需要什么。**单次读取操作**取代了数千次单独的 `/proc` 文件访问。**零解析**，因为你在内核中正确格式化了数据。**可组合性**与标准 Unix 工具配合使用，因为迭代器输出通过普通文件描述符传递。

### 迭代器类型和能力

内核为许多子系统提供迭代器。**任务迭代器**（`iter/task`）遍历所有任务，让你访问进程状态、凭据、资源使用和父子关系。**文件迭代器**（`iter/task_file`）遍历打开的文件描述符，显示文件、套接字、管道和其他 fd 类型。**网络迭代器**（`iter/tcp`、`iter/udp`）遍历活动网络连接及完整的套接字状态。**BPF 对象迭代器**（`iter/bpf_map`、`iter/bpf_prog`）枚举已加载的 BPF 程序和 map 以进行内省。

我们的教程专注于任务和 task_file 迭代器，因为它们解决了常见的监控需求，并展示了适用于所有迭代器类型的核心概念。

## 实现：双模式任务迭代器

让我们构建一个完整的示例，在一个工具中演示两种迭代器类型。我们将创建一个程序，可以显示进程的内核堆栈跟踪或打开的文件描述符，并可选择按进程名称进行过滤。

### 完整的 BPF 程序：task_stack.bpf.c

```c
// SPDX-License-Identifier: GPL-2.0
/* Kernel task stack and file descriptor iterator */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define MAX_STACK_TRACE_DEPTH   64
unsigned long entries[MAX_STACK_TRACE_DEPTH] = {};
#define SIZE_OF_ULONG (sizeof(unsigned long))

/* Filter: only show stacks for tasks with this name (empty = show all) */
char target_comm[16] = "";
__u32 stacks_shown = 0;
__u32 files_shown = 0;

/* Task stack iterator */
SEC("iter/task")
int dump_task_stack(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	long i, retlen;
	int match = 1;

	if (task == (void *)0) {
		/* End of iteration - print summary */
		if (stacks_shown > 0) {
			BPF_SEQ_PRINTF(seq, "\n=== Summary: %u task stacks shown ===\n",
				       stacks_shown);
		}
		return 0;
	}

	/* Filter by task name if specified */
	if (target_comm[0] != '\0') {
		match = 0;
		for (i = 0; i < 16; i++) {
			if (task->comm[i] != target_comm[i])
				break;
			if (task->comm[i] == '\0') {
				match = 1;
				break;
			}
		}
		if (!match)
			return 0;
	}

	/* Get kernel stack trace for this task */
	retlen = bpf_get_task_stack(task, entries,
				    MAX_STACK_TRACE_DEPTH * SIZE_OF_ULONG, 0);
	if (retlen < 0)
		return 0;

	stacks_shown++;

	/* Print task info and stack trace */
	BPF_SEQ_PRINTF(seq, "=== Task: %s (pid=%u, tgid=%u) ===\n",
		       task->comm, task->pid, task->tgid);
	BPF_SEQ_PRINTF(seq, "Stack depth: %u frames\n", retlen / SIZE_OF_ULONG);

	for (i = 0; i < MAX_STACK_TRACE_DEPTH; i++) {
		if (retlen > i * SIZE_OF_ULONG)
			BPF_SEQ_PRINTF(seq, "  [%2ld] %pB\n", i, (void *)entries[i]);
	}
	BPF_SEQ_PRINTF(seq, "\n");

	return 0;
}

/* Task file descriptor iterator */
SEC("iter/task_file")
int dump_task_file(struct bpf_iter__task_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	__u32 fd = ctx->fd;
	long i;
	int match = 1;

	if (task == (void *)0 || file == (void *)0) {
		if (files_shown > 0 && ctx->meta->seq_num > 0) {
			BPF_SEQ_PRINTF(seq, "\n=== Summary: %u file descriptors shown ===\n",
				       files_shown);
		}
		return 0;
	}

	/* Filter by task name if specified */
	if (target_comm[0] != '\0') {
		match = 0;
		for (i = 0; i < 16; i++) {
			if (task->comm[i] != target_comm[i])
				break;
			if (task->comm[i] == '\0') {
				match = 1;
				break;
			}
		}
		if (!match)
			return 0;
	}

	if (ctx->meta->seq_num == 0) {
		BPF_SEQ_PRINTF(seq, "%-16s %8s %8s %6s %s\n",
			       "COMM", "TGID", "PID", "FD", "FILE_OPS");
	}

	files_shown++;

	BPF_SEQ_PRINTF(seq, "%-16s %8d %8d %6d 0x%lx\n",
		       task->comm, task->tgid, task->pid, fd,
		       (long)file->f_op);

	return 0;
}
```

### 理解 BPF 代码

程序实现了两个共享通用过滤逻辑的独立迭代器。`SEC("iter/task")` 注解将 `dump_task_stack` 注册为任务迭代器 - 内核将为系统中的每个任务调用此函数一次。上下文结构 `bpf_iter__task` 提供三个关键部分：包含迭代元数据和用于输出的 seq_file 的 `meta` 字段，指向当前 task_struct 的 `task` 指针，以及当迭代结束时为 NULL 的任务指针，以便你可以打印摘要。

任务堆栈迭代器展示了内核内过滤的实际应用。当 `task` 为 NULL 时，我们已到达迭代的结尾，可以打印摘要统计信息，显示有多少任务与我们的过滤器匹配。对于每个任务，我们首先通过将 `task->comm`（进程名称）与 `target_comm` 进行比较来应用过滤。我们不能在 BPF 中使用像 `strcmp()` 这样的标准库函数，所以我们手动循环遍历字符逐字节比较。如果名称不匹配且启用了过滤，我们立即返回 0 且不输出 - 这个任务在内核中完全被跳过，不会跨越到用户空间。

一旦任务通过过滤，我们使用 `bpf_get_task_stack()` 提取其内核堆栈跟踪。这个 BPF 辅助函数将最多 64 个堆栈帧捕获到我们的 `entries` 数组中，返回写入的字节数。我们使用 `BPF_SEQ_PRINTF()` 格式化输出，它写入内核的 seq_file 基础设施。特殊的 `%pB` 格式说明符将内核地址符号化，将原始指针转换为人类可读的函数名称，如 `schedule+0x42/0x100`。这使得堆栈跟踪立即可用于调试。

文件描述符迭代器演示了不同的迭代器类型。`SEC("iter/task_file")` 告诉内核为所有任务的每个打开的文件描述符调用此函数。上下文提供 `task`、`file`（内核的 struct file 指针）和 `fd`（数字文件描述符）。我们应用相同的任务名称过滤，然后将输出格式化为表格。使用 `ctx->meta->seq_num` 检测第一次输出让我们可以只打印一次列标题。

注意过滤如何在任何昂贵的操作之前发生。我们首先检查任务名称，只有在匹配时才提取堆栈跟踪或格式化文件信息。这最小化了内核快速路径中的工作 - 不匹配的任务只需进行字符串比较就被拒绝，没有内存分配、没有格式化、没有输出。

### 完整的用户空间程序：task_stack.c

```c
// SPDX-License-Identifier: GPL-2.0
/* Userspace program for task stack and file iterator */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "task_stack.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void run_iterator(const char *name, struct bpf_program *prog)
{
	struct bpf_link *link;
	int iter_fd, len;
	char buf[8192];

	link = bpf_program__attach_iter(prog, NULL);
	if (!link) {
		fprintf(stderr, "Failed to attach %s iterator\n", name);
		return;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		fprintf(stderr, "Failed to create %s iterator: %d\n", name, iter_fd);
		bpf_link__destroy(link);
		return;
	}

	while ((len = read(iter_fd, buf, sizeof(buf) - 1)) > 0) {
		buf[len] = '\0';
		printf("%s", buf);
	}

	close(iter_fd);
	bpf_link__destroy(link);
}

int main(int argc, char **argv)
{
	struct task_stack_bpf *skel;
	int err;
	int show_files = 0;

	libbpf_set_print(libbpf_print_fn);

	/* Parse arguments */
	if (argc > 1 && strcmp(argv[1], "--files") == 0) {
		show_files = 1;
		argc--;
		argv++;
	}

	/* Open BPF application */
	skel = task_stack_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Configure filter before loading */
	if (argc > 1) {
		strncpy(skel->bss->target_comm, argv[1], sizeof(skel->bss->target_comm) - 1);
		printf("Filtering for tasks matching: %s\n\n", argv[1]);
	} else {
		printf("Usage: %s [--files] [comm]\n", argv[0]);
		printf("  --files    Show open file descriptors instead of stacks\n");
		printf("  comm       Filter by process name\n\n");
	}

	/* Load BPF program */
	err = task_stack_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	if (show_files) {
		printf("=== BPF Task File Descriptor Iterator ===\n\n");
		run_iterator("task_file", skel->progs.dump_task_file);
	} else {
		printf("=== BPF Task Stack Iterator ===\n\n");
		run_iterator("task", skel->progs.dump_task_stack);
	}

cleanup:
	task_stack_bpf__destroy(skel);
	return err;
}
```

### 理解用户空间代码

用户空间程序展示了一旦你理解了模式，迭代器的使用是多么简单。`run_iterator()` 函数封装了三步迭代器生命周期。首先，`bpf_program__attach_iter()` 将 BPF 程序附加到迭代器基础设施，注册它以在迭代期间被调用。其次，`bpf_iter_create()` 创建表示迭代器实例的文件描述符。第三，简单的 `read()` 调用使用迭代器输出。

这就是使其强大的原因：当你从迭代器 fd 读取时，内核透明地开始遍历任务或文件。对于每个元素，它调用你的 BPF 程序并传递元素的上下文。你的 BPF 代码过滤并格式化输出到 seq_file 缓冲区。内核累积此输出并通过 read() 调用返回它。从用户空间的角度来看，它只是在读取文件 - 所有迭代、过滤和格式化的复杂性都隐藏在内核中。

main 函数处理模式选择和配置。我们解析命令行参数以确定是显示堆栈还是文件，以及要过滤的进程名称。至关重要的是，我们在加载 BPF 程序之前设置 `skel->bss->target_comm`。这将过滤字符串写入 BPF 程序的全局数据节，使其在程序运行时对内核代码可见。这就是我们如何在没有复杂通信通道的情况下将配置从用户空间传递到内核的方法。

加载后，我们根据 `--files` 标志选择要运行哪个迭代器。两个迭代器使用相同的过滤逻辑，但产生不同的输出 - 一个显示堆栈跟踪，另一个显示文件描述符。共享的过滤代码展示了 BPF 程序如何在不同的迭代器类型之间实现可重用的逻辑。

## 编译和执行

导航到 bpf_iters 目录并构建：

```bash
cd bpf-developer-tutorial/src/features/bpf_iters
make
```

Makefile 使用 BTF 支持编译 BPF 程序，并生成包含嵌入在 C 结构中的编译字节码的骨架头。这个骨架 API 使 BPF 程序加载变得简单。

显示所有 systemd 进程的内核堆栈跟踪：

```bash
sudo ./task_stack systemd
```

预期输出：

```
Filtering for tasks matching: systemd

=== BPF Task Stack Iterator ===

=== Task: systemd (pid=1, tgid=1) ===
Stack depth: 6 frames
  [ 0] ep_poll+0x447/0x460
  [ 1] do_epoll_wait+0xc3/0xe0
  [ 2] __x64_sys_epoll_wait+0x6d/0x110
  [ 3] x64_sys_call+0x19b1/0x2310
  [ 4] do_syscall_64+0x7e/0x170
  [ 5] entry_SYSCALL_64_after_hwframe+0x76/0x7e

=== Summary: 1 task stacks shown ===
```

显示 bash 进程的打开文件描述符：

```bash
sudo ./task_stack --files bash
```

预期输出：

```
Filtering for tasks matching: bash

=== BPF Task File Descriptor Iterator ===

COMM                 TGID      PID     FD FILE_OPS
bash                12345    12345      0 0xffffffff81e3c6e0
bash                12345    12345      1 0xffffffff81e3c6e0
bash                12345    12345      2 0xffffffff81e3c6e0
bash                12345    12345    255 0xffffffff82145dc0

=== Summary: 4 file descriptors shown ===
```

不带过滤运行以查看所有任务：

```bash
sudo ./task_stack
```

这显示了系统中每个任务的堆栈。在典型的桌面上，这可能会显示数百个任务。注意它与为所有进程解析 `/proc/*/stack` 相比运行速度有多快 - 迭代器效率更高。

## 何时使用 BPF 迭代器与 /proc

选择 **BPF 迭代器**当你需要过滤的内核数据而不需要用户空间处理开销、不匹配 `/proc` 文本的自定义输出格式、频繁运行的性能关键监控，或与基于 BPF 的可观测性基础设施集成时。当你监控许多实体但只关心一个子集，或者当你需要在内核中聚合和转换数据时，迭代器表现出色。

选择 **/proc** 当你需要简单的一次性查询、调试或原型设计（开发速度比运行时性能更重要）、希望在内核版本之间获得最大可移植性（迭代器需要相对较新的内核），或在无法加载 BPF 程序的受限环境中运行时。

基本权衡是处理位置。迭代器将过滤和格式化推入内核以提高效率和灵活性，而 `/proc` 保持内核简单并在用户空间进行所有处理。对于复杂系统的生产监控，迭代器通常因其性能优势和编程灵活性而获胜。

## 总结和下一步

BPF 迭代器通过直接从 BPF 代码启用可编程、过滤的迭代，彻底改变了我们导出内核数据的方式。与其重复读取和解析 `/proc` 文件，你编写一个 BPF 程序，在内核内迭代内核结构，在源头应用过滤，并完全按需格式化输出。这消除了来自系统调用、模式转换和用户空间解析的大量开销，同时在输出格式方面提供了完全的灵活性。

我们的双模式迭代器演示了任务和文件迭代，展示了一个 BPF 程序如何使用共享过滤逻辑导出内核数据的多个视图。内核处理复杂的迭代机制，而你的 BPF 代码纯粹专注于过滤和格式化。迭代器通过其文件描述符接口与标准 Unix 工具无缝集成，使它们成为复杂监控管道的可组合构建块。

> 如果你想深入了解 eBPF，请查看我们的教程仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- **BPF 迭代器文档：** <https://docs.kernel.org/bpf/bpf_iterators.html>
- **内核迭代器自测：** Linux 内核树 `tools/testing/selftests/bpf/*iter*.c`
- **教程仓库：** <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/bpf_iters>
- **libbpf 迭代器 API：** <https://github.com/libbpf/libbpf>
- **BPF 辅助函数手册：** <https://man7.org/linux/man-pages/man7/bpf-helpers.7.html>

示例改编自 Linux 内核 BPF 自测，并增加了教育性增强。需要 Linux 内核 5.8+ 以获得迭代器支持、启用 BTF 和 libbpf。完整源代码可在教程仓库中获得。
