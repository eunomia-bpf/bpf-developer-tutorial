# eBPF 教程：BPF 工作队列用于异步可睡眠任务

你是否曾经需要你的 eBPF 程序睡眠、分配内存或等待设备 I/O？传统的 eBPF 程序在受限的上下文中运行，阻塞操作会导致系统崩溃。但是，如果你的 HID 设备需要在注入的按键事件之间进行时序延迟，或者你的清理例程需要在释放资源时睡眠怎么办？

这就是 **BPF 工作队列**所实现的功能。由 Red Hat 的 Benjamin Tissoires 于 2024 年为 HID-BPF 设备处理而创建，工作队列让你可以调度在进程上下文中运行的异步工作，在那里允许睡眠和阻塞操作。在本教程中，我们将探讨为什么创建工作队列、它们与定时器有何不同，并构建一个演示异步回调执行的完整示例。

## BPF 工作队列简介：解决睡眠问题

### 问题：当 eBPF 无法睡眠时

在 BPF 工作队列出现之前，开发者有 `bpf_timer` 用于延迟执行。定时器非常适合在延迟后调度回调，非常适合更新计数器或触发周期性事件。但有一个根本性的限制使得定时器对某些关键用例不可用：**bpf_timer 在 softirq（软件中断）上下文中运行**。

Softirq 上下文有内核强制执行的严格规则。你不能睡眠或等待 I/O - 任何这样做的尝试都会导致内核恐慌或死锁。你不能使用 `GFP_KERNEL` 标志的 `kzalloc()` 分配内存，因为内存分配可能需要等待页面。你不能与需要等待响应的硬件设备通信。本质上，你不能执行任何可能导致 CPU 等待的阻塞操作。

这个限制在 Red Hat 的 Benjamin Tissoires 于 2023 年开发 HID-BPF 时成为一个真正的问题。HID 设备（键盘、鼠标、平板电脑、游戏控制器）经常需要定时器根本无法处理的操作。想象一下实现键盘宏功能，按下 F1 输入 "hello" - 你需要在每次按键之间延迟 10ms，以便系统正确处理事件。或者考虑一个固件有问题的设备，在系统唤醒后需要重新初始化 - 你必须发送命令并等待硬件响应。softirq 上下文中的定时器回调无法做到这一切。

正如 Benjamin Tissoires 在他的内核补丁中解释的那样："我需要类似于 bpf_timers 的东西，但不在软 IRQ 上下文中……bpf_timer 功能会阻止我 kzalloc 并等待设备。"

### 解决方案：进程上下文执行

2024 年初，Benjamin 提出并开发了 **bpf_wq** - 本质上是"在进程上下文而不是 softirq 中的 bpf_timer"。内核社区在 2024 年 4 月将其合并到 Linux v6.10+ 中。关键见解简单但强大：通过在进程上下文中运行回调（通过内核的工作队列基础设施），BPF 程序可以访问全套内核操作。

以下是进程上下文的变化：

| 功能 | bpf_timer (softirq) | bpf_wq (进程) |
|---------|---------------------|------------------|
| **可以睡眠？** | ❌ 否 - 会崩溃 | ✅ 是 - 安全睡眠 |
| **内存分配** | ❌ 仅限有限标志 | ✅ 完整 `kzalloc()` 支持 |
| **设备 I/O** | ❌ 不能等待 | ✅ 可以等待响应 |
| **阻塞操作** | ❌ 禁止 | ✅ 完全支持 |
| **延迟** | 非常低（微秒） | 较高（毫秒） |
| **用例** | 时间关键快速路径 | 可睡眠慢速路径 |

工作队列启用了经典的"快速路径 + 慢速路径"模式。你的 eBPF 程序在快速路径中立即处理性能关键操作，然后调度昂贵的清理或 I/O 操作在慢速路径中异步运行。快速路径保持响应性，而慢速路径获得所需的能力。

### 实际应用

应用跨越多个领域。**HID 设备处理**是最初的动机 - 注入带时序延迟的键盘宏、无需内核驱动程序即可动态修复损坏的设备固件、从睡眠中唤醒后重新初始化设备、即时转换输入事件。所有这些都需要只有工作队列才能提供的可睡眠操作。

**网络数据包处理**受益于异步清理模式。你的 XDP 程序在快速路径中执行速率限制并丢弃数据包（非阻塞），而工作队列在后台清理过时的跟踪条目。这可以防止内存泄漏而不影响数据包处理性能。

**安全监控**可以立即应用快速规则，然后使用工作队列查询信誉数据库或外部威胁情报服务。快速路径做出即时决策，而慢速路径根据复杂分析更新策略。

**资源清理**推迟昂贵的操作。与其在释放内存、关闭连接或压缩数据结构时阻塞主代码路径，不如调度工作队列在后台处理清理。

## 实现：简单的工作队列测试

让我们构建一个演示工作队列生命周期的完整示例。我们将创建一个在 `unlink` 系统调用上触发、调度异步工作并验证主路径和工作队列回调都正确执行的程序。

### 完整的 BPF 程序：wq_simple.bpf.c

```c
// SPDX-License-Identifier: GPL-2.0
/* Simple BPF workqueue example */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"

char LICENSE[] SEC("license") = "GPL";

/* Element with embedded workqueue */
struct elem {
	int value;
	struct bpf_wq work;
};

/* Array to store our element */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} array SEC(".maps");

/* Result variables */
__u32 wq_executed = 0;
__u32 main_executed = 0;

/* Workqueue callback - runs asynchronously in workqueue context */
static int wq_callback(void *map, int *key, void *value)
{
	struct elem *val = value;
	/* This runs later in workqueue context */
	wq_executed = 1;
	val->value = 42; /* Modify the value asynchronously */
	return 0;
}

/* Main program - schedules work */
SEC("fentry/do_unlinkat")
int test_workqueue(void *ctx)
{
	struct elem init = {.value = 0}, *val;
	struct bpf_wq *wq;
	int key = 0;

	main_executed = 1;

	/* Initialize element in map */
	bpf_map_update_elem(&array, &key, &init, 0);

	/* Get element from map */
	val = bpf_map_lookup_elem(&array, &key);
	if (!val)
		return 0;

	/* Initialize workqueue */
	wq = &val->work;
	if (bpf_wq_init(wq, &array, 0) != 0)
		return 0;

	/* Set callback function */
	if (bpf_wq_set_callback(wq, wq_callback, 0))
		return 0;

	/* Schedule work to run asynchronously */
	if (bpf_wq_start(wq, 0))
		return 0;

	return 0;
}
```

### 理解 BPF 代码

程序演示了从初始化到异步执行的完整工作队列工作流程。我们首先定义一个嵌入工作队列的结构。`struct elem` 包含应用数据（`value`）和工作队列句柄（`struct bpf_wq work`）。这种嵌入模式至关重要 - 工作队列基础设施需要知道哪个 map 包含工作队列结构，将其嵌入到 map 值中建立了这种关系。

我们的 map 是一个只有一个条目的简单数组，为了本例的简单性而选择。在生产代码中，你通常会使用哈希 map 来跟踪多个实体，每个实体都有自己的嵌入式工作队列。全局变量 `wq_executed` 和 `main_executed` 作为测试工具，让用户空间验证两个代码路径都运行了。

工作队列回调显示了所有工作队列回调必须遵循的签名：`int callback(void *map, int *key, void *value)`。内核在进程上下文中异步调用此函数，传递包含工作队列的 map、条目的键和指向值的指针。这个签名为回调提供了关于哪个元素触发它的完整上下文以及对元素数据的访问。我们的回调设置 `wq_executed = 1` 来证明它运行了，并修改 `val->value = 42` 来演示异步修改在 map 中持久化。

附加到 `fentry/do_unlinkat` 的主程序在 `unlink` 系统调用执行时触发。这为我们提供了一种简单的方法来激活程序 - 用户空间只需删除一个文件。我们立即设置 `main_executed = 1` 来标记同步路径。然后我们初始化一个元素并使用 `bpf_map_update_elem()` 将其存储在 map 中。这是必要的，因为工作队列必须嵌入在 map 条目中。

工作队列初始化遵循三步序列。首先，`bpf_wq_init(wq, &array, 0)` 初始化工作队列句柄，传递包含它的 map。验证器使用此信息来验证工作队列及其容器是否正确相关。其次，`bpf_wq_set_callback(wq, wq_callback, 0)` 注册我们的回调函数。验证器在加载时检查此签名，并将拒绝签名不匹配的程序。第三，`bpf_wq_start(wq, 0)` 调度工作队列异步执行。此调用立即返回 - 主程序继续同步执行，而内核将工作排队以便稍后在进程上下文中执行。

所有三个函数中的 flags 参数都保留供将来使用，在当前内核中应为 0。该模式允许将来扩展而不破坏 API 兼容性。

### 完整的用户空间程序：wq_simple.c

```c
// SPDX-License-Identifier: GPL-2.0
/* Userspace test for BPF workqueue */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "wq_simple.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct wq_simple_bpf *skel;
	int err, fd;

	libbpf_set_print(libbpf_print_fn);

	/* Open and load BPF application */
	skel = wq_simple_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = wq_simple_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("BPF workqueue program attached. Triggering unlink syscall...\n");

	/* Create a temporary file to trigger do_unlinkat */
	fd = open("/tmp/wq_test_file", O_CREAT | O_WRONLY, 0644);
	if (fd >= 0) {
		close(fd);
		unlink("/tmp/wq_test_file");
	}

	/* Give workqueue time to execute */
	sleep(1);

	/* Check results */
	printf("\nResults:\n");
	printf("  main_executed = %u (expected: 1)\n", skel->bss->main_executed);
	printf("  wq_executed = %u (expected: 1)\n", skel->bss->wq_executed);

	if (skel->bss->main_executed == 1 && skel->bss->wq_executed == 1) {
		printf("\n✓ Test PASSED!\n");
	} else {
		printf("\n✗ Test FAILED!\n");
		err = 1;
	}

cleanup:
	wq_simple_bpf__destroy(skel);
	return err;
}
```

### 理解用户空间代码

用户空间程序编排测试并验证结果。我们使用 libbpf 的骨架 API，它将编译的 BPF 字节码嵌入到 C 结构中，使加载变得简单。`wq_simple_bpf__open_and_load()` 调用编译（如果需要）、将 BPF 程序加载到内核中，并在一次操作中创建所有 map。

加载后，`wq_simple_bpf__attach()` 将 fentry 程序附加到 `do_unlinkat`。从这一点开始，任何 unlink 系统调用都会触发我们的 BPF 程序。我们通过创建并立即删除临时文件来故意触发这一点。`open()` 创建 `/tmp/wq_test_file`，我们关闭 fd，然后 `unlink()` 删除它。此删除进入内核的 `do_unlinkat` 函数，触发我们的 fentry 探针。

以下是关键的时序方面：工作队列执行是异步的。我们的主 BPF 程序调度工作并立即返回。内核将回调排队以供内核工作线程稍后执行。这就是为什么我们 `sleep(1)` - 在检查结果之前给工作队列时间执行。在生产代码中，你会使用更复杂的同步，但对于简单的测试，sleep 就足够了。

sleep 后，我们从 BPF 程序的 `.bss` 节读取全局变量。骨架通过 `skel->bss->main_executed` 和 `skel->bss->wq_executed` 提供便捷访问。如果两者都为 1，我们知道同步路径（fentry）和异步路径（工作队列回调）都成功执行了。

## 理解工作队列 API

工作队列 API 由管理生命周期的三个基本函数组成。**`bpf_wq_init(wq, map, flags)`** 初始化工作队列句柄，建立工作队列与其包含 map 之间的关系。map 参数至关重要 - 它告诉验证器哪个 map 包含带有嵌入式 `bpf_wq` 结构的值。验证器使用此信息来确保跨异步执行的内存安全。在当前内核中，标志应为 0。

**`bpf_wq_set_callback(wq, callback_fn, flags)`** 注册要异步执行的函数。回调必须具有签名 `int callback(void *map, int *key, void *value)`。验证器在加载时检查此签名，并将拒绝签名不匹配的程序。这种类型安全防止了常见的异步编程错误。标志应为 0。

**`bpf_wq_start(wq, flags)`** 调度工作队列运行。这会立即返回 - 你的 BPF 程序继续同步执行。内核将回调排队以供工作线程在进程上下文中在将来某个时间点执行。回调可能在微秒或毫秒后运行，具体取决于系统负载。标志应为 0。

回调签名值得注意。与接收 `(void *map, __u32 *key, void *value)` 的 `bpf_timer` 回调不同，工作队列回调接收 `(void *map, int *key, void *value)`。注意键类型差异 - `int *` 与 `__u32 *`。这反映了 API 的演变，必须完全匹配，否则验证器会拒绝你的程序。回调在进程上下文中运行，因此它可以安全地执行在 softirq 上下文中会崩溃的操作。

## 何时使用工作队列与定时器

选择 **bpf_timer** 当你需要微秒精度的定时、操作快速且非阻塞、你正在更新计数器或简单状态，或实现周期性快速路径操作（如统计收集或数据包调度）时。定时器在必须以最小延迟执行的时间关键任务方面表现出色。

选择 **bpf_wq** 当你需要睡眠或等待、使用 `kzalloc()` 分配内存、执行设备或网络 I/O，或推迟可以稍后发生的清理操作时。工作队列非常适合"快速路径 + 慢速路径"模式，其中关键操作立即发生，而昂贵的处理异步运行而不阻塞。示例包括 HID 设备 I/O（带延迟的键盘宏注入）、异步 map 清理（防止内存泄漏）、安全策略更新（查询外部数据库）和后台处理（压缩、加密、聚合）。

基本权衡是延迟与能力。定时器具有较低的延迟但受限的能力。工作队列具有较高的延迟但完整的进程上下文能力，包括睡眠和阻塞 I/O。

## 编译和执行

导航到 bpf_wq 目录并构建：

```bash
cd bpf-developer-tutorial/src/features/bpf_wq
make
```

Makefile 使用启用的实验性工作队列功能编译 BPF 程序并生成骨架头。

运行简单的工作队列测试：

```bash
sudo ./wq_simple
```

预期输出：

```
BPF workqueue program attached. Triggering unlink syscall...

Results:
  main_executed = 1 (expected: 1)
  wq_executed = 1 (expected: 1)

✓ Test PASSED!
```

测试验证同步 fentry 探针和异步工作队列回调都成功执行。如果工作队列回调没有运行，`wq_executed` 将为 0，测试将失败。

## 历史时间线和背景

理解工作队列如何产生有助于欣赏它们的设计。2022 年，Benjamin Tissoires 开始研究 HID-BPF，旨在让用户在没有内核驱动程序的情况下修复损坏的 HID 设备。到 2023 年，他意识到 `bpf_timer` 的限制使 HID 设备 I/O 变得不可能 - 你不能在 softirq 上下文中等待硬件响应。2024 年初，他提出 `bpf_wq` 作为"进程上下文中的 bpf_timer"，与 BPF 社区合作设计。内核在 2024 年 4 月将工作队列作为 Linux v6.10 的一部分合并。从那时起，它们已被用于 HID 怪癖、速率限制、异步清理和其他可睡眠操作。

Benjamin 的补丁中的关键引用完美地捕捉了动机："我需要类似于 bpf_timers 的东西，但不在软 IRQ 上下文中……bpf_timer 功能会阻止我 kzalloc 并等待设备。"

这种现实世界的需求推动了设计。工作队列的存在是因为设备处理和资源管理需要定时器根本无法提供的可睡眠、阻塞操作。

## 总结和下一步

BPF 工作队列通过在进程上下文中启用可睡眠、阻塞操作解决了 eBPF 的根本限制。专门为支持 HID 设备处理而创建，其中时序延迟和设备 I/O 至关重要，工作队列为 eBPF 程序解锁了强大的新功能。它们启用了"快速路径 + 慢速路径"模式，其中性能关键操作立即执行，而昂贵的清理和 I/O 异步发生而不阻塞。

我们的简单示例演示了核心工作队列生命周期：在 map 值中嵌入 `bpf_wq`、初始化和配置它、调度异步执行，以及验证回调在进程上下文中运行。相同的模式可以扩展到生产用例，如带异步清理的网络速率限制、带外部服务查询的安全监控，以及带 I/O 操作的设备处理。

> 如果你想深入了解 eBPF，请查看我们的教程仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- **原始内核补丁：** Benjamin Tissoires 的 HID-BPF 和 bpf_wq 补丁（2023-2024）
- **Linux 内核源码：** `kernel/bpf/helpers.c` - 工作队列实现
- **教程仓库：** <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/bpf_wq>

示例改编自 Linux 内核 BPF 自测，并增加了教育性增强。需要 Linux 内核 6.10+ 以获得工作队列支持。完整源代码可在教程仓库中获得。
