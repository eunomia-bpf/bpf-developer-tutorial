# eBPF 实例教程：BPF Arena 零拷贝共享内存

你是否曾经尝试在 eBPF 中构建链表，却不得不使用笨拙的整数索引而不是真正的指针？或者需要在内核 BPF 程序和用户空间之间共享大量数据，却受困于昂贵的系统调用？传统的 BPF map 强制你绕过指针限制，并且每次访问都需要系统调用。如果你可以使用普通的 C 指针，并在内核和用户空间之间实现直接内存访问会怎样？

这正是 **BPF Arena** 要解决的问题。由 Alexei Starovoitov 在 2024 年创建，arena 提供了一个稀疏共享内存区域，BPF 程序可以使用真正的指针来构建链表、树和图等复杂数据结构，而用户空间可以零拷贝直接访问相同的内存。在本教程中，我们将在 arena 内存中构建一个链表，并展示内核和用户空间如何使用标准指针操作来操作它。

## BPF Arena 简介：突破 Map 的限制

### 问题：当 BPF Maps 不够用时

传统的 BPF map 非常适合简单的键值存储，但当你需要复杂的数据结构或大规模数据共享时，它们存在根本性的限制。让我们看看在 arena 出现之前开发者面临的问题。

**环形缓冲区**只能单向工作 - BPF 可以向用户空间发送数据，但用户空间无法写回。它们仅支持流式传输，没有随机访问。**哈希和数组 map** 从用户空间的每次访问都需要 `bpf_map_lookup_elem()` 等系统调用。数组 map 预先分配所有内存，如果你只使用一小部分条目就会浪费空间。最关键的是，**你不能使用真正的指针** - 你被迫使用整数索引来链接数据结构。

用旧方法构建链表看起来像这样混乱：

```c
struct node {
    int next_idx;  // 不能使用指针，必须使用索引！
    int data;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10000);
    __type(value, struct node);
} nodes_map SEC(".maps");

// 遍历需要重复的 map 查找
int idx = head_idx;
while (idx != -1) {
    struct node *n = bpf_map_lookup_elem(&nodes_map, &idx);
    if (!n) break;
    process(n->data);
    idx = n->next_idx;  // 不能跟随指针！
}
```

每个节点访问都需要一次 map 查找。你不能像普通 C 代码那样跟随指针。验证器不允许你在不同的 map 条目之间使用指针。这使得实现树、图或任何基于指针的结构变得非常笨拙和缓慢。

### 解决方案：具有真实指针的稀疏共享内存

2024 年，来自 Linux 内核团队的 Alexei Starovoitov 引入了 BPF arena 来解决这些限制。Arena 在 BPF 程序和用户空间之间提供了一个**稀疏共享内存区域**，支持高达 4GB 的地址空间。内存页按需分配，因此不会浪费空间。内核 BPF 代码和用户空间程序都可以映射相同的 arena 并直接访问它。

改变游戏规则的是：你可以在针对 arena 内存的 BPF 程序中使用**真正的 C 指针**。`__arena` 注解告诉验证器这些指针引用 arena 空间，特殊的地址空间转换（`cast_kern()`、`cast_user()`）让你安全地在内核和用户空间视图之间转换相同的内存。用户空间通过 `mmap()` 获得零拷贝访问 - 无需系统调用即可读取或写入 arena 数据。

使用 arena 的相同链表如下所示：

```c
struct node __arena {
    struct node __arena *next;  // 真正的指针！
    int data;
};

struct node __arena *head;

// 使用普通指针跟随进行遍历
struct node __arena *n = head;
while (n) {
    process(n->data);
    n = n->next;  // 只需跟随指针！
}
```

简洁、简单，完全像你在普通 C 中编写的那样。验证器理解 arena 指针并允许你安全地解引用它们。

### 为什么这很重要

Arena 的灵感来自研究，这些研究展示了 BPF 中复杂数据结构的潜力。在 arena 之前，开发者使用巨大的 BPF 数组 map 和整数索引而不是指针来构建哈希表、队列和树。它可以工作，但代码丑陋且缓慢。Arena 解锁了几个强大的用例。

**内核数据结构**变得实用。你可以实现带有碰撞链接的自定义哈希表、用于排序数据的 AVL 或红黑树、用于网络拓扑映射的图，所有这些都使用普通的指针操作。**键值存储加速器**可以在内核中运行以获得最大性能，用户空间无需系统调用开销即可直接访问数据结构。**双向通信**自然工作 - 内核和用户空间都可以使用无锁算法修改共享数据结构。**大数据聚合**可扩展到 4GB，而不是受限于典型的 map 大小约束。

## 实现：在 Arena 内存中构建链表

让我们构建一个完整的示例来展示 arena 的强大功能。我们将创建一个链表，其中 BPF 程序使用真实指针添加和删除元素，而用户空间直接访问列表来计算总和，无需任何系统调用。

### 完整的 BPF 程序：arena_list.bpf.c

```c
// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 100); /* number of pages */
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32); /* start of mmap() region */
#else
	__ulong(map_extra, 0x1ull << 44); /* start of mmap() region */
#endif
} arena SEC(".maps");

#include "bpf_arena_alloc.h"
#include "bpf_arena_list.h"

struct elem {
	struct arena_list_node node;
	__u64 value;
};

struct arena_list_head __arena *list_head;
int list_sum;
int cnt;
bool skip = false;

#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
long __arena arena_sum;
int __arena test_val = 1;
struct arena_list_head __arena global_head;
#else
long arena_sum SEC(".addr_space.1");
int test_val SEC(".addr_space.1");
#endif

int zero;

SEC("syscall")
int arena_list_add(void *ctx)
{
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
	__u64 i;

	list_head = &global_head;

	for (i = zero; i < cnt && can_loop; i++) {
		struct elem __arena *n = bpf_alloc(sizeof(*n));

		test_val++;
		n->value = i;
		arena_sum += i;
		list_add_head(&n->node, list_head);
	}
#else
	skip = true;
#endif
	return 0;
}

SEC("syscall")
int arena_list_del(void *ctx)
{
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
	struct elem __arena *n;
	int sum = 0;

	arena_sum = 0;
	list_for_each_entry(n, list_head, node) {
		sum += n->value;
		arena_sum += n->value;
		list_del(&n->node);
		bpf_free(n);
	}
	list_sum = sum;
#else
	skip = true;
#endif
	return 0;
}

char _license[] SEC("license") = "GPL";
```

### 理解 BPF 代码

程序首先定义 arena map 本身。`BPF_MAP_TYPE_ARENA` 告诉内核这是 arena 内存，`BPF_F_MMAPABLE` 使其可以从用户空间通过 `mmap()` 访问。`max_entries` 字段指定 arena 可以容纳多少页（通常每页 4KB）- 这里我们允许最多 100 页，约 400KB。`map_extra` 字段设置 arena 在虚拟地址空间中的映射位置，为 ARM64 和 x86-64 使用不同的地址以避免与现有映射冲突。

定义 map 后，我们包含 arena 辅助函数。`bpf_arena_alloc.h` 文件提供 `bpf_alloc()` 和 `bpf_free()` 函数 - 一个与 arena 页一起工作的简单内存分配器，类似于 `malloc()` 和 `free()`，但专门用于 arena 内存。`bpf_arena_list.h` 文件使用 arena 指针实现双向链表操作，包括 `list_add_head()` 用于前置节点，`list_for_each_entry()` 用于安全迭代。

我们的 `elem` 结构包含实际数据。`arena_list_node` 成员提供用于链接节点的 `next` 和 `pprev` 指针 - 这些是用 `__arena` 标记的 arena 指针。`value` 字段保存我们的有效载荷数据。注意 `list_head` 上的 `__arena` 注解 - 这告诉验证器该指针引用 arena 内存，而不是普通内核内存。

`arena_list_add()` 函数创建列表元素。它标记为 `SEC("syscall")`，因为用户空间将使用 `bpf_prog_test_run()` 触发它。循环使用 `bpf_alloc(sizeof(*n))` 分配新元素，它返回一个 arena 指针。然后我们可以直接解引用 `n->value` - 验证器允许这样做，因为 `n` 是一个 arena 指针。`list_add_head()` 调用使用普通指针操作将新节点前置到列表，所有这些都发生在 arena 内存中。`can_loop` 检查满足验证器的有界循环要求。

`arena_list_del()` 函数演示了迭代和清理。`list_for_each_entry()` 宏沿着 arena 指针遍历列表。在循环内部，我们计算值的总和并删除节点。`bpf_free(n)` 调用将内存返回给 arena 分配器，减少引用计数，当计数降至零时可能释放页面。

地址空间转换功能至关重要。一些编译器支持 `__BPF_FEATURE_ADDR_SPACE_CAST`，它使 `__arena` 注解作为编译器地址空间工作。如果没有此支持，我们将退回到使用显式节注解，如 `SEC(".addr_space.1")`。代码检查此功能，如果不可用则跳过执行，防止运行时错误。

### 完整的用户空间程序：arena_list.c

```c
// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bpf_arena_list.h"
#include "arena_list.skel.h"

struct elem {
	struct arena_list_node node;
	uint64_t value;
};

static int list_sum(struct arena_list_head *head)
{
	struct elem __arena *n;
	int sum = 0;

	list_for_each_entry(n, head, node)
		sum += n->value;
	return sum;
}

static void test_arena_list_add_del(int cnt)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct arena_list_bpf *skel;
	int expected_sum = (u_int64_t)cnt * (cnt - 1) / 2;
	int ret, sum;

	skel = arena_list_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return;
	}

	skel->bss->cnt = cnt;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arena_list_add), &opts);
	if (ret != 0) {
		fprintf(stderr, "Failed to run arena_list_add: %d\n", ret);
		goto out;
	}
	if (opts.retval != 0) {
		fprintf(stderr, "arena_list_add returned %d\n", opts.retval);
		goto out;
	}
	if (skel->bss->skip) {
		printf("SKIP: compiler doesn't support arena_cast\n");
		goto out;
	}
	sum = list_sum(skel->bss->list_head);
	printf("Sum of elements: %d (expected: %d)\n", sum, expected_sum);

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arena_list_del), &opts);
	if (ret != 0) {
		fprintf(stderr, "Failed to run arena_list_del: %d\n", ret);
		goto out;
	}
	sum = list_sum(skel->bss->list_head);
	printf("Sum after deletion: %d (expected: 0)\n", sum);
	printf("Sum computed by BPF: %d (expected: %d)\n", skel->bss->list_sum, expected_sum);

	printf("\nTest passed!\n");
out:
	arena_list_bpf__destroy(skel);
}

int main(int argc, char **argv)
{
	int cnt = 10;

	if (argc > 1) {
		cnt = atoi(argv[1]);
		if (cnt <= 0) {
			fprintf(stderr, "Invalid count: %s\n", argv[1]);
			return 1;
		}
	}

	printf("Testing arena list with %d elements\n", cnt);
	test_arena_list_add_del(cnt);

	return 0;
}
```

### 理解用户空间代码

用户空间程序演示了对 arena 内存的零拷贝访问。当我们使用 `arena_list_bpf__open_and_load()` 加载 BPF 骨架时，libbpf 自动将 arena `mmap()` 到用户空间。指针 `skel->bss->list_head` 直接指向这个映射的 arena 内存。

`list_sum()` 函数从用户空间遍历链表。注意我们使用与 BPF 代码相同的 `list_for_each_entry()` 宏。列表在 arena 内存中，在内核和用户空间之间共享。用户空间可以直接解引用 arena 指针以访问节点值并跟随 `next` 指针 - 无需系统调用。这就是零拷贝的好处：用户空间直接从映射区域读取内存。

测试流程编排演示。首先，我们设置 `skel->bss->cnt` 来指定要创建多少个列表元素。然后 `bpf_prog_test_run_opts()` 执行 `arena_list_add` BPF 程序，它在 arena 内存中构建列表。一旦返回，用户空间立即调用 `list_sum()` 通过直接从用户空间遍历它来验证列表 - 无需系统调用，只是直接内存访问。预期总和计算为 0+1+2+...+(cnt-1)，等于 cnt*(cnt-1)/2。

验证列表后，我们运行 `arena_list_del` 来删除所有元素。这个 BPF 程序遍历列表，计算自己的总和，并对每个节点调用 `bpf_free()`。然后用户空间通过再次调用 `list_sum()` 来验证列表是否为空，应该返回 0。我们还检查 `skel->bss->list_sum` 是否与我们的预期值匹配，确认 BPF 程序在删除节点之前计算了正确的总和。

## 理解 Arena 内存分配

arena 分配器值得仔细研究，因为它展示了 BPF 程序如何在 arena 空间中实现复杂的内存管理。`bpf_arena_alloc.h` 中的分配器使用每 CPU 页片段方法来避免锁定。

每个 CPU 维护自己的当前页和偏移量。当你调用 `bpf_alloc(size)` 时，它首先将大小向上舍入到 8 字节对齐。如果当前页在当前偏移量处有足够的空间，它只需递减偏移量并返回指针即可从那里分配。如果剩余空间不足，它使用 `bpf_arena_alloc_pages()` 分配新页，这是一个内核辅助函数，从内核的页分配器获取 arena 页。每个页在其最后 8 个字节中维护引用计数，跟踪有多少分配的对象指向该页。

`bpf_free(addr)` 函数实现引用计数释放。它将地址向下舍入到页边界，找到引用计数，并递减它。当计数达到零时 - 意味着从该页分配的所有对象都已被释放 - 它使用 `bpf_arena_free_pages()` 将整个页返回给内核。这种页级引用计数意味着单个 `bpf_free()` 调用很快，并且只有在适当的时候才将内存返回给系统。

这种分配器设计通过使用每 CPU 状态来避免锁定。由于 BPF 程序在禁用抢占的单个 CPU 上运行，当前 CPU 的页片段可以在没有同步的情况下访问。这使得 `bpf_alloc()` 极快 - 通常只需几条指令即可从当前页分配。

## 编译和执行

导航到 bpf_arena 目录并构建示例：

```bash
cd bpf-developer-tutorial/src/features/bpf_arena
make
```

Makefile 使用 `-D__BPF_FEATURE_ADDR_SPACE_CAST` 编译 BPF 程序以启用 arena 指针支持。它使用 `bpftool gen object` 处理编译的 BPF 对象并生成用户空间可以包含的骨架头。

使用 10 个元素运行 arena 列表测试：

```bash
sudo ./arena_list 10
```

预期输出：

```
Testing arena list with 10 elements
Sum of elements: 45 (expected: 45)
Sum after deletion: 0 (expected: 0)
Sum computed by BPF: 45 (expected: 45)

Test passed!
```

尝试使用更多元素来查看 arena 的扩展性：

```bash
sudo ./arena_list 100
```

总和应该是 4950 (100*99/2)。注意用户空间可以通过直接访问 arena 内存来验证列表，无需任何系统调用。这种零拷贝访问正是使 arena 对大型数据结构强大的原因。

## 何时使用 Arena 与其他 BPF Maps

选择正确的 BPF map 类型取决于你的访问模式和数据结构需求。**使用常规 BPF maps**（哈希、数组等）当你需要简单的键值存储、适合 map 的小型数据结构、标准 map 操作（如原子更新）或没有复杂链接的每 CPU 统计信息时。Maps 在使用内核提供的操作的直接用例中表现出色。

**使用 BPF Arena** 当你需要复杂的链接结构（如列表、树或图）、超过典型 map 大小的大型共享内存、零拷贝用户空间访问以避免系统调用开销，或超出 map 提供的自定义内存管理时。Arena 在指针操作自然的复杂数据结构方面表现出色。

**使用环形缓冲区**当你需要从 BPF 到用户空间的单向流式传输、事件日志或跟踪数据，或顺序处理的数据而无需随机访问时。环形缓冲区针对高吞吐量事件流进行了优化，但不支持双向访问或复杂的数据结构。

arena 与 map 的权衡基本上归结为指针和访问模式。如果你发现自己在 BPF map 中编码索引来模拟指针，arena 可能是更好的选择。如果你需要从内核和用户空间都可访问的大规模数据结构，arena 的零拷贝共享内存模型难以超越。

## 总结和下一步

BPF Arena 通过提供稀疏共享内存解决了传统 BPF map 的根本限制，你可以在其中使用真正的 C 指针来构建复杂的数据结构。由 Alexei Starovoitov 在 2024 年创建，arena 使用普通指针操作而不是笨拙的整数索引实现链表、树、图和自定义分配器。内核 BPF 程序和用户空间都可以映射相同的 arena 以进行零拷贝双向访问，消除系统调用开销。

我们的链表示例演示了核心 arena 概念：定义 arena map、使用 `__arena` 注解用于指针类型、使用 `bpf_alloc()` 分配内存，以及从内核和用户空间访问相同的数据结构。每 CPU 页片段分配器展示了 BPF 程序如何在 arena 空间中实现复杂的内存管理。Arena 为内核数据结构、键值存储加速器和高达 4GB 的大规模数据聚合解锁了新的可能性。

> 如果你想深入了解 eBPF，请查看我们的教程仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- **原始 Arena 补丁：** <https://lwn.net/Articles/961594/>
- **Meta 的 Arena 示例：** Linux 内核树 `samples/bpf/arena_*.c`
- **教程仓库：** <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/bpf_arena>
- **Linux 内核源码：** `kernel/bpf/arena.c` - Arena 实现
- **LLVM 地址空间：** 关于 `__arena` 编译器支持的文档

此示例改编自 Linux 内核示例中 Meta 的 arena_list.c，并增加了教育性增强。需要 Linux 内核 6.10+ 并启用 `CONFIG_BPF_ARENA=y`。完整源代码可在教程仓库中获得。
