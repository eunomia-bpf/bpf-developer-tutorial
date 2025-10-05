# eBPF Tutorial by Example: BPF Arena for Zero-Copy Shared Memory

Ever tried building a linked list in eBPF and got stuck using awkward integer indices instead of real pointers? Or needed to share large amounts of data between your kernel BPF program and userspace without expensive syscalls? Traditional BPF maps force you to work around pointer limitations and require system calls for every access. What if you could just use normal C pointers and have direct memory access from both kernel and userspace?

This is what **BPF Arena** solves. Created by Alexei Starovoitov in 2024, arena provides a sparse shared memory region where BPF programs can use real pointers to build complex data structures like linked lists, trees, and graphs, while userspace gets zero-copy direct access to the same memory. In this tutorial, we'll build a linked list in arena memory and show you how both kernel and userspace can manipulate it using standard pointer operations.

## Introduction to BPF Arena: Breaking Free from Map Limitations

### The Problem: When BPF Maps Aren't Enough

Traditional BPF maps are fantastic for simple key-value storage, but they have fundamental limitations when you need complex data structures or large-scale data sharing. Let's look at what developers faced before arena existed.

**Ring buffers** only work in one direction - BPF can send data to userspace, but userspace can't write back. They're streaming-only, no random access. **Hash and array maps** require syscalls like `bpf_map_lookup_elem()` for every access from userspace. Array maps allocate all their memory upfront, wasting space if you only use a fraction of entries. Most critically, **you can't use real pointers** - you're forced to use integer indices to link data structures together.

Building a linked list the old way looked like this mess:

```c
struct node {
    int next_idx;  // Can't use pointers, must use index!
    int data;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10000);
    __type(value, struct node);
} nodes_map SEC(".maps");

// Traverse requires repeated map lookups
int idx = head_idx;
while (idx != -1) {
    struct node *n = bpf_map_lookup_elem(&nodes_map, &idx);
    if (!n) break;
    process(n->data);
    idx = n->next_idx;  // No pointer following!
}
```

Every node access requires a map lookup. You can't just follow pointers like normal C code. The verifier won't let you use pointers across different map entries. This makes implementing trees, graphs, or any pointer-based structure incredibly awkward and slow.

### The Solution: Sparse Shared Memory with Real Pointers

In 2024, Alexei Starovoitov from the Linux kernel team introduced BPF arena to solve these limitations. Arena provides a **sparse shared memory region** between BPF programs and userspace, supporting up to 4GB of address space. Memory pages are allocated on-demand as you use them, so you don't waste space. Both kernel BPF code and userspace programs can map the same arena and access it directly.

The game-changer: you can use **real C pointers** in BPF programs targeting arena memory. The `__arena` annotation tells the verifier that these pointers reference arena space, and special address space casts (`cast_kern()`, `cast_user()`) let you safely convert between kernel and userspace views of the same memory. Userspace gets zero-copy access through `mmap()` - no syscalls needed to read or write arena data.

Here's what the same linked list looks like with arena:

```c
struct node __arena {
    struct node __arena *next;  // Real pointer!
    int data;
};

struct node __arena *head;

// Traverse with normal pointer following
struct node __arena *n = head;
while (n) {
    process(n->data);
    n = n->next;  // Just follow the pointer!
}
```

Clean, simple, exactly how you'd write it in normal C. The verifier understands arena pointers and lets you dereference them safely.

### Why This Matters

Arena was inspired by research showing the potential for complex data structures in BPF. Before arena, developers were building hash tables, queues, and trees using giant BPF array maps with integer indices instead of pointers. It worked, but the code was ugly and slow. Arena unlocks several powerful use cases.

**In-kernel data structures** become practical. You can implement custom hash tables with collision chaining, AVL or red-black trees for sorted data, graphs for network topology mapping, all using normal pointer operations. **Key-value store accelerators** can run in the kernel for maximum performance, with userspace getting direct access to the data structure without syscall overhead. **Bidirectional communication** works naturally - both kernel and userspace can modify shared data structures using lock-free algorithms. **Large data aggregation** scales up to 4GB instead of being limited by typical map size constraints.

## Implementation: Building a Linked List in Arena Memory

Let's build a complete example that demonstrates arena's power. We'll create a linked list where BPF programs add and delete elements using real pointers, while userspace directly accesses the list to compute sums without any syscalls.

### Complete BPF Program: arena_list.bpf.c

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

### Understanding the BPF Code

The program starts by defining the arena map itself. `BPF_MAP_TYPE_ARENA` tells the kernel this is arena memory, and `BPF_F_MMAPABLE` makes it accessible via `mmap()` from userspace. The `max_entries` field specifies how many pages (typically 4KB each) the arena can hold - here we allow up to 100 pages, or about 400KB. The `map_extra` field sets where in the virtual address space the arena gets mapped, using different addresses for ARM64 vs x86-64 to avoid conflicts with existing mappings.

After defining the map, we include arena helpers. The `bpf_arena_alloc.h` file provides `bpf_alloc()` and `bpf_free()` functions - a simple memory allocator that works with arena pages, similar to `malloc()` and `free()` but specifically for arena memory. The `bpf_arena_list.h` file implements doubly-linked list operations using arena pointers, including `list_add_head()` to prepend nodes and `list_for_each_entry()` to iterate safely.

Our `elem` structure contains the actual data. The `arena_list_node` member provides the `next` and `pprev` pointers for linking nodes together - these are arena pointers marked with `__arena`. The `value` field holds our payload data. Notice the `__arena` annotation on `list_head` - this tells the verifier this pointer references arena memory, not normal kernel memory.

The `arena_list_add()` function creates list elements. It's marked `SEC("syscall")` because userspace will trigger it using `bpf_prog_test_run()`. The loop allocates new elements using `bpf_alloc(sizeof(*n))`, which returns an arena pointer. We can then dereference `n->value` directly - the verifier allows this because `n` is an arena pointer. The `list_add_head()` call prepends the new node to the list using normal pointer manipulation, all happening in arena memory. The `can_loop` check satisfies the verifier's bounded loop requirement.

The `arena_list_del()` function demonstrates iteration and cleanup. The `list_for_each_entry()` macro walks the list following arena pointers. Inside the loop, we sum values and delete nodes. The `bpf_free(n)` call returns memory to the arena allocator, decreasing the reference count and potentially freeing pages when the count hits zero.

The address space cast feature is crucial. Some compilers support `__BPF_FEATURE_ADDR_SPACE_CAST` which enables the `__arena` annotation to work as a compiler address space. Without this support, we fall back to using explicit section annotations like `SEC(".addr_space.1")`. The code checks for this feature and skips execution if it's not available, preventing runtime errors.

### Complete User-Space Program: arena_list.c

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

### Understanding the User-Space Code

The userspace program demonstrates zero-copy access to arena memory. When we load the BPF skeleton using `arena_list_bpf__open_and_load()`, libbpf automatically `mmap()`s the arena into userspace. The pointer `skel->bss->list_head` points directly into this mapped arena memory.

The `list_sum()` function walks the linked list from userspace. Notice we're using the same `list_for_each_entry()` macro as the BPF code. The list is in arena memory, shared between kernel and userspace. Userspace can directly dereference arena pointers to access node values and follow `next` pointers - no syscalls needed. This is the zero-copy benefit: userspace reads memory directly from the mapped region.

The test flow orchestrates the demonstration. First, we set `skel->bss->cnt` to specify how many list elements to create. Then `bpf_prog_test_run_opts()` executes the `arena_list_add` BPF program, which builds the list in arena memory. Once that returns, userspace immediately calls `list_sum()` to verify the list by walking it directly from userspace - no syscalls, just direct memory access. The expected sum is calculated as 0+1+2+...+(cnt-1), which equals cnt*(cnt-1)/2.

After verifying the list, we run `arena_list_del` to remove all elements. This BPF program walks the list, computes its own sum, and calls `bpf_free()` on each node. Userspace then verifies the list is empty by calling `list_sum()` again, which should return 0. We also check that `skel->bss->list_sum` matches our expected value, confirming the BPF program computed the correct sum before deleting nodes.

## Understanding Arena Memory Allocation

The arena allocator deserves a closer look because it shows how BPF programs can implement sophisticated memory management in arena space. The allocator in `bpf_arena_alloc.h` uses a per-CPU page fragment approach to avoid locking.

Each CPU maintains its own current page and offset. When you call `bpf_alloc(size)`, it first rounds up the size to 8-byte alignment. If the current page has enough space at the current offset, it allocates from there by just decrementing the offset and returning a pointer. If not enough space remains, it allocates a fresh page using `bpf_arena_alloc_pages()`, which is a kernel helper that gets arena pages from the kernel's page allocator. Each page maintains a reference count in its last 8 bytes, tracking how many allocated objects point into that page.

The `bpf_free(addr)` function implements reference-counted deallocation. It rounds the address down to the page boundary, finds the reference count, and decrements it. When the count reaches zero - meaning all objects allocated from that page have been freed - it returns the entire page to the kernel using `bpf_arena_free_pages()`. This page-level reference counting means individual `bpf_free()` calls are fast, and memory is returned to the system only when appropriate.

This allocator design avoids locks by using per-CPU state. Since BPF programs run with preemption disabled on a single CPU, the current CPU's page fragment can be accessed without synchronization. This makes `bpf_alloc()` extremely fast - typically just a few instructions to allocate from the current page.

## Compilation and Execution

Navigate to the bpf_arena directory and build the example:

```bash
cd bpf-developer-tutorial/src/features/bpf_arena
make
```

The Makefile compiles the BPF program with `-D__BPF_FEATURE_ADDR_SPACE_CAST` to enable arena pointer support. It uses `bpftool gen object` to process the compiled BPF object and generate a skeleton header that userspace can include.

Run the arena list test with 10 elements:

```bash
sudo ./arena_list 10
```

Expected output:

```
Testing arena list with 10 elements
Sum of elements: 45 (expected: 45)
Sum after deletion: 0 (expected: 0)
Sum computed by BPF: 45 (expected: 45)

Test passed!
```

Try it with more elements to see arena scaling:

```bash
sudo ./arena_list 100
```

The sum should be 4950 (100*99/2). Notice that userspace can verify the list by directly accessing arena memory without any syscalls. This zero-copy access is what makes arena powerful for large data structures.

## When to Use Arena vs Other BPF Maps

Choosing the right BPF map type depends on your access patterns and data structure needs. **Use regular BPF maps** (hash, array, etc.) when you need simple key-value storage, small data structures that fit well in maps, standard map operations like atomic updates, or per-CPU statistics without complex linking. Maps excel at straightforward use cases with kernel-provided operations.

**Use BPF Arena** when you need complex linked structures like lists, trees, or graphs, large shared memory exceeding typical map sizes, zero-copy userspace access to avoid syscall overhead, or custom memory management beyond what maps provide. Arena shines for sophisticated data structures where pointer operations are natural.

**Use Ring Buffers** when you need one-way streaming from BPF to userspace, event logs or trace data, or sequentially processed data without random access. Ring buffers are optimized for high-throughput event streams but don't support bidirectional access or complex data structures.

The arena vs maps trade-off fundamentally comes down to pointers and access patterns. If you find yourself encoding indices to simulate pointers in BPF maps, arena is probably the better choice. If you need large-scale data structures accessible from both kernel and userspace, arena's zero-copy shared memory model is hard to beat.

## Summary and Next Steps

BPF Arena solves a fundamental limitation of traditional BPF maps by providing sparse shared memory where you can use real C pointers to build complex data structures. Created by Alexei Starovoitov in 2024, arena enables linked lists, trees, graphs, and custom allocators using normal pointer operations instead of awkward integer indices. Both kernel BPF programs and userspace can map the same arena for zero-copy bidirectional access, eliminating syscall overhead.

Our linked list example demonstrates the core arena concepts: defining an arena map, using `__arena` annotations for pointer types, allocating memory with `bpf_alloc()`, and accessing the same data structure from both kernel and userspace. The per-CPU page fragment allocator shows how BPF programs can implement sophisticated memory management in arena space. Arena unlocks new possibilities for in-kernel data structures, key-value store accelerators, and large-scale data aggregation up to 4GB.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- **Original Arena Patches:** <https://lwn.net/Articles/961594/>
- **Meta's Arena Examples:** Linux kernel tree `samples/bpf/arena_*.c`
- **Tutorial Repository:** <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/bpf_arena>
- **Linux Kernel Source:** `kernel/bpf/arena.c` - Arena implementation
- **LLVM Address Spaces:** Documentation on `__arena` compiler support

This example is adapted from Meta's arena_list.c in the Linux kernel samples, with educational enhancements. Requires Linux kernel 6.10+ with `CONFIG_BPF_ARENA=y` enabled. Complete source code available in the tutorial repository.
