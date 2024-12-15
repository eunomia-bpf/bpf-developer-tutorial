# eBPF 入门实践教程十六：编写 eBPF 程序 Memleak 监控内存泄漏

eBPF（扩展的伯克利数据包过滤器）是一项强大的网络和性能分析工具，被广泛应用在 Linux 内核上。eBPF 使得开发者能够动态地加载、更新和运行用户定义的代码，而无需重启内核或更改内核源代码。

在本篇教程中，我们将探讨如何使用 eBPF 编写 Memleak 程序，以监控程序的内存泄漏。

## 背景及其重要性

内存泄漏是计算机编程中的一种常见问题，其严重程度不应被低估。内存泄漏发生时，程序会逐渐消耗更多的内存资源，但并未正确释放。随着时间的推移，这种行为会导致系统内存逐渐耗尽，从而显著降低程序及系统的整体性能。

内存泄漏有多种可能的原因。这可能是由于配置错误导致的，例如程序错误地配置了某些资源的动态分配。它也可能是由于软件缺陷或错误的内存管理策略导致的，如在程序执行过程中忘记释放不再需要的内存。此外，如果一个应用程序的内存使用量过大，那么系统性能可能会因页面交换（swapping）而大幅下降，甚至可能导致应用程序被系统强制终止（Linux 的 OOM killer）。

### 调试内存泄漏的挑战

调试内存泄漏问题是一项复杂且挑战性的任务。这涉及到详细检查应用程序的配置、内存分配和释放情况，通常需要应用专门的工具来帮助诊断。例如，有一些工具可以在应用程序启动时将 malloc() 函数调用与特定的检测工具关联起来，如 Valgrind memcheck，这类工具可以模拟 CPU 来检查所有内存访问，但可能会导致应用程序运行速度大大减慢。另一个选择是使用堆分析器，如 libtcmalloc，它相对较快，但仍可能使应用程序运行速度降低五倍以上。此外，还有一些工具，如 gdb，可以获取应用程序的核心转储并进行后处理以分析内存使用情况。然而，这些工具通常在获取核心转储时需要暂停应用程序，或在应用程序终止后才能调用 free() 函数。

## eBPF 的作用

在这种背景下，eBPF 的作用就显得尤为重要。eBPF 提供了一种高效的机制来监控和追踪系统级别的事件，包括内存的分配和释放。通过 eBPF，我们可以跟踪内存分配和释放的请求，并收集每次分配的调用堆栈。然后，我们可以分

析这些信息，找出执行了内存分配但未执行释放操作的调用堆栈，这有助于我们找出导致内存泄漏的源头。这种方式的优点在于，它可以实时地在运行的应用程序中进行，而无需暂停应用程序或进行复杂的前后处理。

`memleak` eBPF 工具可以跟踪并匹配内存分配和释放的请求，并收集每次分配的调用堆栈。随后，`memleak` 可以打印一个总结，表明哪些调用堆栈执行了分配，但是并没有随后进行释放。例如，我们运行命令：

```console
# ./memleak -p $(pidof allocs)
Attaching to pid 5193, Ctrl+C to quit.
[11:16:33] Top 2 stacks with outstanding allocations:
        80 bytes in 5 allocations from stack
                 main+0x6d [allocs]
                 __libc_start_main+0xf0 [libc-2.21.so]

[11:16:34] Top 2 stacks with outstanding allocations:
        160 bytes in 10 allocations from stack
                 main+0x6d [allocs]
                 __libc_start_main+0xf0 [libc-2.21.so]
```

运行这个命令后，我们可以看到分配但未释放的内存来自于哪些堆栈，并且可以看到这些未释放的内存的大小和数量。

随着时间的推移，很显然，`allocs` 进程的 `main` 函数正在泄漏内存，每次泄漏 16 字节。幸运的是，我们不需要检查每个分配，我们得到了一个很好的总结，告诉我们哪个堆栈负责大量的泄漏。

## memleak 的实现原理

在基本层面上，`memleak` 的工作方式类似于在内存分配和释放路径上安装监控设备。它通过在内存分配和释放函数中插入 eBPF 程序来达到这个目标。这意味着，当这些函数被调用时，`memleak` 就会记录一些重要信息，如调用者的进程 ID（PID）、分配的内存地址以及分配的内存大小等。当释放内存的函数被调用时，`memleak` 则会在其内部的映射表（map）中删除相应的内存分配记录。这种机制使得 `memleak` 能够准确地追踪到哪些内存块已被分配但未被释放。

对于用户态的常用内存分配函数，如 `malloc` 和 `calloc` 等，`memleak` 利用了用户态探测（uprobe）技术来实现监控。uprobe 是一种用于用户空间应用程序的动态追踪技术，它可以在运行时不修改二进制文件的情况下在任意位置设置断点，从而实现对特定函数调用的追踪。Uprobe 在内核态 eBPF 运行时，也可能产生比较大的性能开销，这时候也可以考虑使用用户态 eBPF 运行时，例如  [bpftime](https://github.com/eunomia-bpf/bpftime)。bpftime 是一个基于 LLVM JIT/AOT 的用户态 eBPF 运行时，它可以在用户态运行 eBPF 程序，和内核态的 eBPF 兼容，避免了内核态和用户态之间的上下文切换，从而提高了 eBPF 程序的执行效率。对于 uprobe 而言，bpftime 的性能开销比 kernel 小一个数量级。

对于内核态的内存分配函数，如 `kmalloc` 等，`memleak` 则选择使用了 tracepoint 来实现监控。Tracepoint 是一种在 Linux 内核中提供的动态追踪技术，它可以在内核运行时动态地追踪特定的事件，而无需重新编译内核或加载内核模块。

## 内核态 eBPF 程序实现

## `memleak` 内核态 eBPF 程序实现

`memleak` 的内核态 eBPF 程序包含一些用于跟踪内存分配和释放的关键函数。在我们深入了解这些函数之前，让我们首先观察 `memleak` 所定义的一些数据结构，这些结构在其内核态和用户态程序中均有使用。

```c
#ifndef __MEMLEAK_H
#define __MEMLEAK_H

#define ALLOCS_MAX_ENTRIES 1000000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240

struct alloc_info {
    __u64 size;            // 分配的内存大小
    __u64 timestamp_ns;    // 分配时的时间戳，单位为纳秒
    int stack_id;          // 分配时的调用堆栈ID
};

union combined_alloc_info {
    struct {
        __u64 total_size : 40;        // 所有未释放分配的总大小
        __u64 number_of_allocs : 24;   // 所有未释放分配的总次数
    };
    __u64 bits;    // 结构的位图表示
};

#endif /* __MEMLEAK_H */
```

这里定义了两个主要的数据结构：`alloc_info` 和 `combined_alloc_info`。

`alloc_info` 结构体包含了一个内存分配的基本信息，包括分配的内存大小 `size`、分配发生时的时间戳 `timestamp_ns`，以及触发分配的调用堆栈 ID `stack_id`。

`combined_alloc_info` 是一个联合体（union），它包含一个嵌入的结构体和一个 `__u64` 类型的位图表示 `bits`。嵌入的结构体有两个成员：`total_size` 和 `number_of_allocs`，分别代表所有未释放分配的总大小和总次数。其中 40 和 24 分别表示 total_size 和 number_of_allocs这两个成员变量所占用的位数，用来限制其大小。通过这样的位数限制，可以节省combined_alloc_info结构的存储空间。同时，由于total_size和number_of_allocs在存储时是共用一个unsigned long long类型的变量bits，因此可以通过在成员变量bits上进行位运算来访问和修改total_size和number_of_allocs，从而避免了在程序中定义额外的变量和函数的复杂性。

接下来，`memleak` 定义了一系列用于保存内存分配信息和分析结果的 eBPF 映射（maps）。这些映射都以 `SEC(".maps")` 的形式定义，表示它们属于 eBPF 程序的映射部分。

```c
const volatile size_t min_size = 0;
const volatile size_t max_size = -1;
const volatile size_t page_size = 4096;
const volatile __u64 sample_rate = 1;
const volatile bool trace_all = false;
const volatile __u64 stack_flags = 0;
const volatile bool wa_missing_free = false;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_t);
    __type(value, u64);
    __uint(max_entries, 10240);
} sizes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); /* address */
    __type(value, struct alloc_info);
    __uint(max_entries, ALLOCS_MAX_ENTRIES);
} allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); /* stack id */
    __type(value, union combined_alloc_info);
    __uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
} combined_allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 10240);
} memptrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __type(key, u32);
} stack_traces SEC(".maps");

static union combined_alloc_info initial_cinfo;
```

这段代码首先定义了一些可配置的参数，如 `min_size`, `max_size`, `page_size`, `sample_rate`, `trace_all`, `stack_flags` 和 `wa_missing_free`，分别表示最小分配大小、最大分配大小、页面大小、采样率、是否追踪所有分配、堆栈标志和是否工作在缺失释放（missing free）模式。

接着定义了五个映射：

1. `sizes`：这是一个哈希类型的映射，键为进程 ID，值为 `u64` 类型，存储每个进程的分配大小。
2. `allocs`：这也是一个哈希类型的映射，键为分配的地址，值为 `alloc_info` 结构体，存储每个内存分配的详细信息。
3. `combined_allocs`：这是另一个哈希类型的映射，键为堆栈 ID，值为 `combined_alloc_info` 联合体，存储所有未释放分配的总大小和总次数。
4. `memptrs`：这也是一个哈希类型的映射，键和值都为 `u64` 类型，用于在用户空间和内核空间之间传递内存指针。
5. `stack_traces`：这是一个堆栈追踪类型的映射，键为 `u32` 类型，用于存储堆栈 ID。

以用户态的内存分配追踪部分为例，主要是挂钩内存相关的函数调用，如 `malloc`, `free`, `calloc`, `realloc`, `mmap` 和 `munmap`，以便在调用这些函数时进行数据记录。在用户态，`memleak` 主要使用了 uprobes 技术进行挂载。

每个函数调用被分为 "enter" 和 "exit" 两部分。"enter" 部分记录的是函数调用的参数，如分配的大小或者释放的地址。"exit" 部分则主要用于获取函数的返回值，如分配得到的内存地址。

这里，`gen_alloc_enter`, `gen_alloc_exit`, `gen_free_enter` 是实现记录行为的函数，他们分别用于记录分配开始、分配结束和释放开始的相关信息。

函数原型示例如下：

```c
SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
    // 记录分配开始的相关信息
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit)
{
    // 记录分配结束的相关信息
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void *address)
{
    // 记录释放开始的相关信息
    return gen_free_enter(address);
}
```

其中，`malloc_enter` 和 `free_enter` 是分别挂载在 `malloc` 和 `free` 函数入口处的探针（probes），用于在函数调用时进行数据记录。而 `malloc_exit` 则是挂载在 `malloc` 函数的返回处的探针，用于记录函数的返回值。

这些函数使用了 `BPF_KPROBE` 和 `BPF_KRETPROBE` 这两个宏来声明，这两个宏分别用于声明 kprobe（内核探针）和 kretprobe（内核返回探针）。具体来说，kprobe 用于在函数调用时触发，而 kretprobe 则是在函数返回时触发。

`gen_alloc_enter` 函数是在内存分配请求的开始时被调用的。这个函数主要负责在调用分配内存的函数时收集一些基本的信息。下面我们将深入探讨这个函数的实现。

```c
static int gen_alloc_enter(size_t size)
{
    if (size < min_size || size > max_size)
        return 0;

    if (sample_rate > 1) {
        if (bpf_ktime_get_ns() % sample_rate != 0)
            return 0;
    }

    const pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&sizes, &pid, &size, BPF_ANY);

    if (trace_all)
        bpf_printk("alloc entered, size = %lu\n", size);

    return 0;
}

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
    return gen_alloc_enter(size);
}
```

首先，`gen_alloc_enter` 函数接收一个 `size` 参数，这个参数表示请求分配的内存的大小。如果这个值不在 `min_size` 和 `max_size` 之间，函数将直接返回，不再进行后续的操作。这样可以使工具专注于追踪特定范围的内存分配请求，过滤掉不感兴趣的分配请求。

接下来，函数检查采样率 `sample_rate`。如果 `sample_rate` 大于1，意味着我们不需要追踪所有的内存分配请求，而是周期性地追踪。这里使用 `bpf_ktime_get_ns` 获取当前的时间戳，然后通过取模运算来决定是否需要追踪当前的内存分配请求。这是一种常见的采样技术，用于降低性能开销，同时还能够提供一个代表性的样本用于分析。

之后，函数使用 `bpf_get_current_pid_tgid` 函数获取当前进程的 PID。注意这里的 PID 实际上是进程和线程的组合 ID，我们通过右移 32 位来获取真正的进程 ID。

函数接下来更新 `sizes` 这个 map，这个 map 以进程 ID 为键，以请求的内存分配大小为值。`BPF_ANY` 表示如果 key 已存在，那么更新 value，否则就新建一个条目。

最后，如果启用了 `trace_all` 标志，函数将打印一条信息，说明发生了内存分配。

`BPF_KPROBE` 宏用于

最后定义了 `BPF_KPROBE(malloc_enter, size_t size)`，它会在 `malloc` 函数被调用时被 BPF uprobe 拦截执行，并通过 `gen_alloc_enter` 来记录内存分配大小。
我们刚刚分析了内存分配的入口函数 `gen_alloc_enter`，现在我们来关注这个过程的退出部分。具体来说，我们将讨论 `gen_alloc_exit2` 函数以及如何从内存分配调用中获取返回的内存地址。

```c
static int gen_alloc_exit2(void *ctx, u64 address)
{
    const pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct alloc_info info;

    const u64* size = bpf_map_lookup_elem(&sizes, &pid);
    if (!size)
        return 0; // missed alloc entry

    __builtin_memset(&info, 0, sizeof(info));

    info.size = *size;
    bpf_map_delete_elem(&sizes, &pid);

    if (address != 0) {
        info.timestamp_ns = bpf_ktime_get_ns();

        info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);

        bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);

        update_statistics_add(info.stack_id, info.size);
    }

    if (trace_all) {
        bpf_printk("alloc exited, size = %lu, result = %lx\n",
                info.size, address);
    }

    return 0;
}
static int gen_alloc_exit(struct pt_regs *ctx)
{
    return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit)
{
    return gen_alloc_exit(ctx);
}
```

`gen_alloc_exit2` 函数在内存分配操作完成时被调用，这个函数接收两个参数，一个是上下文 `ctx`，另一个是内存分配函数返回的内存地址 `address`。

首先，它获取当前线程的 PID，然后使用这个 PID 作为键在 `sizes` 这个 map 中查找对应的内存分配大小。如果没有找到（也就是说，没有对应的内存分配操作的入口），函数就会直接返回。

接着，函数清除 `info` 结构体的内容，并设置它的 `size` 字段为之前在 map 中找到的内存分配大小。并从 `sizes` 这个 map 中删除相应的元素，因为此时内存分配操作已经完成，不再需要这个信息。

接下来，如果 `address` 不为 0（也就是说，内存分配操作成功了），函数就会进一步收集一些额外的信息。首先，它获取当前的时间戳作为内存分配完成的时间，并获取当前的堆栈跟踪。这些信息都会被储存在 `info` 结构体中，并随后更新到 `allocs` 这个 map 中。

最后，函数调用 `update_statistics_add` 更新统计数据，如果启用了所有内存分配操作的跟踪，函数还会打印一些关于内存分配操作的信息。

请注意，`gen_alloc_exit` 函数是 `gen_alloc_exit2` 的一个包装，它将 `PT_REGS_RC(ctx)` 作为 `address` 参数传递给 `gen_alloc_exit2`。
在我们的讨论中，我们刚刚提到在 `gen_alloc_exit2` 函数中，调用了 `update_statistics_add` 函数以更新内存分配的统计数据。下面我们详细看一下这个函数的具体实现。

```c
static void update_statistics_add(u64 stack_id, u64 sz)
{
    union combined_alloc_info *existing_cinfo;

    existing_cinfo = bpf_map_lookup_or_try_init(&combined_allocs, &stack_id, &initial_cinfo);
    if (!existing_cinfo)
        return;

    const union combined_alloc_info incremental_cinfo = {
        .total_size = sz,
        .number_of_allocs = 1
    };

    __sync_fetch_and_add(&existing_cinfo->bits, incremental_cinfo.bits);
}
```

`update_statistics_add` 函数接收两个参数：当前的堆栈 ID `stack_id` 以及内存分配的大小 `sz`。这两个参数都在内存分配事件中收集到，并且用于更新内存分配的统计数据。

首先，函数尝试在 `combined_allocs` 这个 map 中查找键值为当前堆栈 ID 的元素，如果找不到，就用 `initial_cinfo`（这是一个默认的 combined_alloc_info 结构体，所有字段都为零）来初始化新的元素。

接着，函数创建一个 `incremental_cinfo`，并设置它的 `total_size` 为当前内存分配的大小，设置 `number_of_allocs` 为 1。这是因为每次调用 `update_statistics_add` 函数都表示有一个新的内存分配事件发生，而这个事件的内存分配大小就是 `sz`。

最后，函数使用 `__sync_fetch_and_add` 函数原子地将 `incremental_cinfo` 的值加到 `existing_cinfo` 中。请注意这个步骤是线程安全的，即使有多个线程并发地调用 `update_statistics_add` 函数，每个内存分配事件也能正确地记录到统计数据中。

总的来说，`update_statistics_add` 函数实现了内存分配统计的更新逻辑，通过维护每个堆栈 ID 的内存分配总量和次数，我们可以深入了解到程序的内存分配行为。
在我们对内存分配的统计跟踪过程中，我们不仅要统计内存的分配，还要考虑内存的释放。在上述代码中，我们定义了一个名为 `update_statistics_del` 的函数，其作用是在内存释放时更新统计信息。而 `gen_free_enter` 函数则是在进程调用 `free` 函数时被执行。

```c
static void update_statistics_del(u64 stack_id, u64 sz)
{
    union combined_alloc_info *existing_cinfo;

    existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
    if (!existing_cinfo) {
        bpf_printk("failed to lookup combined allocs\n");
        return;
    }

    const union combined_alloc_info decremental_cinfo = {
        .total_size = sz,
        .number_of_allocs = 1
    };

    __sync_fetch_and_sub(&existing_cinfo->bits, decremental_cinfo.bits);
}
```

`update_statistics_del` 函数的参数为堆栈 ID 和要释放的内存块大小。函数首先在 `combined_allocs` 这个 map 中使用当前的堆栈 ID 作为键来查找相应的 `combined_alloc_info` 结构体。如果找不到，就输出错误信息，然后函数返回。如果找到了，就会构造一个名为 `decremental_cinfo` 的 `combined_alloc_info` 结构体，设置它的 `total_size` 为要释放的内存大小，设置 `number_of_allocs` 为 1。然后使用 `__sync_fetch_and_sub` 函数原子地从 `existing_cinfo` 中减去 `decremental_cinfo` 的值。请注意，这里的 `number_of_allocs` 是负数，表示减少了一个内存分配。

```c
static int gen_free_enter(const void *address)
{
    const u64 addr = (u64)address;

    const struct alloc_info *info = bpf_map_lookup_elem(&allocs, &addr);
    if (!info)
        return 0;

    bpf_map_delete_elem(&allocs, &addr);
    update_statistics_del(info->stack_id, info->size);

    if (trace_all) {
        bpf_printk("free entered, address = %lx, size = %lu\n",
                address, info->size);
    }

    return 0;
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void *address)
{
    return gen_free_enter(address);
}
```

接下来看 `gen_free_enter` 函数。它接收一个地址作为参数，这个地址是内存分配的结果，也就是将要释放的内存的起始地址。函数首先在 `allocs` 这个 map 中使用这个地址作为键来查找对应的 `alloc_info` 结构体。如果找不到，那么就直接返回，因为这意味着这个地址并没有被分配过。如果找到了，那么就删除这个元素，并且调用 `update_statistics_del` 函数来更新统计数据。最后，如果启用了全局追踪，那么还会输出一条信息，包括这个地址以及它的大小。
在我们追踪和统计内存分配的同时，我们也需要对内核态的内存分配和释放进行追踪。在Linux内核中，kmem_cache_alloc函数和kfree函数分别用于内核态的内存分配和释放。

```c
SEC("tracepoint/kmem/kfree")
int memleak__kfree(void *ctx)
{
    const void *ptr;

    if (has_kfree()) {
        struct trace_event_raw_kfree___x *args = ctx;
        ptr = BPF_CORE_READ(args, ptr);
    } else {
        struct trace_event_raw_kmem_free___x *args = ctx;
        ptr = BPF_CORE_READ(args, ptr);
    }

    return gen_free_enter(ptr);
}
```

上述代码片段定义了一个函数memleak__kfree，这是一个bpf程序，会在内核调用kfree函数时执行。首先，该函数检查是否存在kfree函数。如果存在，则会读取传递给kfree函数的参数（即要释放的内存块的地址），并保存到变量ptr中；否则，会读取传递给kmem_free函数的参数（即要释放的内存块的地址），并保存到变量ptr中。接着，该函数会调用之前定义的gen_free_enter函数来处理该内存块的释放。

```c
SEC("tracepoint/kmem/kmem_cache_alloc")
int memleak__kmem_cache_alloc(struct trace_event_raw_kmem_alloc *ctx)
{
    if (wa_missing_free)
        gen_free_enter(ctx->ptr);

    gen_alloc_enter(ctx->bytes_alloc);

    return gen_alloc_exit2(ctx, (u64)(ctx->ptr));
}
```

这段代码定义了一个函数 memleak__kmem_cache_alloc，这也是一个bpf程序，会在内核调用 kmem_cache_alloc 函数时执行。如果标记 wa_missing_free 被设置，则调用 gen_free_enter 函数处理可能遗漏的释放操作。然后，该函数会调用 gen_alloc_enter 函数来处理内存分配，最后调用gen_alloc_exit2函数记录分配的结果。

这两个 bpf 程序都使用了 SEC 宏定义了对应的 tracepoint，以便在相应的内核函数被调用时得到执行。在Linux内核中，tracepoint 是一种可以在内核中插入的静态钩子，可以用来收集运行时的内核信息，它在调试和性能分析中非常有用。

在理解这些代码的过程中，要注意 BPF_CORE_READ 宏的使用。这个宏用于在 bpf 程序中读取内核数据。在 bpf 程序中，我们不能直接访问内核内存，而需要使用这样的宏来安全地读取数据。

### 用户态程序

在理解 BPF 内核部分之后，我们转到用户空间程序。用户空间程序与BPF内核程序紧密配合，它负责将BPF程序加载到内核，设置和管理BPF map，以及处理从BPF程序收集到的数据。用户态程序较长，我们这里可以简要参考一下它的挂载点。

```c
int attach_uprobes(struct memleak_bpf *skel)
{
    ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);

    ATTACH_UPROBE_CHECKED(skel, calloc, calloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, calloc, calloc_exit);

    ATTACH_UPROBE_CHECKED(skel, realloc, realloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, realloc, realloc_exit);

    ATTACH_UPROBE_CHECKED(skel, mmap, mmap_enter);
    ATTACH_URETPROBE_CHECKED(skel, mmap, mmap_exit);

    ATTACH_UPROBE_CHECKED(skel, posix_memalign, posix_memalign_enter);
    ATTACH_URETPROBE_CHECKED(skel, posix_memalign, posix_memalign_exit);

    ATTACH_UPROBE_CHECKED(skel, memalign, memalign_enter);
    ATTACH_URETPROBE_CHECKED(skel, memalign, memalign_exit);

    ATTACH_UPROBE_CHECKED(skel, free, free_enter);
    ATTACH_UPROBE_CHECKED(skel, munmap, munmap_enter);

    // the following probes are intentinally allowed to fail attachment

    // deprecated in libc.so bionic
    ATTACH_UPROBE(skel, valloc, valloc_enter);
    ATTACH_URETPROBE(skel, valloc, valloc_exit);

    // deprecated in libc.so bionic
    ATTACH_UPROBE(skel, pvalloc, pvalloc_enter);
    ATTACH_URETPROBE(skel, pvalloc, pvalloc_exit);

    // added in C11
    ATTACH_UPROBE(skel, aligned_alloc, aligned_alloc_enter);
    ATTACH_URETPROBE(skel, aligned_alloc, aligned_alloc_exit);

    return 0;
}
```

在这段代码中，我们看到一个名为`attach_uprobes`的函数，该函数负责将uprobes（用户空间探测点）挂载到内存分配和释放函数上。在Linux中，uprobes是一种内核机制，可以在用户空间程序中的任意位置设置断点，这使得我们可以非常精确地观察和控制用户空间程序的行为。

这里，每个内存相关的函数都通过两个uprobes进行跟踪：一个在函数入口（enter），一个在函数退出（exit）。因此，每当这些函数被调用或返回时，都会触发一个uprobes事件，进而触发相应的BPF程序。

在具体的实现中，我们使用了`ATTACH_UPROBE`和`ATTACH_URETPROBE`两个宏来附加uprobes和uretprobes（函数返回探测点）。每个宏都需要三个参数：BPF程序的骨架（skel），要监视的函数名，以及要触发的BPF程序的名称。

这些挂载点包括常见的内存分配函数，如malloc、calloc、realloc、mmap、posix_memalign、memalign、free等，以及对应的退出点。另外，我们也观察一些可能的分配函数，如valloc、pvalloc、aligned_alloc等，尽管它们可能不总是存在。

这些挂载点的目标是捕获所有可能的内存分配和释放事件，从而使我们的内存泄露检测工具能够获取到尽可能全面的数据。这种方法可以让我们不仅能跟踪到内存分配和释放，还能得到它们发生的上下文信息，例如调用栈和调用次数，从而帮助我们定位和修复内存泄露问题。

注意，一些内存分配函数可能并不存在或已弃用，比如valloc、pvalloc等，因此它们的附加可能会失败。在这种情况下，我们允许附加失败，并不会阻止程序的执行。这是因为我们更关注的是主流和常用的内存分配函数，而这些已经被弃用的函数往往在实际应用中较少使用。

完整的源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/16-memleak> 关于如何安装依赖，请参考：<https://eunomia.dev/tutorials/11-bootstrap/>

## 编译运行

```console
$ make
$ sudo ./memleak 
using default object: libc.so.6
using page size: 4096
tracing kernel: true
Tracing outstanding memory allocs...  Hit Ctrl-C to end
[17:17:27] Top 10 stacks with outstanding allocations:
1236992 bytes in 302 allocations from stack
        0 [<ffffffff812c8f43>] <null sym>
        1 [<ffffffff812c8f43>] <null sym>
        2 [<ffffffff812a9d42>] <null sym>
        3 [<ffffffff812aa392>] <null sym>
        4 [<ffffffff810df0cb>] <null sym>
        5 [<ffffffff81edc3fd>] <null sym>
        6 [<ffffffff82000b62>] <null sym>
...
```

## 总结

通过本篇 eBPF 入门实践教程，您已经学习了如何编写 Memleak eBPF 监控程序，以实时监控程序的内存泄漏。您已经了解了 eBPF 在内存监控方面的应用，学会了使用 BPF API 编写 eBPF 程序，创建和使用 eBPF maps，并且明白了如何用 eBPF 工具监测和分析内存泄漏问题。我们展示了一个详细的例子，帮助您理解 eBPF 代码的运行流程和原理。

您可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。

接下来的教程将进一步探讨 eBPF 的高级特性，我们会继续分享更多有关 eBPF 开发实践的内容。希望这些知识和技巧能帮助您更好地了解和使用 eBPF，以解决实际工作中遇到的问题。

参考资料：<https://github.com/iovisor/bcc/blob/master/libbpf-tools/memleak.c>
