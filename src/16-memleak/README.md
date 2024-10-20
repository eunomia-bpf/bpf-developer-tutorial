# eBPF Tutorial by Example 16: Monitoring Memory Leaks

eBPF (extended Berkeley Packet Filter) is a powerful network and performance analysis tool that is widely used in the Linux kernel. eBPF allows developers to dynamically load, update, and run user-defined code without restarting the kernel or modifying its source code.

In this tutorial, we will explore how to write a Memleak program using eBPF to monitor memory leaks in programs.

## Background and Importance

Memory leaks are a common problem in computer programming and should not be underestimated. When memory leaks occur, programs gradually consume more memory resources without properly releasing them. Over time, this behavior can lead to a gradual depletion of system memory, significantly reducing the overall performance of the program and system.

There are many possible causes of memory leaks. It may be due to misconfiguration, such as a program incorrectly configuring dynamic allocation of certain resources. It may also be due to software bugs or incorrect memory management strategies, such as forgetting to release memory that is no longer needed during program execution. Additionally, if an application's memory usage is too high, system performance may significantly decrease due to paging/swapping, or it may even cause the application to be forcibly terminated by the system's OOM killer (Out of Memory Killer).

### Challenges of Debugging Memory Leaks

Debugging memory leak issues is a complex and challenging task. This involves detailed examination of the program's configuration, memory allocation, and deallocation, often requiring specialized tools to aid in diagnosis. For example, there are tools that can associate malloc() function calls with specific detection tools, such as Valgrind memcheck, which can simulate the CPU to check all memory accesses, but may greatly slow down the application's execution speed. Another option is to use heap analyzers, such as libtcmalloc, which are relatively faster but may still decrease the application's execution speed by more than five times. Additionally, there are tools like gdb that can obtain core dumps of applications and perform post-processing analysis of memory usage. However, these tools often require pausing the application during core dump acquisition or calling the free() function after the application terminates.

## Role of eBPF

In this context, the role of eBPF becomes particularly important. eBPF provides an efficient mechanism for monitoring and tracking system-level events, including memory allocation and deallocation. With eBPF, we can trace memory allocation and deallocation requests and collect the call stacks for each allocation. We can then analyze this information to identify call stacks that perform memory allocations but do not perform subsequent deallocations, helping us identify the source of memory leaks. The advantage of this approach is that it can be done in real-time within a running application without pausing the application or performing complex post-processing.

The `memleak` eBPF tool can trace and match memory allocation and deallocation requests, and collect the call stacks for each allocation. Subsequently, `memleak` can print a summary indicating which call stacks executed allocations but did not perform subsequent deallocations. For example, running the command:

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

After running this command, we can see which stacks the allocated but not deallocated memory came from, as well as the size and quantity of these unreleased memory blocks.

Over time, it becomes evident that the `main` function of the `allocs` process is leaking memory, 16 bytes at a time. Fortunately, we don't need to inspect each allocation; we have a nice summary that tells us which stack is responsible for the significant leaks.

## Implementation Principle of memleak

At a basic level, `memleak` operates by installing monitoring devices on the memory allocation and deallocation paths. It achieves this by inserting eBPF programs into memory allocation and deallocation functions. This means that when these functions are called, `memleak` will record important information, such as the caller's process ID (PID), the allocated memory address, and the size of the allocated memory. When the function for freeing memory is called, `memleak` will delete the corresponding memory allocation record in its internal map. This mechanism allows `memleak` to accurately trace which memory blocks have been allocated but not deallocated.For commonly used memory allocation functions in user space, such as `malloc` and `calloc`, `memleak` uses user space probing (uprobe) technology for monitoring. Uprobe is a dynamic tracing technology for user space applications, which can set breakpoints at any location at runtime without modifying the binary files, thus achieving tracing of specific function calls.

Uprobe in kernel mode eBPF runtime may also cause relatively large performance overhead. In this case, you can also consider using user mode eBPF runtime, such as [bpftime](https://github.com/eunomia-bpf/bpftime). bpftime is a user mode eBPF runtime based on LLVM JIT/AOT. It can run eBPF programs in user mode and is compatible with kernel mode eBPF, avoiding context switching between kernel mode and user mode, thereby improving the execution efficiency of eBPF programs by 10 times.

For kernel space memory allocation functions, such as `kmalloc`, `memleak` chooses to use tracepoints for monitoring. Tracepoint is a dynamic tracing technology provided in the Linux kernel, which can dynamically trace specific events in the kernel at runtime without recompiling the kernel or loading kernel modules.

## Kernel Space eBPF Program Implementation

## `memleak` Kernel Space eBPF Program Implementation

The kernel space eBPF program of `memleak` contains some key functions for tracking memory allocation and deallocation. Before delving into these functions, let's first take a look at some data structures defined by `memleak`, which are used in both its kernel space and user space programs.

```c
#ifndef __MEMLEAK_H
#define __MEMLEAK_H

#define ALLOCS_MAX_ENTRIES 1000000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240

struct alloc_info {
    __u64 size;            // Size of allocated memory
    __u64 timestamp_ns;    // Timestamp when allocation occurs, in nanoseconds
    int stack_id;          // Call stack ID when allocation occurs
};

union combined_alloc_info {
    struct {
        __u64 total_size : 40;        // Total size of all unreleased allocations
        __u64 number_of_allocs : 24;   // Total number of unreleased allocations
    };
    __u64 bits;    // Bitwise representation of the structure
};

#endif /* __MEMLEAK_H */
```

Here, two main data structures are defined: `alloc_info` and `combined_alloc_info`.

The `alloc_info` structure contains basic information about a memory allocation, including the allocated memory size `size`, the timestamp `timestamp_ns` when the allocation occurs, and the call stack ID `stack_id` that triggers the allocation.

The `combined_alloc_info` is a union that contains an embedded structure and a `__u64` type bitwise representation `bits`. The embedded structure has two members: `total_size` and `number_of_allocs`, representing the total size and total count of unreleased allocations, respectively. The numbers 40 and 24 indicate the number of bits occupied by the `total_size` and `number_of_allocs` members, limiting their size. By using this limitation, storage space for the `combined_alloc_info` structure can be saved. Moreover, since `total_size` and `number_of_allocs` share the same `unsigned long long` type variable `bits` for storage, bitwise operations on the member variable `bits` can be used to access and modify `total_size` and `number_of_allocs`, avoiding the complexity of defining additional variables and functions in the program.

Next, `memleak` defines a series of eBPF maps for storing memory allocation information and analysis results. These maps are defined in the form of `SEC(".maps")`, indicating that they belong to the mapping section of the eBPF program.

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
  //... (continued)__uint(type, BPF_MAP_TYPE_HASH);
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

The code first defines some configurable parameters, such as `min_size`, `max_size`, `page_size`, `sample_rate`, `trace_all`, `stack_flags`, and `wa_missing_free`, representing the minimum allocation size, maximum allocation size, page size, sample rate, whether to trace all allocations, stack flags, and whether to work in missing free mode.

Then, five maps are defined:

1. `sizes`: This is a hash-type map with the key as the process ID and the value as `u64` type, storing the allocation size of each process.
2. `allocs`: This is also a hash-type map with the key as the allocation address and the value as the `alloc_info` structure, storing detailed information about each memory allocation.
3. `combined_allocs`: This is another hash-type map with the key as the stack ID and the value as the `combined_alloc_info` union, storing the total size and count of all unreleased allocations.
4. `memptrs`: This is also a hash-type map with both the key and value as `u64` type, used to pass memory pointers between user space and kernel space.
5. `stack_traces`: This is a stack trace-type map with the key as `u32` type, used to store stack IDs.

Taking the user-space memory allocation tracing as an example, it mainly hooks memory-related function calls such as `malloc`, `free`, `calloc`, `realloc`, `mmap`, and `munmap` to record data when these functions are called. In user space, `memleak` mainly uses uprobes technology for hooking.

Each function call is divided into "enter" and "exit" parts. The "enter" part records the function call parameters, such as the size of the allocation or the address being freed. The "exit" part is mainly used to obtain the return value of the function, such as the memory address obtained from the allocation.

Here, `gen_alloc_enter`, `gen_alloc_exit`, `gen_free_enter` are functions that implement the recording behavior, and they are used to record relevant information when allocation starts, allocation ends, and freeing starts, respectively.

The function prototype is as follows:

```c
SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
    // Record relevant information when allocation starts
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit)
{
    // Record relevant information when allocation ends
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void *address)
{
    // Record relevant information when freeing starts
    return gen_free_enter(address);
}
```

`malloc_enter` and `free_enter` are probes mounted at the entry points of the `malloc` and `free` functions, respectively, to record data during function calls. `malloc_exit` is a probe mounted at the return point of the `malloc` function to record the return value of the function.

These functions are declared using the `BPF_KPROBE` and `BPF_KRETPROBE` macros, which are used to declare kprobes (kernel probes) and kretprobes (kernel return probes), respectively. Specifically, kprobe is triggered during function calls, while kretprobe is triggered during function returns.

The `gen_alloc_enter` function is called at the beginning of a memory allocation request. This function is mainly responsible for collecting some basic information when the function that allocates memory is called. Now, let's take a deep dive into the implementation of this function.

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

First, the `gen_alloc_enter` function takes a `size` parameter that represents the size of the requested memory allocation. If this value is not between `min_size` and `max_size`, the function will return directly without performing any further operations. This allows the tool to focus on tracing memory allocation requests within a specific range and filter out uninteresting allocation requests.

Next, the function checks the sampling rate `sample_rate`. If `sample_rate` is greater than 1, it means that we don't need to trace all memory allocation requests, but rather trace them periodically. Here, `bpf_ktime_get_ns` is used to get the current timestamp, and the modulus operation is used to determine whether to trace the current memory allocation request. This is a common sampling technique used to reduce performance overhead while providing a representative sample for analysis.

Then, the function uses the `bpf_get_current_pid_tgid` function to retrieve the current process's PID. Note that the PID here is actually a combination of the process ID and thread ID, and we shift it right by 32 bits to get the actual process ID.

The function then updates the `sizes` map, which uses the process ID as the key and the requested memory allocation size as the value. `BPF_ANY` indicates that if the key already exists, the value will be updated; otherwise, a new entry will be created.

Finally, if the `trace_all` flag is enabled, the function will print a message indicating that a memory allocation has occurred.

The `BPF_KPROBE` macro is used to intercept the execution of the `malloc` function with a BPF uprobe when the `malloc_enter` function is called, and it records the memory allocation size using `gen_alloc_enter`.
We have just analyzed the entry function `gen_alloc_enter` of memory allocation, now let's focus on the exit part of this process. Specifically, we will discuss the `gen_alloc_exit2` function and how to obtain the returned memory address from the memory allocation call.

```c
static int gen_alloc_exit2(void *ctx, u64 address)
{
    const pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct alloc_info info;

    const u64* size = bpf_map_lookup_elem(&sizes, &pid);
    if (!size)
        return 0; // missed alloc entry

    __builtin_memset(&info, 0, sizeof(info));

    info.size = *size;bpf_map_delete_elem(&sizes, &pid);

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

`gen_alloc_exit2` function is called when the memory allocation operation is completed. This function takes two parameters, one is the context `ctx` and the other is the memory address returned by the memory allocation function `address`.

First, it obtains the PID (Process ID) of the current thread and uses it as a key to look up the corresponding memory allocation size in the `sizes` map. If not found (i.e., no entry for the memory allocation operation), the function simply returns.

Then, it clears the content of the `info` structure and sets its `size` field to the memory allocation size found in the map. It also removes the corresponding element from the `sizes` map because the memory allocation operation has completed and this information is no longer needed.

Next, if `address` is not zero (indicating a successful memory allocation operation), the function further collects some additional information. First, it obtains the current timestamp as the completion time of the memory allocation and fetches the current stack trace. These pieces of information are stored in the `info` structure and subsequently updated in the `allocs` map.

Finally, the function calls `update_statistics_add` to update the statistics data and, if tracing of all memory allocation operations is enabled, it prints some information about the memory allocation operation.

Note that, `gen_alloc_exit` is a wrapper for `gen_alloc_exit2`, which passes `PT_REGS_RC(ctx)` as the `address` parameter to `gen_alloc_exit2`.

In our discussion, we just mentioned that `update_statistics_add` function is called in the `gen_alloc_exit2` function to update the statistics data for memory allocations. Now let's take a closer look at the implementation of this function.

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

The `update_statistics_add` function takes two parameters: the current stack ID `stack_id` and the size of the memory allocation `sz`. These two parameters are collected in the memory allocation event and used to update the statistics data for memory allocations.First, the function tries to find the element with the current stack ID as the key in the `combined_allocs` map. If it is not found, a new element is initialized with `initial_cinfo` (which is a default `combined_alloc_info` structure with all fields set to zero).

Next, the function creates an `incremental_cinfo` and sets its `total_size` to the current memory allocation size and `number_of_allocs` to 1. This is because each call to the `update_statistics_add` function represents a new memory allocation event, and the size of this event's memory allocation is `sz`.

Finally, the function atomically adds the value of `incremental_cinfo` to `existing_cinfo` using the `__sync_fetch_and_add` function. Note that this step is thread-safe, so even if multiple threads call the `update_statistics_add` function concurrently, each memory allocation event will be correctly recorded in the statistics.

In summary, the `update_statistics_add` function implements the logic for updating memory allocation statistics. By maintaining the total amount and number of memory allocations for each stack ID, we can gain insight into the memory allocation behavior of the program.

In our process of tracking memory allocation statistics, we not only need to count memory allocations but also consider memory releases. In the above code, we define a function called `update_statistics_del` that updates the statistics when memory is freed. The function `gen_free_enter` is executed when the process calls the `free` function.

The `update_statistics_del` function takes the stack ID and the size of the memory block to be freed as parameters. First, the function uses the current stack ID as the key to look up the corresponding `combined_alloc_info` structure in the `combined_allocs` map. If it is not found, an error message is output and the function returns. If it is found, a `decremental_cinfo` `combined_alloc_info` structure is constructed with its `total_size` set to the size of the memory to be freed and `number_of_allocs` set to 1. Then the `__sync_fetch_and_sub` function is used to atomically subtract the value of `decremental_cinfo` from `existing_cinfo`. Note that the `number_of_allocs` here is negative, indicating a decrease in memory allocation.

The `gen_free_enter` function takes the address to be freed as a parameter. It first converts the address to an unsigned 64-bit integer (`u64`). Then it looks up the `alloc_info` structure in the `allocs` map using the address as the key. If it is not found, the function returns 0. If it is found, the `alloc_info` structure is deleted from the `allocs` map, and the `update_statistics_del` function is called with the stack ID and size from `info`. If `trace_all` is true, an information message is output.

```c
int BPF_KPROBE(free_enter, void *address)
{
    return gen_free_enter(address);
}
```

Next, let's look at the `gen_free_enter` function. It takes an address as a parameter, which is the result of memory allocation, i.e., the starting address of the memory to be freed. The function first uses this address as a key to search for the corresponding `alloc_info` structure in the `allocs` map. If it is not found, it simply returns because it means that this address has not been allocated. If it is found, the element is deleted, and the `update_statistics_del` function is called to update the statistics data. Finally, if global tracking is enabled, a message is also output, including this address and its size.

While tracking and profiling memory allocation, we also need to track kernel-mode memory allocation and deallocation. In the Linux kernel, the `kmem_cache_alloc` function and the `kfree` function are used for kernel-mode memory allocation and deallocation, respectively.

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

The above code snippet defines a function `memleak__kfree`. This is a BPF program that will be executed when the `kfree` function is called in the kernel. First, the function checks if `kfree` exists. If it does, it reads the argument passed to the `kfree` function (i.e., the address of the memory block to be freed) and saves it in the variable `ptr`. Otherwise, it reads the argument passed to the `kmem_free` function (i.e., the address of the memory block to be freed) and saves it in the variable `ptr`. Then, the function calls the previously defined `gen_free_enter` function to handle the release of this memory block.

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

This code snippet defines a function `memleak__kmem_cache_alloc`. This is also a BPF program that will be executed when the `kmem_cache_alloc` function is called in the kernel. If the `wa_missing_free` flag is set, it calls the `gen_free_enter` function to handle possible missed release operations. Then, the function calls the `gen_alloc_enter` function to handle memory allocation and finally calls the `gen_alloc_exit2` function to record the allocation result.

Both of these BPF programs use the `SEC` macro to define the corresponding tracepoints, so that they can be executed when the corresponding kernel functions are called. In the Linux kernel, a tracepoint is a static hook that can be inserted into the kernel to collect runtime kernel information. It is very useful for debugging and performance analysis.

In the process of understanding this code, pay attention to the use of the `BPF_CORE_READ` macro. This macro is used to read kernel data in BPF programs. In BPF programs, we cannot directly access kernel memory and need to use such macros to safely read data.

### User-Space Program

After understanding the BPF kernel part, let's switch to the user-space program. The user-space program works closely with the BPF kernel program. It is responsible for loading BPF programs into the kernel, setting up and managing BPF maps, and handling data collected from BPF programs. The user-space program is longer, but here we can briefly refer to its mount point.

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

    // the following probes are intentionally allowed to fail attachment

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

In this code snippet, we see a function called `attach_uprobes` that mounts uprobes (user space probes) onto memory allocation and deallocation functions. In Linux, uprobes are a kernel mechanism that allows setting breakpoints at arbitrary locations in user space programs, enabling precise observation and control over the behavior of user space programs.

Here, each memory-related function is traced using two uprobes: one at the entry (enter) of the function and one at the exit. Thus, every time these functions are called or return, a uprobes event is triggered, which in turn triggers the corresponding BPF program.

In the actual implementation, we use two macros, `ATTACH_UPROBE` and `ATTACH_URETPROBE`, to attach uprobes and uretprobes (function return probes), respectively. Each macro takes three arguments: the skeleton of the BPF program (skel), the name of the function to monitor, and the name of the BPF program to trigger.

These mount points include common memory allocation functions such as malloc, calloc, realloc, mmap, posix_memalign, memalign, free, and their corresponding exit points. Additionally, we also observe some possible allocation functions such as valloc, pvalloc, aligned_alloc, although they may not always exist.

The goal of these mount points is to capture all possible memory allocation and deallocation events, allowing our memory leak detection tool to obtain as comprehensive data as possible. This approach enables us to track not only memory allocation and deallocation but also their contextual information such as call stacks and invocation counts, helping us to pinpoint and fix memory leak issues.

Note that some memory allocation functions may not exist or may have been deprecated, such as valloc and pvalloc. Thus, their attachment may fail. In such cases, we allow for attachment failures, which do not prevent the program from executing. This is because we are more focused on mainstream and commonly used memory allocation functions, while these deprecated functions are often used less frequently in practical applications.

Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/16-memleak>

Reference: <https://github.com/iovisor/bcc/blob/master/libbpf-tools/memleak.c>

## Compile and Run

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

## Summary

Through this eBPF introductory tutorial, you have learned how to write a Memleak eBPF monitoring program to monitor memory leaks in real time. You have also learned about the application of eBPF in memory monitoring, how to write eBPF programs using the BPF API, create and use eBPF maps, and how to use eBPF tools to monitor and analyze memory leak issues. We have provided a detailed example to help you understand the execution flow and principles of eBPF code.

You can visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials.

> The original link of this article: <https://eunomia.dev/tutorials/16-memleak>
