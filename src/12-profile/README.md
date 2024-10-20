# eBPF Tutorial by Example 12: Using eBPF Program Profile for Performance Analysis

This tutorial will guide you on using libbpf and eBPF programs for performance analysis. We will leverage the perf mechanism in the kernel to learn how to capture the execution time of functions and view performance data.

libbpf is a C library for interacting with eBPF. It provides the basic functionality for creating, loading, and using eBPF programs. In this tutorial, we will mainly use libbpf for development. Perf is a performance analysis tool in the Linux kernel that allows users to measure and analyze the performance of kernel and user space programs, as well as obtain corresponding call stacks. It collects performance data using hardware counters and software events in the kernel.

## eBPF Tool: profile Performance Analysis Example

The `profile` tool is implemented based on eBPF and utilizes the perf events in the Linux kernel for performance analysis. The `profile` tool periodically samples each processor to capture the execution of kernel and user space functions. It provides the following information for stack traces:

- Address: memory address of the function call
- Symbol: function name
- File Name: name of the source code file
- Line Number: line number in the source code

This information helps developers locate performance bottlenecks and optimize code. Furthermore, flame graphs can be generated based on this information for a more intuitive view of performance data.

In this example, you can compile and run it with the libbpf library (using Ubuntu/Debian as an example):

**NOTE:** To compile the `profile`, you first need to install `Cargo`, as shown in ["The Cargo Book"](https://rustwiki.org/en/cargo/getting-started/installation.html)

```console
$ git submodule update --init --recursive
$ sudo apt install clang libelf1 libelf-dev zlib1g-dev
$ make
$ sudo ./profile 
COMM: chronyd (pid=156) @ CPU 1
Kernel:
  0 [<ffffffff81ee9f56>] _raw_spin_lock_irqsave+0x16
  1 [<ffffffff811527b4>] remove_wait_queue+0x14
  2 [<ffffffff8132611d>] poll_freewait+0x3d
  3 [<ffffffff81326d3f>] do_select+0x7bf
  4 [<ffffffff81327af2>] core_sys_select+0x182
  5 [<ffffffff81327f3a>] __x64_sys_pselect6+0xea
  6 [<ffffffff81ed9e38>] do_syscall_64+0x38
  7 [<ffffffff82000099>] entry_SYSCALL_64_after_hwframe+0x61
Userspace:
  0 [<00007fab187bfe09>]
  1 [<000000000ee6ae98>]

COMM: profile (pid=9843) @ CPU 6
No Kernel Stack
Userspace:
  0 [<0000556deb068ac8>]
  1 [<0000556dec34cad0>]
```

## Implementation Principle

The `profile` tool consists of two parts: the eBPF program in kernel space and the `profile` symbol handling program in user space. The `profile` symbol handling program is responsible for loading the eBPF program and processing the data outputted by the eBPF program.

### Kernel Space Part

The implementation logic of the eBPF program in kernel space mainly relies on perf events to periodically sample the stack of the program, thereby capturing its execution flow.

```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "profile.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("perf_event")
int profile(void *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    int cpu_id = bpf_get_smp_processor_id();
    struct stacktrace_event *event;
    int cp;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 1;

    event->pid = pid;
    event->cpu_id = cpu_id;

    if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
        event->comm[0] = 0;

    event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

    event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

    bpf_ringbuf_submit(event, 0);

    return 0;
}
```

Next, we will focus on the key part of the kernel code.

1. Define eBPF maps `events`:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");
```

Here, a eBPF maps of type `BPF_MAP_TYPE_RINGBUF` is defined. The Ring Buffer is a high-performance circular buffer used to transfer data between the kernel and user space. `max_entries` sets the maximum size of the Ring Buffer.

2. Define `perf_event` eBPF program:

```c
SEC("perf_event")
int profile(void *ctx)
```

Here, a eBPF program named `profile` is defined, which will be executed when a perf event is triggered.

3. Get process ID and CPU ID:

```c
int pid = bpf_get_current_pid_tgid() >> 32;
int cpu_id = bpf_get_smp_processor_id();
```

The function `bpf_get_current_pid_tgid()` returns the PID and TID of the current process. By right shifting 32 bits, we get the PID. The function `bpf_get_smp_processor_id()` returns the ID of the current CPU.

4. Reserve space in the Ring Buffer:

```c
event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
if (!event)
    return 1;
```

Use the `bpf_ringbuf_reserve()` function to reserve space in the Ring Buffer for storing the collected stack information. If the reservation fails, return an error.

5. Get the current process name:

```c

if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
    event->comm[0] = 0;
```

Use the `bpf_get_current_comm()` function to get the current process name and store it in `event->comm`.

6. Get kernel stack information:

```c

event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);
```

Use the `bpf_get_stack()` function to get kernel stack information. Store the result in `event->kstack` and the size in `event->kstack_sz`.

7. Get user space stack information:

```c
event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);
```

Using the `bpf_get_stack()` function with the `BPF_F_USER_STACK` flag retrieves information about the user space stack. Store the result in `event->ustack` and its size in `event->ustack_sz`.

8. Submit the event to the Ring Buffer:

```c
    bpf_ringbuf_submit(event, 0);
```

Finally, use the `bpf_ringbuf_submit()` function to submit the event to the Ring Buffer for the user space program to read and process.

This kernel mode eBPF program captures the program's execution flow by sampling the kernel stack and user space stack of the program periodically. These data are stored in the Ring Buffer for the user mode `profile` program to read.

### User Mode Section

This code is mainly responsible for setting up perf events for each online CPU and attaching eBPF programs:

```c
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                int cpu, int group_fd, unsigned long flags)
{
    int ret;

    ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
    return ret;
}

int main(){
    ...
    for (cpu = 0; cpu < num_cpus; cpu++) {
        /* skip offline/not present CPUs */
        if (cpu >= num_online_cpus || !online_mask[cpu])
            continue;

        /* Set up performance monitoring on a CPU/Core */
        pefd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (pefd < 0) {
            fprintf(stderr, "Fail to set up performance monitor on a CPU/Core\n");
            err = -1;
            goto cleanup;
        }
        pefds[cpu] = pefd;

        /* Attach a BPF program on a CPU */
        links[cpu] = bpf_program__attach_perf_event(skel->progs.profile, pefd);
        if (!links[cpu]) {
            err = -1;
            goto cleanup;
        }
    }
    ...
}
```

The `perf_event_open` function is a wrapper for the perf_event_open system call. It takes a pointer to a perf_event_attr structure to specify the type and attributes of the perf event. The pid parameter is used to specify the process ID to monitor (-1 for monitoring all processes), and the cpu parameter is used to specify the CPU to monitor. The group_fd parameter is used to group perf events, and we use -1 here to indicate no grouping is needed. The flags parameter is used to set some flags, and we use PERF_FLAG_FD_CLOEXEC to ensure file descriptors are closed when executing exec series system calls.

In the main function:

```c
for (cpu = 0; cpu < num_cpus; cpu++) {
    // ...
}
```

This loop sets up perf events and attaches eBPF programs for each online CPU. Firstly, it checks if the current CPU is online and skips if it's not. Then, it uses the perf_event_open() function to set up perf events for the current CPU and stores the returned file descriptor in the pefds array. Finally, it attaches the eBPF program to the perf event using the bpf_program__attach_perf_event() function. The links array is used to store the BPF links for each CPU so that they can be destroyed when the program ends.By doing so, user-mode programs set perf events for each online CPU and attach eBPF programs to these perf events to monitor all online CPUs in the system.

The following two functions are used to display stack traces and handle events received from the ring buffer:

```c
static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
    const struct blazesym_result *result;
    const struct blazesym_csym *sym;
    sym_src_cfg src;
    int i, j;

    if (pid) {
        src.src_type = SRC_T_PROCESS;
        src.params.process.pid = pid;
    } else {
        src.src_type = SRC_T_KERNEL;
        src.params.kernel.kallsyms = NULL;
        src.params.kernel.kernel_image = NULL;
    }

    result = blazesym_symbolize(symbolizer, &src, 1, (const uint64_t *)stack, stack_sz);

    for (i = 0; i < stack_sz; i++) {
        if (!result || result->size <= i || !result->entries[i].size) {
            printf("  %d [<%016llx>]\n", i, stack[i]);
            continue;
        }

        if (result->entries[i].size == 1) {
            sym = &result->entries[i].syms[0];
            if (sym->path && sym->path[0]) {
                printf("  %d [<%016llx>] %s+0x%llx %s:%ld\n",
                       i, stack[i], sym->symbol,
                       stack[i] - sym->start_address,
                       sym->path, sym->line_no);
            } else {
                printf("  %d [<%016llx>] %s+0x%llx\n",
                       i, stack[i], sym->symbol,
                       stack[i] - sym->start_address);
            }
            continue;
        }

        printf("  %d [<%016llx>]\n", i, stack[i]);
        for (j = 0; j < result->entries[i].size; j++) {
            sym = &result->entries[i].syms[j];
            if (sym->path && sym->path[0]) {
                printf("        %s+0x%llx %s:%ld\n",
                       sym->symbol, stack[i] - sym->start_address,
                       sym->path, sym->line_no);
            } else {
                printf("        %s+0x%llx\n", sym->symbol,
                       stack[i] - sym->start_address);
            }
        }
    }

    blazesym_result_free(result);
}

/* Receive events from the ring buffer. */
static int event_handler(void *_ctx, void *data, size_t size)
{
    struct stacktrace_event *event = data;

    if (event->kstack_sz <= 0 && event->ustack_sz <= 0)
        return 1;

    printf("COMM: %s (pid=%d) @ CPU %d\n", event->comm, event->pid, event->cpu_id);

    if (event->kstack_sz > 0) {
        printf("Kernel:\n");
        show_stack_trace(event->kstack, event->kstack_sz / sizeof(__u64), 0);
    } else {
        printf("No Kernel Stack\n");
    }

    if (event->ustack_sz > 0) {
        printf("Userspace:\n");
        show_stack_trace(event->ustack, event->ustack_sz / sizeof(__u64), event->pid);
    } else {
        printf("No Userspace Stack\n");
    }

    printf("\n");
    return 0;
}
```

The `show_stack_trace()` function is used to display the stack trace of the kernel or userspace. It takes a `stack` parameter, which is a pointer to the kernel or userspace stack, and a `stack_sz` parameter, which represents the size of the stack. The `pid` parameter represents the ID of the process to be displayed (set to 0 when displaying the kernel stack). In the function, the source of the stack (kernel or userspace) is determined based on the `pid` parameter, and then the `blazesym_symbolize()` function is called to resolve the addresses in the stack to symbol names and source code locations. Finally, the resolved results are traversed and the symbol names and source code location information are outputted.

The `event_handler()` function is used to handle events received from the ring buffer. It takes a `data` parameter, which points to the data in the ring buffer, and a `size` parameter, which represents the size of the data. The function first converts the `data` pointer to a pointer of type `stacktrace_event`, and then checks the sizes of the kernel and userspace stacks. If the stacks are empty, it returns directly. Next, the function outputs the process name, process ID, and CPU ID information. Then it displays the stack traces of the kernel and userspace respectively. When calling the `show_stack_trace()` function, the addresses, sizes, and process ID of the kernel and userspace stacks are passed in separately.

These two functions are part of the eBPF profiling tool, used to display and process stack trace information collected by eBPF programs, helping users understand program performance and bottlenecks.

### Summary

Through this introductory tutorial on eBPF, we have learned how to use eBPF programs for performance analysis. In this process, we explained in detail how to create eBPF programs, monitor process performance, and retrieve data from the ring buffer for analyzing stack traces. We also learned how to use the `perf_event_open()` function to set up performance monitoring and attach BPF programs to performance events. In this tutorial, we also demonstrated how to write eBPF programs to capture the kernel and userspace stack information of processes in order to analyze program performance bottlenecks. With this example, you can understand the powerful features of eBPF in performance analysis.

If you want to learn more about eBPF knowledge and practices, please refer to the official documentation of eunomia-bpf: <https://github.com/eunomia-bpf/eunomia-bpf>. You can also visit our tutorial code repository <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials.

The next tutorial will further explore advanced features of eBPF. We will continue to share more content about eBPF development practices to help you better understand and master eBPF technology. We hope these contents will be helpful for your learning and practice on the eBPF development journey.

> The original link of this article: <https://eunomia.dev/tutorials/12-profile>
