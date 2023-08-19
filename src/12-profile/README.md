# eBPF 入门实践教程十二：使用 eBPF 程序 profile 进行性能分析

本教程将指导您使用 libbpf 和 eBPF 程序进行性能分析。我们将利用内核中的 perf 机制，学习如何捕获函数的执行时间以及如何查看性能数据。

libbpf 是一个用于与 eBPF 交互的 C 库。它提供了创建、加载和使用 eBPF 程序所需的基本功能。本教程中，我们将主要使用 libbpf 完成开发工作。perf 是 Linux 内核中的性能分析工具，允许用户测量和分析内核及用户空间程序的性能，以及获取对应的调用堆栈。它利用内核中的硬件计数器和软件事件来收集性能数据。

## eBPF 工具：profile 性能分析示例

`profile` 工具基于 eBPF 实现，利用 Linux 内核中的 perf 事件进行性能分析。`profile` 工具会定期对每个处理器进行采样，以便捕获内核函数和用户空间函数的执行。它可以显示栈回溯的以下信息：

- 地址：函数调用的内存地址
- 符号：函数名称
- 文件名：源代码文件名称
- 行号：源代码中的行号

这些信息有助于开发人员定位性能瓶颈和优化代码。更进一步，可以通过这些对应的信息生成火焰图，以便更直观的查看性能数据。

在本示例中，可以通过 libbpf 库编译运行它（以 Ubuntu/Debian 为例）：

**NOTE:** 首先需要安装 `cargo` 才能编译得到 `profile`, 安装方法可以参考[Cargo 手册](https://rustwiki.org/en/cargo/getting-started/installation.html)  

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

## 实现原理

profile 工具由两个部分组成，内核态中的 eBPF 程序和用户态中的 `profile` 符号处理程序。`profile` 符号处理程序负责加载 eBPF 程序，以及处理 eBPF 程序输出的数据。

### 内核态部分

内核态 eBPF 程序的实现逻辑主要是借助 perf event，对程序的堆栈进行定时采样，从而捕获程序的执行流程。

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

接下来，我们将重点讲解内核态代码的关键部分。

1. 定义 eBPF maps `events`：

    ```c

    struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
    } events SEC(".maps");
    ```

    这里定义了一个类型为 `BPF_MAP_TYPE_RINGBUF` 的 eBPF  maps 。Ring Buffer 是一种高性能的循环缓冲区，用于在内核和用户空间之间传输数据。`max_entries` 设置了 Ring Buffer 的最大大小。

2. 定义 `perf_event` eBPF 程序：

    ```c
    SEC("perf_event")
    int profile(void *ctx)
    ```

    这里定义了一个名为 `profile` 的 eBPF 程序，它将在 perf 事件触发时执行。

3. 获取进程 ID 和 CPU ID：

    ```c
    int pid = bpf_get_current_pid_tgid() >> 32;
    int cpu_id = bpf_get_smp_processor_id();
    ```

    `bpf_get_current_pid_tgid()` 函数返回当前进程的 PID 和 TID，通过右移 32 位，我们得到 PID。`bpf_get_smp_processor_id()` 函数返回当前 CPU 的 ID。

4. 预留 Ring Buffer 空间：

    ```c
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 1;
    ```

    通过 `bpf_ringbuf_reserve()` 函数预留 Ring Buffer 空间，用于存储采集的栈信息。若预留失败，返回错误.

5. 获取当前进程名：

    ```c

    if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
        event->comm[0] = 0;
    ```

    使用 `bpf_get_current_comm()` 函数获取当前进程名并将其存储到 `event->comm`。

6. 获取内核栈信息：

    ```c

    event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);
    ```

    使用 `bpf_get_stack()` 函数获取内核栈信息。将结果存储在 `event->kstack`，并将其大小存储在 `event->kstack_sz`。

7. 获取用户空间栈信息：

    ```c
    event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);
    ```

    同样使用 `bpf_get_stack()` 函数，但传递 `BPF_F_USER_STACK` 标志以获取用户空间栈信息。将结果存储在 `event->ustack`，并将其大小存储在 `event->ustack_sz`。

8. 将事件提交到 Ring Buffer：

    ```c
    bpf_ringbuf_submit(event, 0);
    ```

    最后，使用 `bpf_ringbuf_submit()` 函数将事件提交到 Ring Buffer，以便用户空间程序可以读取和处理。

    这个内核态 eBPF 程序通过定期采样程序的内核栈和用户空间栈来捕获程序的执行流程。这些数据将存储在 Ring Buffer 中，以便用户态的 `profile` 程序能读取。

### 用户态部分

这段代码主要负责为每个在线 CPU 设置 perf event 并附加 eBPF 程序：

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

`perf_event_open` 这个函数是一个对 perf_event_open 系统调用的封装。它接收一个 perf_event_attr 结构体指针，用于指定 perf event 的类型和属性。pid 参数用于指定要监控的进程 ID（-1 表示监控所有进程），cpu 参数用于指定要监控的 CPU。group_fd 参数用于将 perf event 分组，这里我们使用 -1，表示不需要分组。flags 参数用于设置一些标志，这里我们使用 PERF_FLAG_FD_CLOEXEC 以确保在执行 exec 系列系统调用时关闭文件描述符。

在 main 函数中：

```c
for (cpu = 0; cpu < num_cpus; cpu++) {
    // ...
}
```

这个循环针对每个在线 CPU 设置 perf event 并附加 eBPF 程序。首先，它会检查当前 CPU 是否在线，如果不在线则跳过。然后，使用 perf_event_open() 函数为当前 CPU 设置 perf event，并将返回的文件描述符存储在 pefds 数组中。最后，使用 bpf_program__attach_perf_event() 函数将 eBPF 程序附加到 perf event。links 数组用于存储每个 CPU 上的 BPF 链接，以便在程序结束时销毁它们。

通过这种方式，用户态程序为每个在线 CPU 设置 perf event，并将 eBPF 程序附加到这些 perf event 上，从而实现对系统中所有在线 CPU 的监控。

以下这两个函数分别用于显示栈回溯和处理从 ring buffer 接收到的事件：

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

`show_stack_trace()` 函数用于显示内核或用户空间的栈回溯。它接收一个 stack 参数，是一个指向内核或用户空间栈的指针，stack_sz 参数表示栈的大小，pid 参数表示要显示的进程的 ID（当显示内核栈时，设置为 0）。函数中首先根据 pid 参数确定栈的来源（内核或用户空间），然后调用 blazesym_symbolize() 函数将栈中的地址解析为符号名和源代码位置。最后，遍历解析结果，输出符号名和源代码位置信息。

`event_handler()` 函数用于处理从 ring buffer 接收到的事件。它接收一个 data 参数，指向 ring buffer 中的数据，size 参数表示数据的大小。函数首先将 data 指针转换为 stacktrace_event 结构体指针，然后检查内核和用户空间栈的大小。如果栈为空，则直接返回。接下来，函数输出进程名称、进程 ID 和 CPU ID 信息。然后分别显示内核栈和用户空间栈的回溯。调用 show_stack_trace() 函数时，分别传入内核栈和用户空间栈的地址、大小和进程 ID。

这两个函数作为 eBPF profile 工具的一部分，用于显示和处理 eBPF 程序收集到的栈回溯信息，帮助用户了解程序的运行情况和性能瓶颈。

### 总结

通过本篇 eBPF 入门实践教程，我们学习了如何使用 eBPF 程序进行性能分析。在这个过程中，我们详细讲解了如何创建 eBPF 程序，监控进程的性能，并从 ring buffer 中获取数据以分析栈回溯。我们还学习了如何使用 perf_event_open() 函数设置性能监控，并将 BPF 程序附加到性能事件上。在本教程中，我们还展示了如何编写 eBPF 程序来捕获进程的内核和用户空间栈信息，进而分析程序性能瓶颈。通过这个例子，您可以了解到 eBPF 在性能分析方面的强大功能。

如果您希望学习更多关于 eBPF 的知识和实践，请查阅 eunomia-bpf 的官方文档：<https://github.com/eunomia-bpf/eunomia-bpf> 。您还可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。

接下来的教程将进一步探讨 eBPF 的高级特性，我们会继续分享更多有关 eBPF 开发实践的内容，帮助您更好地理解和掌握 eBPF 技术，希望这些内容对您在 eBPF 开发道路上的学习和实践有所帮助。
