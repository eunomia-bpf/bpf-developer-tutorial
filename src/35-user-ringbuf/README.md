# eBPF开发实践：使用 user ring buffer 向内核异步发送信息

eBPF，即扩展的Berkeley包过滤器（Extended Berkeley Packet Filter），是Linux内核中的一种革命性技术，它允许开发者在内核态中运行自定义的“微程序”，从而在不修改内核代码的情况下改变系统行为或收集系统细粒度的性能数据。

eBPF的一个独特之处是它不仅可以在内核态运行程序，从而访问系统底层的状态和资源，同时也可以通过特殊的数据结构与用户态程序进行通信。关于这方面的一个重要概念就是内核态和用户态之间的环形队列——ring buffer。在许多实时或高性能要求的应用中，环形队列是一种常用的数据结构。由于它的FIFO（先进先出）特性，使得数据在生产者和消费者之间可以持续、线性地流动，从而避免了频繁的IO操作和不必要的内存 reallocation开销。

在eBPF中，分别提供了两种环形队列: user ring buffer 和 kernel ring buffer，以实现用户态和内核态之间的高效数据通信。本文是 eBPF 开发者教程的一部分，更详细的内容可以在这里找到：<https://eunomia.dev/tutorials/> 源代码在 [GitHub 仓库](https://github.com/eunomia-bpf/bpf-developer-tutorial) 中开源。

## 用户态和内核态环形队列—user ring buffer和kernel ring buffer

围绕内核态和用户态这两个主要运行级别，eBPF提供了两种相应的环形队列数据结构：用户态环形队列——User ring buffer和内核态环形队列——Kernel ring buffer。

Kernel ring buffer 则由 eBPF实现，专为Linux内核设计，用于追踪和记录内核日志、性能统计信息等，它的能力是内核态和用户态数据传输的核心，可以从内核态向用户态传送数据。Kernel ring buffer 在 5.7 版本的内核中被引入，目前已经被广泛应用于内核日志系统、性能分析工具等。

对于内核态往用户态发送应用场景，如内核监控事件的发送、异步通知、状态更新通知等，ring buffer 数据结构都能够胜任。比如，当我们需要监听网络服务程序的大量端口状态时，这些端口的开启、关闭、错误等状态更新就需由内核实时传递到用户空间进行处理。而Linux 内核的日志系统、性能分析工具等，也需要频繁地将大量数据发送到用户空间，以支持用户人性化地展示和分析这些数据。在这些场景中，ring buffer在内核态往用户态发送数据中表现出了极高的效率。

User ring buffer 是基于环形缓冲器的一种新型 Map 类型，它提供了单用户空间生产者/单内核消费者的语义。这种环形队列的优点是对异步消息传递提供了优秀的支持，避免了不必要的同步操作，使得内核到用户空间的数据传输可以被优化，并且降低了系统调用的系统开销。User ring buffer 在 6.1 版本的内核中被引入，目前的使用场景相对较少。

bpftime 是一个用户空间 eBPF 运行时，允许现有 eBPF 应用程序在非特权用户空间使用相同的库和工具链运行。它为 eBPF 提供了 Uprobe 和 Syscall 跟踪点，与内核 Uprobe 相比，性能有了显著提高，而且无需手动检测代码或重启进程。运行时支持用户空间共享内存中的进程间 eBPF 映射，也兼容内核 eBPF 映射，允许与内核 eBPF 基础架构无缝运行。它包括一个适用于各种架构的高性能 LLVM JIT，以及一个适用于 x86 的轻量级 JIT 和一个解释器。GitHub 地址：<https://github.com/eunomia-bpf/bpftime>

在 bpftime 中，我们使用 user ring buffer 来实现用户态 eBPF 往内核态 eBPF 发送数据，并更新内核态 eBPF 对应的 maps，让内核态和用户态的 eBPF 一起协同工作。user ring buffer 的异步特性，可以避免系统调用不必要的同步操作，从而提高了内核态和用户态之间的数据传输效率。

eBPF 的双向环形队列也和 io_uring 在某些方面有相似之处，但它们的设计初衷和应用场景有所不同：

- **设计焦点**：io_uring主要专注于提高异步I/O操作的性能和效率，而eBPF的环形队列更多关注于内核和用户空间之间的数据通信和事件传输。
- **应用范围**：io_uring主要用于文件I/O和网络I/O的场景，而eBPF的环形队列则更广泛，不限于I/O操作，还包括系统调用跟踪、网络数据包处理等。
- **灵活性和扩展性**：eBPF提供了更高的灵活性和扩展性，允许用户定义复杂的数据处理逻辑，并在内核态执行。

下面，我们将通过一段代码示例，详细展示如何利用 user ring buffer，实现从用户态向内核传送数据，并以 kernel ring buffer 相应地从内核态向用户态传送数据。

## 一、实现：在用户态和内核态间使用 ring buffer 传送数据

借助新的 BPF MAP，我们可以实现在用户态和内核态间通过环形缓冲区传送数据。在这个示例中，我们将详细说明如何在用户空间创建一个 "用户环形缓冲区" (user ring buffer) 并向其写入数据，然后在内核空间中通过 `bpf_user_ringbuf_drain` 函数来消费这些数据。同时，我们也会使用 "内核环形缓冲区" (kernel ring buffer) 来从内核空间反馈数据到用户空间。为此，我们需要在用户空间和内核空间分别创建并操作这两个环形缓冲区。

完整的代码可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/35-user-ringbuf> 中找到。

### 创建环形缓冲区

在内核空间，我们创建了一个类型为 `BPF_MAP_TYPE_USER_RINGBUF` 的 `user_ringbuf`，以及一个类型为 `BPF_MAP_TYPE_RINGBUF` 的 `kernel_ringbuf`。在用户空间，我们创建了一个 `struct ring_buffer_user` 结构体的实例，并通过 `ring_buffer_user__new` 函数和对应的操作来管理这个用户环形缓冲区。

```c
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.kernel_ringbuf), handle_event, NULL, NULL);
    if (!rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    user_ringbuf = user_ring_buffer__new(bpf_map__fd(skel->maps.user_ringbuf), NULL);
```

### 编写内核态程序

我们定义一个 `kill_exit` 的 tracepoint 程序，每当有进程退出时，它会通过 `bpf_user_ringbuf_drain` 函数读取 `user_ringbuf` 中的用户数据，然后通过 `bpf_ringbuf_reserve` 函数在 `kernel_ringbuf` 中创建一个新的记录，并写入相关信息。最后，通过 `bpf_ringbuf_submit` 函数将这个记录提交，使得该记录能够被用户空间读取。

```c
// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "user_ringbuf.h"

char _license[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
    __uint(max_entries, 256 * 1024);
} user_ringbuf SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kernel_ringbuf SEC(".maps");

int read = 0;

static long
do_nothing_cb(struct bpf_dynptr *dynptr, void *context)
{
    struct event *e;
    pid_t pid;
    /* get PID and TID of exiting thread/process */
    pid = bpf_get_current_pid_tgid() >> 32;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&kernel_ringbuf, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    __sync_fetch_and_add(&read, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
    long num_samples;
    int err = 0;
    
    // receive data from userspace
    num_samples = bpf_user_ringbuf_drain(&user_ringbuf, do_nothing_cb, NULL, 0);

    return 0;
}
```

### 编写用户态程序

在用户空间，我们通过 `ring_buffer_user__reserve` 函数在 ring buffer 中预留出一段空间，这段空间用于写入我们希望传递给内核的信息。然后，通过 `ring_buffer_user__submit` 函数提交数据，之后这些数据就可以在内核态被读取。

```c
static int write_samples(struct user_ring_buffer *ringbuf)
{
    int i, err = 0;
    struct user_sample *entry;

    entry = user_ring_buffer__reserve(ringbuf, sizeof(*entry));
    if (!entry)
    {
        err = -errno;
        goto done;
    }

    entry->i = getpid();
    strcpy(entry->comm, "hello");

    int read = snprintf(entry->comm, sizeof(entry->comm), "%u", i);
    if (read <= 0)
    {
        /* Assert on the error path to avoid spamming logs with
         * mostly success messages.
         */
        err = read;
        user_ring_buffer__discard(ringbuf, entry);
        goto done;
    }

    user_ring_buffer__submit(ringbuf, entry);

done:
    drain_current_samples();

    return err;
}
```

### 初始化环形缓冲区并轮询

最后，对 ring buffer 进行初始化并定时轮询，这样我们就可以实时得知内核态的数据消费情况，我们还可以在用户空间对 `user_ringbuf` 进行写入操作，然后在内核态对其进行读取和处理。

```c
    write_samples(user_ringbuf);

    /* Process events */
    printf("%-8s %-5s %-16s %-7s %-7s %s\n",
           "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
    while (!exiting)
    {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR)
        {
            err = 0;
            break;
        }
        if (err < 0)
        {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }
```

通过以上步骤，我们实现了用户态与内核态间环形缓冲区的双向数据传输。

## 二、编译和运行代码

为了编译和运行以上代码，我们可以通过以下命令来实现：

```sh
make
```

关于如何安装依赖，请参考：<https://eunomia.dev/tutorials/11-bootstrap/>

运行结果将展示如何使用 user ring buffer 和 kernel ringbuffer 在用户态和内核态间进行高效的数据传输:

```console
$ sudo ./user_ringbuf
Draining current samples...
TIME     EVENT COMM             PID   
16:31:37 SIGN  node             1707   
Draining current samples...
16:31:38 SIGN  node             1981   
Draining current samples...
16:31:38 SIGN  node             1707   
Draining current samples...
16:31:38 SIGN  node             1707   
Draining current samples...
```

## 总结

在本篇文章中，我们介绍了如何使用eBPF的user ring buffer和kernel ring buffer在用户态和内核态之间进行数据传输。通过这种方式，我们可以有效地将用户态的数据传送给内核，或者将内核生成的数据反馈给用户，从而实现了内核态和用户态的双向通信。

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。

参考资料：

1. [https://lwn.net/Articles/907056/](https://lwn.net/Articles/907056/)

> 原文地址：<https://eunomia.dev/zh/tutorials/35-user-ringbuf/> 转载请注明出处。
