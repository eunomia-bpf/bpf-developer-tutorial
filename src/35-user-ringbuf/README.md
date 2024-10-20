# eBPF Development Practices: Asynchronously Send to Kernel with User Ring Buffer

eBPF, or Extended Berkeley Packet Filter, is a revolutionary technology in the Linux kernel that allows developers to run custom "micro programs" in kernel mode, thereby changing system behavior or collecting fine-grained performance data without modifying kernel code.

One unique aspect of eBPF is that it not only allows programs to run in kernel mode to access low-level system states and resources, but it can also communicate with user mode programs through special data structures. One important concept in this regard is the ring buffer between kernel mode and user mode. In many real-time or high-performance applications, the ring buffer is a commonly used data structure. Due to its FIFO (first in, first out) characteristics, data can flow continuously and linearly between the producer and the consumer, avoiding frequent IO operations and unnecessary memory reallocation overhead.

In eBPF, two types of ring buffers are provided: user ring buffer and kernel ring buffer, to achieve efficient data communication between user mode and kernel mode. This article is part of the eBPF developer tutorial. More detailed content can be found here: <https://eunomia.dev/tutorials/> The source code is open source in the <https://github.com/eunomia-bpf/bpf-developer-tutorial>.

## User mode and kernel mode ring buffers—user ring buffer and kernel ring buffer

Around the two main run levels of kernel mode and user mode, eBPF provides two corresponding ring buffer data structures: User ring buffer and Kernel ring buffer.

Kernel ring buffer is implemented by eBPF and is specially designed for the Linux kernel to track and record kernel logs, performance statistics, etc. It is the core of data transfer from kernel mode to user mode and can send data from kernel mode to user mode. Kernel ring buffer was introduced in the 5.7 version of the kernel and is now widely used in the kernel logging system, performance analysis tools, etc.

For scenarios where the kernel sends to user mode, such as sending kernel monitoring events, asynchronous notifications, status update notifications, etc., the ring buffer data structure can handle them. For example, when we need to monitor the status of a large number of ports of network service programs, the opening, closing, errors, and other status updates of these ports need to be real-time transferred to the user space for processing. Linux kernel's logging system, performance analysis tools, etc., also need to frequently send large amounts of data to user space to support user-friendly display and analysis of these data. In these scenarios, the ring buffer shows extremely high efficiency in sending data from the kernel to the user.

User ring buffer is a new type of Map type based on the ring buffer, it provides the semantics of a single user space producer/single kernel consumer. The advantage of this ring buffer is that it provides excellent support for asynchronous message passing, avoiding unnecessary synchronization operations, optimizing data transfer from the kernel to user space, and reducing the system overhead of system calls. User ring buffer was introduced in the 6.1 version of the kernel and its current use cases are relatively limited.

bpftime is a user space eBPF runtime that allows existing eBPF applications to run in unprivileged user space using the same libraries and toolchain. It provides Uprobe and Syscall tracing points for eBPF, which significantly improves performance compared to kernel Uprobe and does not require manual code detection or process restart. The runtime supports process eBPF mapping in user space shared memory, and is also compatible with kernel eBPF mapping, allowing seamless operation with the kernel eBPF infrastructure. It includes a high-performance LLVM JIT for various architectures, a lightweight JIT for x86, and an interpreter. GitHub address: <https://github.com/eunomia-bpf/bpftime>

In bpftime, we use the user ring buffer to implement data transmission from user mode eBPF to kernel mode eBPF, and update the maps corresponding to kernel mode eBPF, so that kernel mode and user mode eBPF can work together. The asynchronous characteristics of user ring buffer can avoid unnecessary synchronization operations of system calls, thereby improving the efficiency of data transmission between kernel mode and user mode.

The bi-directional ring buffer of eBPF also has similarities to io_uring in some respects, but their design intentions and use cases are different:

- **Design focus**: io_uring primarily focuses on improving the performance and efficiency of asynchronous I/O operations, while eBPF's ring buffer focuses more on data communication and event transmission between the kernel and user space.
- **Application range**: io_uring is mainly used in file I/O and network I/O scenarios, while eBPF's ring buffer is more widespread, not limited to I/O operations, but also including system call tracing, network packet processing, etc.
- **Flexibility and extensibility**: eBPF provides higher flexibility and extensibility, allowing users to define complex data processing logic and execute it in kernel mode.

Following is a code example where we will show in detail how to use user ring buffer to transmit data from user mode to the kernel, and how to respond accordingly with kernel ring buffer to transmit data from kernel mode to user mode.

## I. Implementation: Using Ring Buffer to Transfer Data Between User Mode and Kernel Mode

With the help of the new BPF MAP, we can implement the transfer of data between user mode and kernel mode through the ring buffer. In this example, we will detail how to create a "user ring buffer" in user space and write data to it and then consume this data in kernel space with the `bpf_user_ringbuf_drain` function. At the same time, we will use the "kernel ring buffer" to feed back data from kernel space to user space. To do this, we need to create and operate these two ring buffers separately in user space and kernel space.

The complete code can be found at <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/35-user-ringbuf>.

### Create Ring Buffer

In kernel mode, we created a `user_ringbuf` of type `BPF_MAP_TYPE_USER_RINGBUF` and a `kernel_ringbuf` of type `BPF_MAP_TYPE_RINGBUF`. In user mode, we created an instance of the `struct ring_buffer_user` structure and managed this user ring buffer through the `ring_buffer_user__new` function and corresponding operations.

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

### Writing Kernel Mode Programs

We define a `kill_exit` tracepoint program that will read user data from `user_ringbuf` with the `bpf_user_ringbuf_drain` function whenever a process exits. Then, it creates a new record in `kernel_ringbuf` with the `bpf_ringbuf_reserve` function and writes relevant information. Finally, the record is submitted with the `bpf_ringbuf_submit` function so that it can be read by user mode.

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

### Writing User Mode Programs

In user mode, we reserved a section of space in the ring buffer with the `ring_buffer_user__reserve` function. This space is used to write the information we want to pass to the kernel. Then, the data is submitted using the `ring_buffer_user__submit` function, after which this data can be read and processed in kernel mode.

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

### Initialization of the Ring Buffer and Poll

Finally, initialize the ring buffer and periodically poll, so we can know in real-time the consumption of data in kernel mode. We can also write to the `user_ringbuf` in user mode, then read and process it in kernel mode.

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

Through the above steps, we have implemented two-way data transmission between user mode and kernel mode.

## II. Compile and Run the Code

To compile and run the above code, we can run the following command:

```sh
make
```

For information on how to install dependencies, refer to: <https://eunomia.dev/tutorials/11-bootstrap/>

The execution result displays how to use the user ring buffer and kernel ringbuffer for efficient data transmission between user mode and kernel mode:

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

## Conclusion

In this article, we discussed how to use eBPF's user ring buffer and kernel ring buffer for data transmission between user mode and kernel mode. Through this method, we can effectively deliver user data to the kernel or feed back kernel-generated data to the user, thus implementing two-way communication between the kernel and user modes.

If you want to learn more about eBPF knowledge and practices, you can visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or our website at <https://eunomia.dev/zh/tutorials/> for more examples and complete tutorials.

References:

1. [https://lwn.net/Articles/907056/](https://lwn.net/Articles/907056/)

> Original URL: <https://eunomia.dev/zh/tutorials/35-user-ringbuf/> Please indicate the source when reprinting.
