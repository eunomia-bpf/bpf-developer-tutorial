# eBPF Tutorial by Example 8: Monitoring Process Exit Events, Output with Ring Buffer

eBPF (Extended Berkeley Packet Filter) is a powerful network and performance analysis tool on the Linux kernel. It allows developers to dynamically load, update, and run user-defined code at runtime in the kernel.

This article is the eighth part of the eBPF Tutorial by Example, focusing on monitoring process exit events with eBPF.

## Ring Buffer

There is now a new BPF data structure available called the eBPF ring buffer. It solves the memory efficiency and event reordering issues of the BPF perf buffer, which is currently the de facto standard for sending data from the kernel to user space. It provides compatibility with perf buffer for easy migration while also introducing new reserved/commit APIs for improved usability. Additionally, synthetic and real-world benchmark tests have shown that in nearly all cases, the eBPF ring buffer should be the default choice for sending data from BPF programs to user space.

### eBPF Ring Buffer vs eBPF Perf Buffer

Whenever a BPF program needs to send collected data to user space for post-processing and logging, it typically uses the BPF perf buffer (perfbuf). Perfbuf is a collection of per-CPU circular buffers that allow efficient data exchange between the kernel and user space. It works well in practice, but it has two main drawbacks that have proven to be inconvenient: inefficient memory usage and event reordering.

To address these issues, starting from Linux 5.8, BPF introduces a new BPF data structure called BPF ring buffer. It is a multiple producer, single consumer (MPSC) queue that can be safely shared across multiple CPUs.

The BPF ring buffer supports familiar features from BPF perf buffer:

- Variable-length data records.
- Efficient reading of data from user space through memory-mapped regions without additional memory copies and/or entering kernel system calls.
- Support for epoll notifications and busy loop operations with absolute minimal latency.

At the same time, the BPF ring buffer solves the following problems of the BPF perf buffer:

- Memory overhead.
- Data ordering.
- Unnecessary work and additional data copying.

## exitsnoop

This article is the eighth part of the eBPF Tutorial by Example, focusing on monitoring process exit events with eBPF and using the ring buffer to print output to user space.

The steps for printing output to user space using the ring buffer are similar to perf buffer. First, a header file needs to be defined:

Header File: exitsnoop.h

```c
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
    int pid;
    int ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    char comm[TASK_COMM_LEN];
};

#endif /* __BOOTSTRAP_H */
```

Source File: exitsnoop.bpf.c

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "exitsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, tid;
    u64 id, ts, *start_ts, start_time = 0;
    
    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task();
    start_time = BPF_CORE_READ(task, start_time);

    e->duration_ns = bpf_ktime_get_ns() - start_time;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

The ring buffer uses a reserve/submit pattern. First, you call `bpf_ringbuf_reserve` to allocate space in the buffer. This gives you a pointer where you can write your data. Once you've filled in all the fields, you call `bpf_ringbuf_submit` to make it available to user-space. If anything goes wrong before submit, you can call `bpf_ringbuf_discard` instead.

This is different from perf buffers where you pass a complete struct to `bpf_perf_event_output`. The reserve/submit pattern is more flexible and can be more efficient since you're writing directly into the buffer without extra copies.

The program filters out thread exits by checking `if (pid != tid)`. When a thread exits, its TID differs from the main process PID. We only want to track full process exits, not individual thread exits, so we skip those events.

This example demonstrates how to capture process exit events using exitsnoop and a ring buffer in an eBPF program, and transfer relevant information to user space. This is useful for analyzing process exit reasons and monitoring system behavior.

## Compile and Run

We use eunomia-bpf to compile and run this example. You can install it from <https://github.com/eunomia-bpf/eunomia-bpf>.

Compile:

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

Or

```console
$ ecc exitsnoop.bpf.c exitsnoop.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```

Run:

```console
$ sudo ./ecli run package.json 
TIME     PID     PPID    EXIT_CODE  DURATION_NS  COMM".
21:40:09  42050  42049   0          0            which
21:40:09  42049  3517    0          0            sh
21:40:09  42052  42051   0          0            ps
21:40:09  42051  3517    0          0            sh
21:40:09  42055  42054   0          0            sed
21:40:09  42056  42054   0          0            cat
21:40:09  42057  42054   0          0            cat
21:40:09  42058  42054   0          0            cat
21:40:09  42059  42054   0          0            cat
```

## Summary

This article introduces how to develop a simple BPF program using eunomia-bpf that can monitor process exit events in a Linux system and send the captured events to user space programs via a ring buffer. In this article, we compiled and ran this example using eunomia-bpf.

To better understand and practice eBPF programming, we recommend reading the official documentation of eunomia-bpf at: <https://github.com/eunomia-bpf/eunomia-bpf>. Additionally, we provide a complete tutorial and source code for you to view and learn from at <https://github.com/eunomia-bpf/bpf-developer-tutorial>. We hope this tutorial helps you get started with eBPF development and provides useful references for your further learning and practice.
