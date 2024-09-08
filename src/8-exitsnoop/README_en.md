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

This code demonstrates how to monitor process exit events using exitsnoop and print output to user space using a ring buffer:

1. First, we include the required headers and exitsnoop.h.
2. We define a global variable named "LICENSE" with the content "Dual BSD/GPL", which is the license requirement for eBPF programs.
3. We define a mapping named rb of type BPF_MAP_TYPE_RINGBUF, which will be used to transfer data from kernel space to user space. We specify max_entries as 256 * 1024, representing the maximum capacity of the ring buffer.
4. We define an eBPF program named handle_exit, which will be executed when a process exit event is triggered. It takes a trace_event_raw_sched_process_template struct pointer named ctx as the parameter.
5. We use the bpf_get_current_pid_tgid() function to obtain the PID and TID of the current task. For the main thread, the PID and TID are the same; for child threads, they are different. Since we only care about the exit of the process (main thread), we return 0 if the PID and TID are different, ignoring the exit events of child threads.
6. We use the bpf_ringbuf_reserve function to reserve space for the event struct e in the ring buffer. If the reservation fails, we return 0.
7. We use the bpf_get_current_task() function to obtain a task_struct structure pointer for the current task.
8. We fill in the process-related information into the reserved event struct e, including the duration of the process, PID, PPID, exit code, and process name.
9. Finally, we use the bpf_ringbuf_submit function to submit the filled event struct e to the ring buffer, for further processing and output in user space.

This example demonstrates how to capture process exit events using exitsnoop and a ring buffer in an eBPF program, and transfer relevant information to user space. This is useful for analyzing process exit reasons and monitoring system behavior.

## Compile and Run

eunomia-bpf is an open-source eBPF dynamic loading runtime and development toolchain that combines with Wasm. Its purpose is to simplify the development, build, distribution, and execution of eBPF programs. You can refer to <https://github.com/eunomia-bpf/eunomia-bpf> to download and install the ecc compiler toolchain and ecli runtime. We will use eunomia-bpf to compile and run this example.

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
