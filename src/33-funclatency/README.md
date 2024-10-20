# Measuring Function Latency with eBPF

In modern software systems, understanding the performance characteristics of functions—especially those critical to the operation of your application—is paramount. One key metric in performance analysis is **function latency**, which is the time taken by a function to execute from start to finish. By analyzing function latency, developers can identify bottlenecks, optimize performance, and ensure that their systems operate efficiently under various conditions.

This blog post will dive into how to measure function latency using eBPF, an incredibly powerful tool for tracing and monitoring both kernel and user-space programs.

## What is eBPF?

eBPF (Extended Berkeley Packet Filter) is a revolutionary technology that allows developers to write small programs that run in the Linux kernel. Originally designed for packet filtering, eBPF has evolved into a versatile tool for tracing, monitoring, and profiling system behavior. With eBPF, you can instrument almost any part of the Linux kernel or user-space programs to collect performance data, enforce security policies, or even debug systems in real time—all without the need to modify the kernel source code or restart the system.

eBPF programs are executed in a sandboxed environment within the kernel, ensuring safety and stability. These programs can attach to various hooks within the kernel, such as system calls, network events, and tracepoints, or even user-space functions using uprobes (user-level probes). The data collected by eBPF programs can then be exported to user space for analysis, making it an invaluable tool for system observability. `Uprobe` in kernel mode eBPF runtime may also cause relatively large performance overhead. In this case, you can also consider using user mode eBPF runtime, such as [bpftime](https://github.com/eunomia-bpf/bpftime).

## Why is Function Latency Important?

Function latency is a critical metric in performance analysis for both kernel and user-space applications. It provides insights into how long a particular function takes to execute, which is crucial for:

- **Identifying Performance Bottlenecks**: High function latency may indicate inefficiencies or issues within the code that need optimization.
- **Ensuring System Responsiveness**: In real-time systems or latency-sensitive applications, understanding and minimizing function latency is essential to maintain responsiveness.
- **Profiling and Benchmarking**: By measuring the latency of various functions, developers can benchmark their systems and compare the performance of different implementations or configurations.
- **Debugging and Diagnostics**: When a system exhibits unexpected behavior or performance degradation, measuring function latency can help pinpoint the source of the problem.

Both kernel-space (e.g., system calls, file operations) and user-space (e.g., library functions) functions can be profiled for latency, providing a comprehensive view of system performance.

## eBPF Kernel Code for Function Latency

Below is an eBPF program designed to measure the latency of a function by hooking into its entry and exit points. The program uses kprobes and kretprobes (for kernel functions) or uprobes and uretprobes (for user-space functions) to capture the start and end times of the function execution.

```c
// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "funclatency.h"
#include "bits.bpf.h"

const volatile pid_t targ_tgid = 0;
const volatile int units = 0;

/* key: pid.  value: start time */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, u32);
    __type(value, u64);
} starts SEC(".maps");

__u32 hist[MAX_SLOTS] = {};

static void entry(void)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;
    u64 nsec;

    if (targ_tgid && targ_tgid != tgid)
        return;
    nsec = bpf_ktime_get_ns();
    bpf_map_update_elem(&starts, &pid, &nsec, BPF_ANY);
}

SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe)
{
    entry();
    return 0;
}

static void exit(void)
{
    u64 *start;
    u64 nsec = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64 slot, delta;

    start = bpf_map_lookup_elem(&starts, &pid);
    if (!start)
        return;

    delta = nsec - *start;

    switch (units) {
    case USEC:
        delta /= 1000;
        break;
    case MSEC:
        delta /= 1000000;
        break;
    }

    slot = log2l(delta);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;
    __sync_fetch_and_add(&hist[slot], 1);
}

SEC("kretprobe/dummy_kretprobe")
int BPF_KRETPROBE(dummy_kretprobe)
{
    exit();
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### Explanation of the Code

1. **Header Files**: The code begins by including the necessary headers like `vmlinux.h` (which provides kernel definitions) and `bpf_helpers.h` (which offers helper functions for eBPF programs).

2. **Global Variables**: `targ_tgid` is a target process ID (or thread group ID), and `units` determines the time unit for latency measurement (e.g., microseconds or milliseconds).

3. **BPF Maps**: A hash map (`starts`) is defined to store the start time of function executions for each process ID. Another array (`hist`) is used to store the latency distribution.

4. **Entry Function**: The `entry()` function captures the current timestamp when the function is entered and stores it in the `starts` map keyed by the process ID.

5. **Exit Function**: The `exit()` function calculates the latency by subtracting the stored start time from the current time. The result is then categorized into a histogram slot, which is incremented to record the occurrence of that latency range.

6. **Probes**: The `kprobe` and `kretprobe` are used to attach to the entry and exit points of the function, respectively. These probes trigger the `entry()` and `exit()` functions to measure the latency.

7. **License**: The program is licensed under GPL to ensure compliance with kernel licensing requirements.

## Running the Function Latency Tool

### User-Space Function Latency

To trace the latency of a user-space function, such as the `read` function in the `libc` library, you can run the following command:

```console
# ./funclatency /usr/lib/x86_64-linux-gnu/libc.so.6:read    
tracing /usr/lib/x86_64-linux-gnu/libc.so.6:read...
tracing func read in /usr/lib/x86_64-linux-gnu/libc.so.6...
Tracing /usr/lib/x86_64-linux-gnu/libc.so.6:read.  Hit Ctrl-C to exit
^C
     nsec                : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
       128 -> 255        : 0        |                                        |
       512 -> 1023       : 0        |                                        |
      65536 -> 131071     : 651      |****************************************+|
    131072 -> 262143     : 107      |******                                  |
    262144 -> 524287     : 36       |**                                      |
    524288 -> 1048575    : 8        |                                        |
   8388608 -> 16777215   : 2        |                                        |
Exiting trace of /usr/lib/x86_64-linux-gnu/libc.so.6:read
```

### Kernel-Space Function Latency

To trace the latency of a kernel-space function, such as `vfs_read`, run the following command:

```console
# sudo ./funclatency -u vfs_read
Tracing vfs_read.  Hit Ctrl-C to exit
^C
     usec                : count    distribution
         0 -> 1          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 3397     |****************************************|
        32 -> 63         : 2175     |*************************               |
        64 -> 127        : 184      |**                                      |
       1024 -> 2047       : 0        |                                        |
       4096 -> 8191       : 5        |                                        |
   2097152 -> 4194303    : 2        |                                        |
Exiting trace of vfs_read
```

These commands trace the execution of the specified function, either in user-space or kernel-space, and print a histogram of the observed latencies, showing the distribution of function execution times.

You can find the source code in <https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/33-funclatency>

## Conclusion

Measuring function latency with eBPF offers deep insights into the performance of both user-space and kernel-space code. By understanding function latency, developers can identify performance bottlenecks, improve system responsiveness, and ensure the smooth operation of their applications.

This

 blog post covered the basics of using eBPF to trace function latency, including an overview of the eBPF kernel code used to perform the tracing. The examples provided demonstrated how to run the tool to trace both user-space and kernel-space functions.

For those interested in learning more about eBPF, including more advanced examples and tutorials, please visit our [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) or our website [https://eunomia.dev/tutorials/](https://eunomia.dev/tutorials/).

If you are looking for a production-ready tool for function latency measurement, you might want to check out the full implementation available in the [BCC repository](https://github.com/iovisor/bcc/blob/master/libbpf-tools/funclatency.c).
