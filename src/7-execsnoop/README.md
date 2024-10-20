# eBPF Tutorial by Example 7: Capturing Process Execution, Output with perf event array

eBPF (Extended Berkeley Packet Filter) is a powerful network and performance analysis tool on the Linux kernel that allows developers to dynamically load, update, and run user-defined code at runtime.

This article is the seventh part of the eBPF Tutorial by Example and mainly introduces how to capture process execution events in the Linux kernel and print output to the user command line via a perf event array. This eliminates the need to view the output of eBPF programs by checking the `/sys/kernel/debug/tracing/trace_pipe` file. After sending information to user space via the perf event array, complex data processing and analysis can be performed.

## perf buffer

eBPF provides two circular buffers for transferring information from eBPF programs to user space controllers. The first one is the perf circular buffer, which has existed since at least kernel v4.15. The second one is the BPF circular buffer introduced later. This article only considers the perf circular buffer.

## execsnoop

To print output to the user command line via the perf event array, a header file and a C source file need to be written. The example code is as follows:

Header file: execsnoop.h

```c
#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#define TASK_COMM_LEN 16

struct event {
    int pid;
    int ppid;
    int uid;
    int retval;
    bool is_exit;
    char comm[TASK_COMM_LEN];
};

#endif /* __EXECSNOOP_H */
```

Source file: execsnoop.bpf.c

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "execsnoop.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_syscalls_sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    u64 id;
    pid_t pid, tgid;
    struct event event={0};
    struct task_struct *task;

    uid_t uid = (u32)bpf_get_current_uid_gid();
    id = bpf_get_current_pid_tgid();
    tgid = id >> 32;

    event.pid = tgid;
    event.uid = uid;
    task = (struct task_struct*)bpf_get_current_task();
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    char *cmd_ptr = (char *) BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_str(&event.comm, sizeof(event.comm), cmd_ptr);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

This code defines an eBPF program for capturing the entry of the `execve` system call.

In the entry program, we first obtain the process ID and user ID of the current process, then use the `bpf_get_current_task` function to obtain the `task_struct` structure of the current process, and use the `bpf_probe_read_str` function to read the process name. Finally, we use the `bpf_perf_event_output` function to output the process execution event to the perf buffer.

With this code, we can capture process execution events in the Linux kernel and analyze the process execution conditions.Instructions: Translate the following Chinese text to English while maintaining the original formatting:

We use eunomia-bpf to compile and execute this example. You can refer to the following link to download and install the ecc compilation toolchain and ecli runtime: [https://github.com/eunomia-bpf/eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf).

Compile using a container:

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

Or compile using ecc:

```shell
ecc execsnoop.bpf.c execsnoop.h
```

Run:

```console
$ sudo ./ecli run package.json 
TIME     PID     PPID    UID     COMM    
21:28:30  40747  3517    1000    node
21:28:30  40748  40747   1000    sh
21:28:30  40749  3517    1000    node
21:28:30  40750  40749   1000    sh
21:28:30  40751  3517    1000    node
21:28:30  40752  40751   1000    sh
21:28:30  40753  40752   1000    cpuUsage.sh
```

## Summary

This article introduces how to capture events of processes running in the Linux kernel and print output to the user command-line using the perf event array. After sending information to the user space via the perf event array, complex data processing and analysis can be performed. In the corresponding kernel code of libbpf, a structure and corresponding header file can be defined as follows:

```c
struct {
 __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
 __uint(key_size, sizeof(u32));
 __uint(value_size, sizeof(u32));
} events SEC(".maps");
```

This allows sending information directly to the user space.

For more examples and detailed development guide, please refer to the official documentation of eunomia-bpf: [https://github.com/eunomia-bpf/eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf).

If you want to learn more about eBPF knowledge and practice, you can visit our tutorial code repository [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) to get more examples and complete tutorials."
