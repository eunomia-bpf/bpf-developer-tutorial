# eBPF 入门实践教程七：捕获进程执行/退出时间，通过 perf event array 向用户态打印输出

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具，它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践教程的第七篇，主要介绍如何捕获 Linux 内核中进程执行的事件，并且通过 perf event array 向用户态命令行打印输出，不需要再通过查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看 eBPF 程序的输出。通过 perf event array 向用户态发送信息之后，可以进行复杂的数据处理和分析。

## perf buffer

eBPF 提供了两个环形缓冲区，可以用来将信息从 eBPF 程序传输到用户区控制器。第一个是perf环形缓冲区，，它至少从内核v4.15开始就存在了。第二个是后来引入的 BPF 环形缓冲区。本文只考虑perf环形缓冲区。

## execsnoop

通过 perf event array 向用户态命令行打印输出，需要编写一个头文件，一个 C 源文件。示例代码如下：

头文件：execsnoop.h

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

源文件：execsnoop.bpf.c

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
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
 u64 id;
 pid_t pid, tgid;
 struct event event;
 struct task_struct *task;

 uid_t uid = (u32)bpf_get_current_uid_gid();
 id = bpf_get_current_pid_tgid();
 pid = (pid_t)id;
 tgid = id >> 32;

 event.pid = tgid;
 event.uid = uid;
 task = (struct task_struct*)bpf_get_current_task();
 event.ppid = BPF_CORE_READ(task, real_parent, tgid);
 bpf_get_current_comm(&event.comm, sizeof(event.comm));
 bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
 return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

这段代码定义了个 eBPF 程序，用于捕获进程执行 execve 系统调用的入口。

在入口程序中，我们首先获取了当前进程的进程 ID 和用户 ID，然后通过 bpf_get_current_task 函数获取了当前进程的 task_struct 结构体，并通过 bpf_probe_read_str 函数读取了进程名称。最后，我们通过 bpf_perf_event_output 函数将进程执行事件输出到 perf buffer。

使用这段代码，我们就可以捕获 Linux 内核中进程执行的事件, 并分析进程的执行情况。

eunomia-bpf 是一个结合 Wasm 的开源 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。可以参考 <https://github.com/eunomia-bpf/eunomia-bpf> 下载和安装 ecc 编译工具链和 ecli 运行时。我们使用 eunomia-bpf 编译运行这个例子。

使用容器编译：

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

或者使用 ecc 编译：

```shell
ecc execsnoop.bpf.c execsnoop.h
```

运行

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

## 总结

本文介绍了如何捕获 Linux 内核中进程执行的事件，并且通过 perf event array 向用户态命令行打印输出，通过 perf event array 向用户态发送信息之后，可以进行复杂的数据处理和分析。在 libbpf 对应的内核态代码中，定义这样一个结构体和对应的头文件：

```c
struct {
 __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
 __uint(key_size, sizeof(u32));
 __uint(value_size, sizeof(u32));
} events SEC(".maps");
```

就可以往用户态直接发送信息。

更多的例子和详细的开发指南，请参考 eunomia-bpf 的官方文档：<https://github.com/eunomia-bpf/eunomia-bpf>

完整的教程和源代码已经全部开源，可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 中查看。
