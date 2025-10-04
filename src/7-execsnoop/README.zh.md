# eBPF 入门实践教程七：捕获进程执行事件，通过 perf event array 向用户态打印输出

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

这个程序展示了如何使用 perf event array 将数据从内核空间传输到用户空间。

为什么需要 perf buffer？之前的例子我们使用 `bpf_printk` 打印到 trace_pipe，这种方式调试很方便，但对生产环境不够灵活，perf buffer 让我们能够高效地将结构化数据从内核传输到用户空间程序，在那里可以进行复杂的处理、过滤和格式化输出。

看看代码如何工作：我们首先定义了一个 `BPF_MAP_TYPE_PERF_EVENT_ARRAY` 类型的 map。在 tracepoint 中，我们收集进程信息：PID、PPID、UID 和命令名。使用 `BPF_CORE_READ` 从内核结构体中安全地读取父进程 ID，使用 `bpf_probe_read_str` 读取命令行参数。最后，`bpf_perf_event_output` 将整个 event 结构体发送到用户空间。

用户空间程序（这里是 ecli）会接收这些事件并格式化输出。这种模式让我们可以在用户空间做更复杂的处理，比如过滤、聚合或者写入数据库。

我们使用 eunomia-bpf 来编译和运行这个示例。你可以从 <https://github.com/eunomia-bpf/eunomia-bpf> 安装它。

使用容器编译：

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
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

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。
