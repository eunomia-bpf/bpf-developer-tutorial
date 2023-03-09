# eBPF 入门开发实践教程八：在 eBPF 中使用 exitsnoop 监控进程退出事件，使用 ring buffer 向用户态打印输出

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践教程的第八篇，在 eBPF 中使用 exitsnoop 监控进程退出事件。

## ring buffer

现在有一个新的 BPF 数据结构可用。BPF 环形缓冲区（ring buffer）。它解决了 BPF perf buffer（当今从内核向用户空间发送数据的事实上的标准）的内存效率和事件重排问题，同时达到或超过了它的性能。它既提供了与 perf buffer 兼容以方便迁移，又有新的保留/提交API，具有更好的可用性。另外，合成和真实世界的基准测试表明，在几乎所有的情况下，所以考虑将其作为从BPF程序向用户空间发送数据的默认选择。

### BPF ringbuf vs BPF perfbuf

今天，只要BPF程序需要将收集到的数据发送到用户空间进行后处理和记录，它通常会使用BPF perf buffer（perfbuf）来实现。Perfbuf 是每个CPU循环缓冲区的集合，它允许在内核和用户空间之间有效地交换数据。它在实践中效果很好，但由于其按CPU设计，它有两个主要的缺点，在实践中被证明是不方便的：内存的低效使用和事件的重新排序。

为了解决这些问题，从Linux 5.8开始，BPF提供了一个新的BPF数据结构（BPF map）。BPF环形缓冲区（ringbuf）。它是一个多生产者、单消费者（MPSC）队列，可以同时在多个CPU上安全共享。

BPF ringbuf 支持来自 BPF perfbuf 的熟悉的功能:

- 变长的数据记录。
- 能够通过内存映射区域有效地从用户空间读取数据，而不需要额外的内存拷贝和/或进入内核的系统调用。
- 既支持epoll通知，又能以绝对最小的延迟进行忙环操作。

同时，BPF ringbuf解决了BPF perfbuf的以下问题:

- 内存开销。
- 数据排序。
- 浪费的工作和额外的数据复制。

## exitsnoop

本文是 eBPF 入门开发实践教程的第八篇，在 eBPF 中使用 exitsnoop 监控进程退出事件，并使用 ring buffer 向用户态打印输出。

使用 ring buffer 向用户态打印输出的步骤和 perf buffer 类似，首先需要定义一个头文件：

头文件：exitsnoop.h

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

源文件：exitsnoop.bpf.c

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
 u64 id, ts, *start_ts, duration_ns = 0;
 
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

 e->duration_ns = duration_ns;
 e->pid = pid;
 e->ppid = BPF_CORE_READ(task, real_parent, tgid);
 e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
 bpf_get_current_comm(&e->comm, sizeof(e->comm));

 /* send data to user-space for post-processing */
 bpf_ringbuf_submit(e, 0);
 return 0;
}
```

这段代码是一个 BPF 程序，用于监控 Linux 系统中的进程退出事件。

该程序通过注册一个 tracepoint，来监控进程退出事件。Tracepoint 是一种内核特性，允许内核模块获取特定事件的通知。在本程序中，注册的 tracepoint 是“tp/sched/sched_process_exit”，表示该程序监控的是进程退出事件。

当系统中发生进程退出事件时，BPF 程序会捕获该事件，并调用“handle_exit”函数来处理它。该函数首先检查当前退出事件是否是进程退出事件（而不是线程退出事件），然后在 BPF 环形缓冲区（“rb”）中保留一个事件结构体，并填充该结构体中的其他信息，例如进程 ID、进程名称、退出代码和退出信号等信息。最后，该函数还会调用 BPF 的“perf_event_output”函数，将捕获的事件发送给用户空间程序。

总而言之，这段代码是一个 BPF 程序，用于监控 Linux 系统中的进程退出事件.

## Compile and Run

eunomia-bpf 是一个结合 Wasm 的开源 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。可以参考 <https://github.com/eunomia-bpf/eunomia-bpf> 下载和安装 ecc 编译工具链和 ecli 运行时。我们使用 eunomia-bpf 编译运行这个例子。

Compile:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
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
TIME     PID     PPID    EXIT_CODE  DURATION_NS  COMM    
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

## 总结

本文介绍了如何使用 eunomia-bpf 开发一个简单的 BPF 程序，该程序可以监控 Linux 系统中的进程退出事件, 并将捕获的事件通过 ring buffer 发送给用户空间程序。在本文中，我们使用 eunomia-bpf 编译运行了这个例子。如果你想了解更多的例子和详细的开发指南，请参考 eunomia-bpf 的官方文档：<https://github.com/eunomia-bpf/eunomia-bpf>

完整的教程和源代码已经全部开源，可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 中查看。
