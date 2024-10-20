# eBPF 入门开发实践教程九：捕获进程调度延迟，以直方图方式记录

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

runqlat 是一个 eBPF 工具，用于分析 Linux 系统的调度性能。具体来说，runqlat 用于测量一个任务在被调度到 CPU 上运行之前在运行队列中等待的时间。这些信息对于识别性能瓶颈和提高 Linux 内核调度算法的整体效率非常有用。

## runqlat 原理

本教程是 eBPF 入门开发实践系列的第九部分，主题是 "捕获进程调度延迟"。在此，我们将介绍一个名为 runqlat 的程序，其作用是以直方图的形式记录进程调度延迟。

Linux 操作系统使用进程来执行所有的系统和用户任务。这些进程可能被阻塞、杀死、运行，或者正在等待运行。处在后两种状态的进程数量决定了 CPU 运行队列的长度。

进程有几种可能的状态，如：

- 可运行或正在运行
- 可中断睡眠
- 不可中断睡眠
- 停止
- 僵尸进程

等待资源或其他函数信号的进程会处在可中断或不可中断的睡眠状态：进程被置入睡眠状态，直到它需要的资源变得可用。然后，根据睡眠的类型，进程可以转移到可运行状态，或者保持睡眠。

即使进程拥有它需要的所有资源，它也不会立即开始运行。它会转移到可运行状态，与其他处在相同状态的进程一起排队。CPU可以在接下来的几秒钟或毫秒内执行这些进程。调度器为 CPU 排列进程，并决定下一个要执行的进程。

根据系统的硬件配置，这个可运行队列（称为 CPU 运行队列）的长度可以短也可以长。短的运行队列长度表示 CPU 没有被充分利用。另一方面，如果运行队列长，那么可能意味着 CPU 不够强大，无法执行所有的进程，或者 CPU 的核心数量不足。在理想的 CPU 利用率下，运行队列的长度将等于系统中的核心数量。

进程调度延迟，也被称为 "run queue latency"，是衡量线程从变得可运行（例如，接收到中断，促使其处理更多工作）到实际在 CPU 上运行的时间。在 CPU 饱和的情况下，你可以想象线程必须等待其轮次。但在其他奇特的场景中，这也可能发生，而且在某些情况下，它可以通过调优减少，从而提高整个系统的性能。

我们将通过一个示例来阐述如何使用 runqlat 工具。这是一个负载非常重的系统：

```shell
# runqlat
Tracing run queue latency... Hit Ctrl-C to end.
^C
     usecs               : count     distribution
         0 -> 1          : 233      |***********                             |
         2 -> 3          : 742      |************************************    |
         4 -> 7          : 203      |**********                              |
         8 -> 15         : 173      |********                                |
        16 -> 31         : 24       |*                                       |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 30       |*                                       |
       128 -> 255        : 6        |                                        |
       256 -> 511        : 3        |                                        |
       512 -> 1023       : 5        |                                        |
      1024 -> 2047       : 27       |*                                       |
      2048 -> 4095       : 30       |*                                       |
      4096 -> 8191       : 20       |                                        |
      8192 -> 16383      : 29       |*                                       |
     16384 -> 32767      : 809      |****************************************|
     32768 -> 65535      : 64       |***                                     |
```

在这个输出中，我们看到了一个双模分布，一个模在0到15微秒之间，另一个模在16到65毫秒之间。这些模式在分布（它仅仅是 "count" 列的视觉表示）中显示为尖峰。例如，读取一行：在追踪过程中，809个事件落入了16384到32767微秒的范围（16到32毫秒）。

在后续的教程中，我们将深入探讨如何利用 eBPF 对此类指标进行深度跟踪和分析，以更好地理解和优化系统性能。同时，我们也将学习更多关于 Linux 内核调度器、中断处理和 CPU 饱

runqlat 的实现利用了 eBPF 程序，它通过内核跟踪点和函数探针来测量进程在运行队列中的时间。当进程被排队时，trace_enqueue 函数会在一个映射中记录时间戳。当进程被调度到 CPU 上运行时，handle_switch 函数会检索时间戳，并计算当前时间与排队时间之间的时间差。这个差值（或 delta）被用于更新进程的直方图，该直方图记录运行队列延迟的分布。该直方图可用于分析 Linux 内核的调度性能。

## runqlat 代码实现

### runqlat.bpf.c

首先我们需要编写一个源代码文件 runqlat.bpf.c:

```c
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "runqlat.h"
#include "bits.bpf.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

#define MAX_ENTRIES 10240
#define TASK_RUNNING  0

const volatile bool filter_cg = false;
const volatile bool targ_per_process = false;
const volatile bool targ_per_thread = false;
const volatile bool targ_per_pidns = false;
const volatile bool targ_ms = false;
const volatile pid_t targ_tgid = 0;

struct {
 __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
 __type(key, u32);
 __type(value, u32);
 __uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, u32);
 __type(value, u64);
} start SEC(".maps");

static struct hist zero;

/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, u32);
 __type(value, struct hist);
} hists SEC(".maps");

static int trace_enqueue(u32 tgid, u32 pid)
{
 u64 ts;

 if (!pid)
  return 0;
 if (targ_tgid && targ_tgid != tgid)
  return 0;

 ts = bpf_ktime_get_ns();
 bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
 return 0;
}

static unsigned int pid_namespace(struct task_struct *task)
{
 struct pid *pid;
 unsigned int level;
 struct upid upid;
 unsigned int inum;

 /*  get the pid namespace by following task_active_pid_ns(),
  *  pid->numbers[pid->level].ns
  */
 pid = BPF_CORE_READ(task, thread_pid);
 level = BPF_CORE_READ(pid, level);
 bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
 inum = BPF_CORE_READ(upid.ns, ns.inum);

 return inum;
}

static int handle_switch(bool preempt, struct task_struct *prev, struct task_struct *next)
{
 struct hist *histp;
 u64 *tsp, slot;
 u32 pid, hkey;
 s64 delta;

 if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
  return 0;

 if (get_task_state(prev) == TASK_RUNNING)
  trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));

 pid = BPF_CORE_READ(next, pid);

 tsp = bpf_map_lookup_elem(&start, &pid);
 if (!tsp)
  return 0;
 delta = bpf_ktime_get_ns() - *tsp;
 if (delta < 0)
  goto cleanup;

 if (targ_per_process)
  hkey = BPF_CORE_READ(next, tgid);
 else if (targ_per_thread)
  hkey = pid;
 else if (targ_per_pidns)
  hkey = pid_namespace(next);
 else
  hkey = -1;
 histp = bpf_map_lookup_or_try_init(&hists, &hkey, &zero);
 if (!histp)
  goto cleanup;
 if (!histp->comm[0])
  bpf_probe_read_kernel_str(&histp->comm, sizeof(histp->comm),
     next->comm);
 if (targ_ms)
  delta /= 1000000U;
 else
  delta /= 1000U;
 slot = log2l(delta);
 if (slot >= MAX_SLOTS)
  slot = MAX_SLOTS - 1;
 __sync_fetch_and_add(&histp->slots[slot], 1);

cleanup:
 bpf_map_delete_elem(&start, &pid);
 return 0;
}

SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
 if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
  return 0;

 return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p)
{
 if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
  return 0;

 return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
 return handle_switch(preempt, prev, next);
}

char LICENSE[] SEC("license") = "GPL";
```

这其中定义了一些常量和全局变量，用于过滤对应的追踪目标：

```c
#define MAX_ENTRIES 10240
#define TASK_RUNNING  0

const volatile bool filter_cg = false;
const volatile bool targ_per_process = false;
const volatile bool targ_per_thread = false;
const volatile bool targ_per_pidns = false;
const volatile bool targ_ms = false;
const volatile pid_t targ_tgid = 0;
```

这些变量包括最大映射项数量、任务状态、过滤选项和目标选项。这些选项可以通过用户空间程序设置，以定制 eBPF 程序的行为。

接下来，定义了一些 eBPF 映射：

```c
struct {
 __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
 __type(key, u32);
 __type(value, u32);
 __uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, u32);
 __type(value, u64);
} start SEC(".maps");

static struct hist zero;

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, u32);
 __type(value, struct hist);
} hists SEC(".maps");
```

这些映射包括：

- cgroup_map 用于过滤 cgroup；
- start 用于存储进程入队时的时间戳；
- hists 用于存储直方图数据，记录进程调度延迟。

接下来是一些辅助函数：

trace_enqueue 函数用于在进程入队时记录其时间戳：

```c
static int trace_enqueue(u32 tgid, u32 pid)
{
 u64 ts;

 if (!pid)
  return 0;
 if (targ_tgid && targ_tgid != tgid)
  return 0;

 ts = bpf_ktime_get_ns();
 bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
 return 0;
}
```

pid_namespace 函数用于获取进程所属的 PID namespace：

```c
static unsigned int pid_namespace(struct task_struct *task)
{
 struct pid *pid;
 unsigned int level;
 struct upid upid;
 unsigned int inum;

 /*  get the pid namespace by following task_active_pid_ns(),
  *  pid->numbers[pid->level].ns
  */
 pid = BPF_CORE_READ(task, thread_pid);
 level = BPF_CORE_READ(pid, level);
 bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
 inum = BPF_CORE_READ(upid.ns, ns.inum);

 return inum;
}
```

handle_switch 函数是核心部分，用于处理调度切换事件，计算进程调度延迟并更新直方图数据：

```c
static int handle_switch(bool preempt, struct task_struct *prev, struct task_struct *next)
{
 ...
}
```

首先，函数根据 filter_cg 的设置判断是否需要过滤 cgroup。然后，如果之前的进程状态为 TASK_RUNNING，则调用 trace_enqueue 函数记录进程的入队时间。接着，函数查找下一个进程的入队时间戳，如果找不到，直接返回。计算调度延迟（delta），并根据不同的选项设置（targ_per_process，targ_per_thread，targ_per_pidns），确定直方图映射的键（hkey）。然后查找或初始化直方图映射，更新直方图数据，最后删除进程的入队时间戳记录。

接下来是 eBPF 程序的入口点。程序使用三个入口点来捕获不同的调度事件：

- handle_sched_wakeup：用于处理 sched_wakeup 事件，当一个进程从睡眠状态被唤醒时触发。
- handle_sched_wakeup_new：用于处理 sched_wakeup_new 事件，当一个新创建的进程被唤醒时触发。
- handle_sched_switch：用于处理 sched_switch 事件，当调度器选择一个新的进程运行时触发。

这些入口点分别处理不同的调度事件，但都会调用 handle_switch 函数来计算进程的调度延迟并更新直方图数据。

最后，程序包含一个许可证声明：

```c
char LICENSE[] SEC("license") = "GPL";
```

这一声明指定了 eBPF 程序的许可证类型，这里使用的是 "GPL"。这对于许多内核功能是必需的，因为它们要求 eBPF 程序遵循 GPL 许可证。

### runqlat.h

然后我们需要定义一个头文件`runqlat.h`，用来给用户态处理从内核态上报的事件：

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __RUNQLAT_H
#define __RUNQLAT_H

#define TASK_COMM_LEN 16
#define MAX_SLOTS 26

struct hist {
 __u32 slots[MAX_SLOTS];
 char comm[TASK_COMM_LEN];
};

#endif /* __RUNQLAT_H */
```

## 编译运行

eunomia-bpf 是一个结合 Wasm 的开源 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。可以参考 <https://github.com/eunomia-bpf/eunomia-bpf> 下载和安装 ecc 编译工具链和 ecli 运行时。我们使用 eunomia-bpf 编译运行这个例子。

Compile:

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

或者

```console
$ ecc runqlat.bpf.c runqlat.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```

Run:

```console
$ sudo ecli run examples/bpftools/runqlat/package.json -h
Usage: runqlat_bpf [--help] [--version] [--verbose] [--filter_cg] [--targ_per_process] [--targ_per_thread] [--targ_per_pidns] [--targ_ms] [--targ_tgid VAR]

A simple eBPF program

Optional arguments:
  -h, --help            shows help message and exits 
  -v, --version         prints version information and exits 
  --verbose             prints libbpf debug information 
  --filter_cg           set value of bool variable filter_cg 
  --targ_per_process    set value of bool variable targ_per_process 
  --targ_per_thread     set value of bool variable targ_per_thread 
  --targ_per_pidns      set value of bool variable targ_per_pidns 
  --targ_ms             set value of bool variable targ_ms 
  --targ_tgid           set value of pid_t variable targ_tgid 

Built with eunomia-bpf framework.
See https://github.com/eunomia-bpf/eunomia-bpf for more information.

$ sudo ecli run examples/bpftools/runqlat/package.json
key =  4294967295
comm = rcu_preempt

     (unit)              : count    distribution
         0 -> 1          : 9        |****                                    |
         2 -> 3          : 6        |**                                      |
         4 -> 7          : 12       |*****                                   |
         8 -> 15         : 28       |*************                           |
        16 -> 31         : 40       |*******************                     |
        32 -> 63         : 83       |****************************************|
        64 -> 127        : 57       |***************************             |
       128 -> 255        : 19       |*********                               |
       256 -> 511        : 11       |*****                                   |
       512 -> 1023       : 2        |                                        |
      1024 -> 2047       : 2        |                                        |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 0        |                                        |
      8192 -> 16383      : 0        |                                        |
     16384 -> 32767      : 1        |                                        |

$ sudo ecli run examples/bpftools/runqlat/package.json --targ_per_process
key =  3189
comm = cpptools

     (unit)              : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 1        |***                                     |
        16 -> 31         : 2        |*******                                 |
        32 -> 63         : 11       |****************************************|
        64 -> 127        : 8        |*****************************           |
       128 -> 255        : 3        |**********                              |
```

完整源代码请见：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/9-runqlat>

参考资料：

- <https://www.brendangregg.com/blog/2016-10-08/linux-bcc-runqlat.html>
- <https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqlat.c>

## 总结

runqlat 是一个 Linux 内核 BPF 程序，通过柱状图来总结调度程序运行队列延迟，显示任务等待运行在 CPU 上的时间长度。编译这个程序可以使用 ecc 工具，运行时可以使用 ecli 命令。

runqlat 是一种用于监控Linux内核中进程调度延迟的工具。它可以帮助您了解进程在内核中等待执行的时间，并根据这些信息优化进程调度，提高系统的性能。可以在 libbpf-tools 中找到最初的源代码：<https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqlat.bpf.c>

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。
