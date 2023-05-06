# eBPF 入门开发实践教程九：捕获进程调度延迟，以直方图方式记录

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

runqlat 是一个 eBPF 工具，用于分析 Linux 系统的调度性能。具体来说，runqlat 用于测量一个任务在被调度到 CPU 上运行之前在运行队列中等待的时间。这些信息对于识别性能瓶颈和提高 Linux 内核调度算法的整体效率非常有用。

## runqlat 原理

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

首先，定义了一些常量和全局变量：

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
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
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

## 总结

runqlat 是一个 Linux 内核 BPF 程序，通过柱状图来总结调度程序运行队列延迟，显示任务等待运行在 CPU 上的时间长度。编译这个程序可以使用 ecc 工具，运行时可以使用 ecli 命令。

runqlat 是一种用于监控Linux内核中进程调度延迟的工具。它可以帮助您了解进程在内核中等待执行的时间，并根据这些信息优化进程调度，提高系统的性能。可以在 libbpf-tools 中找到最初的源代码：<https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqlat.bpf.c>

更多的例子和详细的开发指南，请参考 eunomia-bpf 的官方文档：<https://github.com/eunomia-bpf/eunomia-bpf>

完整的教程和源代码已经全部开源，可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 中查看。
