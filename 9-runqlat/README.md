## eBPF 入门开发实践指南九：一个 Linux 内核 BPF 程序，通过柱状图来总结调度程序运行队列延迟，显示任务等待运行在 CPU 上的时间长度
eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

## runqlat是什么？
	bcc-tools 是一组用于在 Linux 系统上使用 BPF 程序的工具。runqlat 是 bcc-tools 中的一个工具，用于分析 Linux 系统的调度性能。
	具体来说，runqlat 用于测量一个任务在被调度到 CPU 上运行之前在运行队列中等待的时间。这些信息对于识别性能瓶颈和提高 Linux 内核
	调度算法的整体效率非常有用

## runqlat原理：
	使用内核跟踪点和函数探针的结合来测量任务在运行队列中的时间。当任务被排队时，trace_enqueue 函数会在一个映射中记录时间戳。
	当任务被调度到 CPU 上运行时，handle_switch 函数会检索时间戳，并计算当前时间与排队时间之间的时间差。这个差值（或 delta）
	然后用于更新任务的直方图，该直方图记录运行队列延迟的分布。该直方图可用于分析 Linux 内核的调度性能。
## runqlat
```
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

#define MAX_ENTRIES	10240
#define TASK_RUNNING 	0

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
这是一个 Linux 内核 BPF 程序，旨在收集和报告运行队列的延迟。BPF 是 Linux 内核中一项技术，它允许将程序附加到内核中的特定点并进行安全高效的执行。这些程序可用于收集有关内核行为的信息，并实现自定义行为。这个 BPF 程序使用 BPF maps和来自 bpf_helpers.h 和 bpf_tracing.h 头文件的帮助程序的组合来收集有关任务何时从内核的运行队列中排队和取消排队的信息，并记录任务在被安排执行之前在运行队列上等待的时间。然后，它使用这些信息生成直方图，显示不同组任务的运行队列延迟分布。这些直方图可用于识别和诊断内核调度行为中的性能问题。



## Compile and Run

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
$ sudo ecli examples/bpftools/runqlat/package.json -h
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

$ sudo ecli examples/bpftools/runqlat/package.json
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

$ sudo ecli examples/bpftools/runqlat/package.json --targ_per_process
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

## details in bcc

```text
Demonstrations of runqlat, the Linux eBPF/bcc version.


This program summarizes scheduler run queue latency as a histogram, showing
how long tasks spent waiting their turn to run on-CPU.

Here is a heavily loaded system:

# ./runqlat 
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

The distribution is bimodal, with one mode between 0 and 15 microseconds,
and another between 16 and 65 milliseconds. These modes are visible as the
spikes in the ASCII distribution (which is merely a visual representation
of the "count" column). As an example of reading one line: 809 events fell
into the 16384 to 32767 microsecond range (16 to 32 ms) while tracing.

I would expect the two modes to be due the workload: 16 hot CPU-bound threads,
and many other mostly idle threads doing occasional work. I suspect the mostly
idle threads will run with a higher priority when they wake up, and are
the reason for the low latency mode. The high latency mode will be the
CPU-bound threads. More analysis with this and other tools can confirm.


A -m option can be used to show milliseconds instead, as well as an interval
and a count. For example, showing three x five second summary in milliseconds:

# ./runqlat -m 5 3
Tracing run queue latency... Hit Ctrl-C to end.

     msecs               : count     distribution
         0 -> 1          : 3818     |****************************************|
         2 -> 3          : 39       |                                        |
         4 -> 7          : 39       |                                        |
         8 -> 15         : 62       |                                        |
        16 -> 31         : 2214     |***********************                 |
        32 -> 63         : 226      |**                                      |

     msecs               : count     distribution
         0 -> 1          : 3775     |****************************************|
         2 -> 3          : 52       |                                        |
         4 -> 7          : 37       |                                        |
         8 -> 15         : 65       |                                        |
        16 -> 31         : 2230     |***********************                 |
        32 -> 63         : 212      |**                                      |

     msecs               : count     distribution
         0 -> 1          : 3816     |****************************************|
         2 -> 3          : 49       |                                        |
         4 -> 7          : 40       |                                        |
         8 -> 15         : 53       |                                        |
        16 -> 31         : 2228     |***********************                 |
        32 -> 63         : 221      |**                                      |

This shows a similar distribution across the three summaries.


A -p option can be used to show one PID only, which is filtered in kernel for
efficiency. For example, PID 4505, and one second summaries:

# ./runqlat -mp 4505 1
Tracing run queue latency... Hit Ctrl-C to end.

     msecs               : count     distribution
         0 -> 1          : 1        |*                                       |
         2 -> 3          : 2        |***                                     |
         4 -> 7          : 1        |*                                       |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 25       |****************************************|
        32 -> 63         : 3        |****                                    |

     msecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 2        |**                                      |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 1        |*                                       |
        16 -> 31         : 30       |****************************************|
        32 -> 63         : 1        |*                                       |

     msecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 28       |****************************************|
        32 -> 63         : 2        |**                                      |

     msecs               : count     distribution
         0 -> 1          : 1        |*                                       |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 27       |****************************************|
        32 -> 63         : 4        |*****                                   |
[...]

For comparison, here is pidstat(1) for that process:

# pidstat -p 4505 1
Linux 4.4.0-virtual (bgregg-xxxxxxxx)  02/08/2016  _x86_64_ (8 CPU)

08:56:11 AM   UID       PID    %usr %system  %guest    %CPU   CPU  Command
08:56:12 AM     0      4505    9.00    3.00    0.00   12.00     0  bash
08:56:13 AM     0      4505    7.00    5.00    0.00   12.00     0  bash
08:56:14 AM     0      4505   10.00    2.00    0.00   12.00     0  bash
08:56:15 AM     0      4505   11.00    2.00    0.00   13.00     0  bash
08:56:16 AM     0      4505    9.00    3.00    0.00   12.00     0  bash
[...]

This is a synthetic workload that is CPU bound. It's only spending 12% on-CPU
each second because of high CPU demand on this server: the remaining time
is spent waiting on a run queue, as visualized by runqlat.


Here is the same system, but when it is CPU idle:

# ./runqlat 5 1
Tracing run queue latency... Hit Ctrl-C to end.

     usecs               : count     distribution
         0 -> 1          : 2250     |********************************        |
         2 -> 3          : 2340     |**********************************      |
         4 -> 7          : 2746     |****************************************|
         8 -> 15         : 418      |******                                  |
        16 -> 31         : 93       |*                                       |
        32 -> 63         : 28       |                                        |
        64 -> 127        : 119      |*                                       |
       128 -> 255        : 9        |                                        |
       256 -> 511        : 4        |                                        |
       512 -> 1023       : 20       |                                        |
      1024 -> 2047       : 22       |                                        |
      2048 -> 4095       : 5        |                                        |
      4096 -> 8191       : 2        |                                        |

Back to a microsecond scale, this time there is little run queue latency past 1
millisecond, as would be expected.


Now 16 threads are performing heavy disk I/O:

# ./runqlat 5 1
Tracing run queue latency... Hit Ctrl-C to end.

     usecs               : count     distribution
         0 -> 1          : 204      |                                        |
         2 -> 3          : 944      |*                                       |
         4 -> 7          : 16315    |*********************                   |
         8 -> 15         : 29897    |****************************************|
        16 -> 31         : 1044     |*                                       |
        32 -> 63         : 23       |                                        |
        64 -> 127        : 128      |                                        |
       128 -> 255        : 24       |                                        |
       256 -> 511        : 5        |                                        |
       512 -> 1023       : 13       |                                        |
      1024 -> 2047       : 15       |                                        |
      2048 -> 4095       : 13       |                                        |
      4096 -> 8191       : 10       |                                        |

The distribution hasn't changed too much. While the disks are 100% busy, there
is still plenty of CPU headroom, and threads still don't spend much time
waiting their turn.


A -P option will print a distribution for each PID:

# ./runqlat -P
Tracing run queue latency... Hit Ctrl-C to end.
^C

pid = 0
     usecs               : count     distribution
         0 -> 1          : 351      |********************************        |
         2 -> 3          : 96       |********                                |
         4 -> 7          : 437      |****************************************|
         8 -> 15         : 12       |*                                       |
        16 -> 31         : 10       |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 16       |*                                       |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 0        |                                        |
      1024 -> 2047       : 0        |                                        |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 0        |                                        |
      8192 -> 16383      : 1        |                                        |

pid = 12929
     usecs               : count     distribution
         0 -> 1          : 1        |****************************************|
         2 -> 3          : 0        |                                        |
         4 -> 7          : 1        |****************************************|

pid = 12930
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 1        |****************************************|
        32 -> 63         : 0        |                                        |
        64 -> 127        : 1        |****************************************|

pid = 12931
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 1        |********************                    |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 2        |****************************************|

pid = 12932
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 1        |****************************************|
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 1        |****************************************|

pid = 7
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 426      |*************************************   |
         4 -> 7          : 457      |****************************************|
         8 -> 15         : 16       |*                                       |

pid = 9
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 425      |****************************************|
         8 -> 15         : 16       |*                                       |

pid = 11
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 10       |****************************************|

pid = 14
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 8        |****************************************|
         4 -> 7          : 2        |**********                              |

pid = 18
     usecs               : count     distribution
         0 -> 1          : 414      |****************************************|
         2 -> 3          : 0        |                                        |
         4 -> 7          : 20       |*                                       |
         8 -> 15         : 8        |                                        |

pid = 12928
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 1        |****************************************|
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 1        |****************************************|

pid = 1867
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 15       |****************************************|
        16 -> 31         : 1        |**                                      |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 4        |**********                              |

pid = 1871
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 2        |****************************************|
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 1        |********************                    |

pid = 1876
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 1        |****************************************|
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 1        |****************************************|

pid = 1878
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 3        |****************************************|

pid = 1880
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 3        |****************************************|

pid = 9307
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 1        |****************************************|

pid = 1886
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 1        |********************                    |
         8 -> 15         : 2        |****************************************|

pid = 1888
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 3        |****************************************|

pid = 3297
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 1        |****************************************|

pid = 1892
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 1        |********************                    |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 2        |****************************************|

pid = 7024
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 4        |****************************************|

pid = 16468
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 3        |****************************************|

pid = 12922
     usecs               : count     distribution
         0 -> 1          : 1        |****************************************|
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 1        |****************************************|
        16 -> 31         : 1        |****************************************|
        32 -> 63         : 0        |                                        |
        64 -> 127        : 1        |****************************************|

pid = 12923
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 1        |********************                    |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 2        |****************************************|
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 1        |********************                    |
      1024 -> 2047       : 1        |********************                    |

pid = 12924
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 2        |********************                    |
         8 -> 15         : 4        |****************************************|
        16 -> 31         : 1        |**********                              |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 0        |                                        |
      1024 -> 2047       : 1        |**********                              |

pid = 12925
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 1        |****************************************|

pid = 12926
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 1        |****************************************|
         4 -> 7          : 0        |                                        |
         8 -> 15         : 1        |****************************************|
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 1        |****************************************|

pid = 12927
     usecs               : count     distribution
         0 -> 1          : 1        |****************************************|
         2 -> 3          : 0        |                                        |
         4 -> 7          : 1        |****************************************|


A -L option will print a distribution for each TID:

# ./runqlat -L
Tracing run queue latency... Hit Ctrl-C to end.
^C

tid = 0
     usecs               : count     distribution
         0 -> 1          : 593      |****************************            |
         2 -> 3          : 829      |****************************************|
         4 -> 7          : 300      |**************                          |
         8 -> 15         : 321      |***************                         |
        16 -> 31         : 132      |******                                  |
        32 -> 63         : 58       |**                                      |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 13       |                                        |

tid = 7
     usecs               : count     distribution
         0 -> 1          : 8        |********                                |
         2 -> 3          : 19       |********************                    |
         4 -> 7          : 37       |****************************************|
[...]


And a --pidnss option (short for PID namespaces)  will print for each PID
namespace, for analyzing container performance:

# ./runqlat --pidnss -m
Tracing run queue latency... Hit Ctrl-C to end.
^C

pidns = 4026532870
     msecs               : count     distribution
         0 -> 1          : 40       |****************************************|
         2 -> 3          : 1        |*                                       |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 2        |**                                      |
        64 -> 127        : 5        |*****                                   |

pidns = 4026532809
     msecs               : count     distribution
         0 -> 1          : 67       |****************************************|

pidns = 4026532748
     msecs               : count     distribution
         0 -> 1          : 63       |****************************************|

pidns = 4026532687
     msecs               : count     distribution
         0 -> 1          : 7        |****************************************|

pidns = 4026532626
     msecs               : count     distribution
         0 -> 1          : 45       |****************************************|
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 3        |**                                      |

pidns = 4026531836
     msecs               : count     distribution
         0 -> 1          : 314      |****************************************|
         2 -> 3          : 1        |                                        |
         4 -> 7          : 11       |*                                       |
         8 -> 15         : 28       |***                                     |
        16 -> 31         : 137      |*****************                       |
        32 -> 63         : 86       |**********                              |
        64 -> 127        : 1        |                                        |

pidns = 4026532382
     msecs               : count     distribution
         0 -> 1          : 285      |****************************************|
         2 -> 3          : 5        |                                        |
         4 -> 7          : 16       |**                                      |
         8 -> 15         : 9        |*                                       |
        16 -> 31         : 69       |*********                               |
        32 -> 63         : 25       |***                                     |

Many of these distributions have two modes: the second, in this case, is
caused by capping CPU usage via CPU shares.


USAGE message:

# ./runqlat -h
usage: runqlat.py [-h] [-T] [-m] [-P] [--pidnss] [-L] [-p PID]
                  [interval] [count]

Summarize run queue (scheduler) latency as a histogram

positional arguments:
  interval            output interval, in seconds
  count               number of outputs

optional arguments:
  -h, --help          show this help message and exit
  -T, --timestamp     include timestamp on output
  -m, --milliseconds  millisecond histogram
  -P, --pids          print a histogram per process ID
  --pidnss            print a histogram per PID namespace
  -L, --tids          print a histogram per thread ID
  -p PID, --pid PID   trace this PID only

examples:
    ./runqlat            # summarize run queue latency as a histogram
    ./runqlat 1 10       # print 1 second summaries, 10 times
    ./runqlat -mT 1      # 1s summaries, milliseconds, and timestamps
    ./runqlat -P         # show each PID separately
    ./runqlat -p 185     # trace PID 185 only

```

## 总结
一个 Linux 内核 BPF 程序，通过柱状图来总结调度程序运行队列延迟，显示任务等待运行在 CPU 上的时间长度
编译这个程序可以使用 ecc 工具，运行时可以使用 ecli 命令，runqlat是一种用于监控Linux内核中进程调度延迟的工具。它可以帮助您了解进程在内核中等待执行的时间，并根据这些信息优化进程调度，提高系统的性能。要使用runq-lat，需要在终端中输入runq-lat命令，然后按照提示操作即可。更多的例子和详细的开发指南，请参考 eunomia-bpf 的官方文档：https://github.com/eunomia-bpf/eunomia-bpf
## origin

origin from:

<https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqlat.bpf.c>

This program summarizes scheduler run queue latency as a histogram, showing
how long tasks spent waiting their turn to run on-CPU.
