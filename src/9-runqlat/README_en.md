# eBPF Tutorial by Example 9: Capturing Scheduling Latency and Recording as Histogram

eBPF (Extended Berkeley Packet Filter) is a powerful network and performance analysis tool on the Linux kernel. It allows developers to dynamically load, update, and run user-defined code at runtime.

runqlat is an eBPF tool used for analyzing the scheduling performance of the Linux system. Specifically, runqlat is used to measure the time a task waits in the run queue before being scheduled to run on a CPU. This information is very useful for identifying performance bottlenecks and improving the overall efficiency of the Linux kernel scheduling algorithm.

## runqlat Principle

This tutorial is the ninth part of the eBPF beginner's development series, with the topic "Capturing Process Scheduling Latency". Here, we will introduce a program called runqlat, which records process scheduling latency as a histogram.

The Linux operating system uses processes to execute all system and user tasks. These processes can be blocked, killed, running, or waiting to run. The number of processes in the latter two states determines the length of the CPU run queue.

Processes can have several possible states, such as:

- Runnable or running
- Interruptible sleep
- Uninterruptible sleep
- Stopped
- Zombie process

Processes waiting for resources or other function signals are in the interruptible or uninterruptible sleep state: the process is put to sleep until the resource it needs becomes available. Then, depending on the type of sleep, the process can transition to the runnable state or remain asleep.

Even when a process has all the resources it needs, it does not start running immediately. It transitions to the runnable state and is queued together with other processes in the same state. The CPU can execute these processes in the next few seconds or milliseconds. The scheduler arranges the processes for the CPU and determines the next process to run.

Depending on the hardware configuration of the system, the length of this runnable queue (known as the CPU run queue) can be short or long. A short run queue length indicates that the CPU is not being fully utilized. On the other hand, if the run queue is long, it may mean that the CPU is not powerful enough to handle all the processes or that the number of CPU cores is insufficient. In an ideal CPU utilization, the length of the run queue will be equal to the number of cores in the system.

Process scheduling latency, also known as "run queue latency," is the time it takes for a thread to go from becoming runnable (e.g., receiving an interrupt that prompts it to do more work) to actually running on the CPU. In the case of CPU saturation, you can imagine that the thread has to wait for its turn. But in other peculiar scenarios, this can also happen, and in some cases, it can be reduced by tuning to improve the overall system performance.

We will illustrate how to use the runqlat tool through an example. This is a heavily loaded system:

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
```

## runqlat Code Implementation

### runqlat.bpf.c

First, we need to write a source code file `runqlat.bpf.c`:

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

#### Constants and Global Variables

The code defines several constants and volatile global variables used for filtering corresponding tracing targets. These variables include:

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

- `MAX_ENTRIES`: The maximum number of map entries.
- `TASK_RUNNING`: The task status value.
- `filter_cg`, `targ_per_process`, `targ_per_thread`, `targ_per_pidns`, `targ_ms`, `targ_tgid`: Boolean variables for filtering and target options. These options can be set by user-space programs to customize the behavior of the eBPF program.

#### eBPF Maps

The code defines several eBPF maps including:

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

- `cgroup_map`: A cgroup array map used for filtering cgroups.
- `start`: A hash map used to store timestamps when processes are enqueued.
- `hists`: A hash map used to store histogram data for recording process scheduling delays.

#### Helper Functions

The code includes two helper functions:

- `trace_enqueue`: This function is used to record the timestamp when a process is enqueued. It takes the `tgid` and `pid` values as parameters. If the `pid` value is 0 or the `targ_tgid` value is not 0 and not equal to `tgid`, the function returns 0. Otherwise, it retrieves the current timestamp using `bpf_ktime_get_ns` and updates the `start` map with the `pid` key and the timestamp value.

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

- `pid_namespace`: This function is used to get the PID namespace of a process. It takes a `task_struct` pointer as a parameter and returns the PID namespace of the process. The function retrieves the PID namespace by following `task_active_pid_ns()` and `pid->numbers[pid->level].ns`.

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

The `handle_switch` function is the core part, used to handle scheduling switch events, calculate process scheduling latency, and update histogram data:

```c
static int handle_switch(bool preempt, struct task_struct *prev, struct task_struct *next)
{
 ...
}
```

Firstly, the function determines whether to filter cgroup based on the setting of `filter_cg`. Then, if the previous process state is `TASK_RUNNING`, the `trace_enqueue` function is called to record the enqueue time of the process. Then, the function looks up the enqueue timestamp of the next process. If it is not found, it returns directly. The scheduling latency (delta) is calculated, and the key for the histogram map (hkey) is determined based on different options (targ_per_process, targ_per_thread, targ_per_pidns). Then, the histogram map is looked up or initialized, and the histogram data is updated. Finally, the enqueue timestamp record of the process is deleted.

Next is the entry point of the eBPF program. The program uses three entry points to capture different scheduling events:

- `handle_sched_wakeup`: Used to handle the `sched_wakeup` event triggered when a process is woken up from sleep state.
- `handle_sched_wakeup_new`: Used to handle the `sched_wakeup_new` event triggered when a newly created process is woken up.
- `handle_sched_switch`: Used to handle the `sched_switch` event triggered when the scheduler selects a new process to run.

These entry points handle different scheduling events, but all call the `handle_switch` function to calculate the scheduling latency of the process and update the histogram data.

Finally, the program includes a license declaration:

```c
char LICENSE[] SEC("license") = "GPL";
```

This declaration specifies the license type of the eBPF program, which is "GPL" in this case. This is required for many kernel features as they require eBPF programs to follow the GPL license.

### runqlat.h

Next, we need to define a header file `runqlat.h` for handling events reported from kernel mode to user mode:

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

## Compilation and Execution

We will use `eunomia-bpf` to compile and run this example. You can refer to <https://github.com/eunomia-bpf/eunomia-bpf> to download and install the `ecc` compilation toolkit and `ecli` runtime.

Compile:

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

or

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
key = 3189
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

Complete source code can be found at: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/9-runqlat>

References:

- <https://www.brendangregg.com/blog/2016-10-08/linux-bcc-runqlat.html>
- <https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqlat.c>

## Summary

runqlat is a Linux kernel BPF program that summarizes scheduler run queue latency using a bar chart to show the length of time tasks wait to run on a CPU. To compile this program, you can use the `ecc` tool and to run it, you can use the `ecli` command.

runqlat is a tool for monitoring process scheduling latency in the Linux kernel. It can help you understand the time processes spend waiting to run in the kernel and optimize process scheduling based on this information to improve system performance. The original source code can be found in libbpf-tools: <https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqlat.bpf.c>

If you want to learn more about eBPF knowledge and practices, you can visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials.
