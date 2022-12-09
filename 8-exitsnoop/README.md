## eBPF 入门开发实践指南八：在 eBPF 中使用 exitsnoop 监控 进程退出事件：
##exitsnoop
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

=======
这段代码是一个 BPF 程序，用于监控 Linux 系统中的进程退出事件。BPF（Berkeley Packet Filter）是一种内核态程序设计语言，允许开发人员编写内核模块以捕获和处理内核事件。
该程序通过注册一个 tracepoint，来监控进程退出事件。Tracepoint 是一种内核特性，允许内核模块获取特定事件的通知。在本程序中，注册的 tracepoint 是“tp/sched/sched_process_exit”，表示该程序监控的是进程退出事件。
当系统中发生进程退出事件时，BPF 程序会捕获该事件，并调用“handle_exit”函数来处理它。该函数首先检查当前退出事件是否是进程退出事件（而不是线程退出事件），然后在 BPF 环形缓冲区（“rb”）中保留一个事件结构体，并填充该结构体中的其他信息，例如进程 ID、进程名称、退出代码和退出信号等信息。最后，该函数还会调用 BPF 的“perf_event_output”函数，将捕获的事件发送给用户空间程序。
总而言之，这段代码是一个 BPF 程序，用于监控 Linux 系统中的进程退出事件
>>>>>>> Stashed changes


## origin

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqslower.bpf.c

result:

```
$ sudo ecli/build/bin/Release/ecli run examples/bpftools/runqslower/package.json

running and waiting for the ebpf events from perf event...
time task prev_task delta_us pid prev_pid 
20:11:59 gnome-shell swapper/0 32 2202 0 
20:11:59 ecli swapper/3 23 3437 0 
20:11:59 rcu_sched swapper/1 1 14 0 
20:11:59 gnome-terminal- swapper/1 13 2714 0 
20:11:59 ecli swapper/3 2 3437 0 
20:11:59 kworker/3:3 swapper/3 3 215 0 
20:11:59 containerd swapper/1 8 1088 0 
20:11:59 ecli swapper/2 5 3437 0 
20:11:59 HangDetector swapper/3 6 854 0 
20:11:59 ecli swapper/2 60 3437 0 
20:11:59 rcu_sched swapper/1 26 14 0 
20:11:59 kworker/0:1 swapper/0 26 3414 0 
20:11:59 ecli swapper/2 6 3437 0 
```

这段代码定义了一个 eBPF 程序，该程序用于跟踪进程在运行队列中的等待时间。它通过使用 tracepoint 和 perf event 输出来实现。

程序首先定义了两个 BPF 内核映射：start 映射用于存储每个进程在被调度运行之前的时间戳，events 映射用于存储 perf 事件。

然后，程序定义了一些帮助函数，用于跟踪每个进程的调度状态。 trace_enqueue 函数用于在进程被调度运行之前记录时间戳， handle_switch 函数用于处理进程切换，并计算进程在队列中等待的时间。

接下来，程序定义了五个 tracepoint 程序，用于捕获不同的调度器事件。 sched_wakeup 和 sched_wakeup_new 程序用于捕获新进程被唤醒的事件， sched_switch 程序用于捕获进程切换事件， handle_sched_wakeup 和 handle_sched_wakeup_new 程序用于捕获 raw tracepoint 事件。这些 tracepoint 程序调用了前面定义的帮助函数来跟踪进程的调度状态。

最后，程序将计算得到的等待时间输出到 perf 事件中，供用户空间工具进行捕获和分析。

## Compile and Run

Compile:

```
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
