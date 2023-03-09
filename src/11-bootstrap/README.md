# eBPF 入门开发实践教程十一：在 eBPF 中使用 bootstrap 开发用户态程序并跟踪 exec() 和 exit() 系统调用

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

## 什么是bootstrap?


Bootstrap是一个工具，它使用BPF（Berkeley Packet Filter）程序跟踪执行exec()系统调用（使用SEC（“tp/sched/sched_process_exec”）handle_exit BPF程序），这大致对应于新进程的生成（忽略fork（）部分）。此外，它还跟踪exit（）（使用SEC（“tp/sched/sched_process_exit”）handle_exit BPF程序）以了解每个进程何时退出。这两个BPF程序共同工作，允许捕获有关任何新进程的有趣信息，例如二进制文件的文件名，以及测量进程的生命周期并在进程死亡时收集有趣的统计信息，例如退出代码或消耗的资源量等。我认为这是深入了解内核内部并观察事物如何真正运作的良好起点。

Bootstrap还使用argp API（libc的一部分）进行命令行参数解析。

## Bootstrap

TODO: 添加关于用户态的应用部分，以及关于 libbpf-boostrap 的完整介绍。也许可以参考类似：http://cn-sec.com/archives/1267522.html 的文档。

```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	u64 ts;

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = false;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

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

	/* if we recorded start of the process, calculate lifetime duration */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &pid);

	/* if process didn't live long enough, return early */
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = true;
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

这是一段使用BPF（Berkeley Packet Filter）的C程序，用于跟踪进程启动和退出事件，并显示有关它们的信息。BPF是一种强大的机制，允许您将称为BPF程序的小程序附加到Linux内核的各个部分。这些程序可用于过滤，监视或修改内核的行为。

程序首先定义一些常量，并包含一些头文件。然后定义了一个名为env的struct，用于存储一些程序选项，例如详细模式和进程报告的最小持续时间。

然后，程序定义了一个名为parse_arg的函数，用于解析传递给程序的命令行参数。它接受三个参数：一个表示正在解析的选项的整数key，一个表示选项参数的字符指针arg和一个表示当前解析状态的struct argp_state指针state。该函数处理选项并在env struct中设置相应的值。

然后，程序定义了一个名为sig_handler的函数，当被调用时会将全局标志exiting设置为true。这用于在接收到信号时允许程序干净地退出。

接下来，我们将继续描述这段代码中的其他部分。

程序定义了一个名为exec_start的BPF map，它的类型为BPF_MAP_TYPE_HASH，最大条目数为8192，键类型为pid_t，值类型为u64。

另外，程序还定义了一个名为rb的BPF map，它的类型为BPF_MAP_TYPE_RINGBUF，最大条目数为256 * 1024。

程序还定义了一个名为min_duration_ns的常量，其值为0。

程序定义了一个名为handle_exec的SEC（static evaluator of code）函数，它被附加到跟踪进程执行的BPF程序上。该函数记录为该PID执行exec（）的时间，并在指定了最小持续时间时不发出exec事件。如果未指定最小持续时间，则会从BPF ringbuf保留样本并使用数据填充样本，然后将其提交给用户空间进行后处理。

程序还定义了一个名为handle_exit的SEC函数，它被附加到跟踪进程退出的BPF程序上。该函数会在确定PID和TID后计算进程的生命周期，然后根据min_duration_ns的值决定是否发出退出事件。如果进程的生命周期足够长，则会从BPF ringbuf保留样本并使用数据填充样本，然后将其提交给用户空间进行后处理。

最后，主函数调用bpf_ringbuf_poll来轮询BPF ringbuf，并在接收到新的事件时处理该事件。这个函数会持续运行，直到全局标志exiting被设置为true，此时它会清理资源并退出。


编译运行上述代码：

```console
$ ecc bootstrap.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
$ sudo ecli package.json
Runing eBPF program...
```


## 总结

这是一个使用BPF的C程序，用于跟踪进程的启动和退出事件，并显示有关这些事件的信息。它通过使用argp API来解析命令行参数，并使用BPF地图存储进程的信息，包括进程的PID和执行文件的文件名。程序还使用了SEC函数来附加BPF程序，以监视进程的执行和退出事件。最后，程序在终端中打印出启动和退出的进程信息。

编译这个程序可以使用 ecc 工具，运行时可以使用 ecli 命令。更多的例子和详细的开发指南，请参考 eunomia-bpf 的官方文档：https://github.com/eunomia-bpf/eunomia-bpf
