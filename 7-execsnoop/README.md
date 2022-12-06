# eBPF 入门实践教程七：捕获进程执行/退出时间，通过 perf event array 向用户态打印输出

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具，它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践指南的第七篇，主要介绍如何捕获 Linux 内核中进程执行的事件，并且通过 perf event array 向用户态命令行打印输出，不需要再通过查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看 eBPF 程序的输出。

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
#include "execsnoop.bpf.h"

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
	unsigned int ret;
	struct event event;
	struct task_struct *task;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;

	uid_t uid = (u32)bpf_get_current_uid_gid();
	int i;
	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	tgid = id >> 32;

	event.pid = tgid;
	event.uid = uid;
	task = (struct task_struct*)bpf_get_current_task();
	bpf_probe_read_str(&event.comm, sizeof(event.comm), task->comm);
	event.is_exit = false;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
	u64 id;
	pid_t pid;
	int ret;
	struct event event;

	u32 uid = (u32)bpf_get_current_uid_gid();

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;

	ret = ctx->ret;
	event.retval = ret;
	event.pid = pid;
	event.uid = uid;
	event.is_exit = true;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

```

这段代码定义了两个 eBPF 程序，一个用于捕获进程执行 execve 系统调用的入口，另一个用于捕获进程执行 execve 系统调用的出口。

在入口程序中，我们首先获取了当前进程的进程 ID 和用户 ID，然后通过 bpf_get_current_task 函数获取了当前进程的 task_struct 结构体，并通过 bpf_probe_read_str 函数读取了进程名称。最后，我们通过 bpf_perf_event_output 函数将进程执行事件输出到 perf buffer。

在出口程序中，我们首先获取了进程的进程 ID 和用户 ID，然后通过 bpf_get_current_comm 函数获取了进程的名称，最后通过 bpf_perf_event_output 函数将进程执行事件输出到 perf buffer。

使用这段代码，我们就可以捕获 Linux 内核中进程执行的事件。我们可以通过工具（例如 eunomia-bpf）来查看这些事件，并分析进程的执行情况。

## Compile and Run

Compile:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Run:

```
$ sudo ./ecli run package.json

running and waiting for the ebpf events from perf event...
time pid ppid uid retval args_count args_size comm args 
23:07:35 32940 32783 1000 0 1 13 cat /usr/bin/cat 
23:07:43 32946 24577 1000 0 1 10 bash /bin/bash 
23:07:43 32948 32946 1000 0 1 18 lesspipe /usr/bin/lesspipe 
23:07:43 32949 32948 1000 0 2 36 basename /usr/bin/basename 
23:07:43 32951 32950 1000 0 2 35 dirname /usr/bin/dirname 
23:07:43 32952 32946 1000 0 2 22 dircolors /usr/bin/dircolors 
23:07:48 32953 32946 1000 0 2 25 ls /usr/bin/ls 
23:07:53 32957 32946 1000 0 2 17 sleep /usr/bin/sleep 
23:07:57 32959 32946 1000 0 1 17 oneko /usr/games/oneko 

```
