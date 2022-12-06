# eBPF 入门开发实践指南六：捕获进程发送信号的系统调用集合，使用 hash map 保存状态

## sigsnoop

示例代码如下：

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "sigsnoop.h"

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct event);
} values SEC(".maps");


static int probe_entry(pid_t tpid, int sig)
{
	struct event event = {};
	__u64 pid_tgid;
	__u32 pid, tid;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	event.pid = pid;
	event.tpid = tpid;
	event.sig = sig;
	bpf_get_current_comm(event.comm, sizeof(event.comm));
	bpf_map_update_elem(&values, &tid, &event, BPF_ANY);
	return 0;
}

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;
	struct event *eventp;

	eventp = bpf_map_lookup_elem(&values, &tid);
	if (!eventp)
		return 0;

	eventp->ret = ret;
	bpf_printk("PID %d (%s) sent signal %d to PID %d, ret = %d",
		   eventp->pid, eventp->comm, eventp->sig, eventp->tpid, eventp->ret);

cleanup:
	bpf_map_delete_elem(&values, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int tkill_entry(struct trace_event_raw_sys_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_tkill")
int tkill_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

上面的代码定义了一个 eBPF 程序，用于捕获进程发送信号的系统调用，包括 kill、tkill 和 tgkill。它通过使用 tracepoint 来捕获系统调用的进入和退出事件，并在这些事件发生时执行指定的探针函数，例如 probe_entry 和 probe_exit。

在探针函数中，我们使用 bpf_map 存储捕获的事件信息，包括发送信号的进程 ID、接收信号的进程 ID、信号值和系统调用的返回值。在系统调用退出时，我们将获取存储在 bpf_map 中的事件信息，并使用 bpf_printk 打印进程 ID、进程名称、发送的信号和系统调用的返回值。

最后，我们还需要使用 SEC 宏来定义探针，并指定要捕获的系统调用的名称，以及要执行的探针函数。

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/sigsnoop.bpf.c

## Compile and Run

Compile:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Or compile with `ecc`:

```console
$ ecc sigsnoop.bpf.c sigsnoop.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```

Run:

```console
$ sudo ./ecli examples/bpftools/sigsnoop/package.json
TIME     PID     TPID    SIG     RET     COMM    
20:43:44  21276  3054    0       0       cpptools-srv
20:43:44  22407  3054    0       0       cpptools-srv
20:43:44  20222  3054    0       0       cpptools-srv
20:43:44  8933   3054    0       0       cpptools-srv
20:43:44  2915   2803    0       0       node
20:43:44  2943   2803    0       0       node
20:43:44  31453  3054    0       0       cpptools-srv
$ sudo ./ecli examples/bpftools/sigsnoop/package.json  -h
Usage: sigsnoop_bpf [--help] [--version] [--verbose] [--filtered_pid VAR] [--target_signal VAR] [--failed_only]

A simple eBPF program

Optional arguments:
  -h, --help            shows help message and exits 
  -v, --version         prints version information and exits 
  --verbose             prints libbpf debug information 
  --filtered_pid        set value of pid_t variable filtered_pid 
  --target_signal       set value of int variable target_signal 
  --failed_only         set value of bool variable failed_only 

Built with eunomia-bpf framework.
See https://github.com/eunomia-bpf/eunomia-bpf for more information.
```
