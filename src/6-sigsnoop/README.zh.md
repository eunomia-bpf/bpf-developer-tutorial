# eBPF 入门开发实践教程六：捕获进程发送信号的系统调用集合，使用 hash map 保存状态

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具，它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践教程的第六篇，主要介绍如何实现一个 eBPF 工具，捕获进程发送信号的系统调用集合，使用 hash map 保存状态。

## sigsnoop

示例代码如下：

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

struct event {
 unsigned int pid;
 unsigned int tpid;
 int sig;
 int ret;
 char comm[TASK_COMM_LEN];
};

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
 __u32 tid;

 pid_tgid = bpf_get_current_pid_tgid();
 tid = (__u32)pid_tgid;
 event.pid = pid_tgid >> 32;
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
 bpf_printk("PID %d (%s) sent signal %d ",
           eventp->pid, eventp->comm, eventp->sig);
 bpf_printk("to PID %d, ret = %d",
           eventp->tpid, ret);

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

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

这个程序展示了一个重要的 eBPF 模式：如何在系统调用的入口和出口之间保存和关联信息。

为什么需要 hash map？因为我们需要在两个不同的探针函数之间共享数据，当系统调用进入时（`sys_enter_kill`），我们知道目标进程 ID 和信号值，但还不知道操作是否成功。当系统调用退出时（`sys_exit_kill`），我们得到了返回值，但已经失去了对参数的访问。hash map 让我们能够在入口处保存信息，然后在出口处检索它。

看看代码如何工作：`probe_entry` 在系统调用进入时触发，我们使用线程 ID 作为键，将事件信息存储到 hash map 中。`probe_exit` 在系统调用返回时触发，使用相同的线程 ID 查找之前保存的信息，添加返回值，然后打印完整的事件。最后删除 map 条目以避免内存泄漏。

这种模式非常常见——任何时候你需要关联系统调用的参数和返回值，都可以使用这个技术。

我们使用 eunomia-bpf 来编译和运行这个示例。你可以从 <https://github.com/eunomia-bpf/eunomia-bpf> 安装它。

编译运行上述代码：

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

或者

```console
$ ecc sigsnoop.bpf.c
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
$ sudo ecli run package.json
Runing eBPF program...
```

运行这段程序后，可以通过查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看 eBPF 程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
    systemd-journal-363     [000] d...1   672.563868: bpf_trace_printk: PID 363 (systemd-journal) sent signal 0
     systemd-journal-363     [000] d...1   672.563869: bpf_trace_printk: to PID 1400, ret = 0
     systemd-journal-363     [000] d...1   672.563870: bpf_trace_printk: PID 363 (systemd-journal) sent signal 0
     systemd-journal-363     [000] d...1   672.563870: bpf_trace_printk: to PID 1527, ret = -3
```

## 总结

本文主要介绍如何实现一个 eBPF 工具，捕获进程发送信号的系统调用集合，使用 hash map 保存状态。使用 hash map 需要定义一个结构体：

```c
struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, __u32);
 __type(value, struct event);
} values SEC(".maps");
```

并使用一些对应的 API 进行访问，例如 bpf_map_lookup_elem、bpf_map_update_elem、bpf_map_delete_elem 等。

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。
