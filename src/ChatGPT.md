# chat with ChatGPT

## Thread 1

我希望你帮助我编写一些 eBPF 程序，描述一下这个 eBPF 程序的作用。我们会使用 eunomia-bpf 这个工具来编写 eBPF 程序。请告诉我 eunomia-bpf 是什么。

> eBPF 是一种内核的网络程序。它可以在内核空间中执行，并且可以实时地监控内核的行为。eunomia-bpf 是一个工具，可以用来编写 eBPF 程序。它提供了一个简单的接口，使用户可以编写 eBPF 程序来实现特定的目标。例如，eBPF 程序可以用来监控内核网络流量，或者实现虚拟机监控等功能。

这是一个使用 eunomia-bpf 的例子：

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}
```

kprobe 是 eBPF 用于处理内核空间入口和出口（返回）探针（kprobe 和 kretprobe）的一个例子。它将 kprobe 和 kretprobe BPF 程序附加到 do_unlinkat() 函数上，并使用 bpf_printk() 宏分别记录 PID、文件名和返回值。

要编译这个程序，请使用 ecc 工具：

```console
$ ecc kprobe-link.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

然后运行：

```console
sudo ecli run package.json
```

在 /sys/kernel/debug/tracing/trace_pipe 文件中，应该能看到类似下面的 kprobe 演示输出：

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9346    [005] d..3  4710.951696: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test1
              rm-9346    [005] d..4  4710.951819: bpf_trace_printk: KPROBE EXIT: ret = 0
              rm-9346    [005] d..3  4710.951852: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test2
              rm-9346    [005] d..4  4710.951895: bpf_trace_printk: KPROBE EXIT: ret = 0
```

> 这段程序使用 eBPF 实现了一个 kprobe，用来监控内核中 do_unlinkat() 函数的调用。kprobe 的目的是实时监控内核函数的调用情况，通过记录调用时的参数和返回值，来提供实时状态的反馈。在这个例子中，kprobe 记录了进入 do_unlinkat() 函数时的 PID 和文件名，并在函数返回时记录了返回值。
>
> eBPF 程序使用 ecc 工具编译成二进制文件，然后通过 ecli 工具运行。运行时，ecli 会将 eBPF 程序附加到内核上，并通过 /sys/kernel/debug/tracing/trace_pipe 文件来输出 kprobe 的日志信息。
>
> 这个程序的作用是实时监控内核中 do_unlinkat() 函数的调用情况，并记录相关信息。通过这种方式，我们可以对内核的行为进行实时监控，并及时发现可能的异常情况。

请帮我编写一个eBPF 程序，通过定义两个函数 tracepoint__syscalls__sys_enter_open 和 tracepoint__syscalls__sys_enter_openat 并使用 SEC 宏把它们附加到 sys_enter_open 和 sys_enter_openat 两个 tracepoint（即在进入 open 和 openat 系统调用时执行）。这两个函数通过使用 bpf_get_current_pid_tgid 函数获取调用 open 或 openat 系统调用的进程 ID，并使用 bpf_printk 函数在内核日志中打印出来。

> 编写 eBPF 程序可以实现上述目标，具体代码如下：

```c
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_open")
int BPF_TRACEPOINT(sys_enter_open)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("sys_enter_open: pid = %d\n", pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int BPF_TRACEPOINT(sys_enter_openat)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("sys_enter_openat: pid = %d\n", pid);
    return 0;
}
```

> 这段程序定义了两个函数 tracepoint__syscalls__sys_enter_open 和 tracepoint__syscalls__sys_enter_openat，并使用 SEC 宏把它们附加到 sys_enter_open 和 sys_enter_openat 两个 tracepoint 上。这两个函数分别在进入 open 和 openat 系统调用时执行，并使用 bpf_get_current_pid_tgid 函数获取调用 open 或 openat 系统调用的进程 ID，并使用 bpf_printk 函数在内核日志中打印出来。
> 这段程序的作用是实时监控内核中 open 和 openat 系统调用的情况，并记录调用这两个系统调用的进程 ID。通过这种方式，我们可以实时监控进程对文件系统的访问情况，并及时发现可能的异常情况。
> 要编译这段程序，请使用 ecc 工具：
>
> ```console
> $ ecc open
> ```

很好。

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (pid_filter && pid != pid_filter)
        return 0;
    bpf_printk("BPF triggered from PID %d.\n", pid);
    return 0;
}
```

这段程序通过定义一个 handle_tp 函数并使用 SEC 宏把它附加到 sys_enter_write tracepoint（即在进入 write 系统调用时执行）。该函数通过使用 bpf_get_current_pid_tgid 和 bpf_printk 函数获取调用 write 系统调用的进程 ID，并在内核日志中打印出来。请告诉我它的输出结果。

> 这段程序的作用是实时监控内核中 write 系统调用的情况，并记录调用 write 系统调用的进程 ID。当进程调用 write 系统调用时，该函数会执行，并使用 bpf_printk 函数在内核日志中打印出调用 write 系统调用的进程 ID。具体的输出结果应该类似于：
>
> BPF triggered from PID 123.
> 这段程序会在内核日志中打印出调用 write 系统调用的进程 ID，例如 "BPF triggered from PID 123"。这里的 PID 指的是调用 write 系统调用的进程 ID。
>
> 需要注意的是，如果 pid_filter 变量不为 0，那么只有当调用 write 系统调用的进程 ID 等于 pid_filter 时，才会执行 bpf_printk 函数，其他情况都不会打印内核日志。因此，如果要输出所有调用 write 系统调用的进程 ID，需要确保 pid_filter 变量的值为 0。

是的。
要编译和运行这段程序，可以使用 ecc 工具和 ecli 命令。首先使用 ecc 编译程序：

```console
$ ecc hello.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

或使用 docker 镜像进行编译：

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

然后使用 ecli 运行编译后的程序：

```console
$ sudo ecli run ./package.json
Runing eBPF program...
```

运行这段程序后，可以通过查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看 eBPF 程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: write system call from PID 3840345.
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: write system call from PID 3840345.
```

请告诉我如何编译运行实时监控内核中 open 和 openat 系统调用的 eBPF 程序。

> 要编译和运行实时监控内核中 open 和 openat 系统调用的 eBPF 程序，可以按照下面的步骤进行：
>
> 将程序保存到文件中，例如叫做 "open.bpf.c"。

```c
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_open")
int BPF_TRACEPOINT(sys_enter_open)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("sys_enter_open: pid = %d\n", pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int BPF_TRACEPOINT(sys_enter_openat)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("sys_enter_openat: pid = %d\n", pid);
    return 0;
}
```

> 使用 ecc 工具编译程序：

```console
$ ecc open.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

> 使用 ecli 命令运行编译后的程序：

```console
$ sudo ecli run ./package.json
Runing eBPF program...
```

> 查看 /sys/kernel/debug

请继续。查看 /sys/kernel/debug

> 运行 eBPF 程序后，可以通过查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看 eBPF 程序的输出。例如，如果有进程在调用 open 或 openat 系统调用，那么可以看到类似下面的输出：

```c
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
sys_enter_open: pid = 123
sys_enter_openat: pid = 456
```

> 这些输出表明，在运行 eBPF 程序的过程中，有两个进程（PID 为 123 和 456）分别调用了 open 和 openat 系统调用。对于每个系统调用，eBPF 程序都会记录调用进程的 ID，并在内核日志中输出。
> 需要注意的是，如果内核中有多个进程同时调用 open 或 openat 系统调用，那么输出结果可能会有所不同。例如，可能会有多个进程的 ID 同时出现在内核日志中。这取决于系统的具体情况。

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "sigsnoop.h"

#define MAX_ENTRIES 10240

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

> 在探针函数中，我们使用 bpf_map 存储捕获的事件信息，包括发送信号的进程 ID、接收信号的进程 ID、信号值和系统调用的返回值。在系统调用退出时，我们将获取存储在 bpf_map 中的事件信息，并使用 bpf_printk 打印进程 ID、进程名称、发送的信号和系统调用的返回值。
>
> 要编译这段 eBPF 程序，需要使用 LLVM Clang 工具链，并确保安装了 eBPF 相关的头文件，例如 vmlinux.h 和 bpf_helpers.h。
>
> 首先，按照以下命令编译 eBPF 程序：
>
> $ clang -O2 -Wall -target bpf -c sigsnoop.c -o sigsnoop.o
>
> 编译完成后，可以使用 bpftool 工具将 eBPF 字节码文件加载到内核中：
>
> $ sudo bpftool prog load sigsnoop.o /sys/fs/bpf/sigsnoop
> 最后，查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看 eBPF 程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: PID 3840345 (bash) sent signal 15 to PID 3840345, ret = 0
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: PID 3840345 (bash) sent signal 17 to PID 3840345, ret = 0
```

> 输出结果显示了进程发送信号的细节，包括发送信号的进程 ID、发送信号的进程名、信号值以及接收到信号的进程 ID。

请告诉我如何编写一段 eBPF 程序，追踪 stat 相关的系统调用。

> 下面是一个示例 eBPF 程序，用于跟踪执行 stat 相关系统调用（例如 stat、fstat、lstat）的进程信息和文件路径。

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "sigsnoop.h"

#define MAX_ENTRIES 10240

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct event);
} values SEC(".maps");


static int probe_stat_entry(void *ctx)
{
    struct event event = {};
    __u64 pid_tgid;
    __u32 pid, tid;

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    event.pid = pid;
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    bpf_map_update_elem(&values, &tid, &event, BPF_ANY);
    return 0;
}

static int probe_stat_exit(void *ctx, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct event *eventp;

    eventp = bpf_map_lookup_elem(&values, &tid);
    if (!eventp)
        return 0;

    eventp->ret = ret;
    if (ret == 0)
        bpf_probe_read_str(eventp->path, sizeof(eventp->path), (void *)ctx->args[0]);

    bpf_printk("PID %d (%s) executed stat syscall, file path = %s, ret = %d",
           eventp->pid, eventp->comm, eventp->path, eventp->ret);

cleanup:
    bpf_map_delete_elem(&values, &tid);
    return 0;
}

SEC("kprobe/sys_stat")
int sys_stat_entry(struct pt_regs *ctx)
{
    return probe_stat_entry(ctx);
}

SEC("kretprobe/sys_stat")
int sys_stat_exit(struct pt_regs *ctx)
{
    return probe_stat_exit(ctx, PT_REGS_RC(ctx));
}

SEC("kprobe/sys_fstat")
int sys
```

我如何使用 eunomia-bpf 编译运行它？

> 下面是一个简单的 eBPF 程序，用于跟踪 stat 相关的系统调用。它通过定义两个函数：tracepoint__syscalls__sys_enter_stat 和 tracepoint__syscalls__sys_exit_stat，并使用 SEC 宏把它们附加到 stat 系统调用的进入和退出事件上，来捕获 stat 系统调用。

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, struct event);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_stat")
int sys_enter_stat(struct trace_event_raw_sys_enter *ctx)
{
    struct event event = {};
    __u64 pid_tgid;
    __u32 pid;
    int fd = (int)ctx->args[0];

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    event.pid = pid;
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    bpf_map_update_elem(&events, &fd, &event, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_stat")
int sys_exit_stat(struct trace_event_raw_sys_exit *ctx)
{
    struct event *eventp;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    int fd = (int)ctx->args[0];

    eventp = bpf_map_lookup_elem(&events, &fd);
    if (!eventp)
        return 0;

    eventp->ret = ctx->ret;
    bpf_printk("PID %d (%s) called stat on fd %d, ret = %d\n",
           eventp->pid, eventp->comm, fd, eventp->ret);

    bpf_map_delete_elem(&

```

请继续。

> 编译运行 eBPF 程序的方法与之前给出的方法类似，首先使用 ecc 编译程序：

```console
$ ecc stat.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

> 或使用 docker 镜像进行编译：

```sh
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

> 然后使用 ecli 运行编译后的程序：

```sh
$ sudo ecli run ./package.json
Runing eBPF program...
```

> 运行这段程序后，可以通过查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看 eBPF 程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: stat system call from PID 3840345.
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: stat system call from PID 3840345.
```

> 也可以使用其他工具，如 perf 或 bpftrace，来查看 eBPF 程序的输出。例如，使用 perf 命令查看 eBPF 程序的输出：

```
$ perf record -e bpf_printk -a
Running 'record' for 'bpf_printk' (5 secs):

[ perf record: Woken up 1 times to write data ]
[ perf record: Captured and wrote 0.178 MB perf.data (~1623 samples) ]
```

> 使用 perf script 命令来查看 perf.data 中的输出：

```
$ perf script
       bash-37048 [002] ....  1617.738101: bpf_trace_printk: stat system call from PID 370
```

编写一个 eBPF 程序，追踪进程执行。通过 perf event array 向用户态打印输出。

> 下面是一个简单的 eBPF 程序，它定义了一个 kprobe 探针函数，用于捕获内核函数 do_syscall_64 的进入事件，并记录调用该函数的进程的 PID、函数名和返回值。

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_syscall_64")
int BPF_KPROBE(do_syscall_64, struct pt_regs *regs, long id)
{
    pid_t pid;
    const char *func;

    pid = bpf_get_current_pid_tgid() >> 32;
    func = __func__;
    bpf_printk("KPROBE ENTRY pid = %d, func = %s, id = %d\n", pid, func, id);
    return 0;
}

SEC("kretprobe/do_syscall_64")
int BPF_KRETPROBE(do_syscall_64_exit, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}
```

> 要编译这段代码，可以使用 ecc 工具：

```
$ ecc kprobe-syscall.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

> 然后可以使用 ecli 运行编译后的程序：

这是一个 execsnoop 的例子

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

> 这段代码定义了两个 eBPF 程序，一个用于捕获进程执行 execve 系统调用的入口，另一个用于捕获进程执行 execve 系统调用的出口。
> 在入口程序中，我们首先获取了当前进程的进程 ID 和用户 ID，然后通过 bpf_get_current_task 函数获取了当前进程的 task_struct 结构体，并通过 bpf_probe_read_str 函数读取了进程名称。最后，我们通过 bpf_perf_event_output 函数将进程执行事件输出到 perf buffer。
>
> 在出口程序中，我们首先获取了进程的进程 ID 和用户 ID，然后通过 bpf_get_current_comm 函数获取了进程的名称，最后通过 bpf_perf_event_output 函数将进程执行事件输出到 perf buffer。
>
> 使用这段代码，我们就可以捕获 Linux 内核中进程执行的事件。我们可以通过工具（例如 eunomia-bpf）来查看这些事件，并分析进程的执行情况。
>
> 接着，使用如下命令编译这个 eBPF 程序：
>
> clang -O2 -emit-llvm -c -g execsnoop.bpf.c
>
> llc -march=bpf -filetype=obj -o execsnoop.o execsnoop.bpf.ll
>
> 编译后的文件 execsnoop.o 就可以使用 eunomia-bpf 工具来运行了。例如，可以使用如下命令运行这个程序：
>
> eunomia-bpf -o execsnoop.o
>
> 执行这个命令后，程序将在内核中运行，并在追踪到进程执行 execve 系统调用时向用户态命令行打印输出。
>
> 可以通过使用 -p 参数指定进程 ID，来只监控指定的进程。例如：
>
> eunomia-bpf -p 1234 -o execsnoop.o
>
> 这样就只会监控进程 ID 为 1234 的进程的执行。
>
> 还可以通过使用 -C 参数来指定要监控的系统调用，例如：
>
> eunomia-bpf -C execve -o execsnoop.o
>
> 这样就只会监

please give me an eBPF program Trace all stat syscall variants with perf event output.

> 首先，需要定义一个包含所需信息的结构体：

```c
struct stat_event {
    u64 id;
    pid_t pid;
    uid_t uid;
    char comm[TASK_COMM_LEN];
    char pathname[PATH_MAX];
};
```

> 然后，可以定义一个 perf event array 用于向用户态传递输出：

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");
```

> 接下来，可以编写捕获 stat 系统调用的 eBPF 程序：

```c
SEC("tracepoint/syscalls/sys_enter_stat")
int tracepoint__syscalls__sys_enter_stat(struct trace_event_raw_sys_enter *ctx)
{
    // 获取进程 ID 和 UID
    u64 id = bpf_get_current_pid_tgid();
    pid_t pid = (pid_t)id;
    uid_t uid = (u32)bpf_get_current_uid_gid();

    // 获取文件名
    char pathname[PATH_MAX];
    bpf_probe_read_str(pathname, sizeof(pathname), (void *)ctx->args[0]);

    // 获取进程名
    struct task_struct *task;
    struct stat_event event = {};
    task = (struct task_struct *)bpf_get_current_task();
    bpf_probe
```

请继续。

> 这段 eBPF 程序的完整代码如下所示：

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_ENTRIES 10240

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_stat")
int tracepoint__syscalls__sys_enter_stat(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = (u32)id;
    u32 tgid = id >> 32;
    const char *filename = (const char*)(ctx->args[0]);
    struct stat *stat = (struct stat*)(ctx->args[1]);
    int ret = ctx->ret;

    bpf_probe_read_str(&filename, sizeof(filename), filename);
    bpf_probe_read(&stat, sizeof(stat), stat);

    struct data_t {
        u32 pid;
        u32 tgid;
        int ret;
        char filename[256];
    } data = {
        .pid = pid,
        .tgid = tgid,
        .ret = ret,
    };

    bpf_probe_read_str(&data.filename, sizeof(data.filename), filename);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

> 通过这段代码

请继续，通过这段代码

> 您可以使用以下代码来跟踪 stat 相关的系统调用：

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_fstat")
int tracepoint__syscalls__sys_enter_fstat(struct trace_event_raw_sys_enter* ctx)
{
    struct stat *st = (struct stat *)(ctx->args[1]);
    struct event {
        int pid;
        int fd;
        char comm[TASK_COMM_LEN];
        bool is_exit;
        int retval;
    } event = {};

    event.fd = (int)(ctx->args[0]);
    event.pid = (int)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.is_exit = false;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fstat")
int tracepoint__syscalls__sys_exit_fstat(struct trace_event_raw_sys_exit* ctx)
{
    struct event {
        int pid;
        int fd;
        char comm

```

## thread 2

我希望你帮助我编写一些 eBPF 程序，描述一下这个 eBPF 程序的作用。我们会使用 eunomia-bpf 这个工具来编写 eBPF 程序。eBPF 程序主要由两部分构成：内核态部分和用户态部分。内核态部分包含 eBPF 程序的实际逻辑，用户态部分负责加载、运行和监控内核态程序。使用 eunomia-bpf，只需编写内核态代码即可，无需编写用户态代码。如果你理解了这些，请说好的。

> 确实，eBPF 程序由内核态部分和用户态部分构成。eBPF 程序在内核态运行，用户态程序负责加载、运行和监控内核态程序。eunomia-bpf 是一个用于编写和管理 eBPF 程序的工具，它只需要编写内核态代码，无需编写用户态代码。我可以帮助你编写 eBPF 程序，只要你能够告诉我你想要它做什么。
>

这段程序通过定义一个 handle_tp 函数并使用 SEC 宏把它附加到 sys_enter_write tracepoint（即在进入 write 系统调用时执行）。该函数通过使用 bpf_get_current_pid_tgid 和 bpf_printk 函数获取调用 write 系统调用的进程 ID，并在内核日志中打印出来。
请编写一下这个 eBPF 程序，它有一个 hello.bpf.c 文件。

> 可以使用如下代码编写 eBPF 程序：

```c
#include <uapi/linux/bpf.h>
#include <linux/sched.h>

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    bpf_printk("PID of process calling write: %d\n", pid);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

> 这个 eBPF 程序通过定义一个 handle_tp 函数并使用 SEC 宏把它附加到 sys_enter_write tracepoint。在进入 write 系统调用时，handle_tp 函数会被执行。该函数会使用 bpf_get_current_pid_tgid 函数获取调用 write 系统调用的进程 ID，然后使用 bpf_printk 函数在内核日志中打印出来。
>
> eBPF 程序的输出结果将是内核日志中打印的调用 write 系统调用的进程的 PID。例如，如果进程 42 调用了 write 系统调用，则输出结果将是：

```
PID of process calling write: 42
```

> 需要注意的是，在使用此 eBPF 程序之前，需要编译它并将其加载到内核中。此外，由于 eBPF 程序在内核态运行，因此它可能需要特殊权限才能加载和使用。

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (pid_filter && pid != pid_filter)
        return 0;
    bpf_printk("BPF triggered from PID %d.\n", pid);
    return 0;
}
```

不。代码应该是这样的。

> 您的代码看起来正确。它定义了一个 handle_tp 函数，并使用 SEC 宏把它附加到 sys_enter_write tracepoint。在进入 write 系统调用时，handle_tp 函数会被执行。该函数会使用 bpf_get_current_pid_tgid 函数获取调用 write 系统调用的进程 ID，然后使用 bpf_printk 函数在内核日志中打印出来。如果需要，还可以使用 pid_filter 变量来过滤进程。如果您需要进一步改进您的 eBPF 程序，请告诉我您的需求，我可以帮助您实现它。

要编译和运行这段程序，可以使用 ecc 工具和 ecli 命令。首先使用 ecc 编译程序：

```console
$ ecc hello.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

或使用 docker 镜像进行编译：

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

然后使用 ecli 运行编译后的程序：

```console
$ sudo ecli run ./package.json
Runing eBPF program...
```

运行这段程序后，可以通过查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看 eBPF 程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: write system call from PID 3840345.
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: write system call from PID 3840345.
```

> 您的描述是正确的。eBPF 程序需要编译才能运行。可以使用 ecc 工具来编译 eBPF 程序，也可以使用 docker 镜像进行编译。运行 eBPF 程序的方法有多种，可以使用 ecli 命令运行编译后的程序，也可以使用其他工具。输出结果将在内核日志中打印，可以通过查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看。
>
> 请注意，使用 ecc 编译程序后，会生成一个 package.json 文件，其中包含编译后的 eBPF 程序和配置信息。运行 eBPF 程序时，需要指定该文件，以便 ecli 命令能够找到并运行 eBPF 程序。例如，可以使用以下命令运行 eBPF 程序：

```
sudo ecli run ./package.json
```

> 如果您还有任何问题，请随时告诉我，我很乐意帮助您解决问题。

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}
```

kprobe 是 eBPF 用于处理内核空间入口和出口（返回）探针（kprobe 和 kretprobe）的一个例子。它将 kprobe 和 kretprobe BPF 程序附加到 do_unlinkat() 函数上，并使用 bpf_printk() 宏分别记录 PID、文件名和返回值。请告诉我如何编译运行这段程序。

> 您的 eBPF 程序使用 kprobe 和 kretprobe 宏附加到 do_unlinkat 函数上。kprobe 宏将 BPF 程序附加到 do_unlinkat 函数的入口，kretprobe 宏将 BPF 程序附加到 do_unlinkat 函数的出口（返回）处。这样，您就可以在 do_unlinkat 函数的入口和出口（返回）处捕获数据，并使用 bpf_printk 宏在内核日志中打印数据。
>
> 要编译和运行您的 eBPF 程序，您需要安装 bcc 工具集。然后，在终端中输入以下命令：
>
```
# 编译 eBPF 程序
clang -O2 -target bpf -c my_bpf_prog.c -o my_bpf_prog.o

# 运行 eBPF 程序
sudo ./bcc.py run my_bpf_prog.o
```

> 这样，就会编译并运行您的 eBPF 程序。在运行 eBPF 程序时，会在内核日志中打

不对，使用 eunomia-bpf 工具编译。要编译这个程序，请使用 ecc 工具：

```console
$ ecc kprobe-link.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

然后运行：

```console
sudo ecli run package.json
```

在 /sys/kernel/debug/tracing/trace_pipe 文件中，应该能看到类似下面的 kprobe 演示输出：

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9346    [005] d..3  4710.951696: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test1
              rm-9346    [005] d..4  4710.951819: bpf_trace_printk: KPROBE EXIT: ret = 0
              rm-9346    [005] d..3  4710.951852: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test2
              rm-9346    [005] d..4  4710.951895: bpf_trace_printk: KPROBE EXIT: ret = 0
```

> 您的描述是正确的。您可以使用 ecc 工具编译您的 eBPF 程序，编译后会生成一个 package.json 文件。然后，可以使用 ecli 命令运行该程序，以便监控系统调用。运行 eBPF 程序后，您可以查看 /sys/kernel/debug/tracing/trace_pipe 文件，以查看程序的输出。
>
> 请注意，编译和运行 eBPF 程序的步骤可能会有所不同，具体取决于使用的工具和系统环境。如果您在编译和运行 eBPF 程序时遇到任何问题，请随时告评，我很乐意帮助您解决问题。

是的。

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
    return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
    return 0;
}
```

这段程序通过定义两个函数，分别附加到 do_unlinkat 和 do_unlinkat_exit 上。这两个函数分别在进入 do_unlinkat 和离开 do_unlinkat 时执行。这两个函数通过使用 bpf_get_current_pid_tgid 和 bpf_printk 函数来获取调用 do_unlinkat 的进程 ID，文件名和返回值，并在内核日志中打印出来。请告诉我如何编译运行这段程序。

> 您的 eBPF 程序定义了两个函数：do_unlinkat 和 do_unlinkat_exit。这两个函数都使用 BPF_PROG 宏附加到 do_unlinkat 和 do_unlinkat_exit 函数上。do_unlinkat 函数在进入 do_unlinkat 时执行，do_unlinkat_exit 函数在离开 do_unlinkat 时执行。这两个函数通过使用 bpf_get_current_pid_tgid 和 bpf_printk 函数来获取调用 do_unlinkat 的进程 ID，文件名和返回值，并在内核日志中打印出来。
>
> 要编译和运行这段程序，您可以使用 bcc 工具集。首先，在终端中输入以下命令来安装 bcc 工具集：

```
sudo apt install bcc-tools libbcc-examples linux-headers-$(uname -r)
```

> 然后，在终端中输入以下命令来编译您的 eBPF 程序：

我不希望你继续使用 BCC 工具集，请使用 eunomia-bpf

> 好的。您可以使用 eunomia-bpf 工具编译您的 eBPF 程序。首先，在终端中输入以下命令来安装 eunomia-bpf：

sudo npm install -g eunomia-bpf

> 然后，在终端中输入以下命令来编译您的 eBPF 程序：

```
ecc kprobe-link.bpf.c
```

> 编译后，您会得到一个 package.json 文件。您可以使用 ecli 命令运行该程序：

```
sudo ecli run package.json
```

> 运行该程序后，您可以查看 /sys/kernel/debug/tracing/trace_pipe 文件，以查看程序的输出。请注意，编译和运行 eBPF 程序的步骤可能会有所不同，具体取决于使用的工具和系统环境。如果您在编

我们需要编写一段 eBPF 程序来捕获进程打开文件的系统调用，具体实现如下：

```c
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "opensnoop.h"


/// Process ID to trace
const volatile int pid_target = 0;

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;

    if (pid_target && pid_target != pid)
        return false;
    // Use bpf_printk to print the process information
    bpf_printk("Process ID: %d enter sys open\n", pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;

    if (pid_target && pid_target != pid)
        return false;
    // Use bpf_printk to print the process information
    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}

/// Trace open family syscalls.
char LICENSE[] SEC("license") = "GPL";
```

上面的 eBPF 程序通过定义两个函数 tracepoint__syscalls__sys_enter_open 和 tracepoint__syscalls__sys_enter_openat 并使用 SEC 宏把它们附加到 sys_enter_open 和 sys_enter_openat 两个 tracepoint（即在进入 open 和 openat 系统调用时执行）。这两个函数通过使用 bpf_get_current_pid_tgid 函数获取调用 open 或 openat 系统调用的进程 ID，并使用 bpf_printk 函数在内核日志中打印出来。

> 编译运行这段 eBPF 程序，请使用 ecc 工具编译：

```
$ ecc capture-sys-open.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

> 然后运行：

```
sudo ecli run package.json
```

> 在 /sys/kernel/debug/tracing/trace_pipe 文件中，应该能看到类似下面的输出：

```
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              cat-9349    [005] d..3  4710.951696: bpf_trace_printk: Process ID: 9349 enter sys open
              cat-9349    [005] d..3  4710.951696: bpf_trace_printk: Process ID: 9349 enter sys openat
```       

> 如果想要只跟踪特定的进程，可以在程序中设置 pid_target 变量的值，例如：

```
const volatile int pid_target = 1234;
```

> 这样，程序只会输出 PID 为 1234 的进程的信息。

是的，谢谢你。我会继续给你一些 eBPF 程序。

> 好的，请继续。

```c
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bashreadline.h"

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

SEC("uprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const void *ret) {
    char str[MAX_LINE_SIZE];
    char comm[TASK_COMM_LEN];
    u32 pid;

    if (!ret)
        return 0;

    bpf_get_current_comm(&comm, sizeof(comm));

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(str, sizeof(str), ret);

    bpf_printk("PID %d (%s) read: %s ", pid, comm, str);

    return 0;
};

char LICENSE[] SEC("license") = "GPL";
```

这段代码的作用是在 bash 的 readline 函数返回时执行指定的 BPF_KRETPROBE 函数，即 printret 函数。

在 printret 函数中，我们首先获取了调用 readline 函数的进程的进程名称和进程 ID，然后通过 bpf_probe_read_user_str 函数读取了用户输入的命令行字符串，最后通过 bpf_printk 函数打印出进程 ID、进程名称和输入的命令行字符串。

除此之外，我们还需要通过 SEC 宏来定义 uprobe 探针，并使用 BPF_KRETPROBE 宏来定义探针函数。

在 SEC 宏中，我们需要指定 uprobe 的类型、要捕获的二进制文件的路径和要捕获的函数名称。例如，上面的代码中的 SEC 宏的定义如下：

```c
SEC("uprobe//bin/bash:readline")
```

这表示我们要捕获的是 /bin/bash 二进制文件中的 readline 函数。

> 是的，你描述得很清楚。
>
> 编译这段程序的方法与其他 eBPF 程序的编译方法相同，需要使用 eunomia-bpf 工具集。首先使用 ecc 编译程序：

```
$ ecc bashreadline.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

> 然后使用 ecli 运行编译后的程序：

```
$ sudo ecli run ./package.json
Runing eBPF program...
```

> 在 /sys/kernel/debug/tracing/trace_pipe 文件中，应该能看到类似下面的输出：

```
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
PID 1234 (bash) read: some command line input
PID 1234 (bash) read: another command line input
...
```

> 这些输出表示有一个进程 ID 为 1234，名称为 bash 的进程在调用 readline 函数时输入了相应的命令行输入。

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "sigsnoop.h"

#define MAX_ENTRIES 10240

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

> 是的，这段代码通过定义两个 eBPF 程序来捕获进程执行 execve 系统调用的入口和出口事件。在入口程序中，我们获取了当前进程的进程 ID 和用户 ID，并通过 bpf_get_current_task 函数获取了当前进程的 task_struct 结构体，并通过 bpf_probe_read_str 函数读取了进程名称。在出口程序中，我们获取了当前进程的进程 ID 和用户 ID，并获取了 execve 系统调用的返回值。最后，在

```
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */

/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    bpf_printk("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
```

这段代码定义了一个 eBPF 程序，它可以通过 Linux TC（Transmission Control）来捕获数据包并进行处理。在这个程序中，我们限定了只捕获 IPv4 协议的数据包，然后通过 bpf_printk 函数打印出数据包的总长度和 Time-To-Live（TTL）字段的值。

需要注意的是，我们在代码中使用了一些 BPF 库函数，例如 bpf_htons 和 bpf_ntohs 函数，它们用于进行网络字节序和主机字节序之间的转换。此外，我们还使用了一些注释来为 TC 提供附加点和选项信息。例如，在这段代码的开头，我们使用了以下注释：

```c
/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
```

> 这些注释告诉 TC 将 eBPF 程序附加到网络接口的 ingress 附加点，并指定了 handle 和 priority 选项的值。
>
> 总之，这段代码实现了一个简单的 eBPF 程序，用于捕获数据包并打印出它们的信息。

编译运行

```console
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

or compile with `ecc`:

```console
$ ecc tc.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

```shell
$ sudo ecli run ./package.json
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF program.
......
```

The `tc` output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            node-1254811 [007] ..s1 8737831.671074: 0: Got IP packet: tot_len: 79, ttl: 64
            sshd-1254728 [006] ..s1 8737831.674334: 0: Got IP packet: tot_len: 79, ttl: 64
            sshd-1254728 [006] ..s1 8737831.674349: 0: Got IP packet: tot_len: 72, ttl: 64
            node-1254811 [007] ..s1 8737831.674550: 0: Got IP packet: tot_len: 71, ttl: 64
```

通过 tc.bpf.c 中的代码，我们可以发现，该 eBPF 程序通过在 TC 入口阶段注册一个挂载点来捕获网络数据包，并判断数据包的协议类型是否为 IP 协议，如果是，则解析数据包头部，获取关键信息，如包长度、TTL 等，最后通过 bpf_printk 函数将信息打印出来。

这段代码还使用了 @tchook 和 @tcopts 注释，用于指定该 eBPF 程序的挂载点和处理方式。例如，@tchook 注释中的 ifindex 参数指定了该 eBPF 程序

```c
const volatile __u64 min_us = 0;
const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

/* record enqueue timestamp */
static int trace_enqueue(u32 tgid, u32 pid)
{
    u64 ts;

    if (!pid)
        return 0;
    if (targ_tgid && targ_tgid != tgid)
        return 0;
    if (targ_pid && targ_pid != pid)
        return 0;

    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, 0);
    return 0;
}

static int handle_switch(void *ctx, struct task_struct *prev, struct task_struct *next)
{
    struct event event = {};
    u64 *tsp, delta_us;
    u32 pid;

    /* ivcsw: treat like an enqueue event and store timestamp */
    if (get_task_state(prev) == TASK_RUNNING)
        trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));

    pid = BPF_CORE_READ(next, pid);

    /* fetch timestamp and calculate delta */
    tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp)
        return 0;   /* missed enqueue */

    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    if (min_us && delta_us <= min_us)
        return 0;

    event.pid = pid;
    event.prev_pid = BPF_CORE_READ(prev, pid);
    event.delta_us = delta_us;
    bpf_probe_read_kernel_str(&event.task, sizeof(event.task), next->comm);
    bpf_probe_read_kernel_str(&event.prev_task, sizeof(event.prev_task), prev->comm);

    /* output */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                  &event, sizeof(event));

    bpf_map_delete_elem(&start, &pid);
    return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    return trace_enqueue(p->tgid, p->pid);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
    return trace_enqueue(p->tgid, p->pid);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    return handle_switch(ctx, prev, next);
}

SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
    return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p)
{
    return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    return handle_switch(ctx, prev, next);
}
```

> 这段代码定义了一个 eBPF 程序，该程序用于跟踪进程在运行队列中的等待时间。它通过使用 tracepoint 和 perf event 输出来实现。
>
> 程序首先定义了两个 BPF 内核映射：start 映射用于存储每个进程在被调度运行之前的时间戳，events 映射用于存储 perf 事件。
>
> 然后，程序定义了一些帮助函数，用于跟踪每个进程的调度状态。 trace_enqueue 函数用于在进程被调度运行之前记录时间戳， handle_switch 函数用于处理进程切换，并计算进程在队列中等待的时间。
>
> 接下来，程序定义了五个 tracepoint 程序，用于捕获不同的调度器事件。 sched_wakeup 和 sched_wakeup_new 程序用于捕获新进程被唤醒的事件， sched_switch 程序用于捕获进程切换事件， handle_sched_wakeup 和 handle_sched_wakeup_new 程序用于捕获 raw tracepoint 事件。这些 tracepoint 程序调用了前面定义的帮助函数来跟踪进程的调度状态。
>
> 最后，程序将计算得到的等待时间输出到 perf 事件中，供用户空间工具进行捕获和分析。

```
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

> 这个 BPF 程序用于监控进程的调度时间。它使用了 tracepoints 和 raw tracepoints，用于监控进程的唤醒和切换事件，并记录进程调度的时间。它还使用了 BPF 的统计功能，以便对时间进行统计，以查看统计信息。这个程序可以按照进程、进程组或进程命名空间来统计信息，并可以针对特定进程或进程组进行过滤。

它的输出结果类似这样：

```console
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
```

> 本程序监测了系统内进程执行时间。它通过在内核事件 sched_wakeup 和 sched_switch 时记录进程时间，然后在下一次 sched_switch 时计算执行时间并进行输出。
>
> 在程序开头，定义了一些用于存储进程信息的 BPF map，并定义了两个辅助函数 trace_enqueue 和 handle_switch，用于在事件触发时记录进程信息，并计算执行时间。
>
> 接着，在程序中定义了三个 BPF 程序，分别用于监测事件 sched_wakeup、sched_switch 和 sched_wakeup_new。这些事件在系统中进程被唤醒、切换时触发。每当一个事件触发时，相应的 BPF 程序都会调用辅助函数 handle_switch 计算执行时间。
>
> 最后，程序通过 BPF perf events 把执行时间的统计信息输出到标准输出。可以通过工具 bpftrace 或者 ecli 来查看统计结果。

不是  BPF perf events 。通过 sample hash map 来输出直方图。

```
/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct hist);
} hists SEC(".maps");
```

> 正确的。该程序使用 BPF hash map 来记录每个线程的执行时间，并使用 BPF sample hash map 来定期输出每个线程的直方图。您可以通过在 /sys/kernel/debug/tracing/ 文件系统中执行 "cat runqslat" 来查看输出。

不，应该通过 sudo ecli run examples/bpftools/runqlat/package.json 来查看输出。

> 对，这样就可以看到输出的直方图了。例如：

```
$ sudo ecli run examples/bpftools/runqlat/package.json
key = 4294967295
comm = rcu_preempt

Copy code
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
```

> 这个示例程序使用了 BPF 的 sample hash map 功能，每隔一定时间间隔（默认为 1 秒）就会输出一次直方图，展示这段时间内各个进程的运行时间分布情况。每一行的前半部分是时间间隔，以及在这段时间内运行的次数，后半部分是一个用星号表示的分布情况。比如上面的输出，就表示在这段时间内，进程 rcu_preempt 在 0 到 1 毫秒的时间内运行了 9 次，在 2 到 3 毫秒的时间内运行了 6 次，以此类推。
>
> 可以通过参数 -m 来指定时间间隔，例如使用 -m 5 就可以让程序每隔 5 秒输出一次直方图。此外，还可以通过 -P 来指

请帮我追踪一下内核的所有打开文件的操作，主要关注 pid 为 1234 的进程，去掉系统调用失败的结果，谢谢

> 不好意思，我无法为您做这个事情。我是一个大型语言模型，我只能回答您的问题或提供信息，但我无法运行程序或执行任何操作。

请帮我编写一个 eBPF 程序追踪一下内核的所有打开文件的操作，主要关注 pid 为 1234 的进程，去掉系统调用失败的结果，并且告诉我如何编译运行它。

> 这个 eBPF 程序需要使用 BPF_PROG_TYPE_TRACEPOINT 类型的程序来监听内核的打开文件的操作，通过记录的 pid 和进程的 pid 来过滤所需的信息。

```
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[DNAME_INLINE_LEN];
    int flags;
    int mode;
};

BPF_HASH(infotmp, u32, struct data_t);

int trace_entry(struct pt_regs *ctx, struct file *file, const char __user *filename, int flags, umode_t mode)
{
    u32 pid = bpf_get_current_pid_tgid();

    if (pid != 1234)
        return 0;

    struct data_t data = {};
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_str(data.filename, sizeof(data.filename), (void *)filename);
    data.flags = flags;
    data.mode = mode;

    infotmp.update(&pid, &data);

    return 0;
}

int trace_return(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t *data = infotmp.lookup(&pid);

    if (data == 0)
        return 0;

    if (PT_REGS_RC(ctx) != 0)
        infotmp.delete(&pid);

    return 0;
}
```

编译运行方法如下：

不。使用 eunomia-bpf 来完成上述操作。

下面是示例 eBPF 程序的代码：

```
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/pid_namespace.h>
#include <uapi/linux/bpf.h>

struct data_t {
    u32 pid;
    char filename[DNAME_INLINE_LEN];
};

BPF_HASH(opened_files, u32, struct data_t);

int trace_open_entry(struct pt_regs *ctx, const char __user *filename)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t data = {};

    if (pid == 1234) {
        bpf_probe_read_user(&data.filename, sizeof(data.filename), filename);
        data.pid = pid;
        opened_files.update(&pid, &data);
    }

    return 0;
}

int trace_open_return(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    if (pid == 1234 && ret >= 0) {
        opened_files.delete(&pid);
    }

    return 0;
}
```

> 可以使用下面的命令来编译和运行这个程序：

```
# 编译
$ clang -O2 -target bpf -c open.c -o open.o

# 运行
$ sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter_openat /pid == 1234/ { @[comm] = count();
```
