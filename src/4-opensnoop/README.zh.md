# eBPF 入门开发实践教程四：在 eBPF 中捕获进程打开文件的系统调用集合，使用全局变量过滤进程 pid

eBPF（Extended Berkeley Packet Filter）是一种内核执行环境，它可以让用户在内核中运行一些安全的、高效的程序。它通常用于网络过滤、性能分析、安全监控等场景。eBPF 之所以强大，是因为它能够在内核运行时捕获和修改数据包或者系统调用，从而实现对操作系统行为的监控和调整。

本文是 eBPF 入门开发实践教程的第四篇，主要介绍如何捕获进程打开文件的系统调用集合，并使用全局变量在 eBPF 中过滤进程 pid。

在 Linux 系统中，进程与文件之间的交互是通过系统调用来实现的。系统调用是用户态程序与内核态程序之间的接口，它们允许用户态程序请求内核执行特定操作。在本教程中，我们关注的是 sys_openat 系统调用，它用于打开文件。

当进程打开一个文件时，它会向内核发出 sys_openat 系统调用，并传递相关参数（例如文件路径、打开模式等）。内核会处理这个请求，并返回一个文件描述符（file descriptor），这个描述符将在后续的文件操作中用作引用。通过捕获 sys_openat 系统调用，我们可以了解进程在什么时候以及如何打开文件。

## 在 eBPF 中捕获进程打开文件的系统调用集合

首先，我们需要编写一段 eBPF 程序来捕获进程打开文件的系统调用，具体实现如下：

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/// @description "Process ID to trace"
const volatile int pid_target = 0;

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (pid_target && pid_target != pid)
        return false;
    // Use bpf_printk to print the process information
    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}

/// "Trace open family syscalls."
char LICENSE[] SEC("license") = "GPL";
```

这段 eBPF 程序实现了：

1. 引入头文件：<vmlinux.h> 包含了内核数据结构的定义，<bpf/bpf_helpers.h> 包含了 eBPF 程序所需的辅助函数。
2. 定义全局变量 `pid_target`，用于过滤指定进程 ID。这里设为 0 表示捕获所有进程的 sys_openat 调用。
3. 使用 `SEC` 宏定义一个 eBPF 程序，关联到 tracepoint "tracepoint/syscalls/sys_enter_openat"。这个 tracepoint 会在进程发起 `sys_openat` 系统调用时触发。
4. 实现 eBPF 程序 `tracepoint__syscalls__sys_enter_openat`，它接收一个类型为 `struct trace_event_raw_sys_enter` 的参数 `ctx`。这个结构体包含了关于系统调用的信息。
5. 使用 `bpf_get_current_pid_tgid()` 函数获取当前进程的 PID 和 TID（线程 ID）。由于我们只关心 PID，所以将其值右移 32 位赋值给 `u32` 类型的变量 `pid`。
6. 检查 `pid_target` 变量是否与当前进程的 pid 相等。如果 `pid_target` 不为 0 且与当前进程的 pid 不相等，则返回 `false`，不对该进程的 `sys_openat` 调用进行捕获。
7. 使用 `bpf_printk()` 函数打印捕获到的进程 ID 和 `sys_openat` 调用的相关信息。这些信息可以在用户空间通过 BPF 工具查看。
8. 将程序许可证设置为 "GPL"，这是运行 eBPF 程序的必要条件。

这个 eBPF 程序可以通过 libbpf 或 eunomia-bpf 等工具加载到内核并执行。它将捕获指定进程（或所有进程）的 sys_openat 系统调用，并在用户空间输出相关信息。

eunomia-bpf 是一个结合 Wasm 的开源 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。可以参考 <https://github.com/eunomia-bpf/eunomia-bpf> 下载和安装 ecc 编译工具链和 ecli 运行时。我们使用 eunomia-bpf 编译运行这个例子。完整代码请查看 <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/4-opensnoop> 。

编译运行上述代码：

```console
$ ecc opensnoop.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
$ sudo ecli run package.json
Runing eBPF program...
```

运行这段程序后，可以通过查看 `/sys/kernel/debug/tracing/trace_pipe` 文件来查看 eBPF 程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101179: bpf_trace_printk: Process ID: 3840345 enter sys openat
           <...>-3840345 [010] d... 3220702.158000: bpf_trace_printk: Process ID: 3840345 enter sys openat
```

此时，我们已经能够捕获进程打开文件的系统调用了。

## 使用全局变量在 eBPF 中过滤进程 pid

全局变量在 eBPF 程序中充当一种数据共享机制，它们允许用户态程序与 eBPF 程序之间进行数据交互。这在过滤特定条件或修改 eBPF 程序行为时非常有用。这种设计使得用户态程序能够在运行时动态地控制 eBPF 程序的行为。

在我们的例子中，全局变量 `pid_target` 用于过滤进程 PID。用户态程序可以设置此变量的值，以便在 eBPF 程序中只捕获与指定 PID 相关的 `sys_openat` 系统调用。

使用全局变量的原理是，全局变量在 eBPF 程序的数据段（data section）中定义并存储。当 eBPF 程序加载到内核并执行时，这些全局变量会保持在内核中，可以通过 BPF 系统调用进行访问。用户态程序可以使用 BPF 系统调用中的某些特性，如 `bpf_obj_get_info_by_fd` 和 `bpf_obj_get_info`，获取 eBPF 对象的信息，包括全局变量的位置和值。

可以通过执行 ecli -h 命令来查看 opensnoop 的帮助信息：

```console
$ ecli package.json -h
Usage: opensnoop_bpf [--help] [--version] [--verbose] [--pid_target VAR]

Trace open family syscalls.

Optional arguments:
  -h, --help    shows help message and exits 
  -v, --version prints version information and exits 
  --verbose     prints libbpf debug information 
  --pid_target  Process ID to trace 

Built with eunomia-bpf framework.
See https://github.com/eunomia-bpf/eunomia-bpf for more information.
```

可以通过 `--pid_target` 选项来指定要捕获的进程的 pid，例如：

```console
$ sudo ./ecli run package.json --pid_target 618
Runing eBPF program...
```

运行这段程序后，可以通过查看 `/sys/kernel/debug/tracing/trace_pipe` 文件来查看 eBPF 程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101179: bpf_trace_printk: Process ID: 618 enter sys openat
           <...>-3840345 [010] d... 3220702.158000: bpf_trace_printk: Process ID: 618 enter sys openat
```

## 总结

本文介绍了如何使用 eBPF 程序来捕获进程打开文件的系统调用。在 eBPF 程序中，我们可以通过定义 `tracepoint__syscalls__sys_enter_open` 和 `tracepoint__syscalls__sys_enter_openat` 函数并使用 `SEC` 宏把它们附加到 sys_enter_open 和 sys_enter_openat 两个 tracepoint 来捕获进程打开文件的系统调用。我们可以使用 `bpf_get_current_pid_tgid` 函数获取调用 open 或 openat 系统调用的进程 ID，并使用 `bpf_printk` 函数在内核日志中打印出来。在 eBPF 程序中，我们还可以通过定义一个全局变量 `pid_target` 来指定要捕获的进程的 pid，从而过滤输出，只输出指定的进程的信息。

通过学习本教程，您应该对如何在 eBPF 中捕获和过滤特定进程的系统调用有了更深入的了解。这种方法在系统监控、性能分析和安全审计等场景中具有广泛的应用。

更多的例子和详细的开发指南，请参考 eunomia-bpf 的官方文档：<https://github.com/eunomia-bpf/eunomia-bpf>

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。
