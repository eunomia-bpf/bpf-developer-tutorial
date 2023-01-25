# eBPF 入门开发实践教程四：在 eBPF 中捕获进程打开文件的系统调用集合，使用全局变量过滤进程 pid

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具，它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践教程的第四篇，主要介绍如何捕获进程打开文件的系统调用集合，并使用全局变量在 eBPF 中过滤进程 pid。

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
 u32 pid = id;

 if (pid_target && pid_target != pid)
  return false;
 // Use bpf_printk to print the process information
 bpf_printk("Process ID: %d enter sys openat\n", pid);
 return 0;
}

/// "Trace open family syscalls."
char LICENSE[] SEC("license") = "GPL";

```

上面的 eBPF 程序通过定义函数  tracepoint__syscalls__sys_enter_openat 并使用 SEC 宏把它们附加到 sys_enter_openat 的 tracepoint（即在进入 openat 系统调用时执行）。这个函数通过使用 bpf_get_current_pid_tgid 函数获取调用 openat 系统调用的进程 ID，并使用 bpf_printk 函数在内核日志中打印出来。

eunomia-bpf 是一个结合 Wasm 的开源 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。可以参考 <https://github.com/eunomia-bpf/eunomia-bpf> 下载和安装 ecc 编译工具链和 ecli 运行时。我们使用 eunomia-bpf 编译运行这个例子。

编译运行上述代码：

```console
$ ecc fentry-link.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
$ sudo ecli package.json
Runing eBPF program...
```

运行这段程序后，可以通过查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看 eBPF 程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101179: bpf_trace_printk: Process ID: 3840345 enter sys openat
           <...>-3840345 [010] d... 3220702.158000: bpf_trace_printk: Process ID: 3840345 enter sys openat
```

此时，我们已经能够捕获进程打开文件的系统调用了。

## 使用全局变量在 eBPF 中过滤进程 pid

在上面的程序中，我们定义了一个全局变量 pid_target 来指定要捕获的进程的 pid。在 tracepoint__syscalls__sys_enter_open 和 tracepoint__syscalls__sys_enter_openat 函数中，我们可以使用这个全局变量来过滤输出，只输出指定的进程的信息。

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

可以通过 --pid_target 参数来指定要捕获的进程的 pid，例如：

```console
$ sudo ./ecli run package.json  --pid_target 618
Runing eBPF program...
```

运行这段程序后，可以通过查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看 eBPF 程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101179: bpf_trace_printk: Process ID: 618 enter sys openat
           <...>-3840345 [010] d... 3220702.158000: bpf_trace_printk: Process ID: 618 enter sys openat
```

## 总结

本文介绍了如何使用 eBPF 程序来捕获进程打开文件的系统调用。在 eBPF 程序中，我们可以通过定义 tracepoint__syscalls__sys_enter_open 和 tracepoint__syscalls__sys_enter_openat 函数并使用 SEC 宏把它们附加到 sys_enter_open 和 sys_enter_openat 两个 tracepoint 来捕获进程打开文件的系统调用。我们可以使用 bpf_get_current_pid_tgid 函数获取调用 open 或 openat 系统调用的进程 ID，并使用 bpf_printk 函数在内核日志中打印出来。在 eBPF 程序中，我们还可以通过定义一个全局变量 pid_target 来指定要捕获的进程的 pid，从而过滤输出，只输出指定的进程的信息。

更多的例子和详细的开发指南，请参考 eunomia-bpf 的官方文档：<https://github.com/eunomia-bpf/eunomia-bpf>

完整的教程和源代码已经全部开源，可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 中查看。
