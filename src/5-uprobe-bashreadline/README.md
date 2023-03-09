# eBPF 入门开发实践教程五：在 eBPF 中使用  uprobe 捕获 bash 的 readline 函数调用

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具，它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践教程的第五篇，主要介绍如何使用 uprobe 捕获 bash 的 readline 函数调用。

## 什么是uprobe

uprobe是一种用户空间探针，uprobe探针允许在用户空间程序中动态插桩，插桩位置包括：函数入口、特定偏移处，以及函数返回处。当我们定义uprobe时，内核会在附加的指令上创建快速断点指令（x86机器上为int3指令），当程序执行到该指令时，内核将触发事件，程序陷入到内核态，并以回调函数的方式调用探针函数，执行完探针函数再返回到用户态继续执行后序的指令。

uprobe基于文件，当一个二进制文件中的一个函数被跟踪时，所有使用到这个文件的进程都会被插桩，包括那些尚未启动的进程，这样就可以在全系统范围内跟踪系统调用。

uprobe适用于在用户态去解析一些内核态探针无法解析的流量，例如http2流量（报文header被编码，内核无法解码），https流量（加密流量，内核无法解密）。

## 使用 uprobe 捕获 bash 的 readline 函数调用

uprobe 是一种用于捕获用户空间函数调用的 eBPF 的探针，我们可以通过它来捕获用户空间程序调用的系统函数。

例如，我们可以使用 uprobe 来捕获 bash 的 readline 函数调用，从而获取用户在 bash 中输入的命令行。示例代码如下：

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

/* Format of u[ret]probe section definition supporting auto-attach:
 * u[ret]probe/binary:function[+offset]
 *
 * binary can be an absolute/relative path or a filename; the latter is resolved to a
 * full binary path via bpf_program__attach_uprobe_opts.
 *
 * Specifying uprobe+ ensures we carry out strict matching; either "uprobe" must be
 * specified (and auto-attach is not possible) or the above format is specified for
 * auto-attach.
 */
SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const void *ret)
{
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

接下来，我们需要使用 BPF_KRETPROBE 宏来定义探针函数，例如：

```c
BPF_KRETPROBE(printret, const void *ret)
```

这里的 printret 是探针函数的名称，const void *ret 是探针函数的参数，它代表被捕获的函数的返回值。

eunomia-bpf 是一个结合 Wasm 的开源 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。可以参考 <https://github.com/eunomia-bpf/eunomia-bpf> 下载和安装 ecc 编译工具链和 ecli 运行时。我们使用 eunomia-bpf 编译运行这个例子。

编译运行上述代码：

```console
$ ecc bashreadline.bpf.c bashreadline.h
Compiling bpf object...
Packing ebpf object and config into package.json...
$ sudo ecli package.json
Runing eBPF program...
```

运行这段程序后，可以通过查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看 eBPF 程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            bash-32969   [000] d..31 64001.375748: bpf_trace_printk: PID 32969 (bash) read: fff 
            bash-32969   [000] d..31 64002.056951: bpf_trace_printk: PID 32969 (bash) read: fff
```

可以看到，我们成功的捕获了 bash 的 readline 函数调用，并获取了用户在 bash 中输入的命令行。

## 总结

在上述代码中，我们使用了 SEC 宏来定义了一个 uprobe 探针，它指定了要捕获的用户空间程序 (bin/bash) 和要捕获的函数 (readline)。此外，我们还使用了 BPF_KRETPROBE 宏来定义了一个用于处理 readline 函数返回值的回调函数 (printret)。该函数可以获取到 readline 函数的返回值，并将其打印到内核日志中。通过这样的方式，我们就可以使用 eBPF 来捕获 bash 的 readline 函数调用，并获取用户在 bash 中输入的命令行。

更多的例子和详细的开发指南，请参考 eunomia-bpf 的官方文档：<https://github.com/eunomia-bpf/eunomia-bpf>

完整的教程和源代码已经全部开源，可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 中查看。
