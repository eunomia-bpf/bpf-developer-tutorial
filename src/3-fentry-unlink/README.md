# eBPF 入门开发实践教程三：在 eBPF 中使用 fentry 监测捕获 unlink 系统调用

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践教程的第三篇，在 eBPF 中使用 fentry 捕获 unlink 系统调用。

## Fentry

fentry（function entry）和 fexit（function exit）是 eBPF（扩展的伯克利包过滤器）中的两种探针类型，用于在 Linux 内核函数的入口和退出处进行跟踪。它们允许开发者在内核函数执行的特定阶段收集信息、修改参数或观察返回值。这种跟踪和监控功能在性能分析、故障排查和安全分析等场景中非常有用。

与 kprobes 相比，fentry 和 fexit 程序有更高的性能和可用性。在这个例子中，我们可以直接访问函数的指针参数，就像在普通的 C 代码中一样，而不需要使用各种读取帮助程序。fexit 和 kretprobe 程序最大的区别在于，fexit 程序可以访问函数的输入参数和返回值，而 kretprobe 只能访问返回值。从 5.5 内核开始，fentry 和 fexit 对 eBPF 程序可用。

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

这段程序是用 C 语言编写的 eBPF（扩展的伯克利包过滤器）程序，它使用 BPF 的 fentry 和 fexit 探针来跟踪 Linux 内核函数 `do_unlinkat`。在这个教程中，我们将以这段程序作为示例，让您学会如何在 eBPF 中使用 fentry 监测捕获 unlink 系统调用。

程序包含以下部分：

1. 包含头文件：包括 vmlinux.h（用于访问内核数据结构）、bpf/bpf_helpers.h（包含eBPF帮助函数）、bpf/bpf_tracing.h（用于eBPF跟踪相关功能）。
2. 定义许可证：这里定义了一个名为 `LICENSE` 的字符数组，包含许可证信息“Dual BSD/GPL”。
3. 定义 fentry 探针：我们定义了一个名为 `BPF_PROG(do_unlinkat)` 的 fentry 探针，该探针在 `do_unlinkat` 函数的入口处被触发。这个探针获取当前进程的 PID（进程ID）并将其与文件名一起打印到内核日志。
4. 定义 fexit 探针：我们还定义了一个名为 `BPF_PROG(do_unlinkat_exit)` 的 fexit 探针，该探针在 `do_unlinkat` 函数的退出处被触发。与 fentry 探针类似，这个探针也会获取当前进程的 PID 并将其与文件名和返回值一起打印到内核日志。

通过这个示例，您可以学习如何在 eBPF 中使用 fentry 和 fexit 探针来监控和捕获内核函数调用，例如在本教程中的 unlink 系统调用。

eunomia-bpf 是一个结合 Wasm 的开源 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。可以参考 <https://github.com/eunomia-bpf/eunomia-bpf> 下载和安装 ecc 编译工具链和 ecli 运行时。我们使用 eunomia-bpf 编译运行这个例子。

编译运行上述代码：

```console
$ ecc fentry-link.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
$ sudo ecli run package.json
Runing eBPF program...
```

在另外一个窗口中：

```shell
touch test_file
rm test_file
touch test_file2
rm test_file2
```

运行这段程序后，可以通过查看 `/sys/kernel/debug/tracing/trace_pipe` 文件来查看 eBPF 程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9290    [004] d..2  4637.798698: bpf_trace_printk: fentry: pid = 9290, filename = test_file
              rm-9290    [004] d..2  4637.798843: bpf_trace_printk: fexit: pid = 9290, filename = test_file, ret = 0
              rm-9290    [004] d..2  4637.798698: bpf_trace_printk: fentry: pid = 9290, filename = test_file2
              rm-9290    [004] d..2  4637.798843: bpf_trace_printk: fexit: pid = 9290, filename = test_file2, ret = 0
```

## 总结

这段程序是一个 eBPF 程序，通过使用 fentry 和 fexit 捕获 `do_unlinkat` 和 `do_unlinkat_exit` 函数，并通过使用 `bpf_get_current_pid_tgid` 和 `bpf_printk` 函数获取调用 do_unlinkat 的进程的 ID、文件名和返回值，并在内核日志中打印出来。

编译这个程序可以使用 ecc 工具，运行时可以使用 ecli 命令，并通过查看 `/sys/kernel/debug/tracing/trace_pipe` 文件查看 eBPF 程序的输出。更多的例子和详细的开发指南，请参考 eunomia-bpf 的官方文档：<https://github.com/eunomia-bpf/eunomia-bpf>

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。
