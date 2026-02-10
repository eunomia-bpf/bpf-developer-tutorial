# eBPF 入门开发实践教程三：在 eBPF 中使用 fentry 监测捕获 unlink 系统调用

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践教程的第三篇，在 eBPF 中使用 fentry 捕获 unlink 系统调用。

## Fentry

fentry（function entry）和 fexit（function exit）是 eBPF（扩展的伯克利包过滤器）中的两种探针类型，用于在 Linux 内核函数的入口和退出处进行跟踪。它们允许开发者在内核函数执行的特定阶段收集信息、修改参数或观察返回值。这种跟踪和监控功能在性能分析、故障排查和安全分析等场景中非常有用。

与 kprobes 相比，fentry 和 fexit 程序有更高的性能和可用性。它们的运行速度大约是 kprobes 的 10 倍，因为使用了 BPF trampoline 机制而不是基于断点的旧方法。在这个例子中，我们可以直接访问函数的指针参数，就像在普通的 C 代码中一样，而不需要使用 `BPF_CORE_READ` 这样的读取帮助程序。

fexit 和 kretprobe 程序最大的区别在于，fexit 程序可以同时访问函数的输入参数和返回值，而 kretprobe 只能访问返回值。这让你可以在一个地方看到完整的函数执行情况。从 5.5 内核开始（x86），fentry 和 fexit 对 eBPF 程序可用。

> arm64 内核版本需要 6.0
>
> 参考 learning eBPF 文档：
>
> 从内核版本 5.5 开始（适用于 x86 处理器；*BPF trampoline* 支持在 Linux 6.0 之前不适用于 ARM 处理器），引入了一种更高效的机制来跟踪进入和退出内核函数的方式以及 *BPF trampoline* 的概念。如果您正在使用足够新的内核，fentry/fexit 现在是首选的跟踪进入或退出内核函数的方法。
> 
> 参考：https://kernelnewbies.org/Linux_6.0#ARM





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

这段程序是用 C 语言编写的 eBPF 程序，它使用 BPF 的 fentry 和 fexit 探针来跟踪 Linux 内核函数 `do_unlinkat`。

让我们看看代码的工作原理。首先我们包含了必要的头文件：vmlinux.h 用于访问内核数据结构，bpf_helpers.h 包含 eBPF 帮助函数，bpf_tracing.h 用于跟踪相关功能。然后定义了许可证信息 "Dual BSD/GPL"，这是内核加载 eBPF 程序所必需的。

fentry 探针附加到 `do_unlinkat` 函数的入口点。注意我们可以直接访问 `name->name` 而不需要任何特殊的帮助函数——这是使用 fentry 而不是 kprobes 的好处之一。我们获取当前进程 PID，然后将其与文件名一起打印到内核日志。

fexit 探针在函数返回时触发，可以同时访问原始参数（dfd 和 name）和返回值（ret）。这让你可以完整地看到函数做了什么。如果 ret 是 0，文件删除成功；如果是负数，说明出错了，你可以看到错误代码。

我们使用 eunomia-bpf 来编译和运行这个示例。你可以从 <https://github.com/eunomia-bpf/eunomia-bpf> 安装它。

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

## 故障排查

如果您在运行此示例时遇到错误，以下是一些常见问题和解决方案：

### 错误："failed to attach: ERROR: strerror_r(-524)=22"

此错误（错误代码 -524 = ENOTSUPP）通常表示您的内核不支持 fentry/fexit。以下是排查方法：

**1. 检查内核版本：**

```console
$ uname -r
```

您需要：
- x86/x86_64 处理器需要内核 5.5 或更高版本
- ARM/ARM64 处理器需要内核 6.0 或更高版本

如果您的内核版本过旧，您有两个选择：
- 将内核升级到支持的版本
- 使用 kprobe 示例代替（参见 [示例 2-kprobe-unlink](../2-kprobe-unlink/)）

**2. 验证 BTF（BPF Type Format）支持：**

fentry/fexit 需要 BTF 支持。检查是否已启用：

```console
$ cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF
CONFIG_DEBUG_INFO_BTF=y
```

如果 BTF 未启用，您需要：
- 使用已启用 BTF 支持的内核
- 使用 kprobe 示例作为替代方案

**3. 检查内核函数是否存在：**

`do_unlinkat` 函数在某些内核版本中可能有不同的名称或未导出。您可以检查可用的函数：

```console
$ sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep unlink
```

如果未列出 `do_unlinkat`，则该函数可能在您的内核上无法用于跟踪。

**4. 验证内核配置：**

确保您的内核编译时包含了必要的 eBPF 功能：

```console
$ cat /boot/config-$(uname -r) | grep BPF
```

查找这些重要设置：
- `CONFIG_BPF=y`
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_BPF_JIT=y`

如果检查这些项目后仍然遇到问题，请通过运行以下命令报告您的内核版本和操作系统发行版：

```console
$ uname -a
$ cat /etc/os-release
```

## 总结

这段程序是一个 eBPF 程序，通过使用 fentry 和 fexit 捕获 `do_unlinkat` 和 `do_unlinkat_exit` 函数，并通过使用 `bpf_get_current_pid_tgid` 和 `bpf_printk` 函数获取调用 do_unlinkat 的进程的 ID、文件名和返回值，并在内核日志中打印出来。

编译这个程序可以使用 ecc 工具，运行时可以使用 ecli 命令，并通过查看 `/sys/kernel/debug/tracing/trace_pipe` 文件查看 eBPF 程序的输出。

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。
