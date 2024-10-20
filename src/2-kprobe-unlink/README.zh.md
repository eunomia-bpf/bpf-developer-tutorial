# eBPF 入门开发实践教程二：在 eBPF 中使用 kprobe 监测捕获 unlink 系统调用

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践教程的第二篇，在 eBPF 中使用 kprobe 捕获 unlink 系统调用。本文会先讲解关于 kprobes 的基本概念和技术背景，然后介绍如何在 eBPF 中使用 kprobe 捕获 unlink 系统调用。

## kprobes 技术背景

开发人员在内核或者模块的调试过程中，往往会需要要知道其中的一些函数有无被调用、何时被调用、执行是否正确以及函数的入参和返回值是什么等等。比较简单的做法是在内核代码对应的函数中添加日志打印信息，但这种方式往往需要重新编译内核或模块，重新启动设备之类的，操作较为复杂甚至可能会破坏原有的代码执行过程。

而利用 kprobes 技术，用户可以定义自己的回调函数，然后在内核或者模块中几乎所有的函数中（有些函数是不可探测的，例如kprobes自身的相关实现函数，后文会有详细说明）动态地插入探测点，当内核执行流程执行到指定的探测函数时，会调用该回调函数，用户即可收集所需的信息了，同时内核最后还会回到原本的正常执行流程。如果用户已经收集足够的信息，不再需要继续探测，则同样可以动态地移除探测点。因此 kprobes 技术具有对内核执行流程影响小和操作方便的优点。

kprobes 技术包括的3种探测手段分别时 kprobe、jprobe 和 kretprobe。首先 kprobe 是最基本的探测方式，是实现后两种的基础，它可以在任意的位置放置探测点（就连函数内部的某条指令处也可以），它提供了探测点的调用前、调用后和内存访问出错3种回调方式，分别是 `pre_handler`、`post_handler` 和 `fault_handler`，其中 `pre_handler` 函数将在被探测指令被执行前回调，`post_handler` 会在被探测指令执行完毕后回调（注意不是被探测函数），`fault_handler` 会在内存访问出错时被调用；jprobe 基于 kprobe 实现，它用于获取被探测函数的入参值；最后 kretprobe 从名字中就可以看出其用途了，它同样基于 kprobe 实现，用于获取被探测函数的返回值。

kprobes 的技术原理并不仅仅包含纯软件的实现方案，它也需要硬件架构提供支持。其中涉及硬件架构相关的是 CPU 的异常处理和单步调试技术，前者用于让程序的执行流程陷入到用户注册的回调函数中去，而后者则用于单步执行被探测点指令，因此并不是所有的架构均支持 kprobes。目前 kprobes 技术已经支持多种架构，包括 i386、x86_64、ppc64、ia64、sparc64、arm、ppc 和 mips（有些架构实现可能并不完全，具体可参考内核的 Documentation/kprobes.txt）。

kprobes 的特点与使用限制：

1. kprobes 允许在同一个被探测位置注册多个 kprobe，但是目前 jprobe 却不可以；同时也不允许以其他的 jprobe 回调函数和 kprobe 的 `post_handler` 回调函数作为被探测点。
2. 一般情况下，可以探测内核中的任何函数，包括中断处理函数。不过在 kernel/kprobes.c 和 arch/*/kernel/kprobes.c 程序中用于实现 kprobes 自身的函数是不允许被探测的，另外还有`do_page_fault` 和 `notifier_call_chain`；
3. 如果以一个内联函数为探测点，则 kprobes 可能无法保证对该函数的所有实例都注册探测点。由于 gcc 可能会自动将某些函数优化为内联函数，因此可能无法达到用户预期的探测效果；
4. 一个探测点的回调函数可能会修改被探测函数的运行上下文，例如通过修改内核的数据结构或者保存与`struct pt_regs`结构体中的触发探测器之前寄存器信息。因此 kprobes 可以被用来安装 bug 修复代码或者注入故障测试代码；
5. kprobes 会避免在处理探测点函数时再次调用另一个探测点的回调函数，例如在`printk()`函数上注册了探测点，而在它的回调函数中可能会再次调用`printk`函数，此时将不再触发`printk`探测点的回调，仅仅是增加了`kprobe`结构体中`nmissed`字段的数值；
6. 在 kprobes 的注册和注销过程中不会使用 mutex 锁和动态的申请内存；
7. kprobes 回调函数的运行期间是关闭内核抢占的，同时也可能在关闭中断的情况下执行，具体要视CPU架构而定。因此不论在何种情况下，在回调函数中不要调用会放弃 CPU 的函数（如信号量、mutex 锁等）；
8. kretprobe 通过替换返回地址为预定义的 trampoline 的地址来实现，因此栈回溯和 gcc 内嵌函数`__builtin_return_address()`调用将返回 trampoline 的地址而不是真正的被探测函数的返回地址；
9. 如果一个函数的调用次数和返回次数不相等，则在类似这样的函数上注册 kretprobe 将可能不会达到预期的效果，例如`do_exit()`函数会存在问题，而`do_execve()`函数和`do_fork()`函数不会；
10. 当在进入和退出一个函数时，如果 CPU 运行在非当前任务所有的栈上，那么往该函数上注册 kretprobe 可能会导致不可预料的后果，因此，kprobes 不支持在 X86_64 的结构下为`__switch_to()`函数注册 kretprobe，将直接返回`-EINVAL`。

## kprobe 示例

完整代码如下：

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

这段代码是一个简单的 eBPF 程序，用于监测和捕获在 Linux 内核中执行的 unlink 系统调用。unlink 系统调用的功能是删除一个文件，这个 eBPF 程序通过使用 kprobe（内核探针）在`do_unlinkat`函数的入口和退出处放置钩子，实现对该系统调用的跟踪。

首先，我们导入必要的头文件，如 vmlinux.h，bpf_helpers.h，bpf_tracing.h 和 bpf_core_read.h。接着，我们定义许可证，以允许程序在内核中运行。

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

接下来，我们定义一个名为`BPF_KPROBE(do_unlinkat)`的 kprobe，当进入`do_unlinkat`函数时，它会被触发。该函数接受两个参数：`dfd`（文件描述符）和`name`（文件名结构体指针）。在这个 kprobe 中，我们获取当前进程的 PID（进程标识符），然后读取文件名。最后，我们使用`bpf_printk`函数在内核日志中打印 PID 和文件名。

```c
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
```

接下来，我们定义一个名为`BPF_KRETPROBE(do_unlinkat_exit)`的 kretprobe，当从`do_unlinkat`函数退出时，它会被触发。这个 kretprobe 的目的是捕获函数的返回值（ret）。我们再次获取当前进程的 PID，并使用`bpf_printk`函数在内核日志中打印 PID 和返回值。

```c
SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}
```

eunomia-bpf 是一个结合 Wasm 的开源 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。可以参考 <https://github.com/eunomia-bpf/eunomia-bpf> 下载和安装 ecc 编译工具链和 ecli 运行时。

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

在另外一个窗口中：

```shell
touch test1
rm test1
touch test2
rm test2
```

在 /sys/kernel/debug/tracing/trace_pipe 文件中，应该能看到类似下面的 kprobe 演示输出：

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9346    [005] d..3  4710.951696: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test1
              rm-9346    [005] d..4  4710.951819: bpf_trace_printk: KPROBE EXIT: ret = 0
              rm-9346    [005] d..3  4710.951852: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test2
              rm-9346    [005] d..4  4710.951895: bpf_trace_printk: KPROBE EXIT: ret = 0
```

## 总结

通过本文的示例，我们学习了如何使用 eBPF 的 kprobe 和 kretprobe 捕获 unlink 系统调用。更多的例子和详细的开发指南，请参考 eunomia-bpf 的官方文档：<https://github.com/eunomia-bpf/eunomia-bpf>

本文是 eBPF 入门开发实践教程的第二篇。下一篇文章将介绍如何在 eBPF 中使用 fentry 监测捕获 unlink 系统调用。

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。
