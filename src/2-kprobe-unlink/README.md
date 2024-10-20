# eBPF Tutorial by Example 2: Monitoring unlink System Calls with kprobe

eBPF (Extended Berkeley Packet Filter) is a powerful network and performance analysis tool on the Linux kernel. It allows developers to dynamically load, update, and run user-defined code at runtime.

This article is the second part of the eBPF Tutorial by Example, focusing on using kprobe to capture the unlink system call in eBPF. The article will first explain the basic concepts and technical background of kprobes, and then introduce how to use kprobe to capture the unlink system call in eBPF.

## Background of kprobes Technology

During the debugging process of the kernel or modules, developers often need to know whether certain functions are called, when they are called, whether the execution is correct, and what the input and return values of the functions are. A simple approach is to add log print information to the corresponding functions in the kernel code. However, this approach often requires recompiling the kernel or modules, restarting the device, etc., which is complex and may disrupt the original code execution process.

By using the kprobes technology, users can define their own callback functions and dynamically insert probes into almost all functions in the kernel or modules (some functions cannot be probed, such as the kprobes' own implementation functions, which will be explained in detail later). When the kernel execution flow reaches the specified probe function, it will invoke the callback function, allowing the user to collect the desired information. The kernel will then return to the normal execution flow. If the user has collected sufficient information and no longer needs to continue probing, the probes can be dynamically removed. Therefore, the kprobes technology has the advantages of minimal impact on the kernel execution flow and easy operation.

The kprobes technology includes three detection methods: kprobe, jprobe, and kretprobe. First, kprobe is the most basic detection method and serves as the basis for the other two. It allows probes to be placed at any position (including within a function). It provides three callback modes for probes: `pre_handler`, `post_handler`, and `fault_handler`. The `pre_handler` function is called before the probed instruction is executed, the `post_handler` is called after the probed instruction is completed (note that it is not the probed function), and the `fault_handler` is called when a memory access error occurs. The jprobe is based on kprobe and is used to obtain the input values of the probed function. Finally, as the name suggests, kretprobe is also based on kprobe and is used to obtain the return values of the probed function.

The kprobes technology is not only implemented through software but also requires support from the hardware architecture. This involves CPU exception handling and single-step debugging techniques. The former is used to make the program's execution flow enter the user-registered callback function, and the latter is used to single-step execute the probed instruction. Therefore, not all architectures support kprobes. Currently, kprobes technology supports various architectures, including i386, x86_64, ppc64, ia64, sparc64, arm, ppc, and mips (note that some architecture implementations may not be complete, see the kernel's Documentation/kprobes.txt for details).

Features and Usage Restrictions of kprobes:

1. kprobes allows multiple kprobes to be registered at the same probe position, but jprobe currently does not support this. It is also not allowed to use other jprobe callback functions or the `post_handler` callback function of kprobe as probe points.
2. In general, any function in the kernel can be probed, including interrupt handlers. However, the functions used to implement kprobes themselves in kernel/kprobes.c and arch/*/kernel/kprobes.c are not allowed to be probed. Additionally, `do_page_fault` and `notifier_call_chain` are also not allowed.
3. If an inline function is used as a probe point, kprobes may not be able to guarantee that probe points are registered for all instances of that function. Since gcc may automatically optimize certain functions as inline functions, the desired probing effect may not be achieved.
4. The callback function of a probe point may modify the runtime context of the probed function, such as by modifying the kernel's data structure or saving register information before triggering the prober in the `struct pt_regs` structure. Therefore, kprobes can be used to install bug fixes or inject fault testing code.
5. kprobes avoids calling the callback function of another probe point again when processing the probe point function. For example, if a probe point is registered on the `printk()` function and the callback function may call `printk()` again, the callback for the `printk` probe point will not be triggered again. Only the `nmissed` field in the `kprobe` structure will be incremented.
6. mutex locks and dynamic memory allocation are not used in the registration and removal process of kprobes.

7. During the execution of kprobes callback functions, kernel preemption is disabled, and it may also be executed with interrupts disabled, which depends on the CPU architecture. Therefore, regardless of the situation, do not call functions that will give up the CPU in the callback function (such as semaphore, mutex lock, etc.);
8. kretprobe is implemented by replacing the return address with the pre-defined trampoline address, so stack backtraces and gcc inline function `__builtin_return_address()` will return the address of the trampoline instead of the actual return address of the probed function;
9. If the number of function calls and return calls of a function are unequal, registering kretprobe on such a function may not achieve the expected effect, for example, the `do_exit()` function will have problems, while the `do_execve()` function and `do_fork()` function will not;
10. When entering and exiting a function, if the CPU is running on a stack that does not belong to the current task, registering kretprobe on that function may have unpredictable consequences. Therefore, kprobes does not support registering kretprobe for the `__switch_to()` function under the X86_64 architecture and will directly return `-EINVAL`.

## kprobe Example

The complete code is as follows:

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

This code is a simple eBPF program used to monitor and capture the unlink system call executed in the Linux kernel. The unlink system call is used to delete a file. This eBPF program traces this system call by placing hooks at the entry and exit points of the `do_unlinkat` function using a kprobe (kernel probe).

First, we import necessary header files such as vmlinux.h, bpf_helpers.h, bpf_tracing.h, and bpf_core_read.h. Then, we define a license to allow the program to run in the kernel.

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

Next, we define a kprobe named `BPF_KPROBE(do_unlinkat)` which gets triggered when the `do_unlinkat` function is entered. It takes two parameters: `dfd` (file descriptor) and `name` (filename structure pointer). In this kprobe, we retrieve the PID (process identifier) of the current process and then read the filename. Finally, we use the `bpf_printk` function to print the PID and filename in the kernel log.

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

Next, we define a kretprobe named `BPF_KRETPROBE(do_unlinkat_exit)` that will be triggered when exiting the `do_unlinkat` function. The purpose of this kretprobe is to capture the return value (`ret`) of the function. We again obtain the PID of the current process and use the `bpf_printk` function to print the PID and return value in the kernel log.

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

eunomia-bpf is an open-source eBPF dynamic loading runtime and development toolchain that combines with Wasm. Its goal is to simplify the development, build, distribution, and execution of eBPF programs. You can refer to <https://github.com/eunomia-bpf/eunomia-bpf> to download and install the ecc compiler toolchain and ecli runtime.

To compile this program, use the ecc tool:

```console
$ ecc kprobe-link.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

Then run:

```console
sudo ecli run package.json
```

In another window:

```shell
touch test1
rm test1
touch test2
rm test2
```

You should see kprobe demo output similar to the following in the /sys/kernel/debug/tracing/trace_pipe file:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9346    [005] d..3  4710.951696: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test1
              rm-9346    [005] d..4  4710.951819: bpf_trace_printk: KPROBE EXIT: ret = 0
              rm-9346    [005] d..3  4710.951852: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test2
              rm-9346    [005] d..4  4710.951895: bpf_trace_printk: KPROBE EXIT: ret = 0
```

## Summary

In this article's example, we learned how to use eBPF's kprobe and kretprobe to capture the unlink system call. For more examples and detailed development guides, please refer to the official documentation of eunomia-bpf: <https://github.com/eunomia-bpf/eunomia-bpf>

This article is the second part of the introductory eBPF development tutorial. The next article will explain how to use fentry to monitor and capture the unlink system call in eBPF.

If you'd like to learn more about eBPF knowledge and practices, you can visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials.
