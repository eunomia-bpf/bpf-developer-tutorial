# eBPF Tutorial by Example 3: Monitoring unlink System Calls with fentry

eBPF (Extended Berkeley Packet Filter) is a powerful network and performance analysis tool on the Linux kernel. It allows developers to dynamically load, update, and execute user-defined code at runtime in the kernel.

This article is the third part of the eBPF Tutorial by Example, focusing on capturing unlink system calls using fentry in eBPF.

## What is fentry and Why Use It?

fentry (function entry) and fexit (function exit) are the modern way to trace kernel functions in eBPF. They were introduced in kernel 5.5 for x86 processors and 6.0 for ARM processors. Think of them as the faster, more efficient successors to kprobes.

The big advantage of fentry/fexit over kprobes is performance and convenience. With fentry, you can directly access function parameters just like in regular C code - no need for special helpers like `BPF_CORE_READ`. This makes your code simpler and faster. fexit gives you an extra bonus - you can access both the input parameters and the return value at the same time, while kretprobe only gives you the return value.

The performance difference is real. fentry/fexit programs run about 10x faster than kprobes because they use a BPF trampoline mechanism instead of the older breakpoint-based approach. If you're building production monitoring tools that run on every function call, this matters a lot.

Note that if you're on ARM, you'll need kernel 6.0 or newer. For x86, kernel 5.5+ works fine. If you're stuck on an older kernel, you'll need to use kprobes instead.





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

Let's break down how this program works. The fentry probe attaches to the entry of `do_unlinkat` and can access the function's parameters directly. Notice how we access `name->name` without any special helpers - this is one of the benefits of using fentry instead of kprobes.

The fexit probe is even more interesting. It gets triggered when the function returns, and it can access both the original parameters (dfd and name) and the return value (ret). This gives you complete visibility into what the function did. If ret is 0, the file was successfully deleted. If it's negative, something went wrong and you can see the error code.

The `BPF_PROG` macro is similar to `BPF_KPROBE` from the previous tutorial, but it's designed for fentry/fexit. It handles the parameter unwrapping automatically so you can focus on your logic.

We use eunomia-bpf to compile and run this example. You can install it from <https://github.com/eunomia-bpf/eunomia-bpf>.

To compile and run the above code:

```console
$ ecc fentry-link.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
$ sudo ecli run package.json
Running eBPF program...
```

In another window:

```shell
touch test_file
rm test_file
touch test_file2
rm test_file2
```

After running this program, you can view the output of the eBPF program by examining the `/sys/kernel/debug/tracing/trace_pipe` file:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9290    [004] d..2  4637.798698: bpf_trace_printk: fentry: pid = 9290, filename = test_file
              rm-9290    [004] d..2  4637.798843: bpf_trace_printk: fexit: pid = 9290, filename = test_file, ret = 0
              rm-9290    [004] d..2  4637.798698: bpf_trace_printk: fentry: pid = 9290, filename = test_file2
              rm-9290    [004] d..2  4637.798843: bpf_trace_printk: fexit: pid = 9290, filename = test_file2, ret = 0
```

## Troubleshooting

If you encounter errors when running this example, here are some common issues and solutions:

### Error: "failed to attach: ERROR: strerror_r(-524)=22"

This error (error code -524 = ENOTSUPP) typically means your kernel doesn't support fentry/fexit. Here's how to troubleshoot:

**1. Check your kernel version:**

```console
$ uname -r
```

You need:
- Kernel 5.5 or newer for x86/x86_64 processors
- Kernel 6.0 or newer for ARM/ARM64 processors

If your kernel is too old, you have two options:
- Upgrade your kernel to a supported version
- Use the kprobe example instead (see [example 2-kprobe-unlink](../2-kprobe-unlink/))

**2. Verify BTF (BPF Type Format) support:**

BTF is required for fentry/fexit to work. Check if it's enabled:

```console
$ cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF
CONFIG_DEBUG_INFO_BTF=y
```

If BTF is not enabled, you'll need to either:
- Use a kernel with BTF support enabled
- Use the kprobe example as an alternative

**3. Check if the kernel function exists:**

The function `do_unlinkat` may have a different name or may not be exported in some kernel versions. You can check available functions:

```console
$ sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep unlink
```

If `do_unlinkat` is not listed, the function may not be available for tracing on your kernel.

**4. Verify your kernel configuration:**

Ensure your kernel was compiled with the necessary eBPF features:

```console
$ cat /boot/config-$(uname -r) | grep BPF
```

Look for these important settings:
- `CONFIG_BPF=y`
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_BPF_JIT=y`

If you're still experiencing issues after checking these items, please report your kernel version and OS distribution by running:

```console
$ uname -a
$ cat /etc/os-release
```

## Summary

This program is an eBPF program that captures the `do_unlinkat` and `do_unlinkat_exit` functions using fentry and fexit, and uses `bpf_get_current_pid_tgid` and `bpf_printk` functions to obtain the ID, filename, and return value of the process calling do_unlinkat, and print them in the kernel log.

To compile this program, you can use the ecc tool, and to run it, you can use the ecli command, and view the output of the eBPF program by checking the `/sys/kernel/debug/tracing/trace_pipe` file.

If you'd like to learn more about eBPF knowledge and practices, you can visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials.
