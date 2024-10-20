# eBPF Tutorial by Example 3: Monitoring unlink System Calls with fentry

eBPF (Extended Berkeley Packet Filter) is a powerful network and performance analysis tool on the Linux kernel. It allows developers to dynamically load, update, and execute user-defined code at runtime in the kernel.

This article is the third part of the eBPF Tutorial by Example, focusing on capturing unlink system calls using fentry in eBPF.

## Fentry

fentry (function entry) and fexit (function exit) are two types of probes in eBPF (Extended Berkeley Packet Filter) used for tracing at the entry and exit points of Linux kernel functions. They allow developers to collect information, modify parameters, or observe return values at specific stages of kernel function execution. This tracing and monitoring functionality is very useful in performance analysis, troubleshooting, and security analysis scenarios.

Compared to kprobes, fentry and fexit programs have higher performance and availability. In this example, we can directly access the pointers to the functions' parameters, just like in regular C code, without needing various read helpers. The main difference between fexit and kretprobe programs is that fexit programs can access both the input parameters and return values of a function, while kretprobe programs can only access the return value. Starting from the 5.5 kernel, fentry and fexit are available for eBPF programs.

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

This program is an eBPF (Extended Berkeley Packet Filter) program written in the C language. It uses BPF fentry and fexit probes to trace the Linux kernel function `do_unlinkat`. In this tutorial, we will use this program as an example to learn how to use fentry in eBPF to detect and capture unlink system calls.

The program consists of the following parts:

1. Include header files: including vmlinux.h (for accessing kernel data structures), bpf/bpf_helpers.h (which includes eBPF helper functions), bpf/bpf_tracing.h (for eBPF tracing-related functionalities).
2. Define license: Here, a character array named `LICENSE` is defined, containing the license information "Dual BSD/GPL".
3. Define fentry probe: We define an fentry probe named `BPF_PROG(do_unlinkat)` that is triggered at the entry point of the `do_unlinkat` function. This probe retrieves the PID (Process ID) of the current process and prints it along with the filename to the kernel log.
4. Define fexit probe: We also define an fexit probe named `BPF_PROG(do_unlinkat_exit)` that is triggered at the exit point of the `do_unlinkat` function. Similar to the fentry probe, this probe also retrieves the PID of the current process and prints it along with the filename and return value to the kernel log.

Through this example, you can learn how to use fentry and fexit probes in eBPF to monitor and capture kernel function calls, such as the unlink system call in this tutorial. "eunomia-bpf is an open source eBPF dynamic loading runtime and development toolchain combined with Wasm. Its goal is to simplify the development, building, distribution, and running of eBPF programs. You can refer to [here](https://github.com/eunomia-bpf/eunomia-bpf) to download and install the ecc compilation toolchain and ecli runtime. We use eunomia-bpf to compile and run this example.

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

## Summary

This program is an eBPF program that captures the `do_unlinkat` and `do_unlinkat_exit` functions using fentry and fexit, and uses `bpf_get_current_pid_tgid` and `bpf_printk` functions to obtain the ID, filename, and return value of the process calling do_unlinkat, and print them in the kernel log.

To compile this program, you can use the ecc tool, and to run it, you can use the ecli command, and view the output of the eBPF program by checking the `/sys/kernel/debug/tracing/trace_pipe` file.

If you'd like to learn more about eBPF knowledge and practices, you can visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials.
