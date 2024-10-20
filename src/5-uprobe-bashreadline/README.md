# eBPF Tutorial by Example 5: Capturing readline Function Calls with Uprobe

eBPF (Extended Berkeley Packet Filter) is a powerful network and performance analysis tool on the Linux kernel that allows developers to dynamically load, update, and run user-defined code at runtime.

This article is the fifth part of the eBPF Tutorial by Example, which mainly introduces how to capture readline function calls in bash using uprobe.

## What is uprobe

uprobe is a user-space probe that allows dynamic instrumentation in user-space programs. The probe locations include function entry, specific offsets, and function returns. When we define an uprobe, the kernel creates fast breakpoint instructions (int3 instructions on x86 machines) on the attached instructions. When the program executes this instruction, the kernel triggers an event, causing the program to enter kernel mode and call the probe function through a callback function. After executing the probe function, the program returns to user mode to continue executing subsequent instructions.

uprobe is file-based. When a function in a binary file is traced, all processes that use the file are instrumented, including those that have not yet been started, allowing system calls to be tracked system-wide.

uprobe is suitable for parsing some traffic in user mode that cannot be resolved by kernel mode probes, such as HTTP/2 traffic (where the header is encoded and cannot be decoded by the kernel) and HTTPS traffic (which is encrypted and cannot be decrypted by the kernel). For more information, see the example in [eBPF Tutorial by Example: Capturing SSL/TLS Plaintext Data from Multiple Libraries with Uprobe](../30-sslsniff/README.md).

Uprobe in kernel mode eBPF runtime may also cause relatively large performance overhead. In this case, you can also consider using user mode eBPF runtime, such as [bpftime](https://github.com/eunomia-bpf/bpftime). bpftime is a user mode eBPF runtime based on LLVM JIT/AOT. It can run eBPF programs in user mode and is compatible with kernel mode eBPF, avoiding context switching between kernel mode and user mode, thereby improving the execution efficiency of eBPF programs by 10 times.

## Capturing readline Function Calls in bash using uprobe

uprobe is an eBPF probe used to capture user-space function calls, allowing us to capture system functions called by user-space programs.

For example, we can use uprobe to capture readline function calls in bash and get the command line input from the user. The example code is as follows:

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

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

The purpose of this code is to execute the specified BPF_PROBE function (printret function) when the readline function in bash returns.

In the printret function, we first obtain the process name and process ID of the process calling the readline function. Then, we use the bpf_probe_read_user_str function to read the user input command line string. Lastly, we use the bpf_printk function to print the process ID, process name, and input command line string.

In addition, we also need to define the uprobe probe using the SEC macro and define the probe function using the BPF_KRETPROBE macro.In the `SEC` macro in the code above, we need to specify the type of the uprobe, the path of the binary file to capture, and the name of the function to capture. For example, the definition of the `SEC` macro in the code above is as follows:

```c
SEC("uprobe//bin/bash:readline")
```

This indicates that we want to capture the `readline` function in the `/bin/bash` binary file.

Next, we need to use the `BPF_KRETPROBE` macro to define the probe function. For example:

```c
BPF_KRETPROBE(printret, const void *ret)
```

Here, `printret` is the name of the probe function, and `const void *ret` is the parameter of the probe function, which represents the return value of the captured function.

Then, we use the `bpf_get_current_comm` function to get the name of the current task and store it in the `comm` array.

```c
bpf_get_current_comm(&comm, sizeof(comm));
```

We use the `bpf_get_current_pid_tgid` function to get the PID of the current process and store it in the `pid` variable.

```c
pid = bpf_get_current_pid_tgid() >> 32;
```

We use the `bpf_probe_read_user_str` function to read the return value of the `readline` function from the user space and store it in the `str` array.

```c
bpf_probe_read_user_str(str, sizeof(str), ret);
```

Finally, we use the `bpf_printk` function to output the PID, task name, and user input string.

```c
bpf_printk("PID %d (%s) read: %s ", pid, comm, str);
```

eunomia-bpf is an open-source eBPF dynamic loading runtime and development toolchain combined with Wasm. Its purpose is to simplify the development, build, distribution, and running of eBPF programs. You can refer to <https://github.com/eunomia-bpf/eunomia-bpf> to download and install the ecc compiler toolchain and ecli runtime. We use eunomia-bpf to compile and run this example.

Compile and run the above code:

```console
$ ecc bashreadline.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
$ sudo ecli run package.json
Running eBPF program...
```

After running this program, you can view the output of the eBPF program by checking the file `/sys/kernel/debug/tracing/trace_pipe`:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            bash-32969   [000] d..31 64001.375748: bpf_trace_printk: PID 32969 (bash) read: fff 
            bash-32969   [000] d..31 64002.056951: bpf_trace_printk: PID 32969 (bash) read: fff
```

You can see that we have successfully captured the `readline` function call of `bash` and obtained the command line entered by the user in `bash`.

## Summary

In the above code, we used the `SEC` macro to define an uprobe probe, which specifies the user space program (`bin/bash`) to be captured and the function (`readline`) to be captured. In addition, we used the `BPF_KRETPROBE` macro to define a callback function (`printret`) for handling the return value of the `readline` function. This function can retrieve the return value of the `readline` function and print it to the kernel log. In this way, we can use eBPF to capture the `readline` function call of `bash` and obtain the command line entered by the user in `bash`.

If you want to learn more about eBPF knowledge and practices, you can visit our tutorial code repository <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> to get more examples and complete tutorials.
