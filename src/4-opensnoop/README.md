# eBPF Tutorial by Example 4: Capturing Opening Files and Filter with Global Variables

eBPF (Extended Berkeley Packet Filter) is a kernel execution environment that allows users to run secure and efficient programs in the kernel. It is commonly used for network filtering, performance analysis, security monitoring, and other scenarios. The power of eBPF lies in its ability to capture and modify network packets or system calls at runtime in the kernel, enabling monitoring and adjustment of the operating system's behavior.

This article is the fourth part of the eBPF Tutorial by Example, mainly focusing on how to capture the system call collection of process opening files and filtering process PIDs using global variables in eBPF.

In Linux system, the interaction between processes and files is achieved through system calls. System calls serve as the interface between user space programs and kernel space programs, allowing user programs to request specific operations from the kernel. In this tutorial, we focus on the sys_openat system call, which is used to open files.

When a process opens a file, it issues a sys_openat system call to the kernel and passes relevant parameters (such as file path, open mode, etc.). The kernel handles this request and returns a file descriptor, which serves as a reference for subsequent file operations. By capturing the sys_openat system call, we can understand when and how a process opens a file.

## Capturing the System Call Collection of Process Opening Files in eBPF

First, we need to write an eBPF program to capture the system call of a process opening a file. The specific implementation is as follows:

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

Let's look at the key parts of this program. The global variable `pid_target` is declared with `const volatile`. The `const` means the eBPF program can't modify it (it's read-only from the kernel's perspective), while `volatile` tells the compiler that user-space can modify it before loading the program. This combination lets you pass runtime configuration from user-space to your eBPF program.

When `pid_target` is 0, the program captures openat calls from all processes. If you set it to a specific PID, it only monitors that process. This filtering happens in the kernel, which is much more efficient than filtering in user-space - you're not wasting resources sending events you don't care about.

The filtering logic is straightforward. We get the current process ID using `bpf_get_current_pid_tgid()` and shift it right by 32 bits to extract just the PID (the function returns both PID and TID packed into a 64-bit value). Then we check if it matches our target. If not, we return early and skip the event.

The annotation `/// @description "Process ID to trace"` above the global variable is special - eunomia-bpf uses it to automatically generate command-line help text. This makes your tool more user-friendly without extra code.

This eBPF program can be loaded into the kernel and executed using tools like libbpf or eunomia-bpf. It captures the sys_openat system call of the specified process (or all processes) and outputs relevant information in user-space.

We use eunomia-bpf to compile and run this example. You can install it from <https://github.com/eunomia-bpf/eunomia-bpf>. The complete code is at <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/4-opensnoop>.

Compile and run the above code:

```console
$ ecc opensnoop.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
$ sudo ecli run package.json
Running eBPF program...
```

After running this program, you can view the output of the eBPF program by viewing the `/sys/kernel/debug/tracing/trace_pipe` file:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101179: bpf_trace_printk: Process ID: 3840345 enter sys openat
           <...>-3840345 [010] d... 3220702.158000: bpf_trace_printk: Process ID: 3840345 enter sys openat
```

At this point, we are able to capture the sys_openat system call for opening files by processes.

## How Global Variables Work in eBPF

Global variables in eBPF are stored in the data section of your compiled program. When you load the eBPF program into the kernel, these variables get their initial values. The neat part is that user-space can modify these values before the program starts running, effectively passing configuration parameters into your kernel code.

In our example, the global variable `pid_target` is used to filter process PIDs. User space programs can set the value of this variable to capture only the `sys_openat` system calls related to the specified PID in the eBPF program.

The principle of using global variables is that they are defined and stored in the data section of eBPF programs. When the eBPF program is loaded into the kernel and executed, these global variables are retained in the kernel and can be accessed through BPF system calls. User space programs can use certain features of BPF system calls, such as `bpf_obj_get_info_by_fd` and `bpf_obj_get_info`, to obtain information about the eBPF object, including the position and value of global variables.

You can view the help information for opensnoop by executing the command `ecli -h`:

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

You can specify the PID of the process to capture by using the `--pid_target` option, for example:

```console
$ sudo ./ecli run package.json  --pid_target 618
Running eBPF program...
```

After running this program, you can view the output of the eBPF program by viewing the `/sys/kernel/debug/tracing/trace_pipe` file:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe".\-3840345 [010] d... 3220701.101179: bpf_trace_printk: Process ID: 618 enter sys openat
\-3840345 [010] d... 3220702.158000: bpf_trace_printk: Process ID: 618 enter sys openat
```

## Summary

This article introduces how to use eBPF programs to capture the system calls for process file opening. In an eBPF program, we can capture the system calls for process file opening by defining functions `tracepoint__syscalls__sys_enter_open` and `tracepoint__syscalls__sys_enter_openat` and attaching them to the tracepoints `sys_enter_open` and `sys_enter_openat` using the `SEC` macro. We can use the `bpf_get_current_pid_tgid` function to get the process ID that calls the open or openat system call, and print it out in the kernel log using the `bpf_printk` function. In an eBPF program, we can also filter the output by defining a global variable `pid_target` to specify the pid of the process to be captured, only outputting the information of the specified process.

By learning this tutorial, you should have a deeper understanding of how to capture and filter system calls for specific processes in eBPF. This method has widespread applications in system monitoring, performance analysis, and security auditing.

If you want to learn more about eBPF knowledge and practices, you can visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and a complete tutorial.
