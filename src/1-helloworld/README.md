# eBPF Tutorial by Example 1: Hello World, Framework and Development

In this blog post, we will delve into the basic framework and development process of eBPF (Extended Berkeley Packet Filter). eBPF is a powerful network and performance analysis tool that runs on the Linux kernel, providing developers with the ability to dynamically load, update, and run user-defined code at kernel runtime. This enables developers to implement efficient, secure kernel-level network monitoring, performance analysis, and troubleshooting functionalities.

This article is the second part of the eBPF Tutorial by Example, where we will focus on how to write a simple eBPF program and demonstrate the entire development process through practical examples. Before reading this tutorial, it is recommended that you first learn the concepts of eBPF by studying the first tutorial.

When developing eBPF programs, there are multiple development frameworks to choose from, such as BCC (BPF Compiler Collection) libbpf, cilium/ebpf, eunomia-bpf, etc. Although these tools have different characteristics, their basic development process is similar. In the following content, we will delve into these processes and use the Hello World program as an example to guide readers in mastering the basic skills of eBPF development.

This tutorial will help you understand the basic structure of eBPF programs, the compilation and loading process, the interaction between user space and kernel space, as well as debugging and optimization techniques. By studying this tutorial, you will master the basic knowledge of eBPF development and lay a solid foundation for further learning and practice.

## Preparation of eBPF Development Environment and Basic Development Process

Before starting to write eBPF programs, we need to prepare a suitable development environment and understand the basic development process of eBPF programs. This section will provide a detailed introduction to these subjects.

### Installing the necessary software and tools

To develop eBPF programs, you need to install the following software and tools:

- Linux kernel: Since eBPF is a kernel technology, you need to have a relatively new version of the Linux kernel (minimum version 4.8 and above, suggested version is 5.15+ or 6.2+) to support eBPF functionality.
  - If possible, install a new version of Ubuntu (e.g. 23.10) would be better.
- LLVM and Clang: These tools are used to compile eBPF programs. Installing the latest version of LLVM and Clang ensures that you get the best eBPF support.

An eBPF program consists of two main parts: the kernel space part and the user space part. The kernel space part contains the actual logic of the eBPF program, while the user space part is responsible for loading, running, and monitoring the kernel space program.

Once you have chosen a suitable development framework, such as BCC (BPF Compiler Collection), libbpf, cilium/ebpf, or eunomia-bpf, you can begin developing the user space and kernel space programs. Taking the BCC tool as an example, we will introduce the basic development process of eBPF programs:

1. Installing the BCC tool: Depending on your Linux distribution, follow the guidelines in the BCC documentation to install the BCC tool and its dependencies.
2. Writing an eBPF program (C language): Use the C language to write a simple eBPF program, such as the Hello World program. This program can be executed in kernel space and perform specific tasks, such as counting network packets.
3. Writing a user space program (Python or C, etc.): Use languages like Python or C to write a user space program that is responsible for loading, running, and interacting with the eBPF program. In this program, you need to use the API provided by BCC to load and manipulate the kernel space eBPF program.
4. Compiling the eBPF program: Use the BCC tool to compile the eBPF program written in C language into bytecode that can be executed by the kernel. BCC dynamically compiles the eBPF program from source code at runtime.
5. Loading and running the eBPF program: In the user space program, use the API provided by BCC to load the compiled eBPF program into kernel space and then run it.
6. Interacting with the eBPF program: The user space program interacts with the eBPF program through the API provided by BCC, implementing data collection, analysis, and display functions. For example, you can use the BCC API to read map data in the eBPF program to obtain network packet statistics.
7. Unloading the eBPF program: When the eBPF program is no longer needed, the user space program should unload it from the kernel space using the BCC API.
8. Debugging and optimization: Use tools like bpftool to debug and optimize eBPF programs, improving program performance and stability.

Through the above process, you can develop, compile, run, and debug eBPF programs using the BCC tool. Note that the development process of other frameworks, such as libbpf, cilium/ebpf, and eunomia-bpf, is similar but slightly different. Therefore, when choosing a framework, please refer to the respective official documentation and examples.

By following this process, you can develop an eBPF program that runs in the kernel. eunomia-bpf is an open-source eBPF dynamic loading runtime and development toolchain. It aims to simplify the development, building, distribution, and running of eBPF programs. It is based on the libbpf CO-RE lightweight development framework, supports loading and executing eBPF programs through a user space WebAssembly (WASM) virtual machine, and packages precompiled eBPF programs into universal JSON or WASM modules for distribution. We will use eunomia-bpf for demonstration purposes.

## Download and Install eunomia-bpf Development Tools

You can download and install eunomia-bpf using the following steps:

Download the ecli tool for running eBPF programs:

```console
$ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
$ ./ecli -h
Usage: ecli [--help] [--version] [--json] [--no-cache] url-and-args
```

Download the compiler toolchain for compiling eBPF kernel code into config files or WASM modules:

```console
$ wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
$ ./ecc -h
eunomia-bpf compiler
Usage: ecc [OPTIONS] <SOURCE_PATH> [EXPORT_EVENT_HEADER]
....
```

Note: If you are on the aarch64 platform, please use the [ecc-aarch64](https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc-aarch64) and [ecli-aarch64](https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli-aarch64).

You can also compile using the docker image:

```console
$ docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest # Compile using docker. `pwd` should contain *.bpf.c files and *.h files.
export PATH=PATH:~/.eunomia/bin
Compiling bpf object...
Packing ebpf object and config into /src/package.json...
```

## Hello World - minimal eBPF program

We will start with a simple eBPF program that prints a message in the kernel. We will use the eunomia-bpf compiler toolchain to compile it into a BPF bytecode file, and then load and run the program using the ecli tool. For the sake of the example, we can temporarily disregard the user space program.

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
 pid_t pid = bpf_get_current_pid_tgid() >> 32;
 if (pid_filter && pid != pid_filter)
  return 0;
 bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);
 return 0;
}
```

This program defines a handle_tp function and attaches it to the sys_enter_write tracepoint using the SEC macro (i.e., it is executed when the write system call is entered). The function retrieves the process ID of the write system call invocation using the bpf_get_current_pid_tgid and bpf_printk functions, and prints it in the kernel log.

- `bpf_trace_printk()`: A simple mechanism to output information to the trace_pipe (/sys/kernel/debug/tracing/trace_pipe). This is fine for simple use cases, but it has limitations: a maximum of 3 parameters; the first parameter must be %s (i.e., a string); and the trace_pipe is globally shared in the kernel, so other programs using the trace_pipe concurrently might disrupt its output. A better approach is to use BPF_PERF_OUTPUT(), which will be discussed later.
- `void *ctx`: ctx is originally a parameter of a specific type, but since it is not used here, it is written as void *.
- `return 0;`: This is necessary, returning 0 (to know why, refer to #139 <https://github.com/iovisor/bcc/issues/139>).

To compile and run this program, you can use the ecc tool and ecli command. First, on Ubuntu/Debian, execute the following command:

```shell
sudo apt install clang llvm
```

Compile the program using ecc:

```console
$ ./ecc minimal.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

Or compile using a docker image:

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

Then run the compiled program using ecli:

```console
$ sudo ./ecli run package.json
Running eBPF program...
```

After running this program, you can view the output of the eBPF program by checking the /sys/kernel/debug/tracing/trace_pipe file:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "BPF triggered sys_enter_write"
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: write system call from PID 3840345.
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: write system call from PID 3840345.
```

Once you stop the ecli process by pressing Ctrl+C, the corresponding output will also stop.

Note: If your Linux distribution (e.g. Ubuntu) does not have the tracing subsystem enabled by default, you may not see any output. Use the following command to enable this feature:

```console
$ sudo su
# echo 1 > /sys/kernel/debug/tracing/tracing_on
```

## Basic Framework of eBPF Program

As mentioned above, the basic framework of an eBPF program includes:

- Including header files: You need to include <linux/bpf.h> and <bpf/bpf_helpers.h> header files, among others.
- Defining a license: You need to define a license, typically using "Dual BSD/GPL".
- Defining a BPF function: You need to define a BPF function, for example, named handle_tp, which takes void *ctx as a parameter and returns int. This is usually written in the C language.
- Using BPF helper functions: In the BPF function, you can use BPF helper functions such as bpf_get_current_pid_tgid() and bpf_printk().
- Return value

## Tracepoints

Tracepoints are a kernel static instrumentation technique, technically just trace functions placed in the kernel source code, which are essentially probe points with control conditions inserted into the source code, allowing post-processing with additional processing functions. For example, the most common static tracing method in the kernel is printk, which outputs log messages. For example, there are tracepoints at the start and end of system calls, scheduler events, file system operations, and disk I/O. Tracepoints were first introduced in Linux version 2.6.32 in 2009. Tracepoints are a stable API and their number is limited.

## GitHub Templates: Build eBPF Projects and Development Environments Easily

When faced with creating an eBPF project, are you confused about how to set up the environment and choose a programming language? Don't worry, we have prepared a series of GitHub templates to help you quickly start a brand new eBPF project. Just click the `Use this template` button on GitHub to get started.

- <https://github.com/eunomia-bpf/libbpf-starter-template>: eBPF project template based on the C language and libbpf framework.
- <https://github.com/eunomia-bpf/cilium-ebpf-starter-template>: eBPF project template based on the Go language and cilium/ebpf framework.
- <https://github.com/eunomia-bpf/libbpf-rs-starter-template>: eBPF project template based on the Rust language and libbpf-rs framework.
- <https://github.com/eunomia-bpf/eunomia-template>: eBPF project template based on the C language and eunomia-bpf framework.

These starter templates include the following features:

- A Makefile for building the project with one command.
- A Dockerfile for automatically creating a containerized environment for your eBPF project and publishing it to Github Packages.- GitHub Actions, used for automating build, test, and release processes
- All dependencies required for eBPF development

> By setting an existing repository as a template, you and others can quickly generate new repositories with the same underlying structure, eliminating the tedious process of manual creation and configuration. With GitHub template repositories, developers can focus on the core functionality and logic of their projects without wasting time on setup and structure. For more information about template repositories, please refer to the official documentation: <https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-template-repository>

## Summary

The development and usage process of eBPF programs can be summarized in the following steps:

- Define the interface and types of eBPF programs: This includes defining the interface functions of eBPF programs, defining and implementing eBPF kernel maps and shared memory (perf events), and defining and using eBPF kernel helper functions.
- Write the code for eBPF programs: This includes writing the main logic of the eBPF program, implementing read and write operations on eBPF kernel maps, and using eBPF kernel helper functions.
- Compile the eBPF program: This includes using an eBPF compiler (such as clang) to compile the eBPF program code into eBPF bytecode and generate an executable eBPF kernel module. ecc essentially calls the clang compiler to compile eBPF programs.
- Load the eBPF program into the kernel: This includes loading the compiled eBPF kernel module into the Linux kernel and attaching the eBPF program to the specified kernel events.
- Use the eBPF program: This includes monitoring the execution of the eBPF program and exchanging and sharing data using eBPF kernel maps and shared memory.
- In practical development, there may be additional steps such as configuring compilation and loading parameters, managing eBPF kernel modules and kernel maps, and using other advanced features.

It should be noted that the execution of BPF programs occurs in the kernel space, so special tools and techniques are needed to write, compile, and debug BPF programs. eunomia-bpf is an open-source BPF compiler and toolkit that can help developers write and run BPF programs quickly and easily.

You can also visit our tutorial code repository <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials, all of which are open-source. We will continue to share more about eBPF development practices to help you better understand and master eBPF technology.
