# eBPF Developer Tutorial and Knowledge Base: Learning eBPF Step by Step with Tools

[![CI](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/main.yml/badge.svg)](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/main.yml)

[GitHub](https://github.com/eunomia-bpf/bpf-developer-tutorial)
[Gitee Mirror](https://gitee.com/yunwei37/bpf-developer-tutorial)

This is a development tutorial for eBPF based on CO-RE (Compile Once, Run Everywhere). It provides practical eBPF development practices from beginner to advanced, including basic concepts, code examples, and real-world applications. Unlike BCC, we use frameworks like libbpf, Cilium, libbpf-rs, and eunomia-bpf for development, with examples in languages such as C, Go, and Rust.

This tutorial does not cover complex concepts and scenario introductions. Its main purpose is to provide examples of eBPF tools (**very short, starting with twenty lines of code!**) to help eBPF application developers quickly grasp eBPF development methods and techniques. The tutorial content can be found in the directory, with each directory being an independent eBPF tool example.

The tutorial focuses on eBPF examples in observability, networking, security, and more.

## Table of Contents

### Getting Started Documentation

Includes simple eBPF program samples and introductions.

- [lesson 0-introduce](src/0-introduce/README_en.md) Introduces basic concepts of eBPF and common development tools
- [lesson 1-helloworld](src/1-helloworld/README_en.md) Develops the simplest "Hello World" program using eBPF and introduces the basic framework and development process of eBPF
- [lesson 2-kprobe-unlink](src/2-kprobe-unlink/README_en.md) Uses kprobe in eBPF to capture the unlink system call
- [lesson 3-fentry-unlink](src/3-fentry-unlink/README_en.md) Uses fentry in eBPF to capture the unlink system call
- [lesson 4-opensnoop](src/4-opensnoop/README_en.md) Uses eBPF to capture the system call collection of processes opening files, and filters process PIDs in eBPF using global variables
- [lesson 5-uprobe-bashreadline](src/5-uprobe-bashreadline/README_en.md) Uses uprobe in eBPF to capture the readline function calls in bash
- [lesson 6-sigsnoop](src/6-sigsnoop/README_en.md) Captures the system call collection of processes sending signals and uses a hash map to store states
- [lesson 7-execsnoop](src/7-execsnoop/README_en.md) Captures process execution times and prints output to user space through perf event array
- [lesson 8-exitsnoop](src/8-exitsnoop/README_en.md) Captures process exit events and prints output to user space using a ring buffer
- [lesson 9-runqlat](src/9-runqlat/README_en.md) Captures process scheduling delays and records them in histogram format
- [lesson 10-hardirqs](src/10-hardirqs/README_en.md) Captures interrupt events using hardirqs or softirqs
- [lesson 11-bootstrap](src/11-bootstrap/README_en.md) Writes native libbpf user space code for eBPF using libbpf-bootstrap and establishes a complete libbpf project.
- [lesson 12-profile](src/12-profile/README_en.md) Performs performance analysis using eBPF
- [lesson 13-tcpconnlat](src/13-tcpconnlat/README_en.md) Records TCP connection latency and processes data in user space using libbpf
- [lesson 14-tcpstates](src/14-tcpstates/README_en.md) Records TCP connection state and TCP RTT.- [lesson 15-javagc](src/15-javagc/README_en.md) Capture user-level Java GC event duration using usdt
- [lesson 16-memleak](src/16-memleak/README_en.md) Detect memory leaks
- [lesson 17-biopattern](src/17-biopattern/README_en.md) Capture disk IO patterns
- [lesson 18-further-reading](src/18-further-reading/README_en.md) Further reading: papers list, projects, blogs, etc.
- [lesson 19-lsm-connect](src/19-lsm-connect/README_en.md) Use LSM for security detection and defense
- [lesson 20-tc](src/20-tc/README_en.md) Use eBPF for tc traffic control
- [lesson 21-xdp](src/21-xdp/README_en.md) Use eBPF for XDP packet processing

### Advanced Documentation and Sample Programs

This section covers advanced topics related to eBPF, including using eBPF programs on Android, possible attacks and defenses using eBPF programs, and complex tracing. Combining the user-mode and kernel-mode aspects of eBPF can bring great power (as well as security risks).

Android:

- [Using eBPF programs on Android](src/22-android/README_en.md)

Networking and tracing:

- [Tracing HTTP requests or other layer-7 protocols using eBPF socket filter or syscall trace](src/23-http/README_en.md)
- [Accelerating network request forwarding using sockops](src/29-sockops/README_en.md)
- [Capturing Plain Text Data of Various Libraries' SSL/TLS Using uprobe](src/30-sslsniff/README_en.md)

Security:

- [Use eBPF to modify syscall parameters](src/34-syscall/README.md)
- [The Secure Path Forward for eBPF: Challenges and Innovations](src/18-further-reading/ebpf-security.md)
- [Hiding process or file information using eBPF](src/24-hide/README_en.md)
- [Terminating processes by sending signals using bpf_send_signal](src/25-signal/README_en.md)
- [Adding sudo users using eBPF](src/26-sudo/README_en.md)
- [Replacing text read or written by any program using eBPF](src/27-replace/README_en.md)
- [BPF lifecycle: Running eBPF programs continuously in Detached mode after user-mode applications exit](src/28-detach/README_en.md)

Continuously updated...

## Why write this tutorial?

In the process of learning eBPF, we have been inspired and helped by the [bcc python developer tutorial](src/bcc-documents/tutorial_bcc_python_developer.md). However, from the current perspective, using libbpf to develop eBPF applications is a relatively better choice. However, there seems to be few tutorials that focus on eBPF development based on libbpf and BPF CO-RE, introducing it through examples and tools. Therefore, we initiated this project, adopting a similar organization method as the bcc python developer tutorial, but using CO-RE's libbpf for development.

This project is mainly based on [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) and [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) frameworks, and uses eunomia-bpf to help simplify the development of some user-space libbpf eBPF code, allowing developers to focus on kernel-space eBPF code development.

> - We also provide a small tool called GPTtrace, which uses ChatGPT to automatically write eBPF programs and trace Linux systems through natural language descriptions. This tool allows you to interactively learn eBPF programs: [GPTtrace](https://github.com/eunomia-bpf/GPTtrace)
> - Feel free to raise any questions or issues related to eBPF learning, or bugs encountered in practice, in the issue or discussion section of this repository. We will do our best to help you!

## GitHub Templates: Easily build eBPF projects and development environments, compile and run eBPF programs online with one click

When starting a new eBPF project, are you confused about how to set up the environment and choose a programming language? Don't worry, we have prepared a series of GitHub templates for you to quickly start a brand new eBPF project. Just click the `Use this template` button on GitHub to get started.- <https://github.com/eunomia-bpf/libbpf-starter-template>: eBPF project template based on the C language and libbpf framework

- <https://github.com/eunomia-bpf/cilium-ebpf-starter-template>: eBPF project template based on the Go language and cilium/ framework
- <https://github.com/eunomia-bpf/libbpf-rs-starter-template>: eBPF project template based on the Rust language and libbpf-rs framework
- <https://github.com/eunomia-bpf/eunomia-template>: eBPF project template based on the C language and eunomia-bpf framework

These starter templates include the following features:

- A Makefile to build the project with a single command
- A Dockerfile to automatically create a containerized environment for your eBPF project and publish it to GitHub Packages
- GitHub Actions to automate the build, test, and release processes
- All dependencies required for eBPF development

> By setting an existing repository as a template, you and others can quickly generate new repositories with the same basic structure, eliminating the need for manual creation and configuration. With GitHub template repositories, developers can focus on the core functionality and logic of their projects without wasting time on the setup and structure. For more information about template repositories, see the official documentation: <https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-template-repository>

When you create a new repository using one of the eBPF project templates mentioned above, you can easily set up and launch an online development environment with GitHub Codespaces. Here are the steps to compile and run eBPF programs using GitHub Codespaces:

1. Click the Code button in your new repository and select the Open with Codespaces option:

    ![code](imgs/code-button.png)

2. GitHub will create a new Codespace for you, which may take a few minutes depending on your network speed and the size of the repository.
3. Once your Codespace is launched and ready to use, you can open the terminal and navigate to your project directory.
4. You can follow the instructions in the corresponding repository to compile and run eBPF programs:

    ![codespace](imgs/codespace.png)

With Codespaces, you can easily create, manage, and share cloud-based development environments, speeding up and making your development process more reliable. You can develop with Codespaces anywhere, on any device, just need a computer with a web browser. Additionally, GitHub Codespaces supports pre-configured environments, customized development containers, and customizable development experiences to meet your development needs.

After writing code in a codespace and making a commit, GitHub Actions will compile and automatically publish the container image. Then, you can use Docker to run this eBPF program anywhere with just one command, for example:

```console
$ sudo docker run --rm -it --privileged ghcr.io/eunomia-bpf/libbpf-rs-template:latest
[sudo] password for xxx: 
Tracing run queue latency higher than 10000 us
TIME     COMM             TID     LAT(us)       
12:09:19 systemd-udevd    30786   18300         
12:09:19 systemd-udevd    30796   21941         
12:09:19 systemd-udevd    30793   10323         
12:09:19 systemd-udevd    30795   14827         
12:09:19 systemd-udevd    30790   17973         
12:09:19 systemd-udevd    30793   12328         
12:09:19 systemd-udevd    30796   28721
```

![docker](imgs/docker.png)

## Why do we need tutorials based on libbpf and BPF CO-RE?

> In history, when it comes to developing a BPF application, one could choose the BCC framework to load the BPF program into the kernel when implementing various BPF programs for Tracepoints. BCC provides a built-in Clang compiler that can compile BPF code at runtime and customize it into a program that conforms to a specific host kernel. This is the only way to develop maintainable BPF applications under the constantly changing internal kernel environment. The portability of BPF and the introduction of CO-RE are detailed in the article "BPF Portability and CO-RE", explaining why BCC was the only viable option before and why libbpf is now considered a better choice. Last year, Libbpf saw significant improvements in functionality and complexity, eliminating many differences with BCC (especially for Tracepoints applications) and adding many new and powerful features that BCC does not support (such as global variables and BPF skeletons)
>
> Admittedly, BCC does its best to simplify the work of BPF developers, but sometimes it also increases the difficulty of problem localization and fixing while providing convenience. Users must remember its naming conventions and the autogenerated structures for Tracepoints, and they must rely on rewriting this code to read kernel data and access kprobe parameters. When using BPF maps, it is necessary to write half-object-oriented C code that does not completely match what happens in the kernel. Furthermore, BCC leads to the writing of a large amount of boilerplate code in user space, with manually configuring the most trivial parts.
>
> As mentioned above, BCC relies on runtime compilation and embeds a large LLVM/Clang library, which creates certain gaps between BCC and an ideal usage scenario:
>
> - High resource utilization (memory and CPU) at compile time, which may interfere with the main process in busy servers.
> - It relies on the kernel header package and needs to be installed on each target host. Even so, if certain kernel contents are not exposed through public header files, type definitions need to be copied and pasted into the BPF code to achieve the purpose.
> - Even the smallest compile-time errors can only be detected at runtime, followed by recompiling and restarting the user-space application. This greatly affects the iteration time of development (and increases frustration...).
>
> Libbpf + BPF CO-RE (Compile Once - Run Everywhere) takes a different approach, considering BPF programs as normal user-space programs: they only need to be compiled into small binaries that can be deployed on target hosts without modification. libbpf acts as a loader for BPF programs, responsible for configuration work (relocating, loading, and verifying BPF programs, creating BPF maps, attaching to BPF hooks, etc.), and developers only need to focus on the correctness and performance of BPF programs. This approach minimizes overhead, eliminates dependencies, and improves the overall developer experience.
>
> In terms of API and code conventions, libbpf adheres to the philosophy of "least surprise", where most things need to be explicitly stated: no header files are implied, and no code is rewritten. Most monotonous steps can be eliminated using simple C code and appropriate auxiliary macros. In addition, what users write is the content that needs to be executed, and the structure of BPF applications is one-to-one, finally verified and executed by the kernel.

Reference: [BCC to Libbpf Conversion Guide (Translation) - Deep Dive into eBPF](https://www.ebpf.top/post/bcc-to-libbpf-guid/)

## eunomia-bpf

[eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) is an open-source eBPF dynamic loading runtime and development toolkit designed to simplify the development, building, distribution, and execution of eBPF programs. It is based on the libbpf CO-RE lightweight development framework.

With eunomia-bpf, you can:

- Write only the libbpf kernel mode code when writing eBPF programs or tools, automatically retrieving kernel mode export information.
- Use Wasm to develop eBPF user mode programs, controlling the entire eBPF program loading and execution, as well as handling related data within the WASM virtual machine.
- eunomia-bpf can package pre-compiled eBPF programs into universal JSON or WASM modules for distribution across architectures and kernel versions, allowing dynamic loading and execution without the need for recompilation.

eunomia-bpf consists of a compilation toolchain and a runtime library. Compared to traditional frameworks like BCC and native libbpf, it greatly simplifies the development process of eBPF programs, where in most cases, only the kernel mode code needs to be written to easily build, package, and publish complete eBPF applications. At the same time, the kernel mode eBPF code guarantees 100% compatibility with mainstream development frameworks such as libbpf, libbpfgo, libbpf-rs, and more. When user mode code needs to be written, multiple languages can be used with the help of Webassembly. Compared to script tools like bpftrace, eunomia-bpf maintains similar convenience, while not being limited to trace scenarios and can be used in various other fields such as networking and security.

- eunomia-bpf project GitHub address: <https://github.com/eunomia-bpf/eunomia-bpf>
- gitee mirror: <https://gitee.com/anolis/eunomia>

## Let ChatGPT Help Us

This tutorial uses ChatGPT to learn how to write eBPF programs. At the same time, we try to teach ChatGPT how to write eBPF programs. The general steps are as follows:

1. Teach it the basic knowledge of eBPF programming.
2. Show it some cases: hello world, basic structure of eBPF programs, how to use eBPF programs for tracing, and let it start writing tutorials.
3. Manually adjust the tutorials and correct errors in the code and documents.
4. Feed the modified code back to ChatGPT for further learning.
5. Try to make ChatGPT generate eBPF programs and corresponding tutorial documents automatically! For example:

![ebpf-chatgpt-signal](imgs/ebpf-chatgpt-signal.png)

The complete conversation log can be found here: [ChatGPT.md](ChatGPT.md)

We have also built a demo of a command-line tool. Through training in this tutorial, it can automatically write eBPF programs and trace Linux systems using natural language descriptions: <https://github.com/eunomia-bpf/GPTtrace>

![ebpf-chatgpt-signal](https://github.com/eunomia-bpf/GPTtrace/blob/main/doc/result.gif)
