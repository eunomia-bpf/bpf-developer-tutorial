# eBPF Developer Tutorial: Learning eBPF Step by Step with Examples

[![CI](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/main.yml/badge.svg)](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/main.yml)
[![Test and trigger downstream tutorial sync](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/trigger-sync.yml/badge.svg)](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/trigger-sync.yml)

[GitHub](https://github.com/eunomia-bpf/bpf-developer-tutorial)
[Gitee Mirror](https://gitee.com/yunwei37/bpf-developer-tutorial)
[中文版](README.zh.md)

This is a development tutorial for eBPF based on CO-RE (Compile Once, Run Everywhere). It provides practical eBPF development practices from beginner to advanced, including basic concepts, code examples, and real-world applications. Unlike BCC, we use frameworks like `libbpf`, `Cilium`, `libbpf-rs`, and eunomia-bpf for development, with examples in languages such as `C`, `Go`, and `Rust`.

This tutorial **does not cover complex concepts and scenario introductions**. Its main purpose is to provide examples of eBPF tools (**very short, starting with twenty lines of code!**) to help eBPF application developers quickly grasp eBPF development methods and techniques. The tutorial content can be found in the directory, with each directory being an independent eBPF tool example.

The tutorial focuses on eBPF examples in observability, networking, security, and more.

#### [**中文版在这里**](README.zh.md)

## Table of Contents

### Getting Started Examples

This section contains simple eBPF program examples and introductions. It primarily utilizes the `eunomia-bpf` framework to simplify development and introduces the basic usage and development process of eBPF.

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

### Advanced Documents and Examples

We start to build complete eBPF projects mainly based on `libbpf` and combine them with various application scenarios for practical use.

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

### In-Depth Topics

This section covers advanced topics related to eBPF, including using eBPF programs on Android, possible attacks and defenses using eBPF programs, and complex tracing. Combining the user-mode and kernel-mode aspects of eBPF can bring great power (as well as security risks).

Android:

- [Using eBPF programs on Android](src/22-android/README_en.md)

Networking:

- [Accelerating network request forwarding using sockops](src/29-sockops/README.md)
- [Capturing TCP Information with XDP](src/41-xdp-tcpdump/README.md)
- [XDP Load Balancer](src/42-xdp-loadbalancer/README.md)

tracing:

- [Tracing HTTP requests or other layer-7 protocols using eBPF socket filter or syscall trace](src/23-http/README.md)
- [Capturing Plain Text Data of Various Libraries' SSL/TLS Using uprobe](src/30-sslsniff/README.md)
- [Using eBPF to Trace Go Routine States](src/31-goroutine/README.md)
- [Measuring Function Latency with eBPF](src/33-funclatency/README.md)
- [Use Uprobe to trace Rust programs](src/37-uprobe-rust/README.md)
- [Using eBPF to Trace Nginx Requests](src/39-nginx/README.md)
- [Using eBPF to Trace MySQL Queries](src/40-mysql)

Security:

- [Use eBPF to modify syscall parameters](src/34-syscall/README.md)
- [The Secure Path Forward for eBPF: Challenges and Innovations](src/18-further-reading/ebpf-security.md)
- [Hiding process or file information using eBPF](src/24-hide/README_en.md)
- [Terminating processes by sending signals using bpf_send_signal](src/25-signal/README_en.md)
- [Adding sudo users using eBPF](src/26-sudo/README_en.md)
- [Replacing text read or written by any program using eBPF](src/27-replace/README_en.md)
- [BPF lifecycle: Running eBPF programs continuously in Detached mode after user-mode applications exit](src/28-detach/README_en.md)

Other:

- [Using user ring buffer to send information to the kernel](src/35-user-ringbuf/README.md)
- [Userspace eBPF Runtimes: Overview and Applications](src/36-userspace-ebpf/README.md)
- [Compile Once, Run Everywhere for userspace trace with eBPF and BTF](src/38-btf-uprobe/README.md)

Continuously updating...

## Why write this tutorial?

In the process of learning eBPF, we have been inspired and helped by the [bcc python developer tutorial](src/bcc-documents/tutorial_bcc_python_developer.md). However, from the current perspective, using `libbpf` to develop eBPF applications is a relatively better choice.

This project is mainly based on [libbpf](https://github.com/libbpf/libbpf) frameworks.

> - We also provide a small tool called GPTtrace, which uses ChatGPT to automatically write eBPF programs and trace Linux systems through natural language descriptions. This tool allows you to interactively learn eBPF programs: [GPTtrace](https://github.com/eunomia-bpf/GPTtrace)
> - Feel free to raise any questions or issues related to eBPF learning, or bugs encountered in practice, in the issue or discussion section of this repository. We will do our best to help you!

## Install deps and Compile

- For libbpf based: see [src/11-bootstrap](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/11-bootstrap/README_en.md)
- For eunomia-bpf based: see [src/1-helloworld](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/1-helloworld/README_en.md)

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

## build

The example of local compilation is shown as follows:

```shell
git clone https://github.com/eunomia-bpf/bpf-developer-tutorial.git
cd bpf-developer-tutorial
git submodule update --init --recursive # Synchronize submodule
cd src/24-hide
make
```

## LICENSE

MIT
