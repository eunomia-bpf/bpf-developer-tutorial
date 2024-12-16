# eBPF Developer Tutorial: Learning eBPF Step by Step with Examples

[![Test example CI](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/test-libbpf.yml/badge.svg)](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/test-libbpf.yml)
[![Test and trigger downstream tutorial sync](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/trigger-sync.yml/badge.svg)](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/trigger-sync.yml)

[GitHub](https://github.com/eunomia-bpf/bpf-developer-tutorial)
[Gitee Mirror](https://gitee.com/yunwei37/bpf-developer-tutorial)
[中文版](README.zh.md)

This is a development tutorial for eBPF based on CO-RE (Compile Once, Run Everywhere). It provides practical eBPF development practices from beginner to advanced, including basic concepts, code examples, and real-world applications. Unlike BCC, we use frameworks like `libbpf`, `Cilium`, `libbpf-rs`, and eunomia-bpf for development, with examples in languages such as `C`, `Go`, and `Rust`.

This tutorial **does not cover complex concepts and scenario introductions**. Its main purpose is to provide examples of eBPF tools (**very short, starting with twenty lines of code!**) to help eBPF application developers quickly grasp eBPF development methods and techniques. The tutorial content can be found in the directory, with each directory being an independent eBPF tool example.

The tutorial focuses on eBPF examples in observability, networking, security, and more.

[**中文版在这里**](README.zh.md)

## Table of Contents

### Getting Started Examples

This section contains simple eBPF program examples and introductions. It primarily utilizes the `eunomia-bpf` framework to simplify development and introduces the basic usage and development process of eBPF.

- [lesson 0-introduce](src/0-introduce/README.md) Introduction to Core Concepts and Tools
- [lesson 1-helloworld](src/1-helloworld/README.md) Hello World, Framework and Development
- [lesson 2-kprobe-unlink](src/2-kprobe-unlink/README.md) Monitoring unlink System Calls with kprobe
- [lesson 3-fentry-unlink](src/3-fentry-unlink/README.md) Monitoring unlink System Calls with fentry
- [lesson 4-opensnoop](src/4-opensnoop/README.md) Capturing Opening Files and Filter with Global Variables
- [lesson 5-uprobe-bashreadline](src/5-uprobe-bashreadline/README.md) Capturing readline Function Calls with Uprobe
- [lesson 6-sigsnoop](src/6-sigsnoop/README.md) Capturing Signal Sending and Store State with Hash Maps
- [lesson 7-execsnoop](src/7-execsnoop/README.md) Capturing Process Execution, Output with perf event array
- [lesson 8-exitsnoop](src/8-exitsnoop/README.md) Monitoring Process Exit Events, Output with Ring Buffer
- [lesson 9-runqlat](src/9-runqlat/README.md) Capturing Scheduling Latency and Recording as Histogram
- [lesson 10-hardirqs](src/10-hardirqs/README.md) Capturing Interrupts with hardirqs or softirqs

### Advanced Documents and Examples

We start to build complete eBPF projects mainly based on `libbpf` and combine them with various application scenarios for practical use.

- [lesson 11-bootstrap](src/11-bootstrap/README.md) Develop User-Space Programs with libbpf and Trace exec() and exit()
- [lesson 12-profile](src/12-profile/README.md) Using eBPF Program Profile for Performance Analysis
- [lesson 13-tcpconnlat](src/13-tcpconnlat/README.md) Statistics of TCP Connection Delay with libbpf
- [lesson 14-tcpstates](src/14-tcpstates/README.md) Recording TCP Connection Status and TCP RTT
- [lesson 15-javagc](src/15-javagc/README.md) Capturing User-Space Java GC Duration Using USDT
- [lesson 16-memleak](src/16-memleak/README.md) Monitoring Memory Leaks
- [lesson 17-biopattern](src/17-biopattern/README.md) Count Random/Sequential Disk I/O
- [lesson 18-further-reading](src/18-further-reading/README.md) More Reference Materials： papers, projects
- [lesson 19-lsm-connect](src/19-lsm-connect/README.md) Security Detection and Defense using LSM
- [lesson 20-tc](src/20-tc/README.md) tc Traffic Control
- [lesson 21-xdp](src/21-xdp/README.md) Programmable Packet Processing with XDP

### In-Depth Topics

This section covers advanced topics related to eBPF, including using eBPF programs on Android, possible attacks and defenses using eBPF programs, and complex tracing. Combining the user-mode and kernel-mode aspects of eBPF can bring great power (as well as security risks).

Android:

- [lesson 22-android](src/22-android/README.md) Using eBPF Programs on Android

Networking:

- [lesson 23-http](src/23-http/README.md) L7 Tracing with eBPF: HTTP and Beyond via Socket Filters and Syscall Tracepoints
- [lesson 29-sockops](src/29-sockops/README.md) Accelerating Network Request Forwarding with Sockops
- [lesson 41-xdp-tcpdump](src/41-xdp-tcpdump/README.md) Capturing TCP Information with XDP
- [lesson 42-xdp-loadbalancer](src/42-xdp-loadbalancer/README.md) XDP Load Balancer

Security:

- [lesson 24-hide](src/24-hide/README.md) Hiding Process or File Information
- [lesson 25-signal](src/25-signal/README.md) Using bpf_send_signal to Terminate Malicious Processes in eBPF
- [lesson 26-sudo](src/26-sudo/README.md) Using eBPF to add sudo user
- [lesson 27-replace](src/27-replace/README.md) Replace Text Read or Written by Any Program with eBPF
- [lesson 28-detach](src/28-detach/README.md) Running eBPF After Application Exits: The Lifecycle of eBPF Programs
- [lesson 34-syscall](src/34-syscall/README.md) Modifying System Call Arguments with eBPF

Scheduler:

- [lesson 44-scx-simple](src/44-scx-simple/README.md) Introduction to the BPF Scheduler
- [lesson 45-scx-nest](src/45-scx-nest/README.md) Implementing the `scx_nest` Scheduler

Other:

- [lesson 35-user-ringbuf](src/35-user-ringbuf/README.md) Asynchronously Send to Kernel with User Ring Buffer
- [lesson 36-userspace-ebpf](src/36-userspace-ebpf/README.md) Userspace eBPF Runtimes: Overview and Applications
- [lesson 38-btf-uprobe](src/38-btf-uprobe/README.md) Expanding eBPF Compile Once, Run Everywhere(CO-RE) to Userspace Compatibility
- [lesson 43-kfuncs](src/43-kfuncs/README.md) Extending eBPF Beyond Its Limits: Custom kfuncs in Kernel Modules

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

When starting a new eBPF project, are you confused about how to set up the environment and choose a programming language? Don't worry, we have prepared a series of GitHub templates for you to quickly start a brand new eBPF project. Just click the `Use this template` button on GitHub to get started.

- <https://github.com/eunomia-bpf/libbpf-starter-template>: eBPF project template based on the C language and libbpf framework
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
