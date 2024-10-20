# eBPF Tutorial by Example: Learning CO-RE eBPF Step by Step

[![CI](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/main.yml/badge.svg)](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/main.yml)

This is a development tutorial for eBPF based on CO-RE (Compile Once, Run Everywhere). It provides practical eBPF development practices from beginner to advanced, including basic concepts, code examples, and real-world applications. Unlike BCC, we use frameworks like libbpf, Cilium, libbpf-rs, and eunomia-bpf for development, with examples in languages such as C, Go, and Rust.

This tutorial does not cover complex concepts and scenario introductions. Its main purpose is to provide examples of eBPF tools (**very short, starting with twenty lines of code!**) to help eBPF application developers quickly grasp eBPF development methods and techniques. The tutorial content can be found in the directory, with each directory being an independent eBPF tool example.

For the complete source code of the tutorial, please refer to the repo [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) on GitHub. **If you find this tutorial helpful, please give us a star!**

# Getting Started Examples

This section contains simple eBPF program examples and introductions. It primarily utilizes the `eunomia-bpf` framework to simplify development and introduces the basic usage and development process of eBPF.

- [lesson 0-introduce](0-introduce/README.md) Introduction to Core Concepts and Tools
- [lesson 1-helloworld](1-helloworld/README.md) Hello World, Framework and Development
- [lesson 2-kprobe-unlink](2-kprobe-unlink/README.md) Monitoring unlink System Calls with kprobe
- [lesson 3-fentry-unlink](3-fentry-unlink/README.md) Monitoring unlink System Calls with fentry
- [lesson 4-opensnoop](4-opensnoop/README.md) Capturing Opening Files and Filter with Global Variables
- [lesson 5-uprobe-bashreadline](5-uprobe-bashreadline/README.md) Capturing readline Function Calls with Uprobe
- [lesson 6-sigsnoop](6-sigsnoop/README.md) Capturing Signal Sending and Store State with Hash Maps
- [lesson 7-execsnoop](7-execsnoop/README.md) Capturing Process Execution, Output with perf event array
- [lesson 8-exitsnoop](8-exitsnoop/README.md) Monitoring Process Exit Events, Output with Ring Buffer
- [lesson 9-runqlat](9-runqlat/README.md) Capturing Scheduling Latency and Recording as Histogram
- [lesson 10-hardirqs](10-hardirqs/README.md) Capturing Interrupts with hardirqs or softirqs

# Advanced Documents and Examples

We start to build complete eBPF projects mainly based on `libbpf` and combine them with various application scenarios for practical use.

- [lesson 11-bootstrap](11-bootstrap/README.md) Develop User-Space Programs with libbpf and Trace exec() and exit()
- [lesson 12-profile](12-profile/README.md) Using eBPF Program Profile for Performance Analysis
- [lesson 13-tcpconnlat](13-tcpconnlat/README.md) Statistics of TCP Connection Delay with libbpf
- [lesson 14-tcpstates](14-tcpstates/README.md) Recording TCP Connection Status and TCP RTT
- [lesson 15-javagc](15-javagc/README.md) Capturing User-Space Java GC Duration Using USDT
- [lesson 16-memleak](16-memleak/README.md) Monitoring Memory Leaks
- [lesson 17-biopattern](17-biopattern/README.md) Count Random/Sequential Disk I/O
- [lesson 18-further-reading](18-further-reading/README.md) More Reference Materials： papers, projects
- [lesson 19-lsm-connect](19-lsm-connect/README.md) Security Detection and Defense using LSM
- [lesson 20-tc](20-tc/README.md) tc Traffic Control
- [lesson 21-xdp](21-xdp/README.md) Programmable Packet Processing with XDP

# In-Depth Topics

This section covers advanced topics related to eBPF, including using eBPF programs on Android, possible attacks and defenses using eBPF programs, and complex tracing. Combining the user-mode and kernel-mode aspects of eBPF can bring great power (as well as security risks).

Android:

- [lesson 22-android](22-android/README.md) Using eBPF Programs on Android

Networking:

- [lesson 23-http](23-http/README.md) L7 Tracing with eBPF: HTTP and Beyond via Socket Filters and Syscall Tracepoints
- [lesson 29-sockops](29-sockops/README.md) Accelerating Network Request Forwarding with Sockops
- [lesson 41-xdp-tcpdump](41-xdp-tcpdump/README.md) Capturing TCP Information with XDP
- [lesson 42-xdp-loadbalancer](42-xdp-loadbalancer/README.md) XDP Load Balancer

Security:

- [lesson 24-hide](24-hide/README.md) Hiding Process or File Information
- [lesson 25-signal](25-signal/README.md) Using bpf_send_signal to Terminate Malicious Processes in eBPF
- [lesson 26-sudo](26-sudo/README.md) Using eBPF to add sudo user
- [lesson 27-replace](27-replace/README.md) Replace Text Read or Written by Any Program with eBPF
- [lesson 28-detach](28-detach/README.md) Running eBPF After Application Exits: The Lifecycle of eBPF Programs
- [lesson 34-syscall](34-syscall/README.md) Modifying System Call Arguments with eBPF

Scheduler:

- [lesson 44-scx-simple](44-scx-simple/README.md) Introduction to the BPF Scheduler
- [lesson 45-scx-nest](45-scx-nest/README.md) Implementing the `scx_nest` Scheduler

Other:

- [lesson 35-user-ringbuf](35-user-ringbuf/README.md) Asynchronously Send to Kernel with User Ring Buffer
- [lesson 36-userspace-ebpf](36-userspace-ebpf/README.md) Userspace eBPF Runtimes: Overview and Applications
- [lesson 38-btf-uprobe](38-btf-uprobe/README.md) Expanding eBPF Compile Once, Run Everywhere(CO-RE) to Userspace Compatibility
- [lesson 43-kfuncs](43-kfuncs/README.md) Extending eBPF Beyond Its Limits: Custom kfuncs in Kernel Modules

Continuously updating...

# bcc and bpftrace tutorial

For reference:

- [BPF Features by Linux Kernel Version](bcc-documents/kernel-versions.md)
- [Kernel Configuration for BPF Features](bcc-documents/kernel_config.md)
- [bcc Reference Guide](bcc-documents/reference_guide.md)
- [Special Filtering](bcc-documents/special_filtering.md)
- [bcc Tutorial](bcc-documents/tutorial.md)".- [bcc Python Developer Tutorial](bcc-documents/tutorial_bcc_python_developer.md)
- [bpftrace Tutorial](bpftrace-tutorial/README.md)
