# eBPF Tutorial by Example: Learning CO-RE eBPF Step by Step

[![CI](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/main.yml/badge.svg)](https://github.com/eunomia-bpf/bpf-developer-tutorial/actions/workflows/main.yml)

This is a development tutorial for eBPF based on CO-RE (Compile Once, Run Everywhere). It provides practical eBPF development practices from beginner to advanced, including basic concepts, code examples, and real-world applications. Unlike BCC, we use frameworks like libbpf, Cilium, libbpf-rs, and eunomia-bpf for development, with examples in languages such as C, Go, and Rust.

This tutorial does not cover complex concepts and scenario introductions. Its main purpose is to provide examples of eBPF tools (**very short, starting with twenty lines of code!**) to help eBPF application developers quickly grasp eBPF development methods and techniques. The tutorial content can be found in the directory, with each directory being an independent eBPF tool example.

For the complete source code of the tutorial, please refer to the repo [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) on GitHub. **If you find this tutorial helpful, please give us a star!**

# Getting Started Examples

This section contains simple eBPF program examples and introductions. It primarily utilizes the `eunomia-bpf` framework to simplify development and introduces the basic usage and development process of eBPF.

- [lesson 0-introduce](0-introduce/README.md) Introduces basic concepts of eBPF and common development tools
- [lesson 1-helloworld](1-helloworld/README.md) Develops the simplest "Hello World" program using eBPF and introduces the basic framework and development process of eBPF
- [lesson 2-kprobe-unlink](2-kprobe-unlink/README.md) Uses kprobe in eBPF to capture the unlink system call
- [lesson 3-fentry-unlink](3-fentry-unlink/README.md) Uses fentry in eBPF to capture the unlink system call
- [lesson 4-opensnoop](4-opensnoop/README.md) Uses eBPF to capture the system call collection of processes opening files, and filters process PIDs in eBPF using global variables
- [lesson 5-uprobe-bashreadline](5-uprobe-bashreadline/README.md) Uses uprobe in eBPF to capture the readline function calls in bash
- [lesson 6-sigsnoop](6-sigsnoop/README.md) Captures the system call collection of processes sending signals and uses a hash map to store states
- [lesson 7-execsnoop](7-execsnoop/README.md) Captures process execution times and prints output to user space through perf event array
- [lesson 8-exitsnoop](8-exitsnoop/README.md) Captures process exit events and prints output to user space using a ring buffer
- [lesson 9-runqlat](9-runqlat/README.md) Captures process scheduling delays and records them in histogram format
- [lesson 10-hardirqs](10-hardirqs/README.md) Captures interrupt events using hardirqs or softirqs

# Advanced Documents and Examples

We start to build complete eBPF projects mainly based on `libbpf` and combine them with various application scenarios for practical use.

- [lesson 11-bootstrap](11-bootstrap/README.md) Writes native libbpf user space code for eBPF using libbpf-bootstrap and establishes a complete libbpf project.
- [lesson 12-profile](12-profile/README.md) Performs performance analysis using eBPF
- [lesson 13-tcpconnlat](13-tcpconnlat/README.md) Records TCP connection latency and processes data in user space using libbpf
- [lesson 14-tcpstates](14-tcpstates/README.md) Records TCP connection state and TCP RTT.- [lesson 15-javagc](15-javagc/README.md) Capture user-level Java GC event duration using usdt
- [lesson 16-memleak](16-memleak/README.md) Detect memory leaks
- [lesson 17-biopattern](17-biopattern/README.md) Capture disk IO patterns
- [lesson 18-further-reading](18-further-reading/README.md) Further reading: papers list, projects, blogs, etc.
- [lesson 19-lsm-connect](19-lsm-connect/README.md) Use LSM for security detection and defense
- [lesson 20-tc](20-tc/README.md) Use eBPF for tc traffic control
- [lesson 21-xdp](21-xdp/README.md) Use eBPF for XDP packet processing

# In-Depth Topics

This section covers advanced topics related to eBPF, including using eBPF programs on Android, possible attacks and defenses using eBPF programs, and complex tracing. Combining the user-mode and kernel-mode aspects of eBPF can bring great power (as well as security risks).

Android:

- [Using eBPF programs on Android](22-android/README.md)

Networking and tracing:

- [Tracing HTTP requests or other layer-7 protocols using eBPF socket filter or syscall trace](23-http/README.md)
- [Accelerating network request forwarding using sockops](29-sockops/README.md)
- [Capturing Plain Text Data of Various Libraries' SSL/TLS Using uprobe](30-sslsniff/README.md)
- [Use uprobe to trace Rust programs](37-uprobe-rust/README.md)

Security:

- [Use eBPF to modify syscall parameters](34-syscall/README.md)
- [The Secure Path Forward for eBPF: Challenges and Innovations](18-further-reading/ebpf-security.md)
- [Hiding process or file information using eBPF](24-hide/README.md)
- [Terminating processes by sending signals using bpf_send_signal](25-signal/README.md)
- [Adding sudo users using eBPF](26-sudo/README.md)
- [Replacing text read or written by any program using eBPF](27-replace/README.md)
- [BPF lifecycle: Running eBPF programs continuously in Detached mode after user-mode applications exit](28-detach/README.md)
- [Modifying System Call Parameters with eBPF](34-syscall/README.md)

Other:

- [Using user ring buffer to send information to the kernel](35-user-ringbuf/README.md)
- [Userspace eBPF Runtimes: Overview and Applications](36-userspace-ebpf/README.md)
- [Compile Once, Run Everywhere for userspace with eBPF and BTF](38-btf-uprobe/README.md)

# bcc and bpftrace tutorial

For reference:

- [BPF Features by Linux Kernel Version](bcc-documents/kernel-versions.md)
- [Kernel Configuration for BPF Features](bcc-documents/kernel_config.md)
- [bcc Reference Guide](bcc-documents/reference_guide.md)
- [Special Filtering](bcc-documents/special_filtering.md)
- [bcc Tutorial](bcc-documents/tutorial.md)".- [bcc Python Developer Tutorial](bcc-documents/tutorial_bcc_python_developer.md)
- [bpftrace Tutorial](bpftrace-tutorial/README.md)