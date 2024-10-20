# eBPF Tutorial by Example 0: Introduction to Core Concepts and Tools

This is the first part of a comprehensive development tutorial for eBPF, designed to guide you through practical eBPF development, from beginner to advanced. It covers fundamental concepts, real-world code examples, and applications in modern systems. Rather than focusing on traditional tools like BCC, we will use modern frameworks such as `libbpf`, `Cilium`, `libbpf-rs`, and eunomia-bpf, with examples provided in `C`, `Go`, and `Rust`.

The primary goal of this tutorial is to provide clear and concise examples of eBPF tools (starting with as little as 20 lines of code!) to help developers quickly grasp essential eBPF development techniques. Each example is self-contained and can be found in the directory structure, with every directory representing an independent eBPF tool. You can also visit our tutorial code repository <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorial source code.

## Introduction to eBPF: Secure and Efficient Kernel Extension

eBPF (extended Berkeley Packet Filter) is a groundbreaking technology that allows developers to run small programs directly in kernel space, safely and efficiently. Unlike traditional approaches that required modifying kernel source code or loading new modules, eBPF made it possible to customize and optimize network behavior dynamically, all without disrupting system operations. This flexibility and efficiency made eBPF a pivotal technology for overcoming the limitations of traditional networking stacks.

### What Makes eBPF So Powerful?

- **Direct Kernel Interaction:** eBPF programs execute within the kernel, interacting with system-level events such as network packets, system calls, or tracepoints.
- **Safe Execution:** eBPF ensures safety through a verifier that checks the logic of the program before it runs, preventing potential kernel crashes or security breaches.
- **Minimal Overhead:** eBPF achieves near-native execution speed by employing a Just-In-Time (JIT) compiler, which translates eBPF bytecode into optimized machine code for the specific architecture.

## eBPF: Past, Present, and Future

### Past: Programmable Networking Transformed

When eBPF was introduced in 2014, it revolutionized how developers approached networking by allowing small, programmable kernel-space applications to handle packet processing in real time. By hooking into key kernel points, eBPF enabled custom logic to be applied whenever a network packet arrived, leading to higher efficiency and flexibility. This allowed organizations to tailor networking behavior without the overhead of custom drivers or kernel modifications, creating an ideal solution for cloud-native and data-center environments.
### Present: A Versatile Framework for Modern Computing Needs

eBPF has evolved into a versatile framework that extends beyond its original purpose of networking, now encompassing observability, tracing, security, and even system resource management. eBPF programs can dynamically hook into kernel events, giving developers precise control over system behavior and performance optimization without requiring kernel modifications or reboots. This makes eBPF an essential tool for system administrators and developers who aim to monitor, optimize, and secure their environments.

Here are some key areas where eBPF is widely used today:

- **Networking:** eBPF offers real-time, high-speed packet filtering and processing within the kernel, allowing for the creation of custom protocol parsers and network policies without needing new drivers or system restarts. This enables highly efficient network management in cloud and data center environments.

- **Observability:** eBPF enables developers to gather detailed insights into system behavior by collecting custom metrics and performing in-kernel data aggregation. By tapping into kernel tracepoints and function calls, eBPF helps identify performance issues and track down elusive bugs.

- **Tracing & Profiling:** eBPF provides powerful tracing and profiling capabilities by attaching to kernel functions, tracepoints, and even user-space probes. This allows developers to gain deep insights into system and application behavior, enabling them to optimize performance and resolve complex system issues.

- **Security:** eBPF plays a vital role in real-time security monitoring. It enables deep inspection of system calls, network traffic, and other kernel activities, helping to enforce dynamic security policies and detect anomalous behavior, providing an efficient way to safeguard infrastructure.

- **Scheduler Optimization:** eBPF is increasingly used to enhance CPU scheduling, offering the ability to monitor CPU load and optimize how tasks are distributed across cores. This can lead to more efficient use of CPU resources and improved system responsiveness.

- **HID (Human Interface Device) Driver Enhancements:** Developers use eBPF to optimize HID drivers for devices like keyboards, mice, and touchscreens. By adding custom logic for handling input events, eBPF improves responsiveness in latency-sensitive applications.

Organizations across industries have adopted eBPF at scale:

- **Google:** Uses eBPF for security auditing, packet processing, real-time performance monitoring, and optimizing CPU scheduling across its vast infrastructure.
- **Netflix:** Leverages eBPF for network traffic analysis, ensuring high availability and performance for streaming services.
- **Android:** Applies eBPF to optimize network usage, power consumption, and resource allocation, improving performance and battery life on millions of devices.
- **S&P Global:** Utilizes eBPF through **Cilium** for managing networking across multiple clouds and on-premises systems, ensuring scalability and security.
- **Shopify:** Implements eBPF with **Falco** for intrusion detection, bolstering security on its e-commerce platform.
- **Cloudflare:** Uses eBPF for network observability, security monitoring, and performance optimization, protecting millions of websites globally.

eBPF's ability to dynamically adjust system behavior and extend into user space makes it an essential technology for modern computing. Whether it's optimizing network traffic, improving security, or enhancing system performance, eBPF enables developers to address real-time requirements efficiently and safely.

In addition to its kernel-mode runtime, eBPF can also be extended to user space. For example, [bpftime](https://github.com/eunomia-bpf/bpftime), a user-space eBPF runtime, allows for higher-performance tracing, performance analysis, and plugin support in user-space applications. This extension of eBPF into user space helps improve flexibility and performance in various use cases that go beyond kernel-level tasks.

### Future: The Expanding Potential of eBPF

Looking forward, eBPF is expected to become an even more integral part of operating systems. The focus is on improving its flexibility, modularity, and ease of use, making it accessible for an even broader range of applications. Innovations in memory management, concurrency mechanisms, and better integration with user-space applications are on the horizon. Projects are already underway to compile significant parts of the Linux kernel to the BPF instruction set, potentially revolutionizing how kernel development and analysis are performed.

Advancements such as dynamic stacks, better observability tools for user space (e.g., Fast Uprobes and language-specific stack walkers), and safer program termination mechanisms will continue to strengthen eBPF’s reliability and expand its use cases. Additionally, new tools and libraries will simplify eBPF development, lowering the barrier to entry for both kernel and application developers.

## Getting Started with the Tutorial

This tutorial provides practical eBPF development practices, covering topics from beginner to advanced levels. We focus on hands-on examples in areas like observability, networking, and security, using frameworks like `libbpf`, `libbpf-rs`, and `eunomia-bpf`, with examples in C, Go, and Rust.

### Who Is This Tutorial For?

- **Developers** looking to implement custom kernel solutions.
- **System Administrators** aiming to enhance performance and security.
- **Tech Enthusiasts** exploring cutting-edge kernel technologies.

### What Will You Learn?

- **Core Concepts:** eBPF fundamentals and integration with the Linux kernel.
- **Practical Skills:** Writing and deploying eBPF programs.
- **Advanced Topics:** Exploring security, tracing, and future innovations in eBPF.

---

## Table of Contents

1. **Introduction to eBPF**  
   Basic concepts and the tools you need to get started.

2. **Beginner Examples**  
   Simple programs such as "Hello World" and basic tracing using kprobe and uprobe.

3. **Observability**  
   Examples focused on monitoring network traffic, file operations, and process behavior using eBPF.

4. **Networking**  
   Examples focused on modifying and optimizing network traffic, such as XDP, TC, and socket.

5. **Security**  
   Programs for hiding process and files, sending signals to kill process, and tracking process events for security.

6. **Advanced Use Cases**  
   Complex examples involving performance profiling, scheduler optimization, and eBPF in user space (e.g., bpftime).

7. **In-Depth Topics**  
   Exploring eBPF for Android, using eBPF for network acceleration, and securing systems through syscall modifications.

## How to Use eBPF Programming

Writing eBPF programs from scratch can be complex. To simplify this, LLVM introduced the ability to compile high-level language code into eBPF bytecode in 2015. The eBPF community has since built libraries like `libbpf` to manage these programs. These libraries help load eBPF bytecode into the kernel and perform essential tasks. The Linux kernel source contains numerous eBPF examples in the `samples/bpf/` directory.

A typical eBPF program involves two parts: kernel space code (`*_kern.c`) and user space code (`*_user.c`). The kernel space code defines the logic, while the user space code manages loading and interacting with the kernel. However, tools like `libbpf-bootstrap` and the Go eBPF library help simplify this process, allowing for one-time compilation and easier development.

### Tools for eBPF Development

- **BCC**: A Python-based toolchain that simplifies writing, compiling, and loading eBPF programs. It offers many pre-built tracing tools but has limitations with dependencies and compatibility.
- **eBPF Go Library**: A Go library that decouples the process of obtaining eBPF bytecode from the loading and management of eBPF programs.
- **libbpf-bootstrap**: A modern scaffold based on `libbpf` that provides an efficient workflow for writing eBPF programs, offering a simple one-time compilation process for reusable bytecode.
- **eunomia-bpf**: A toolchain for writing eBPF programs with only kernel space code. It simplifies the development of eBPF programs by dynamically loading them.

These tools help reduce the complexity of developing eBPF programs, making the process more accessible to developers aiming to optimize system performance, security, and observability.

## Some Tips on Learning eBPF Development

This article will not provide a more detailed introduction to the principles of eBPF, but here is a learning plan and reference materials that may be of value:

### Introduction to eBPF (5-7h)

- Google or other search engines: eBPF
- Ask ChatGPT-like things: What is eBPF?

Recommended:

- Read the introduction to ebpf: <https://ebpf.io/> (30min)
- Briefly understand the ebpf kernel-related documentation: <https://docs.ebpf.io/> (Know where to queries for tech details, 30min)

Answer three questions:

1. Understand what eBPF is? Why do we need it? Can't we use kernel modules?
2. What functions does it have? What can it do in the Linux kernel? What are the types of eBPF programs and helpers (not all of them need to be known, but need to know where to find them)?
3. What can it be used for? For example, in which scenarios can it be used? Networking, security, observability?

### Understand how to develop eBPF programs (10-15h)

Understand and try eBPF development frameworks:

- bpftrace tutorial：<https://eunomia.dev/tutorials/bpftrace-tutorial/> （Try it，1h）
- Examples of developing various tools with BCC: <https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md> (Run through, 3-4h)
- Some examples of libbpf: <https://github.com/libbpf/libbpf-bootstrap> (Run any interesting one and read the source code, 2h)
- Tutorials: <https://github.com/eunomia-bpf/bpf-developer-tutorial> (Read part 1-10, 3-4h)

Other development frameworks: Go or Rust language, please search and try on your own (0-2h)

Have questions or things you want to know, whether or not they are related to this project, you can start discussing in the discussions of this project.

Answer some questions and try some experiments (2-5h):

1. How to develop the simplest eBPF program?
2. How to trace a kernel feature or function with eBPF? There are many ways, provide corresponding code examples;
3. What are the solutions for communication between user mode and kernel mode? How to send information from user mode to kernel mode? How to pass information from kernel mode to user mode? Provide code examples;
4. Write your own eBPF program to implement a feature;
5. In the entire lifecycle of an eBPF program, what does it do in user mode and kernel mode?

## References

- eBPF Introduction: <https://ebpf.io/>
- BPF Compiler Collection (BCC): <https://github.com/iovisor/bcc>
- eunomia-bpf: <https://github.com/eunomia-bpf/eunomia-bpf>

You can also visit our tutorial code repository <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorial source code. All content is open source. We will continue to share more content about eBPF development practices to help you better understand and master eBPF technology.".
