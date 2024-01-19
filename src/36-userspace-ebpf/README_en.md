# Userspace eBPF Runtimes: Overview and Applications

Yusheng Zheng

In this blog post, we'll dive into the world of eBPF in userspace. While many are familiar with kernel-based eBPF, userspace eBPF runtimes have been making significant strides and offer compelling use cases. We will also compare userspace eBPF runtimes with Wasm runtimes, another popular technology in the cloud-native and edge computing landscape. Among these, we're excited to introduce [bpftime](https://github.com/eunomia-bpf/bpftime). Powered by an LLVM `JIT/AOT` backend, our benchmarks suggest that bpftime stands out as one of the fastest userspace eBPF runtimes available.

## Introduction to eBPF

### What is eBPF?

eBPF, which stands for "extended Berkeley Packet Filter," is a revolutionary technology that facilitates the dynamic tracing and monitoring of kernel operations without modifying kernel source code or rebooting the system. Originally designed for network packet filtering, eBPF has evolved to support a wide range of applications, from performance analysis to security, making it a versatile tool in a system administrator's arsenal.

The story of eBPF begins with the Berkeley Packet Filter (BPF), introduced in the early 1990s as a way to filter and capture network packets efficiently. Over the years, BPF proved to be an invaluable asset, but there was room for improvement. eBPF emerged as an advanced iteration of BPF, equipped with a richer instruction set and the capability to interact with kernel data structures directly.

The Linux kernel adopted eBPF around 2014, and since then, its popularity and adoption have skyrocketed. Key contributors to the Linux kernel worked diligently to evolve eBPF from a simple packet filter to a generic and powerful bytecode engine.

### Its significance in modern computing and network solutions

In today's complex computing environments, the need for real-time data and insights is paramount. eBPF shines in this regard, allowing developers and administrators to introspect and modify system behaviors on the fly.

Given its dynamic nature, eBPF has become a cornerstone of modern networking solutions. It enables fine-grained traffic control, load balancing, and security enforcement at the kernel level, ensuring optimal performance and security. Furthermore, in the realm of observability, eBPF provides granular insights into system calls, hardware events, and more, facilitating proactive problem detection and resolution.

### eBPF: from kernel runtime to userspace runtime

While the initial design of eBPF was deeply embedded within the kernel, the demand for similar functionality in userspace applications led to the evolution of userspace eBPF runtimes. These runtimes allow developers to leverage eBPF's capabilities outside the kernel, expanding its utility and applicability. Userspace eBPF runtimes make it feasible to apply eBPF's prowess to a broader set of applications, from custom network protocols to novel security solutions, further cementing eBPF's role as a transformative technology in the computing landscape.

## Userspace eBPF Runtimes and Their Role

### What is a userspace eBPF runtime?

A userspace eBPF runtime provides a platform outside of the kernel to run eBPF programs. While one of eBPF's standout attributes is its capability to execute code within the kernel space, offering rapid observability and data aggregation, there are scenarios where having a userspace alternative becomes valuable. These userspace runtimes extend the reach of eBPF's versatility to areas beyond kernel integrations and often serve as experimental grounds, debugging tools, or frameworks for specific use cases.

### Introduction to specific runtimes

#### **ubpf**

[uBPF](https://github.com/iovisor/ubpf) was among the early attempts to bring eBPF to the userspace. Conceived primarily as a proof-of-concept, it served as a user-space interpretation of an eBPF interpreter combined with an x86_64 and arm64 JIT. Despite its origins as an early prototype, uBPF garnered attention and was utilized as a foundation for high-performance networking projects such as DPDK and Oko. Its non-GPL licensing (Apache) makes it favorable for a wide range of projects, inclusive of proprietary ones. However, as of recent, uBPF is catching up with kernel developments, particularly with contributions from Microsoft for its eBPF Windows implementation. However, develop ubpf and rbpf programs may require a specific toolchain, which may be a barrier for some users. ubpf only have a limited hashmap implementation, which may not be enough for some users.

#### **rbpf**

[rbpf](https://github.com/qmonnet/rbpf) is heavily influenced by uBPF but with an emphasis on Rust, a language renowned for its memory safety guarantees. The creation of rbpf was driven by a desire to explore the intersections of eBPF and Rust. While not as widespread in adoption, notable users of rbpf include the Solana team, employing it for blockchain tools with eBPF-driven smart contracts. One of rbpf's advantages lies in its licensing (MIT), allowing for broad reuse across various projects. rbpf also lacks eBPF map support, and only has JIT support for x86_64.

#### **bpftime**

Built atop LLVM JIT/AOT, [bpftime](https://github.com/eunomia-bpf/bpftime) is a cutting-edge, high-performance eBPF runtime designed exclusively for userspace operations. It stands out with its rapid Uprobe capabilities and Syscall hooks, notably outperforming the kernel Uprobe by a tenfold margin. Additionally, bpftime offers programmatic syscall hooking, shared memory maps, and compatibility with familiar toolchains like libbpf and clang. Its design addresses some kernel eBPF limitations and outpaces plugin systems like the Wasm runtime in certain aspects.

## Why is Having a Userspace Version of eBPF Interesting?

eBPF, while renowned for its kernel-space operations, has observed a growing interest in its userspace adaptations. Here's why migrating eBPF to userspace is capturing the attention of technologists:

### Enhanced Performance

In kernel operations, the Uprobe component of eBPF is often beleaguered by performance inefficiencies, primarily due to the overheads introduced by context switches. In latency-sensitive applications, these inefficiencies can be detrimental, affecting real-time monitoring and data processing. By transitioning to userspace, eBPF can bypass these context switch related delays, leading to a more optimized performance. Runtimes like `bpftime` exemplify this, offering substantial performance improvements compared to their kernel counterparts.

### Flexibility and Integration

Userspace eBPF runtimes champion flexibility. Unlike some alternatives, such as the Wasm runtime, which might necessitate manual integrations, userspace eBPF provides the boon of automatic instrumentation. This means they can be seamlessly introduced into running processes without the need for cumbersome restarts or recompilations, ensuring smoother operational flows.

### Augmented Security

Operating in kernel mode, eBPF programs require root access, which can inadvertently expand the attack surface, making systems susceptible to vulnerabilities like container escapes or even potential kernel exploits. Userspace runtimes, however, operate outside this high-risk zone. By functioning in userspace, they demand fewer privileges, inherently reducing the potential avenues for security breaches.

### Debugging and Licensing Flexibility

One of the innate advantages of userspace eBPF runtimes is the ease with which developers can debug their code. The accessibility to integrate breakpoints in a userspace interpreter is a marked advantage over the relatively constrained debugging capabilities in kernel eBPF. Additionally, the licensing flexibility of userspace eBPF runtimes, typically offered under licenses like Apache or MIT, ensures they can be paired with a diverse range of projects, including proprietary ones, sidestepping the GPL constraints associated with kernel code.

## Use Cases: Existing eBPF Userspace Applications

Userspace eBPF is being utilized in a number of notable projects, each harnessing the unique capabilities of eBPF to enhance their functionalities. Here's how Userspace eBPF is currently utilized in various applications:

1. [**Oko:**](https://github.com/Orange-OpenSource/Oko)
  
   Oko is an extension of Open vSwitch-DPDK that provides runtime extension with BPF programs. It enables the use of BPF programs to process packets in userspace, providing flexible packet processing and facilitating the integration of Open vSwitch with other systems.

1. [**DPDK eBPF Support:**](https://www.dpdk.org/wp-content/uploads/sites/35/2018/10/pm-07-DPDK-BPFu6.pdf)

   The DPDK (Data Plane Development Kit) eBPF support facilitates fast packet processing by enabling the use of eBPF programs in userspace, which can be loaded and run to analyze network packets. This enhances the flexibility and programmability of network applications without requiring kernel modifications.

1. [**Solana:**](https://solana.com/)

   Solana utilizes eBPF to implement a JIT (Just-In-Time) compiler, which is essential for executing smart contracts on its blockchain network. The use of eBPF ensures safety, performance, and architecture agnosticism, thus allowing efficient execution of smart contracts across validator nodes on the Solana blockchain.

1. [**eBPF for Windows (Work-In-Progress):**](https://github.com/microsoft/ebpf-for-windows)

   This project is aimed at bringing the eBPF toolchains and APIs familiar in the Linux ecosystem to Windows, allowing existing eBPF toolchains to be utilized on top of Windows. This demonstrates a promising endeavor to extend the capabilities of eBPF beyond Linux, although it's still a work in progress.

The benefits of using eBPF in these applications include:

- **Flexibility:** eBPF provides a flexible framework for running programs in the kernel or userspace, enabling developers to extend the functionality of existing systems without modifying their core code.
- **Performance:** By allowing JIT compilation and efficient packet processing, eBPF can significantly enhance the performance of network applications and blockchain smart contract execution.
- **Safety and Security:** The eBPF framework provides mechanisms for verifying the safety properties of programs before execution, thus ensuring the integrity and security of the systems it is integrated with.
- **Cross-platform Capability:** The architecture-agnostic nature of eBPF instruction set enables cross-platform compatibility, as seen in projects like Solana and the work-in-progress eBPF for Windows.

These attributes make eBPF a powerful tool for augmenting a variety of applications, ranging from network processing to blockchain smart contract execution, and beyond. There are also some papers that discuss the use of eBPF in userspace:

1. [**RapidPatch: Firmware Hotpatching for Real-Time Embedded Devices**](https://www.usenix.org/conference/usenixsecurity22/presentation/he-yi):
  
   This paper introduces a new hotpatching framework named RapidPatch, which is designed to facilitate the propagation of patches by installing generic patches on heterogeneous embedded devices without disrupting other tasks running on them.

   Furthermore, RapidPatch proposes two types of eBPF patches for different types of vulnerabilities and develops an eBPF patch verifier to ensure patch safety.

1. [**Femto-Containers: Lightweight Virtualization and Fault Isolation For Small Software Functions on Low-Power IoT Microcontrollers**](https://arxiv.org/abs/2210.03432):

   This paper presents Femto-Containers, a novel framework that enables the secure deployment, execution, and isolation of small virtual software functions on low-power IoT devices over a network.

   The framework is implemented and provided in RIOT, a popular open source IoT operating system, with an emphasis on secure deployment, execution, and isolation of small virtual software functions on low-power IoT devices, over the network.

   The paper discusses the implementation of a Femto-Container hosting engine integrated within a common low-power IoT operating system (RIOT), enhancing it with the ability to start, update, or terminate Femto-Containers on demand, securely over a standard IPv6/6LoWPAN network.
  
These papers delve into pertinent advancements concerning firmware patching and lightweight virtualization, demonstrating innovations that address critical challenges in the domains of real-time embedded systems and low-power IoT microcontrollers respectively.

## Userspace eBPF Runtime vs Wasm Runtime

In the evolving landscape of cloud-native and edge computing, both eBPF (extended Berkeley Packet Filter) and Wasm (WebAssembly) have emerged as powerful tools. However, they come with their own set of design principles and trade-offs.

### A Comparison of eBPF and Wasm

**eBPF**:

- **Philosophy**: eBPF prioritizes performance, often making it the choice for real-time kernel operations and high-throughput networking tasks.
- **Security**: While performance takes the forefront, security in eBPF is ensured through the use of a verifier, ensuring that all programs are safe to run without causing kernel panics or infinite loops.
  
**Wasm**:

- **Philosophy**: Originally designed for the web, Wasm places a higher emphasis on portability and security. It was conceived to execute code nearly as fast as running native machine code and ensures safety in hostile environments like web browsers.
- **Security**: The primary security model for Wasm revolves around Software Fault Isolation (SFI). This model guarantees safe execution by enforcing sandboxing, even though this can introduce some runtime overheads.

For both technologies, reliance on underlying libraries for complex operations is paramount. For instance, Wasm leans on libraries like `Wasi-nn` for neural network operations. However, when interfacing with such external APIs, especially in Wasm's context, there's a need for additional validation and runtime checks, sometimes leading to substantial performance costs. eBPF, when embedded within the host, capitalizes on its verifier to ensure code safety, offering a more performance-centric approach.

On the language support front, while eBPF's niche and specialized nature mean limited language support, Wasm boasts a broader language portfolio due to its origin and design for the web.

## bpftime Quick Start

With `bpftime`, you can build eBPF applications using familiar tools like clang and libbpf, and execute them in userspace. For instance, the `malloc` eBPF program traces malloc calls using uprobe and aggregates the counts using a hash map.

You can refer to [documents/build-and-test.md](https://eunomia.dev/bpftime/documents/build-and-test) for how to build the project, or using the container images from [GitHub packages](https://github.com/eunomia-bpf/bpftime/pkgs/container/bpftime).

To get started, you can build and run a libbpf based eBPF program starts with `bpftime` cli:

```console
make -C example/malloc # Build the eBPF program example
bpftime load ./example/malloc/malloc
```

In another shell, Run the target program with eBPF inside:

```console
$ bpftime start ./example/malloc/victim
Hello malloc!
malloc called from pid 250215
continue malloc...
malloc called from pid 250215
```

You can also dynamically attach the eBPF program with a running process:

```console
$ ./example/malloc/victim & echo $! # The pid is 101771
[1] 101771
101771
continue malloc...
continue malloc...
```

And attach to it:

```console
$ sudo bpftime attach 101771 # You may need to run make install in root
Inject: "/root/.bpftime/libbpftime-agent.so"
Successfully injected. ID: 1
```

You can see the output from original program:

```console
$ bpftime load ./example/malloc/malloc
...
12:44:35 
        pid=247299      malloc calls: 10
        pid=247322      malloc calls: 10
```

Alternatively, you can also run our sample eBPF program directly in the kernel eBPF, to see the similar output:

```console
$ sudo example/malloc/malloc
15:38:05
        pid=30415       malloc calls: 1079
        pid=30393       malloc calls: 203
        pid=29882       malloc calls: 1076
        pid=34809       malloc calls: 8
```

See [documents/usage.md](https://eunomia.dev/bpftime/documents/usage) for more details.

## Conclusion

Userspace eBPF runtimes are an exciting development that expands the capabilities of eBPF beyond the kernel. As highlighted in this post, they offer compelling benefits like enhanced performance, flexibility, and security compared to kernel-based eBPF. Runtimes like bpftime demonstrate the potential for substantial speedups, even outperforming alternatives like Wasm runtimes in certain dimensions like low-level performance.

With innovative frameworks like RapidPatch and Femto-Containers utilizing userspace eBPF for patching and lightweight virtualization respectively, we are witnessing pioneering use cases that address critical challenges in embedded systems and IoT domains. As eBPF continues its evolution in userspace, we can expect even more creative applications that augment everything from smart contracts to network protocols.

While alternatives like Wasm certainly have their place with a strong emphasis on web portability and security, eBPF's specialized nature gives it an edge for performance-critical tasks. Ultimately, the choice between the two depends on the specific use case and priorities. As they continue to evolve, userspace eBPF runtimes are cementing their position as an indispensable part of the cloud-native technology stack, offering an unparalleled combination of safety, efficiency and innovation.

> We encourage our readers to dive deep into the world of userspace eBPF, starting with our bpftime GitHub repository: <https://github.com/eunomia-bpf/bpftime> Contributions, feedback, or simply using the tool can further the cause and provide invaluable insights to the community.
>
> If you use our project in research, please [cite our repo](https://github.com/eunomia-bpf/bpftime/blob/master/CITATION.cff).

## reference

1. bpftime: <https://github.com/eunomia-bpf/bpftime>
2. ubpf: <https://github.com/iovisor/ubpf>
3. rbpf: <https://github.com/qmonnet/rbpf>
4. Oko: <https://github.com/Orange-OpenSource/Oko>
5. RapidPatch: Firmware Hotpatching for Real-Time Embedded Devices: <https://www.usenix.org/conference/usenixsecurity22/presentation/he-yi>
6. DPDK eBPF Support: <https://www.dpdk.org/wp-content/uploads/sites/35/2018/10/pm-07-DPDK-BPFu6.pdf>
7. Solana: <https://solana.com/>
8. eBPF for Windows (Work-In-Progress): <https://github.com/microsoft/ebpf-for-windows>
9. Femto-Containers: Lightweight Virtualization and Fault Isolation For Small Software Functions on Low-Power IoT Microcontrollers: <https://arxiv.org/abs/2210.03432>
