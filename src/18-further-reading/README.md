# More Reference Materials： papers, projects

You may find more about eBPF in these places:

- A curated list of awesome projects related to eBPF: <https://github.com/zoidbergwill/awesome-ebpf>
- A website of eBPF projects and tutorials: <https://ebpf.io/>

This is also list of eBPF related papers I read in recent years, might be helpful for people who are interested in eBPF related research.

eBPF (extended Berkeley Packet Filter) is an emerging technology that allows safe execution of user-provided programs in the Linux kernel. It has gained widespread adoption in recent years for accelerating network processing, enhancing observability, and enabling programmable packet processing.

This document list some key research papers on eBPF over the past few years. The papers cover several aspects of eBPF, including accelerating distributed systems, storage, and networking, formally verifying the eBPF JIT compiler and verifier, applying eBPF for intrusion detection, and automatically generating hardware designs from eBPF programs.

Some key highlights:

- eBPF enables executing custom functions in the kernel to accelerate distributed protocols, storage engines, and networking applications with improved throughput and lower latency compared to traditional userspace implementations.
- Formal verification of eBPF components like JIT and verifier ensures correctness and reveals bugs in real-world implementations.
- eBPF's programmability and efficiency make it suitable for building intrusion detection and network monitoring applications entirely in the kernel.
- Automated synthesis of hardware designs from eBPF programs allows software developers to quickly generate optimized packet processing pipelines in network cards.

The papers demonstrate eBPF's versatility in accelerating systems, enhancing security, and simplifying network programming. As eBPF adoption grows, it is an important area of systems research with many open problems related to performance, safety, hardware integration, and ease of use.

If you have any suggestions or adding papers, please feel free to open an issue or PR. The list was created in 2023.10, New papers will be added in the future.

> Check out our open-source projects at [eunomia-bpf](https://github.com/eunomia-bpf) and eBPF tutorials at [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial). I'm also looking for a PhD position in the area of systems and networking in 2024/2025. My [Github](https://github.com/yunwei37) and [email](yunwei356@gmail.com).

## XRP: In-Kernel Storage Functions with eBPF

With the emergence of microsecond-scale NVMe storage devices, the Linux kernel storage stack overhead has become significant, almost doubling access times. We present XRP, a framework that allows applications to execute user-defined storage functions, such as index lookups or aggregations, from an eBPF hook in the NVMe driver, safely bypassing most of the kernel’s storage stack. To preserve file system semantics, XRP propagates a small amount of kernel state to its NVMe driver hook where the user-registered eBPF functions are called. We show how two key-value stores, BPF-KV, a simple B+-tree key-value store, and WiredTiger, a popular log-structured merge tree storage engine, can leverage XRP to significantly improve throughput and latency.

OSDI '22 Best Paper: <https://www.usenix.org/conference/osdi22/presentation/zhong>

## Specification and verification in the field: Applying formal methods to BPF just-in-time compilers in the Linux kernel

This paper describes our experience applying formal methods to a critical component in the Linux kernel, the just-in-time compilers ("JITs") for the Berkeley Packet Filter (BPF) virtual machine. We verify these JITs using Jitterbug, the first framework to provide a precise specification of JIT correctness that is capable of ruling out real-world bugs, and an automated proof strategy that scales to practical implementations. Using Jitterbug, we have designed, implemented, and verified a new BPF JIT for 32-bit RISC-V, found and fixed 16 previously unknown bugs in five other deployed JITs, and developed new JIT optimizations; all of these changes have been upstreamed to the Linux kernel. The results show that it is possible to build a verified component within a large, unverified system with careful design of specification and proof strategy.

OSDI 20: <https://www.usenix.org/conference/osdi20/presentation/nelson>

## λ-IO: A Unified IO Stack for Computational Storage

The emerging computational storage device offers an opportunity for in-storage computing. It alleviates the overhead of data movement between the host and the device, and thus accelerates data-intensive applications. In this paper, we present λ-IO, a unified IO stack managing both computation and storage resources across the host and the device. We propose a set of designs – interface, runtime, and scheduling – to tackle three critical issues. We implement λ-IO in full-stack software and hardware environment, and evaluate it with synthetic and real applications against Linux IO, showing up to 5.12× performance improvement.

FAST23: <https://www.usenix.org/conference/fast23/presentation/yang-zhe>

## Extension Framework for File Systems in User space

User file systems offer numerous advantages over their in-kernel implementations, such as ease of development and better system reliability. However, they incur heavy performance penalty. We observe that existing user file system frameworks are highly general; they consist of a minimal interposition layer in the kernel that simply forwards all low-level requests to user space. While this design offers flexibility, it also severely degrades performance due to frequent kernel-user context switching.

This work introduces ExtFUSE, a framework for developing extensible user file systems that also allows applications to register "thin" specialized request handlers in the kernel to meet their specific operative needs, while retaining the complex functionality in user space. Our evaluation with two FUSE file systems shows that ExtFUSE can improve the performance of user file systems with less than a few hundred lines on average. ExtFUSE is available on GitHub.

ATC 19: <https://www.usenix.org/conference/atc19/presentation/bijlani>

## Electrode: Accelerating Distributed Protocols with eBPF

Implementing distributed protocols under a standard Linux kernel networking stack enjoys the benefits of load-aware CPU scaling, high compatibility, and robust security and isolation. However, it suffers from low performance because of excessive user-kernel crossings and kernel networking stack traversing. We present Electrode with a set of eBPF-based performance optimizations designed for distributed protocols. These optimizations get executed in the kernel before the networking stack but achieve similar functionalities as were implemented in user space (e.g., message broadcasting, collecting quorum of acknowledgments), thus avoiding the overheads incurred by user-kernel crossings and kernel networking stack traversing. We show that when applied to a classic Multi-Paxos state machine replication protocol, Electrode improves its throughput by up to 128.4% and latency by up to 41.7%.

NSDI 23: <https://www.usenix.org/conference/nsdi23/presentation/zhou>

## BMC: Accelerating Memcached using Safe In-kernel Caching and Pre-stack Processing

In-memory key-value stores are critical components that help scale large internet services by providing low-latency access to popular data. Memcached, one of the most popular key-value stores, suffers from performance limitations inherent to the Linux networking stack and fails to achieve high performance when using high-speed network interfaces. While the Linux network stack can be bypassed using DPDK based solutions, such approaches require a complete redesign of the software stack and induce high CPU utilization even when client load is low.

To overcome these limitations, we present BMC, an in-kernel cache for Memcached that serves requests before the execution of the standard network stack. Requests to the BMC cache are treated as part of the NIC interrupts, which allows performance to scale with the number of cores serving the NIC queues. To ensure safety, BMC is implemented using eBPF. Despite the safety constraints of eBPF, we show that it is possible to implement a complex cache service. Because BMC runs on commodity hardware and requires modification of neither the Linux kernel nor the Memcached application, it can be widely deployed on existing systems. BMC optimizes the processing time of Facebook-like small-size requests. On this target workload, our evaluations show that BMC improves throughput by up to 18x compared to the vanilla Memcached application and up to 6x compared to an optimized version of Memcached that uses the SO_REUSEPORT socket flag. In addition, our results also show that BMC has negligible overhead and does not deteriorate throughput when treating non-target workloads.

NSDI 21: <https://www.usenix.org/conference/nsdi21/presentation/ghigoff>

## hXDP: Efficient Software Packet Processing on FPGA NICs

FPGA accelerators on the NIC enable the offloading of expensive packet processing tasks from the CPU. However, FPGAs have limited resources that may need to be shared among diverse applications, and programming them is difficult.

We present a solution to run Linux's eXpress Data Path programs written in eBPF on FPGAs, using only a fraction of the available hardware resources while matching the performance of high-end CPUs. The iterative execution model of eBPF is not a good fit for FPGA accelerators. Nonetheless, we show that many of the instructions of an eBPF program can be compressed, parallelized or completely removed, when targeting a purpose-built FPGA executor, thereby significantly improving performance. We leverage that to design hXDP, which includes (i) an optimizing-compiler that parallelizes and translates eBPF bytecode to an extended eBPF Instruction-set Architecture defined by us; a (ii) soft-processor to execute such instructions on FPGA; and (iii) an FPGA-based infrastructure to provide XDP's maps and helper functions as defined within the Linux kernel.

We implement hXDP on an FPGA NIC and evaluate it running real-world unmodified eBPF programs. Our implementation is clocked at 156.25MHz, uses about 15% of the FPGA resources, and can run dynamically loaded programs. Despite these modest requirements, it achieves the packet processing throughput of a high-end CPU core and provides a 10x lower packet forwarding latency.

OSDI 20: <https://www.usenix.org/conference/osdi20/presentation/brunella>

## Network-Centric Distributed Tracing with DeepFlow: Troubleshooting Your Microservices in Zero Code

Microservices are becoming more complicated, posing new challenges for traditional performance monitoring solutions. On the one hand, the rapid evolution of microservices places a significant burden on the utilization and maintenance of existing distributed tracing frameworks. On the other hand, complex infrastructure increases the probability of network performance problems and creates more blind spots on the network side. In this paper, we present DeepFlow, a network-centric distributed tracing framework for troubleshooting microservices. DeepFlow provides out-of-the-box tracing via a network-centric tracing plane and implicit context propagation. In addition, it eliminates blind spots in network infrastructure, captures network metrics in a low-cost way, and enhances correlation between different components and layers. We demonstrate analytically and empirically that DeepFlow is capable of locating microservice performance anomalies with negligible overhead. DeepFlow has already identified over 71 critical performance anomalies for more than 26 companies and has been utilized by hundreds of individual developers. Our production evaluations demonstrate that DeepFlow is able to save users hours of instrumentation efforts and reduce troubleshooting time from several hours to just a few minutes.

SIGCOMM 23: <https://dl.acm.org/doi/10.1145/3603269.3604823>

## Fast In-kernel Traffic Sketching in eBPF

The extended Berkeley Packet Filter (eBPF) is an infrastructure that allows to dynamically load and run micro-programs directly in the Linux kernel without recompiling it.

In this work, we study how to develop high-performance network measurements in eBPF. We take sketches as case-study, given their ability to support a wide-range of tasks while providing low-memory footprint and accuracy guarantees. We implemented NitroSketch, the state-of-the-art sketch for user-space networking and show that best practices in user-space networking cannot be directly applied to eBPF, because of its different performance characteristics. By applying our lesson learned we improve its performance by 40% compared to a naive implementation.

SIGCOMM 23: <https://dl.acm.org/doi/abs/10.1145/3594255.3594256>

## SPRIGHT: extracting the server from serverless computing! high-performance eBPF-based event-driven, shared-memory processing

Serverless computing promises an efficient, low-cost compute capability in cloud environments. However, existing solutions, epitomized by open-source platforms such as Knative, include heavyweight components that undermine this goal of serverless computing. Additionally, such serverless platforms lack dataplane optimizations to achieve efficient, high-performance function chains that facilitate the popular microservices development paradigm. Their use of unnecessarily complex and duplicate capabilities for building function chains severely degrades performance. 'Cold-start' latency is another deterrent.

We describe SPRIGHT, a lightweight, high-performance, responsive serverless framework. SPRIGHT exploits shared memory processing and dramatically improves the scalability of the dataplane by avoiding unnecessary protocol processing and serialization-deserialization overheads. SPRIGHT extensively leverages event-driven processing with the extended Berkeley Packet Filter (eBPF). We creatively use eBPF's socket message mechanism to support shared memory processing, with overheads being strictly load-proportional. Compared to constantly-running, polling-based DPDK, SPRIGHT achieves the same dataplane performance with 10× less CPU usage under realistic workloads. Additionally, eBPF benefits SPRIGHT, by replacing heavyweight serverless components, allowing us to keep functions 'warm' with negligible penalty.

Our preliminary experimental results show that SPRIGHT achieves an order of magnitude improvement in throughput and latency compared to Knative, while substantially reducing CPU usage, and obviates the need for 'cold-start'.

<https://dl.acm.org/doi/10.1145/3544216.3544259>

## KEN: Kernel Extensions using Natural Language

The ability to modify and extend an operating system is an important feature for improving a system's security, reliability, and performance. The extended Berkeley Packet Filters (eBPF) ecosystem has emerged as the standard mechanism for extending the Linux kernel and has recently been ported to Windows. eBPF programs inject new logic into the kernel that the system will execute before or after existing logic. While the eBPF ecosystem provides a flexible mechanism for kernel extension, it is difficult for developers to write eBPF programs today. An eBPF developer must have deep knowledge of the internals of the operating system to determine where to place logic and cope with programming limitations on the control flow and data accesses of their eBPF program enforced by the eBPF verifier. This paper presents KEN, an alternative framework that alleviates the difficulty of writing an eBPF program by allowing Kernel Extensions to be written in Natural language. KEN uses recent advances in large language models (LLMs) to synthesize an eBPF program given a user's English language prompt. To ensure that LLM's output is semantically equivalent to the user's prompt, KEN employs a combination of LLM-empowered program comprehension, symbolic execution, and a series of feedback loops. KEN's key novelty is the combination of these techniques. In particular, the system uses symbolic execution in a novel structure that allows it to combine the results of program synthesis and program comprehension and build on the recent success that LLMs have shown for each of these tasks individually. To evaluate KEN, we developed a new corpus of natural language prompts for eBPF programs. We show that KEN produces correct eBPF programs on 80% which is an improvement of a factor of 2.67 compared to an LLM-empowered program synthesis baseline.

eBPF'24: <https://dl.acm.org/doi/10.1145/3672197.3673434> and arxiv <https://arxiv.org/abs/2312.05531>

## Programmable System Call Security with eBPF

System call filtering is a widely used security mechanism for protecting a shared OS kernel against untrusted user applications. However, existing system call filtering techniques either are too expensive due to the context switch overhead imposed by userspace agents, or lack sufficient programmability to express advanced policies. Seccomp, Linux's system call filtering module, is widely used by modern container technologies, mobile apps, and system management services. Despite the adoption of the classic BPF language (cBPF), security policies in Seccomp are mostly limited to static allow lists, primarily because cBPF does not support stateful policies. Consequently, many essential security features cannot be expressed precisely and/or require kernel modifications.
In this paper, we present a programmable system call filtering mechanism, which enables more advanced security policies to be expressed by leveraging the extended BPF language (eBPF). More specifically, we create a new Seccomp eBPF program type, exposing, modifying or creating new eBPF helper functions to safely manage filter state, access kernel and user state, and utilize synchronization primitives. Importantly, our system integrates with existing kernel privilege and capability mechanisms, enabling unprivileged users to install advanced filters safely. Our evaluation shows that our eBPF-based filtering can enhance existing policies (e.g., reducing the attack surface of early execution phase by up to 55.4% for temporal specialization), mitigate real-world vulnerabilities, and accelerate filters.

<https://arxiv.org/abs/2302.10366>

## Cross Container Attacks: The Bewildered eBPF on Clouds

The extended Berkeley Packet Filter (eBPF) provides powerful and flexible kernel interfaces to extend the kernel functions for user space programs via running bytecode directly in the kernel space. It has been widely used by cloud services to enhance container security, network management, and system observability. However, we discover that the offensive eBPF that have been extensively discussed in Linux hosts can bring new attack surfaces to containers. With eBPF tracing features, attackers can break the container's isolation and attack the host, e.g., steal sensitive data, DoS, and even escape the container. In this paper, we study the eBPF-based cross container attacks and reveal their security impacts in real world services. With eBPF attacks, we successfully compromise five online Jupyter/Interactive Shell services and the Cloud Shell of Google Cloud Platform. Furthermore, we find that the Kubernetes services offered by three leading cloud vendors can be exploited to launch cross-node attacks after the attackers escape the container via eBPF. Specifically, in Alibaba's Kubernetes services, attackers can compromise the whole cluster by abusing their over-privileged cloud metrics or management Pods. Unfortunately, the eBPF attacks on containers are seldom known and can hardly be discovered by existing intrusion detection systems. Also, the existing eBPF permission model cannot confine the eBPF and ensure secure usage in shared-kernel container environments. To this end, we propose a new eBPF permission model to counter the eBPF attacks in containers.

<https://www.usenix.org/conference/usenixsecurity23/presentation/he>

## Comparing Security in eBPF and WebAssembly

This paper examines the security of eBPF and WebAssembly (Wasm), two technologies that have gained widespread adoption in recent years, despite being designed for very different use cases and environments. While eBPF is a technology primarily used within operating system kernels such as Linux, Wasm is a binary instruction format designed for a stack-based virtual machine with use cases extending beyond the web. Recognizing the growth and expanding ambitions of eBPF, Wasm may provide instructive insights, given its design around securely executing arbitrary untrusted programs in complex and hostile environments such as web browsers and clouds. We analyze the security goals, community evolution, memory models, and execution models of both technologies, and conduct a comparative security assessment, exploring memory safety, control flow integrity, API access, and side-channels. Our results show that eBPF has a history of focusing on performance first and security second, while Wasm puts more emphasis on security at the cost of some runtime overheads. Considering language-based restrictions for eBPF and a security model for API access are fruitful directions for future work.

<https://dl.acm.org/doi/abs/10.1145/3609021.3609306>

More about can be found in the first workshop: <https://conferences.sigcomm.org/sigcomm/2023/workshop-ebpf.html>

## A flow-based IDS using Machine Learning in eBPF

eBPF is a new technology which allows dynamically loading pieces of code into the Linux kernel. It can greatly speed up networking since it enables the kernel to process certain packets without the involvement of a userspace program. So far eBPF has been used for simple packet filtering applications such as firewalls or Denial of Service protection. We show that it is possible to develop a flow based network intrusion detection system based on machine learning entirely in eBPF. Our solution uses a decision tree and decides for each packet whether it is malicious or not, considering the entire previous context of the network flow. We achieve a performance increase of over 20% compared to the same solution implemented as a userspace program.

<https://arxiv.org/abs/2102.09980>

## Femto-containers: lightweight virtualization and fault isolation for small software functions on low-power IoT microcontrollers

Low-power operating system runtimes used on IoT microcontrollers typically provide rudimentary APIs, basic connectivity and, sometimes, a (secure) firmware update mechanism. In contrast, on less constrained hardware, networked software has entered the age of serverless, microservices and agility. With a view to bridge this gap, in the paper we design Femto-Containers, a new middleware runtime which can be embedded on heterogeneous low-power IoT devices. Femto-Containers enable the secure deployment, execution and isolation of small virtual software functions on low-power IoT devices, over the network. We implement Femto-Containers, and provide integration in RIOT, a popular open source IoT operating system. We then evaluate the performance of our implementation, which was formally verified for fault-isolation, guaranteeing that RIOT is shielded from logic loaded and executed in a Femto-Container. Our experiments on various popular micro-controller architectures (Arm Cortex-M, ESP32 and RISC-V) show that Femto-Containers offer an attractive trade-off in terms of memory footprint overhead, energy consumption, and security.

<https://dl.acm.org/doi/abs/10.1145/3528535.3565242>

> The original link of this article: <https://eunomia.dev/tutorials/18-further-reading>
