# 用户空间 eBPF 运行时：深度解析与应用实践

郑昱笙

本文旨在对用户空间的 eBPF 运行时和对应的一些应用场景进行剖析和总结。尽管大多数人对基于内核的 eBPF 已有所了解，用户空间 eBPF 的进展和应用实践同样引人注目。本文还将探讨用户空间 eBPF 运行时与 Wasm 运行时的技术比较，后者在云原生和边缘计算领域已获得广泛的关注。我们也新开源了一个用户态 eBPF 运行时 [bpftime](https://github.com/eunomia-bpf/bpftime)。通过 LLVM `JIT/AOT` 后端支持，我们的基准测试表明 bpftime 是最快的用户空间 eBPF 运行时之一，同时还可以让内核中间的 eBPF Uprobe 无缝在用户空间运行，获得近十倍的性能提升。

## eBPF：内核的动态扩展运行时与字节码

### eBPF 究竟是何方神圣？

eBPF，全称 "extended Berkeley Packet Filter"，是一项允许在不更改内核源代码或重启系统的情况下动态干预和修改内核行为的革命性技术。虽然 eBPF 起初是作为网络数据包过滤工具而设计，但如今已广泛应用于从性能分析到安全策略等多个方面，逐渐成为系统管理员的得力助手。

eBPF 的前身，Berkeley Packet Filter (BPF) —— 20 世纪 90 年代初的产物，主要用于网络数据包的高效过滤。尽管 BPF 已被广大用户所认可，eBPF 的出现则为其带来了更为广泛的指令集，并能直接与内核数据结构互动。自 2014 年 Linux 内核引入 eBPF 以后，它的影响力迅速扩张。Linux 的核心开发团队不断地完善 eBPF，使其从一个基础的网络数据包过滤器逐渐演变为一个功能强大的字节码引擎。

### eBPF 对现代计算和网络的深远影响

随着现代计算环境日益复杂，实时数据的采集和深入分析显得尤为重要。在这一背景下，eBPF 凭借其卓越的动态性，为开发者和管理员提供了实时干预系统行为的强大工具。eBPF 以其卓越的灵活性在现代网络解决方案中占据核心地位。它为流量控制、负载均衡及安全策略在内核级别提供了细致的控制手段，确保了系统的性能优化和安全稳定。同时，eBPF 在系统可观察性上也做出了显著贡献，为各种系统调用和硬件事件提供了详细的可编程追踪方案，促进了问题的迅速定位和解决。

## 用户空间 eBPF 运行时：eBPF 的新生代

### 什么是用户空间 eBPF 运行时？

虽然 eBPF 最初是为内核设计的，但它在用户空间的巨大潜力，以及内核对于 `GPL LICENSE` 的限制，也催生了用户空间 eBPF 运行时的产生。这些运行时允许开发者在内核之外利用 eBPF 的能力，提供了一个在内核之外的运行平台，扩展其实用性和适用性，同时不受限于 GPL LICENSE。虽然 eBPF 的一个突出特点是其在内核空间内执行代码的能力，提供快速的可观察性和数据聚合，但在某些情境下，拥有一个用户空间的替代方案变得非常有价值。这些用户空间运行时扩展了 eBPF 多功能性的范围，超越了内核集成，并常常作为特定用例的实验场地、调试工具或框架。

### 特定运行时简介

#### **ubpf**

[uBPF](https://github.com/iovisor/ubpf) 是将 eBPF 引入用户空间的早期尝试之一。主要作为一个概念证明，它作为 eBPF 解释器的用户空间解释与 x86_64 和 arm64 JIT 的结合。尽管其起源是一个早期原型，uBPF 吸引了注意并被用作高性能网络项目（如 DPDK 和 Oko）的基础。它的非 GPL 许可证（Apache）使其适用于各种项目，包括非开源项目。然而，最近，uBPF 正在迎头赶上内核发展，特别是微软为其 eBPF Windows 实现做出的贡献。但是，开发 ubpf 和 rbpf 程序可能需要一个特定的工具链，这对于一些用户可能是一个障碍。ubpf 只有一个有限的哈希 maps 实现，对大多数场景而言可能不够。另外，ubpf 本身只是一个虚拟机/解释器，在实际的使用中，依然需要编写胶水代码，和其他用户空间程序进行编译、链接后才能使用。

#### **rbpf**

[rbpf](https://github.com/qmonnet/rbpf) 和 uBPF 非常相似，但重点是使用了 Rust 进行开发，这是一种因其内存安全保证而著称的语言。创建 rbpf 是由于想要探索 eBPF 和 Rust 的交集。虽然没有广泛采纳，但 rbpf 的知名用户包括 Solana 团队，他们使用它为带有 eBPF 驱动的智能合约的区块链工具。rbpf 的一个优势在于其许可证 (MIT)，允许在各种项目中广泛重用。rbpf 也缺乏 eBPF Maps 支持，并且仅为 x86_64 提供 JIT 支持。同样，rbpf 也需要编译和手动嵌入对应的应用程序中才可以使用。

#### **bpftime**

基于 LLVM JIT/AOT 构建的 [bpftime](https://github.com/eunomia-bpf/bpftime) 是专为用户空间操作设计的一个高性能 eBPF 运行时。它以其快速的 Uprobe 能力和 Syscall 钩子脱颖而出，尤其是 Uprobe 性能比内核提高了十倍。此外，bpftime 提供编程 syscall 钩子、共享内存映射和与熟悉的工具链（如 libbpf 和 clang）的兼容性。其设计解决了一些内核 eBPF 的限制，并在某些方面超越了像 Wasm 运行时这样的插件系统。这是使用 Userspace bpftime 的 eBPF 进行 Hook 的一些性能数据，将用户空间和内核空间进行对比：

| Probe/Tracepoint Types | Kernel (ns)  | Userspace (ns) | Insn Count |
|------------------------|-------------:|---------------:|---------------:|
| Uprobe                 | 3224.172760  | 314.569110     | 4    |
| Uretprobe              | 3996.799580  | 381.270270     | 2    |
| Syscall Tracepoint     | 151.82801    | 232.57691      | 4    |
| Embedding runtime      | Not available |  110.008430   | 4    |

bpftime 可以类似 Kernel 中的 Uprobe 那样，自动将 eBPF 运行时注入到用户空间进程中，无需修改用户空间进程的代码，也无需进行重启进程即可使用。对于 ubpf 和 rbpf 而言，它们依然需要手动编写胶水代码和其他用户空间程序进行集成，相对来说限制了它们的使用场景。在某些场景下，bpftime 可能能作为 kernel eBPF 的一种替代方案，它也不依赖于具体内核版本或 Linux 平台，可以在其他平台上运行。

## 为什么用户空间版本的 eBPF 会吸引如此多的关注？

eBPF，原本因其在内核空间的强大性能而被广泛认知，但近年来，其在用户空间的实现也引起了业界的浓厚兴趣。以下是技术社区对于 eBPF 迁移到用户空间的热切关注的核心原因：

### 性能提升

在内核空间，eBPF 的 Uprobe 组件时常面临因上下文切换带来的性能瓶颈。这在延迟敏感的应用中可能导致不良影响，从而对实时监控和数据处理带来挑战。但用户空间版本的 eBPF 能够绕过与上下文切换有关的性能损失，实现更高的性能优化。例如，`bpftime` 运行时在用户空间的表现，相较于其内核版本，展现出了显著的性能增益。

### 灵活性与集成度

用户空间的 eBPF 运行时带来了更大的灵活性。与其他解决方案如 Wasm 运行时相比，它们无需手动集成即可提供自动插桩的特性。这意味着开发者可以轻松地将其集成进正在运行的进程中，避免了因重新启动或重新编译带来的操作中断。

### 安全性加固

在内核空间，eBPF 的执行通常需要 root 访问权限，这可能无意中增加了系统的攻击面，使其容易受到例如容器逃逸或潜在的内核利用等安全威胁。相反，用户空间的实现在这种高风险环境之外运作。它们在用户空间中运行，大大降低了对高权限的依赖，从而减少了潜在的安全风险。

### 调试与许可的便利性

用户空间 eBPF 的一个显著优点是，它为开发者提供了更加直观的调试环境。相对于内核空间中有限的调试手段，用户空间解释器提供的断点调试功能更为方便。此外，用户空间 eBPF 的许可证更加灵活，通常采用 Apache 或 MIT 这样的开源许可，这意味着它们可以轻松地与各种项目（包括商业项目）相结合，避免了与内核代码相关的 GPL 限制。

## 使用案例：现有的 eBPF 用户空间应用

用户空间 eBPF 正在项目中使用，每个项目都利用 eBPF 的独特功能来增强它们的功能:

1. [**Oko:**](https://github.com/Orange-OpenSource/Oko)

   Oko 是 Open vSwitch-DPDK 的扩展，提供了与 BPF 程序的运行时扩展。它允许使用 BPF 程序在用户空间处理数据包，提供灵活的数据包处理，并促进 Open vSwitch 与其他系统的集成。

1. [**DPDK eBPF 支持:**](https://www.dpdk.org/wp-content/uploads/sites/35/2018/10/pm-07-DPDK-BPFu6.pdf)

   DPDK (数据平面开发套件) eBPF 支持通过允许在用户空间使用 eBPF 程序来促进快速的数据包处理，这些程序可以加载并运行以分析网络数据包。这增强了网络应用的灵活性和可编程性，无需修改内核。

1. [**Solana:**](https://solana.com/)

   Solana 利用 eBPF 实现一个 JIT (即时)编译器，这对于在其区块链网络上执行智能合约是至关重要的。使用 eBPF 确保了安全性、性能和架构中立性，从而允许在 Solana 区块链上的验证器节点上高效地执行智能合约。

1. [**eBPF for Windows (进行中的工作):**](https://github.com/microsoft/ebpf-for-windows)

   该项目旨在将 Linux 生态系统中熟悉的 eBPF 工具链和 API 带到 Windows，允许在 Windows 之上使用现有的 eBPF 工具链。这展示了将 eBPF 的功能扩展到 Linux 之外的有前景的尝试，尽管它仍然是一个进行中的工作。

使用 eBPF 的这些应用的好处包括：

- **灵活性:** eBPF 提供了一个灵活的框架，用于在内核或用户空间中运行程序，使开发人员能够扩展现有系统的功能，而无需修改其核心代码。
- **性能:** 通过允许 JIT 编译和高效的数据包处理，eBPF 可以显著提高网络应用和区块链智能合约执行的性能。
- **安全性和安全性:** eBPF 框架为验证程序执行前的安全属性提供了机制，从而确保了其集成的系统的完整性和安全性。
- **跨平台能力:** eBPF 指令集的架构中立性使得跨平台兼容性成为可能，如 Solana 项目和进行中的 eBPF for Windows 所示。

这些属性使 eBPF 成为增强各种应用的强大工具，从网络处理到区块链智能合约执行，再到更多。还有一些论文讨论了在用户空间中使用 eBPF 的用途：

1. [**RapidPatch: 用于实时嵌入式设备的固件热修复**](https://www.usenix.org/conference/usenixsecurity22/presentation/he-yi):

   本文介绍了一个名为 RapidPatch 的新的热修复框架，该框架旨在通过在异构嵌入式设备上安装通用修复程序来促进修复的传播，而不会中断它们上运行的其他任务。此外，RapidPatch 提出了两种类型的 eBPF 补丁，用于不同类型的漏洞，并开发了一个 eBPF 补丁验证器以确保补丁安全。

2. [**Femto-Containers: 低功耗 IoT 微控制器上的小型软件功能的轻量级虚拟化和故障隔离**](https://arxiv.org/abs/2210.03432):

   本文介绍了 Femto-Containers，这是一个新颖的框架，允许在低功耗 IoT 设备上安全地部署、执行和隔离小型虚拟软件功能。该框架在 RIOT 中实现并提供，RIOT 是一个受欢迎的开源 IoT 操作系统，强调在低功耗 IoT 设备上安全地部署、执行和隔离小型虚拟软件功能。该论文讨论了在一个常见的低功耗 IoT 操作系统 (RIOT) 中集成的 Femto-Container 主机引擎的实现，增强了其在标准的 IPv6/6LoWPAN 网络上按需启动、更新或终止 Femto-Containers 的能力。

这些论文深入探讨了固件补丁和轻量级虚拟化方面的相关进展，展示了针对实时嵌入式系统和低功耗 IoT 微控制器领域的关键挑战的创新。

## 用户空间 eBPF 运行时 vs Wasm 运行时

在不断发展的云原生和边缘计算领域中，eBPF (扩展的伯克利数据包过滤器) 和 Wasm (WebAssembly) 都已成为强大的工具。但它们都有自己的设计原则和权衡取舍。

## eBPF 在用户空间运行时 vs Wasm 运行时：云原生计算的新纪元

在飞速进展的云原生与边缘计算生态中，eBPF (扩展的伯克利数据包过滤器) 和 Wasm (WebAssembly) 被广泛认为是两大技术巨头。这两者虽然都非常强大，但各有其独特的设计哲学与优缺点。

### eBPF 与 Wasm 之间的技术差异

**eBPF**:

- **核心理念**：eBPF 是为了满足高性能要求而设计的，特别是针对实时内核交互和高吞吐量的网络任务。
- **安全性**：尽管eBPF的主要焦点是性能，但其验证器机制确保了执行的程序在不引发内核恐慌或无限循环的前提下的安全性。

**Wasm**:

- **核心理念**：Wasm 诞生于网络环境，其设计重点在于可移植性和执行安全性，旨在实现接近本地机器代码的执行速度。
- **安全性**：Wasm 的安全策略主要基于软件故障隔离 (SFI)。沙盒执行确保了代码的安全性，但这可能会带来某些运行时的额外开销。

这两种技术都依赖于底层的库来执行复杂任务，如 Wasm 所依赖的 `Wasi-nn` 来进行神经网络处理。与这些外部API 交互时，特别是在 Wasm 的环境下，需要进行更多的验证和运行时检查，这可能导致额外的性能损耗。而eBPF则提供了一个更为性能中心化的策略，其验证器确保了代码在主机上的安全执行，而不需要运行时的额外开销。

在语言支持上，由于 eBPF 的专业特性，其语言选择较为有限，通常是 C 和 Rust。而Wasm则支持更多的编程语言，包括但不限于 C、C++、Rust、Go、Python、Java和C#。这使得Wasm在跨平台部署上有更大的灵活性，但也可能因为不恰当的语言选择引入更多的性能开销。

为了给大家提供一个直观的对比，我们在 [https://github.com/eunomia-bpf/bpf-benchmark](https://github.com/eunomia-bpf/bpf-benchmark)中展示了eBPF和Wasm运行时的性能比较。

从更宏观的角度看，eBPF运行时和Wasm实际上可以被视为是相互补充的。尽管 eBPF 拥有出色的验证器机制来确保运行时安全性，但由于其编程语言的局限性和相对较高的开发难度，它并不总是适合作为业务逻辑的首选运行时。反之，eBPF 更适用于像网络流量转发、可观测性和 livepatch 这样的高专业性任务。相对而言，Wasm 运行时可以作为 Serverless 的运行时平台、插件系统和轻量级虚拟化等场景的首选。这两者都有自己的优势，但它们的选择取决于特定的用例和优先级。

## bpftime 快速入门

使用`bpftime`，您可以使用熟悉的工具（如clang和libbpf）构建eBPF应用程序，并在用户空间中执行它们。例如，`malloc` eBPF程序使用uprobe跟踪malloc调用，并使用哈希映射对其进行统计。

您可以参考[documents/build-and-test.md](https://eunomia.dev/bpftime/documents/build-and-test)上的构建项目的方法，或者使用来自[GitHub packages](https://github.com/eunomia-bpf/bpftime/pkgs/container/bpftime)的容器映像。

要开始，请构建并运行一个基于libbpf的eBPF程序，使用以下命令行：

```console
make -C example/malloc # 构建示例的eBPF程序
bpftime load ./example/malloc/malloc
```

在另一个shell中，运行带有eBPF的目标程序：

```console
$ bpftime start ./example/malloc/victim
Hello malloc!
malloc called from pid 250215
continue malloc...
malloc called from pid 250215
```

您还可以动态地将eBPF程序附加到正在运行的进程上：

```console
$ ./example/malloc/victim & echo $! # 进程ID为101771
[1] 101771
101771
continue malloc...
continue malloc...
```

然后附加到该进程：

```console
$ sudo bpftime attach 101771 # 您可能需要以root身份运行make install
Inject: "/root/.bpftime/libbpftime-agent.so"
成功注入。ID: 1
```

您可以看到原始程序的输出：

```console
$ bpftime load ./example/malloc/malloc
...
12:44:35 
        pid=247299      malloc calls: 10
        pid=247322      malloc calls: 10
```

或者，您也可以直接在内核eBPF中运行我们的示例eBPF程序，以查看类似的输出：

```console
$ sudo example/malloc/malloc
15:38:05
        pid=30415       malloc calls: 1079
        pid=30393       malloc calls: 203
        pid=29882       malloc calls: 1076
        pid=34809       malloc calls: 8
```

有关更多详细信息，请参阅[documents/usage.md](https://eunomia.dev/bpftime/documents/usage)。

## 总结与前景

用户空间的eBPF运行时正在打破边界，将eBPF的能力从内核扩展到了更广阔的领域。这种扩展带来了显著的性能、灵活性和安全性提升。例如，`bpftime`运行时显示了其在某些低级性能场景下，甚至超越了像 Wasm 这样的其他技术。也有越来越多的应用将用户空间的 eBPF 用于快速补丁、轻量级虚拟化、网络过滤等场景。

Wasm 的主要焦点在于可移植性、轻量级虚拟化、安全性、多语言等等，而 eBPF 则针对那些对性能有严格要求的基础设施任务提供了更多的性能优势和动态插桩特性。选择哪种技术取决于特定的需求和优先级。随着它们的进一步发展，用户空间的eBPF运行时正在成为云原生技术堆栈中的重要部分，为业界带来前所未有的安全、效率和创新的组合。

> 我们诚邀您深入探索用户空间eBPF的世界，您可以从我们的项目 [https://github.com/eunomia-bpf/bpftime](https://github.com/eunomia-bpf/bpftime) 开始。您的贡献、反馈或仅仅是对此工具的使用和 star，都可以为我们的社区带来巨大价值。
>
> 若您在研究中采用了我们的`bpftime`项目，请[引用我们的仓库](https://github.com/eunomia-bpf/bpftime/blob/master/CITATION.cff)。我们期待您的宝贵意见和反馈，您可以通过 GitHub 仓库的 issue、邮箱 [yunwei356@gmail.com](mailto:yunwei356@gmail.com) 或微信 yunwei2567 与我们联系。

## 参考资料

1. bpftime: <https://github.com/eunomia-bpf/bpftime>
2. ubpf: <https://github.com/iovisor/ubpf>
3. rbpf: <https://github.com/qmonnet/rbpf>
4. Oko: <https://github.com/Orange-OpenSource/Oko>
5. RapidPatch: Firmware Hotpatching for Real-Time Embedded Devices: <https://www.usenix.org/conference/usenixsecurity22/presentation/he-yi>
6. DPDK eBPF Support: <https://www.dpdk.org/wp-content/uploads/sites/35/2018/10/pm-07-DPDK-BPFu6.pdf>
7. Solana: <https://solana.com/>
8. eBPF for Windows (Work-In-Progress): <https://github.com/microsoft/ebpf-for-windows>
9. Femto-Containers: Lightweight Virtualization and Fault Isolation For Small Software Functions on Low-Power IoT Microcontrollers: <https://arxiv.org/abs/2210.03432>
