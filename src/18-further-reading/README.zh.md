# 更多的参考资料：论文、项目等等

可以在这里找到更多关于 eBPF 的信息：

- 一个关于 eBPF 相关内容和信息的详细列表：<https://github.com/zoidbergwill/awesome-ebpf>
- eBPF 相关项目、教程：<https://ebpf.io/>

这是我近年来读过的与 eBPF 相关的论文列表，可能对于对 eBPF 相关研究感兴趣的人有所帮助。

eBPF（扩展的伯克利数据包过滤器）是一种新兴的技术，允许在 Linux 内核中安全地执行用户提供的程序。近年来，它因加速网络处理、增强可观察性和实现可编程数据包处理而得到了广泛的应用。此文档列出了过去几年关于 eBPF 的一些关键研究论文。这些论文涵盖了 eBPF 的几个方面，包括加速分布式系统、存储和网络，正式验证 eBPF 的 JIT 编译器和验证器，将 eBPF 用于入侵检测，以及从 eBPF 程序自动生成硬件设计。

一些关键亮点：

- eBPF 允许在内核中执行自定义函数，以加速分布式协议、存储引擎和网络应用，与传统的用户空间实现相比，可以提高吞吐量和降低延迟。
- eBPF 组件（如 JIT 和验证器）的正式验证确保了正确性，并揭示了实际实现中的错误。
- eBPF 的可编程性和效率使其适合在内核中完全构建入侵检测和网络监控应用。
- 从 eBPF 程序中自动生成硬件设计允许软件开发人员快速生成网络卡中的优化数据包处理管道。

这些论文展示了 eBPF 在加速系统、增强安全性和简化网络编程方面的多功能性。随着 eBPF 的采用不断增加，它是一个与性能、安全性、硬件集成和易用性相关的系统研究的重要领域。

如果您有任何建议或添加论文的意见，请随时开放一个问题或PR。此列表创建于 2023.10，未来将添加新的论文。

> 如果您对 eBPF 有些进一步的兴趣的话，也可以查看我们在 [eunomia-bpf](https://github.com/eunomia-bpf) 的开源项目和 [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) 的 eBPF 教程。我也在寻找 2024/2025 年系统和网络领域的 PhD 相关机会，这是我的 [Github](https://github.com/yunwei37) 和 [邮箱](yunwei356@gmail.com)。

## XRP: In-Kernel Storage Functions with eBPF

随着微秒级 NVMe 存储设备的出现，Linux 内核存储堆栈开销变得显著，几乎使访问时间翻倍。我们介绍了 XRP，一个框架，允许应用程序从 eBPF 在 NVMe 驱动程序中的钩子执行用户定义的存储功能，如索引查找或聚合，安全地绕过大部分内核的存储堆栈。为了保持文件系统的语义，XRP 将少量的内核状态传播到其 NVMe 驱动程序钩子，在那里调用用户注册的 eBPF 函数。我们展示了如何利用 XRP 显著提高两个键值存储，BPF-KV，一个简单的 B+ 树键值存储，和 WiredTiger，一个流行的日志结构合并树存储引擎的吞吐量和延迟。

OSDI '22 最佳论文: <https://www.usenix.org/conference/osdi22/presentation/zhong>

## Specification and verification in the field: Applying formal methods to BPF just-in-time compilers in the Linux kernel

本文描述了我们将形式方法应用于 Linux 内核中的一个关键组件，即 Berkeley 数据包过滤器 (BPF) 虚拟机的即时编译器 ("JIT") 的经验。我们使用 Jitterbug 验证这些 JIT，这是第一个提供 JIT 正确性的精确规范的框架，能够排除实际错误，并提供一个自动化的证明策略，该策略可以扩展到实际实现。使用 Jitterbug，我们设计、实施并验证了一个新的针对 32 位 RISC-V 的 BPF JIT，在五个其他部署的 JIT 中找到并修复了 16 个之前未知的错误，并开发了新的 JIT 优化；所有这些更改都已上传到 Linux 内核。结果表明，在一个大型的、未经验证的系统中，通过仔细设计规范和证明策略，可以构建一个经过验证的组件。

OSDI 20: <https://www.usenix.org/conference/osdi20/presentation/nelson>

## λ-IO: A Unified IO Stack for Computational Storage

新兴的计算存储设备为存储内计算提供了一个机会。它减少了主机与设备之间的数据移动开销，从而加速了数据密集型应用程序。在这篇文章中，我们介绍 λ-IO，一个统一的 IO 堆栈，跨主机和设备管理计算和存储资源。我们提出了一套设计 - 接口、运行时和调度 - 来解决三个关键问题。我们在全堆栈软件和硬件环境中实施了 λ-IO，并使用合成和实际应用程序对其

进行评估，与 Linux IO 相比，显示出高达 5.12 倍的性能提升。

FAST23: <https://www.usenix.org/conference/fast23/presentation/yang-zhe>

## Extension Framework for File Systems in User space

用户文件系统相对于其内核实现提供了许多优势，例如开发的简易性和更好的系统可靠性。然而，它们会导致重大的性能损失。我们观察到现有的用户文件系统框架非常通用；它们由一个位于内核中的最小干预层组成，该层简单地将所有低级请求转发到用户空间。虽然这种设计提供了灵活性，但由于频繁的内核-用户上下文切换，它也严重降低了性能。

这项工作介绍了 ExtFUSE，一个用于开发可扩展用户文件系统的框架，该框架还允许应用程序在内核中注册"薄"的专用请求处理程序，以满足其特定的操作需求，同时在用户空间中保留复杂的功能。我们使用两个 FUSE 文件系统对 ExtFUSE 进行评估，结果表明 ExtFUSE 可以通过平均不到几百行的改动来提高用户文件系统的性能。ExtFUSE 可在 GitHub 上找到。

ATC 19: <https://www.usenix.org/conference/atc19/presentation/bijlani>

## Electrode: Accelerating Distributed Protocols with eBPF

在标准的Linux内核网络栈下实现分布式协议可以享受到负载感知的CPU缩放、高兼容性以及强大的安全性和隔离性。但由于过多的用户-内核切换和内核网络栈遍历，其性能较低。我们介绍了Electrode，这是一套为分布式协议设计的基于eBPF的性能优化。这些优化在网络栈之前在内核中执行，但实现了与用户空间中实现的相似功能（例如，消息广播，收集ack的仲裁），从而避免了用户-内核切换和内核网络栈遍历所带来的开销。我们展示，当应用于经典的Multi-Paxos状态机复制协议时，Electrode可以提高其吞吐量高达128.4%，并将延迟降低高达41.7%。

NSDI 23: [链接](https://www.usenix.org/conference/nsdi23/presentation/zhou)

## BMC: Accelerating Memcached using Safe In-kernel Caching and Pre-stack Processing

内存键值存储是帮助扩展大型互联网服务的关键组件，通过提供对流行数据的低延迟访问。Memcached是最受欢迎的键值存储之一，由于Linux网络栈固有的性能限制，当使用高速网络接口时，其性能不高。虽然可以使用DPDK基础方案绕过Linux网络栈，但这种方法需要对软件栈进行完全重新设计，而且在客户端负载较低时也会导致高CPU利用率。

为了克服这些限制，我们提出了BMC，这是一个为Memcached设计的内核缓存，可以在执行标准网络栈之前服务于请求。对BMC缓存的请求被视为NIC中断的一部分，这允许性能随着为NIC队列服务的核心数量而扩展。为确保安全，BMC使用eBPF实现。尽管eBPF具有安全约束，但我们展示了实现复杂缓存服务是可能的。因为BMC在商用硬件上运行，并且不需要修改Linux内核或Memcached应用程序，所以它可以在现有系统上广泛部署。BMC优化了Facebook样式的小型请求的处理时间。在这个目标工作负载上，我们的评估显示，与原始的Memcached应用程序相比，BMC的吞吐量提高了高达18倍，与使用SO_REUSEPORT套接字标志的优化版Memcached相比，提高了高达6倍。此外，我们的结果还显示，对于非目标工作负载，BMC的开销可以忽略不计，并且不会降低吞吐量。

NSDI 21: [链接](https://www.usenix.org/conference/nsdi21/presentation/ghigoff)

## hXDP: Efficient Software Packet Processing on FPGA NICs

FPGA加速器在NIC上使得从CPU卸载昂贵的数据包处理任务成为可能。但是，FPGA有限的资源可能需要在多个应用程序之间共享，而编程它们则很困难。

我们提出了一种在FPGA上运行Linux的eXpress Data Path程序的解决方案，这些程序使用eBPF编写，仅使用可用硬件资源的一部分，同时匹配高端CPU的性能。eBPF的迭代执行模型不适合FPGA加速器。尽管如此，我们展示了，当针对一个特定的FPGA执行器时，一个eBPF程序的许多指令可以被压缩、并行化或完全删除，从而显著提高性能。我们利用这一点设计了hXDP，它包括(i)一个优化编译器，该编译器并行化并将eBPF字节码转换为我们定义的扩展eBPF指令集架构；(ii)一个在FPGA上执行这些指令的软处理器；以及(iii)一个基于FPGA的基础设施，提供XDP的maps和Linux内核中定义的helper函数。

我们在FPGA NIC上实现了hXDP，并评估了其运行真实世界的未经修改的eBPF程序的性能。我们的实现以156.25MHz的速度时钟，使用约15%的FPGA资源，并可以运行动态加载的程序。尽管有这些适度的要求，但它达到了高端CPU核心的数据包处理吞吐量，并提供了10倍低的数据包转发延迟。

OSDI 20: [链接](https://www.usenix.org/conference/osdi20/presentation/brunella)

## Network-Centric Distributed Tracing with DeepFlow: Troubleshooting Your Microservices in Zero Code

微服务正变得越来越复杂，给传统的性能监控解决方案带来了新的挑战。一方面，微服务的快速演变给现有的分布式跟踪框架的使用和维护带来了巨大的负担。另一方面，复杂的基础设施增加了网络性能问题的概率，并在网络侧创造了更多的盲点。在这篇论文中，我们介绍了 DeepFlow，一个用于微服务故障排除的以网络为中心的分布式跟踪框架。DeepFlow 通过一个以网络为中心的跟踪平面和隐式的上下文传播提供开箱即用的跟踪。此外，它消除了网络基础设施中的盲点，以低成本方式捕获网络指标，并增强了不同组件和层之间的关联性。我们从分析和实证上证明，DeepFlow 能够准确地定位微服务性能异常，而开销几乎可以忽略不计。DeepFlow 已经为超过26家公司发现了71多个关键性能异常，并已被数百名开发人员所使用。我们的生产评估显示，DeepFlow 能够为用户节省数小时的仪表化工作，并将故障排除时间从数小时缩短到几分钟。

SIGCOMM 23: <https://dl.acm.org/doi/10.1145/3603269.3604823>

## Fast In-kernel Traffic Sketching in eBPF

扩展的伯克利数据包过滤器（eBPF）是一个基础设施，允许在不重新编译的情况下动态加载并直接在 Linux 内核中运行微程序。

在这项工作中，我们研究如何在 eBPF 中开发高性能的网络测量。我们以绘图为案例研究，因为它们具有支持广泛任务的能力，同时提供低内存占用和准确性保证。我们实现了 NitroSketch，一个用于用户空间网络的最先进的绘图，并表明用户空间网络的最佳实践不能直接应用于 eBPF，因为它的性能特点不同。通过应用我们学到的经验教训，我们将其性能提高了40%，与初级实现相比。

SIGCOMM 23: <https://dl.acm.org/doi/abs/10.1145/3594255.3594256>

## SPRIGHT: extracting the server from serverless computing! high-performance eBPF-based event-driven, shared-memory processing

无服务器计算在云环境中承诺提供高效、低成本的计算能力。然而，现有的解决方案，如Knative这样的开源平台，包含了繁重的组件，破坏了无服务器计算的目标。此外，这种无服务器平台缺乏数据平面优化，无法实现高效的、高性能的功能链，这也是流行的微服务开发范式的设施。它们为构建功能链使用的不必要的复杂和重复的功能严重降低了性能。"冷启动"延迟是另一个威慑因素。

我们描述了 SPRIGHT，一个轻量级、高性能、响应式的无服务器框架。SPRIGHT 利用共享内存处理显著提高了数据平面的可伸缩性，通过避免不必要的协议处理和序列化-反序列化开销。SPRIGHT 大量利用扩展的伯克利数据包过滤器 (eBPF) 进行事件驱动处理。我们创造性地使用 eBPF 的套接字消息机制支持共享内存处理，其开销严格与负载成正比。与常驻、基于轮询的DPDK相比，SPRIGHT 在真实工作负载下实现了相同的数据平面性能，但 CPU 使用率降低了10倍。此外，eBPF 为 SPRIGHT 带来了好处，替换了繁重的无服务器组件，使我们能够以微不足道的代价保持函数处于"暖"状态。

我们的初步实验结果显示，与 Knative 相比，SPRIGHT 在吞吐量和延迟方面实现了一个数量级的提高，同时大大减少了 CPU 使用，并消除了 "冷启动"的需要。

<https://dl.acm.org/doi/10.1145/3544216.3544259>

## Kgent: Kernel Extensions Large Language Model Agent

修改和扩展操作系统的能力是提高系统安全性、可靠性和性能的重要功能。扩展的伯克利数据包过滤器（eBPF）生态系统已经成为扩展Linux内核的标准机制，并且最近已被移植到Windows。eBPF程序将新逻辑注入内核，使系统在现有逻辑之前或之后执行这些逻辑。虽然eBPF生态系统提供了一种灵活的内核扩展机制，但目前开发人员编写eBPF程序仍然困难。eBPF开发人员必须深入了解操作系统的内部结构，以确定在何处放置逻辑，并应对eBPF验证器对其eBPF程序的控制流和数据访问施加的编程限制。本文介绍了KEN，一种通过允许使用自然语言编写内核扩展来缓解编写eBPF程序难度的替代框架。KEN利用大语言模型（LLMs）的最新进展，根据用户的英文提示生成eBPF程序。为了确保LLM的输出在语义上等同于用户的提示，KEN结合了LLM增强的程序理解、符号执行和一系列反馈循环。KEN的关键创新在于这些技术的结合。特别是，该系统以一种新颖的结构使用符号执行，使其能够结合程序综合和程序理解的结果，并建立在LLMs在每个任务中单独展示的成功基础上。为了评估KEN，我们开发了一个新的自然语言提示eBPF程序的语料库。我们显示，KEN在80%的情况下生成了正确的eBPF程序，这比LLM增强的程序综合基线提高了2.67倍。

eBPF'24: <https://dl.acm.org/doi/10.1145/3672197.3673434> 和arxiv <https://arxiv.org/abs/2312.05531>

## Programmable System Call Security with eBPF

利用 eBPF 进行可编程的系统调用安全

系统调用过滤是一种广泛用于保护共享的 OS 内核免受不受信任的用户应用程序威胁的安全机制。但是，现有的系统调用过滤技术要么由于用户空间代理带来的上下文切换开销过于昂贵，要么缺乏足够的可编程性来表达高级策略。Seccomp 是 Linux 的系统调用过滤模块，广泛用于现代的容器技术、移动应用和系统管理服务。尽管采用了经典的 BPF 语言（cBPF），但 Seccomp 中的安全策略主要限于静态的允许列表，主要是因为 cBPF 不支持有状态的策略。因此，许多关键的安全功能无法准确地表达，和/或需要修改内核。

在这篇论文中，我们介绍了一个可编程的系统调用过滤机制，它通过利用扩展的 BPF 语言（eBPF）使得更高级的安全策略得以表达。更具体地说，我们创建了一个新的 Seccomp eBPF 程序类型，暴露、修改或创建新的 eBPF 助手函数来安全地管理过滤状态、访问内核和用户状态，以及利用同步原语。重要的是，我们的系统与现有的内核特权和能力机制集成，使非特权用户能够安全地安装高级过滤器。我们的评估表明，我们基于 eBPF 的过滤可以增强现有策略（例如，通过时间专化，减少早期执行阶段的攻击面积高达55.4％）、缓解实际漏洞并加速过滤器。

<https://arxiv.org/abs/2302.10366>

## Cross Container Attacks: The Bewildered eBPF on Clouds

在云上困惑的 eBPF 之间的容器攻击

扩展的伯克利数据包过滤器（eBPF）为用户空间程序提供了强大而灵活的内核接口，通过在内核空间直接运行字节码来扩展内核功能。它已被云服务广泛使用，以增强容器安全性、网络管理和系统可观察性。然而，我们发现在 Linux 主机上广泛讨论的攻击性 eBPF 可以为容器带来新的攻击面。通过 eBPF 的追踪特性，攻击者可以破坏容器的隔离并攻击主机，例如，窃取敏感数据、进行 DoS 攻击，甚至逃逸容器。在这篇论文中，我们研究基于 eBPF 的跨容器攻击，并揭示其在实际服务中的安全影响。利用 eBPF 攻击，我们成功地妨害了五个在线的 Jupyter/交互式 Shell 服务和 Google Cloud Platform 的 Cloud Shell。此外，我们发现三家领先的云供应商提供的 Kubernetes 服务在攻击者通过 eBPF 逃逸容器后可以被利用来发起跨节点攻击。具体来说，在阿里巴巴的 Kubernetes 服务中，攻击者可以通过滥用他们过度特权的云指标或管理 Pods 来妨害整个集群。不幸的是，容器上的 eBPF 攻击鲜为人知，并且现有的入侵检测系统几乎无法发现它们。此外，现有的 eBPF 权限模型无法限制 eBPF 并确保在共享内核的容器环境中安全使用。为此，我们提出了一个新的 eBPF 权限模型，以对抗容器中的 eBPF 攻击。

<https://www.usenix.org/conference/usenixsecurity23/presentation/he>

## Comparing Security in eBPF and WebAssembly

比较 eBPF 和 WebAssembly 中的安全性

本文研究了 eBPF 和 WebAssembly（Wasm）的安全性，这两种技术近年来得到了广泛的采用，尽管它们是为非常不同的用途和环境而设计的。当 eBPF 主要用于 Linux 等操作系统内核时，Wasm 是一个为基于堆栈的虚拟机设计的二进制指令格式，其用途超出了 web。鉴于 eBPF 的增长和不断扩大的雄心，Wasm 可能提供有启发性的见解，因为它围绕在如 web 浏览器和云等复杂和敌对环境中安全执行任意不受信任的程序进行设计。我们分析了两种技术的安全目标、社区发展、内存模型和执行模型，并进行了比较安全性评估，探讨了内存安全性、控制流完整性、API 访问和旁路通道。我们的结果表明，eBPF 有一个首先关注性能、其次关注安全的历史，而 Wasm 更强调安全，尽管要支付一些运行时开销。考虑 eBPF 的基于语言的限制和一个用于 API 访问的安全模型是未来工作的有益方向。

<https://dl.acm.org/doi/abs/10.1145/3609021.3609306>

更多内容可以在第一个 eBPF 研讨会中找到：<https://conferences.sigcomm.org/sigcomm/2023/workshop-ebpf.html>

## A flow-based IDS using Machine Learning in eBPF

基于eBPF中的机器学习的流式入侵检测系统

eBPF 是一种新技术，允许动态加载代码片段到 Linux 内核中。它可以大大加速网络，因为它使内核能够处理某些数据包而无需用户空间程序的参与。到目前为止，eBPF 主要用于简单的数据包过滤应用，如防火墙或拒绝服务保护。我们证明在 eBPF 中完全基于机器学习开发流式网络入侵检测系统是可行的。我们的解决方案使用决策树，并为每个数据包决定它是否恶意，考虑到网络流的整个先前上下文。与作为用户空间程序实现的同一解决方案相比，我们实现了超过 20% 的性能提升。

<https://arxiv.org/abs/2102.09980>

## Femto-containers: lightweight virtualization and fault isolation for small software functions on low-power IoT microcontrollers

针对低功耗 IoT 微控制器上的小型软件功能的轻量级虚拟化和故障隔离： Femto-容器

低功耗的 IoT 微控制器上运行的操作系统运行时通常提供基础的 API、基本的连接性和（有时）一个（安全的）固件更新机制。相比之下，在硬件约束较少的场合，网络化软件已进入无服务器、微服务和敏捷的时代。考虑到弥合这一差距，我们在论文中设计了 Femto-容器，这是一种新的中间件运行时，可以嵌入到各种低功耗 IoT 设备中。Femto-容器使得可以在低功耗 IoT 设备上通过网络安全地部署、执行和隔离小型虚拟软件功能。我们实施了 Femto-容器，并在 RIOT 中提供了集成，这是一个受欢迎的开源 IoT 操作系统。然后，我们评估了我们的实现性能，它已被正式验证用于故障隔离，确保 RIOT 受到加载并在 Femto-容器中执行的逻辑的保护。我们在各种受欢迎的微控制器架构（Arm Cortex-M、ESP32 和 RISC-V）上的实验表明，Femto-容器在内存占用开销、能源消耗和安全性方面提供了有吸引力的权衡。

<https://dl.acm.org/doi/abs/10.1145/3528535.3565242>
