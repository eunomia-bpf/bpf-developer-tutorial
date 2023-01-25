# eBPF 入门开发实践教程一：介绍 eBPF 的基本概念、常见的开发工具

<!-- TOC -->

- [eBPF 入门开发实践教程一：介绍 eBPF 的基本概念、常见的开发工具](#ebpf-入门开发实践教程一介绍-ebpf-的基本概念常见的开发工具)
  - [1. 为什么会有 eBPF 技术？](#1-为什么会有-ebpf-技术)
    - [1.1. 起源](#11-起源)
    - [1.2. 执行逻辑](#12-执行逻辑)
    - [1.3. 架构](#13-架构)
      - [1.3.1. 寄存器设计](#131-寄存器设计)
      - [1.3.2. 指令编码格式](#132-指令编码格式)
    - [1.4. 本节参考文章](#14-本节参考文章)
  - [2. 如何使用eBPF编程](#2-如何使用ebpf编程)
  - [编写 eBPF 程序](#编写-ebpf-程序)
    - [2.1. BCC](#21-bcc)
    - [2.2. libbpf-bootstrap](#22-libbpf-bootstrap)
    - [2.3 eunomia-bpf](#23-eunomia-bpf)
  - [参考资料](#参考资料)

<!-- /TOC -->

## 1. 为什么会有 eBPF 技术？

Linux内核一直是实现监控/可观测性、网络和安全功能的理想地方，但是直接在内核中进行监控并不是一个容易的事情。在传统的Linux软件开发中，实现这些功能往往都离不开修改内核源码或加载内核模块。修改内核源码是一件非常危险的行为，稍有不慎可能便会导致系统崩溃，并且每次检验修改的代码都需要重新编译内核，耗时耗力。

加载内核模块虽然来说更为灵活，不需要重新编译源码，但是也可能导致内核崩溃，且随着内核版本的变化，模块也需要进行相应的修改，否则将无法使用。

在这一背景下，eBPF技术应运而生。它是一项革命性技术，能在内核中运行沙箱程序（sandbox programs），而无需修改内核源码或者加载内核模块。用户可以使用其提供的各种接口，实现在内核中追踪、监测系统的作用。

### 1.1. 起源

eBPF的雏形是BPF(Berkeley Packet Filter, 伯克利包过滤器)。BPF于
1992年被Steven McCanne和Van Jacobson在其[论文](https://www.tcpdump.org/papers/bpf-usenix93.pdf)
提出。二人提出BPF的初衷是是提供一种新的数据包过滤方法，该方法的模型如下图所示。
![original_bpf](../imgs/original_bpf.png)

相较于其他过滤方法，BPF有两大创新点，首先是它使用了一个新的虚拟机，可以有效地工作在基于寄存器结构的CPU之上。其次是其不会全盘复制数据包的所有信息，只会复制相关数据，可以有效地提高效率。这两大创新使得BPF在实际应用中得到了巨大的成功，在被移植到Linux系统后，其被上层的`libcap`
和`tcpdump`等应用使用，是一个性能卓越的工具。

传统的BPF是32位架构，其指令集编码格式为：

- 16 bit: 操作指令
- 8 bit: 下一条指令跳向正确目标的偏移量
- 8 bit: 下一条指令跳往错误目标的偏移量

经过十余年的沉积后，2013年，Alexei Starovoitov对BPF进行了彻底地改造，改造后的BPF被命名为eBPF(extended BPF)，于Linux Kernel 3.15中引入Linux内核源码。
eBPF相较于BPF有了革命性的变化。首先在于eBPF支持了更多领域的应用，它不仅支持网络包的过滤，还可以通过
`kprobe`，`tracepoint`,`lsm`等Linux现有的工具对响应事件进行追踪。另一方面，其在使用上也更为
灵活，更为方便。同时，其JIT编译器也得到了升级，解释器也被替换，这直接使得其具有达到平台原生的
执行性能的能力。

### 1.2. 执行逻辑

eBPF在执行逻辑上和BPF有相似之处，eBPF也可以认为是一个基于寄存器的，使用自定义的64位RISC指令集的
微型"虚拟机"。它可以在Linux内核中，以一种安全可控的方式运行本机编译的eBPF程序并且访问内核函数和内存的子集。

在写好程序后，我们将代码使用llvm编译得到使用BPF指令集的ELF文件，解析出需要注入的部分后调用函数将其
注入内核。用户态的程序和注入内核态中的字节码公用一个位于内核的eBPF Map进行通信，实现数据的传递。同时，
为了防止我们写入的程序本身不会对内核产生较大影响，编译好的字节码在注入内核之前会被eBPF校验器严格地检查。

eBPF程序是由事件驱动的，我们在程序中需要提前确定程序的执行点。编译好的程序被注入内核后，如果提前确定的执行点
被调用，那么注入的程序就会被触发，按照既定方式处理。

### 1.3. 架构

#### 1.3.1. 寄存器设计

eBPF有11个寄存器，分别是R0~R10，每个寄存器均是64位大小，有相应的32位子寄存器，其指令集是固定的64位宽。

#### 1.3.2. 指令编码格式

eBPF指令编码格式为：

- 8 bit: 存放真实指令码
- 4 bit: 存放指令用到的目标寄存器号
- 4 bit: 存放指令用到的源寄存器号
- 16 bit: 存放偏移量，具体作用取决于指令类型
- 32 bit: 存放立即数

### 1.4. 本节参考文章

[A thorough introduction to eBPF](https://lwn.net/Articles/740157/)
[bpf简介](https://www.collabora.com/news-and-blog/blog/2019/04/05/an-ebpf-overview-part-1-introduction/)
[bpf架构知识](https://www.collabora.com/news-and-blog/blog/2019/04/15/an-ebpf-overview-part-2-machine-and-bytecode/)

## 2. 如何使用eBPF编程

原始的eBPF程序编写是非常繁琐和困难的。为了改变这一现状，
llvm于2015年推出了可以将由高级语言编写的代码编译为eBPF字节码的功能，同时，其将`bpf()`
等原始的系统调用进行了初步地封装，给出了`libbpf`库。这些库会包含将字节码加载到内核中
的函数以及一些其他的关键函数。在Linux的源码包的`samples/bpf/`目录下，有大量Linux
提供的基于`libbpf`的eBPF样例代码。

一个典型的基于 `libbpf` 的eBPF程序具有`*_kern.c`和`*_user.c`两个文件，
`*_kern.c`中书写在内核中的挂载点以及处理函数，`*_user.c`中书写用户态代码，
完成内核态代码注入以及与用户交互的各种任务。 更为详细的教程可以参考[该视频](https://www.bilibili.com/video/BV1f54y1h74r?spm_id_from=333.999.0.0)
然而由于该方法仍然较难理解且入门存在一定的难度，因此现阶段的eBPF程序开发大多基于一些工具，比如：

- BCC
- BPFtrace
- libbpf-bootstrap

以及还有比较新的工具，例如 `eunomia-bpf`.

## 编写 eBPF 程序

eBPF 程序由内核态部分和用户态部分构成。内核态部分包含程序的实际逻辑，用户态部分负责加载和管理内核态部分。使用 eunomia-bpf 开发工具，只需编写内核态部分的代码。

内核态部分的代码需要符合 eBPF 的语法和指令集。eBPF 程序主要由若干个函数组成，每个函数都有其特定的作用。可以使用的函数类型包括：

- kprobe：插探函数，在指定的内核函数前或后执行。
- tracepoint：跟踪点函数，在指定的内核跟踪点处执行。
- raw_tracepoint：原始跟踪点函数，在指定的内核原始跟踪点处执行。
- xdp：网络数据处理函数，拦截和处理网络数据包。
- perf_event：性能事件函数，用于处理内核性能事件。
- kretprobe：函数返回插探函数，在指定的内核函数返回时执行。
- tracepoint_return：跟踪点函数返回，在指定的内核跟踪点返回时执行。
- raw_tracepoint_return：原始跟踪点函数返回，在指定的内核原始跟踪

### 2.1. BCC

BCC全称为BPF Compiler Collection，该项目是一个python库，
包含了完整的编写、编译、和加载BPF程序的工具链，以及用于调试和诊断性能问题的工具。

自2015年发布以来，BCC经过上百位贡献者地不断完善后，目前已经包含了大量随时可用的跟踪工具。[其官方项目库](https://github.com/iovisor/bcc/blob/master/docs/tutorial.md)
提供了一个方便上手的教程，用户可以快速地根据教程完成BCC入门工作。

用户可以在BCC上使用Python、Lua等高级语言进行编程。
相较于使用C语言直接编程，这些高级语言具有极大的便捷性，用户只需要使用C来设计内核中的
BPF程序，其余包括编译、解析、加载等工作在内，均可由BCC完成。  

然而使用BCC存在一个缺点便是在于其兼容性并不好。基于BCC的
eBPF程序每次执行时候都需要进行编译，编译则需要用户配置相关的头文件和对应实现。在实际应用中，
相信大家也会有体会，编译依赖问题是一个很棘手的问题。也正是因此，在本项目的开发中我们放弃了BCC，
选择了可以做到一次编译-多次运行的libbpf-bootstrap工具。

### 2.2. libbpf-bootstrap

`libbpf-bootstrap`是一个基于`libbpf`库的BPF开发脚手架，从其
[github](https://github.com/libbpf/libbpf-bootstrap) 上可以得到其源码。

`libbpf-bootstrap`综合了BPF社区过去多年的实践，为开发者提了一个现代化的、便捷的工作流，实
现了一次编译，重复使用的目的。

基于`libbpf-bootstrap`的BPF程序对于源文件有一定的命名规则，
用于生成内核态字节码的bpf文件以`.bpf.c`结尾，用户态加载字节码的文件以`.c`结尾，且这两个文件的
前缀必须相同。  

基于`libbpf-bootstrap`的BPF程序在编译时会先将`*.bpf.c`文件编译为
对应的`.o`文件，然后根据此文件生成`skeleton`文件，即`*.skel.h`，这个文件会包含内核态中定义的一些
数据结构，以及用于装载内核态代码的关键函数。在用户态代码`include`此文件之后调用对应的装载函数即可将
字节码装载到内核中。同样的，`libbpf-bootstrap`也有非常完备的入门教程，用户可以在[该处](https://nakryiko.com/posts/libbpf-bootstrap/)
得到详细的入门操作介绍。

### 2.3 eunomia-bpf

开发、构建和分发 eBPF 一直以来都是一个高门槛的工作，使用 BCC、bpftrace 等工具开发效率高、可移植性好，但是分发部署时需要安装 LLVM、Clang等编译环境，每次运行的时候执行本地或远程编译过程，资源消耗较大；使用原生的 CO-RE libbpf时又需要编写不少用户态加载代码来帮助 eBPF 程序正确加载和从内核中获取上报的信息，同时对于 eBPF 程序的分发、管理也没有很好地解决方案。

[eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) 是一个开源的 eBPF 动态加载运行时和开发工具链，是为了简化 eBPF 程序的开发、构建、分发、运行而设计的，基于 libbpf 的 CO-RE 轻量级开发框架。

使用 eunomia-bpf ，可以：

- 在编写 eBPF 程序或工具时只编写内核态代码，自动获取内核态导出信息；
- 使用 WASM 进行用户态交互程序的开发，在 WASM 虚拟机内部控制整个 eBPF 程序的加载和执行，以及处理相关数据；
- eunomia-bpf 可以将预编译的 eBPF 程序打包为通用的 JSON 或 WASM 模块，跨架构和内核版本进行分发，无需重新编译即可动态加载运行。

eunomia-bpf 由一个编译工具链和一个运行时库组成, 对比传统的 BCC、原生 libbpf 等框架，大幅简化了 eBPF 程序的开发流程，在大多数时候只需编写内核态代码，即可轻松构建、打包、发布完整的 eBPF 应用，同时内核态 eBPF 代码保证和主流的 libbpf, libbpfgo, libbpf-rs 等开发框架的 100% 兼容性。需要编写用户态代码的时候，也可以借助 Webassembly 实现通过多种语言进行用户态开发。和 bpftrace 等脚本工具相比, eunomia-bpf 保留了类似的便捷性, 同时不仅局限于 trace 方面, 可以用于更多的场景, 如网络、安全等等。

> - eunomia-bpf 项目 Github 地址: <https://github.com/eunomia-bpf/eunomia-bpf>
> - gitee 镜像: <https://gitee.com/anolis/eunomia>

## 参考资料

- eBPF 介绍：<https://ebpf.io/>
- BPF Compiler Collection (BCC)：<https://github.com/iovisor/bcc>
- eunomia-bpf：<https://github.com/eunomia-bpf/eunomia-bpf>

完整的教程和源代码已经全部开源，可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 中查看。
