# eBPF 开发实践教程：基于 CO-RE，通过小工具快速上手 eBPF 开发

这是一个基于 `CO-RE`（一次编译，到处运行）的 eBPF 的开发教程，提供了从入门到进阶的 eBPF 开发实践，包括基本概念、代码实例、实际应用等内容。和 BCC 不同的是，我们使用 libbpf、Cilium、libbpf-rs、eunomia-bpf 等框架进行开发，包含 C、Go、Rust 等语言的示例。

本教程不会进行复杂的概念讲解和场景介绍，主要希望提供一些 eBPF 小工具的案例（**非常短小，从二十行代码开始入门！**），来帮助 eBPF 应用的开发者快速上手 eBPF 的开发方法和技巧。教程内容可以在目录中找到，每个目录都是一个独立的 eBPF 工具案例。

教程关注于可观测性、网络、安全等等方面的 eBPF 示例。完整的代码和教程可以在 [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) GitHub 开源仓库中找到。**如果您认为本教程对您有所帮助，也请给我们一个 star 鼓励一下！**

# 入门示例

这一部分包含简单的 eBPF 程序示例和介绍。主要利用 `eunomia-bpf` 框架简化开发，介绍 eBPF 的基本用法和开发流程。

- [lesson 0-introduce](0-introduce/README.zh.md) eBPF 示例教程 0：核心概念与工具简介
- [lesson 1-helloworld](1-helloworld/README.zh.md) eBPF 入门开发实践教程一：Hello World，基本框架和开发流程
- [lesson 2-kprobe-unlink](2-kprobe-unlink/README.zh.md) eBPF 入门开发实践教程二：在 eBPF 中使用 kprobe 监测捕获 unlink 系统调用
- [lesson 3-fentry-unlink](3-fentry-unlink/README.zh.md) eBPF 入门开发实践教程三：在 eBPF 中使用 fentry 监测捕获 unlink 系统调用
- [lesson 4-opensnoop](4-opensnoop/README.zh.md) eBPF 入门开发实践教程四：在 eBPF 中捕获进程打开文件的系统调用集合，使用全局变量过滤进程 pid
- [lesson 5-uprobe-bashreadline](5-uprobe-bashreadline/README.zh.md) eBPF 入门开发实践教程五：在 eBPF 中使用  uprobe 捕获 bash 的 readline 函数调用
- [lesson 6-sigsnoop](6-sigsnoop/README.zh.md) eBPF 入门开发实践教程六：捕获进程发送信号的系统调用集合，使用 hash map 保存状态
- [lesson 7-execsnoop](7-execsnoop/README.zh.md) eBPF 入门实践教程七：捕获进程执行事件，通过 perf event array 向用户态打印输出
- [lesson 8-exitsnoop](8-exitsnoop/README.zh.md) eBPF 入门开发实践教程八：在 eBPF 中使用 exitsnoop 监控进程退出事件，使用 ring buffer 向用户态打印输出
- [lesson 9-runqlat](9-runqlat/README.zh.md) eBPF 入门开发实践教程九：捕获进程调度延迟，以直方图方式记录
- [lesson 10-hardirqs](10-hardirqs/README.zh.md) eBPF 入门开发实践教程十：在 eBPF 中使用 hardirqs 或 softirqs 捕获中断事件

# 高级文档和示例

我们开始构建完整的 eBPF 项目，主要基于 `libbpf`，并将其与各种应用场景结合起来，以便实际使用。

- [lesson 11-bootstrap](11-bootstrap/README.zh.md) eBPF 入门开发实践教程十一：在 eBPF 中使用 libbpf 开发用户态程序并跟踪 exec() 和 exit() 系统调用
- [lesson 12-profile](12-profile/README.zh.md) eBPF 入门实践教程十二：使用 eBPF 程序 profile 进行性能分析
- [lesson 13-tcpconnlat](13-tcpconnlat/README.zh.md) eBPF入门开发实践教程十三：统计 TCP 连接延时，并使用 libbpf 在用户态处理数据
- [lesson 14-tcpstates](14-tcpstates/README.zh.md) eBPF入门实践教程十四：记录 TCP 连接状态与 TCP RTT
- [lesson 15-javagc](15-javagc/README.zh.md) eBPF 入门实践教程十五：使用 USDT 捕获用户态 Java GC 事件耗时
- [lesson 16-memleak](16-memleak/README.zh.md) eBPF 入门实践教程十六：编写 eBPF 程序 Memleak 监控内存泄漏
- [lesson 17-biopattern](17-biopattern/README.zh.md) eBPF 入门实践教程十七：编写 eBPF 程序统计随机/顺序磁盘 I/O
- [lesson 18-further-reading](18-further-reading/README.zh.md) 更多的参考资料：论文、项目等等
- [lesson 19-lsm-connect](19-lsm-connect/README.zh.md) eBPF 入门实践教程：使用 LSM 进行安全检测防御
- [lesson 20-tc](20-tc/README.zh.md) eBPF 入门实践教程二十：使用 eBPF 进行 tc 流量控制
- [lesson 21-xdp](21-xdp/README.zh.md) eBPF 入门实践教程二十一： 使用 XDP 进行可编程数据包处理

# 深入主题

这一部分涵盖了与 eBPF 相关的高级主题，包括在 Android 上使用 eBPF 程序、利用 eBPF 程序进行的潜在攻击和防御以及复杂的追踪。结合用户模式和内核模式的 eBPF 可以带来强大的能力（也可能带来安全风险）。

Android:

- [lesson 22-android](22-android/README.zh.md) 在 Android 上使用 eBPF 程序
网络:

- [lesson 23-http](23-http/README.zh.md) 通过 eBPF socket filter 或 syscall trace 追踪 HTTP 请求等七层协议 - eBPF 实践教程
- [lesson 29-sockops](29-sockops/README.zh.md) eBPF 开发实践：使用 sockops 加速网络请求转发
- [lesson 41-xdp-tcpdump](41-xdp-tcpdump/README.zh.md) eBPF 示例教程：使用 XDP 捕获 TCP 信息
- [lesson 42-xdp-loadbalancer](42-xdp-loadbalancer/README.zh.md) eBPF 开发者教程： 简单的 XDP 负载均衡器
安全:

- [lesson 24-hide](24-hide/README.zh.md) eBPF 开发实践：使用 eBPF 隐藏进程或文件信息
- [lesson 25-signal](25-signal/README.zh.md) eBPF 入门实践教程：用 bpf_send_signal 发送信号终止恶意进程
- [lesson 26-sudo](26-sudo/README.zh.md) 使用 eBPF 添加 sudo 用户
- [lesson 27-replace](27-replace/README.zh.md) 使用 eBPF 替换任意程序读取或写入的文本
- [lesson 28-detach](28-detach/README.zh.md) 在应用程序退出后运行 eBPF 程序：eBPF 程序的生命周期
- [lesson 34-syscall](34-syscall/README.zh.md) eBPF 开发实践：使用 eBPF 修改系统调用参数
调度器:

- [lesson 44-scx-simple](44-scx-simple/README.zh.md) eBPF 教程：BPF 调度器入门
- [lesson 45-scx-nest](45-scx-nest/README.zh.md) eBPF 示例教程：实现 `scx_nest` 调度器

其他:

- [lesson 35-user-ringbuf](35-user-ringbuf/README.zh.md) eBPF开发实践：使用 user ring buffer 向内核异步发送信息
- [lesson 36-userspace-ebpf](36-userspace-ebpf/README.zh.md) 用户空间 eBPF 运行时：深度解析与应用实践
- [lesson 38-btf-uprobe](38-btf-uprobe/README.zh.md) 借助 eBPF 和 BTF，让用户态也能一次编译、到处运行
- [lesson 43-kfuncs](43-kfuncs/README.zh.md) 超越 eBPF 的极限：在内核模块中定义自定义 kfunc

持续更新中...

# bcc 和 bpftrace 教程与文档

- [BPF Features by Linux Kernel Version](bcc-documents/kernel-versions.md)
- [Kernel Configuration for BPF Features](bcc-documents/kernel_config.md)
- [bcc Reference Guide](bcc-documents/reference_guide.md)
- [Special Filtering](bcc-documents/special_filtering.md)
- [bcc Tutorial](bcc-documents/tutorial.md)
- [bcc Python Developer Tutorial](bcc-documents/tutorial_bcc_python_developer.md)
- [bpftrace Tutorial](bpftrace-tutorial/README.md)
