# eBPF 开发实践教程：基于 CO-RE，通过小工具快速上手 eBPF 开发

这是一个基于 `CO-RE`（一次编译，到处运行）的 eBPF 的开发教程，提供了从入门到进阶的 eBPF 开发实践，包括基本概念、代码实例、实际应用等内容。和 BCC 不同的是，我们使用 libbpf、Cilium、libbpf-rs、eunomia-bpf 等框架进行开发，包含 C、Go、Rust 等语言的示例。

本教程不会进行复杂的概念讲解和场景介绍，主要希望提供一些 eBPF 小工具的案例（**非常短小，从二十行代码开始入门！**），来帮助 eBPF 应用的开发者快速上手 eBPF 的开发方法和技巧。教程内容可以在目录中找到，每个目录都是一个独立的 eBPF 工具案例。

教程关注于可观测性、网络、安全等等方面的 eBPF 示例。完整的代码和教程可以在 [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) GitHub 开源仓库中找到。**如果您认为本教程对您有所帮助，也请给我们一个 star 鼓励一下！**

# 入门文档

包含简单的 eBPF 程序样例与介绍，这部分主要使用 `eunomia-bpf` 框架简化开发，并介绍了 eBPF 的基本使用方式和开发流程。

- [lesson 0-introduce](0-introduce/README.md) 介绍 eBPF 的基本概念和常见的开发工具
- [lesson 1-helloworld](1-helloworld/README.md) 使用 eBPF 开发最简单的「Hello World」程序，介绍 eBPF 的基本框架和开发流程
- [lesson 2-kprobe-unlink](2-kprobe-unlink/README.md) 在 eBPF 中使用 kprobe 捕获 unlink 系统调用
- [lesson 3-fentry-unlink](3-fentry-unlink/README.md) 在 eBPF 中使用 fentry 捕获 unlink 系统调用
- [lesson 4-opensnoop](4-opensnoop/README.md) 使用 eBPF 捕获进程打开文件的系统调用集合，使用全局变量在 eBPF 中过滤进程 pid
- [lesson 5-uprobe-bashreadline](5-uprobe-bashreadline/README.md) 在 eBPF 中使用 uprobe 捕获 bash 的 readline 函数调用
- [lesson 6-sigsnoop](6-sigsnoop/README.md) 捕获进程发送信号的系统调用集合，使用 hash map 保存状态
- [lesson 7-execsnoop](7-execsnoop/README.md) 捕获进程执行时间，通过 perf event array 向用户态打印输出
- [lesson 8-execsnoop](8-exitsnoop/README.md) 捕获进程退出事件，使用 ring buffer 向用户态打印输出
- [lesson 9-runqlat](9-runqlat/README.md) 捕获进程调度延迟，以直方图方式记录
- [lesson 10-hardirqs](10-hardirqs/README.md) 使用 hardirqs 或 softirqs 捕获中断事件

# 进阶文档和示例

我们开始主要基于 `libbpf` 构建完整的 eBPF 工程，并且把它和各种应用场景结合起来进行实践。

- [lesson 11-bootstrap](11-bootstrap/README.md) 使用 libbpf-boostrap 为 eBPF 编写原生的 libbpf 用户态代码，并建立完整的 libbpf 工程。
- [lesson 12-profile](12-profile/README.md) 使用 eBPF 进行性能分析
- [lesson 13-tcpconnlat](13-tcpconnlat/README.md) 记录 TCP 连接延迟，并使用 libbpf 在用户态处理数据
- [lesson 14-tcpstates](14-tcpstates/README.md) 记录 TCP 连接状态与 TCP RTT
- [lesson 15-javagc](15-javagc/README.md) 使用 usdt 捕获用户态 Java GC 事件耗时
- [lesson 16-memleak](16-memleak/README.md) 检测内存泄漏
- [lesson 17-biopattern](17-biopattern/README.md) 捕获磁盘 IO 模式
- [lesson 18-further-reading](18-further-reading/README.md) 更进一步的相关资料：论文列表、项目、博客等等
- [lesson 19-lsm-connect](19-lsm-connect/README.md) 使用 LSM 进行安全检测防御
- [lesson 20-tc](20-tc/README.md) 使用 eBPF 进行 tc 流量控制
- [lesson 21-xdp](21-xdp/README.md) 使用 eBPF 进行 XDP 报文处理

# 高级主题

这里涵盖了一系列和 eBPF 相关的高级内容，包含在 Android 上使用 eBPF 程序、使用 eBPF 程序进行可能的攻击与防御、复杂的追踪等等。这部分主要基于 libbpf、Cilium 等框架进行开发。

- [在 Android 上使用 eBPF 程序](22-android/README.md)
- [使用 uprobe 捕获多种库的 SSL/TLS 明文数据](30-sslsniff/README.md)
- [使用 eBPF socket filter 或 syscall trace 追踪 HTTP 请求和其他七层协议](23-http/README.md)
- [使用 sockops 加速网络请求转发](29-sockops/README.md)
- [使用 eBPF 隐藏进程或文件信息](24-hide/README.md)
- [使用 bpf_send_signal 发送信号终止进程](25-signal/README.md)
- [使用 eBPF 添加 sudo 用户](26-sudo/README.md)
- [使用 eBPF 替换任意程序读取或写入的文本](27-replace/README.md)
- [BPF 的生命周期：使用 Detached 模式在用户态应用退出后持续运行 eBPF 程序](28-detach/README.md)
- [eBPF 运行时的安全性与面临的挑战](18-further-reading/ebpf-security.zh.md)
- [使用 eBPF 修改系统调用参数](34-syscall/README.md)
- [eBPF开发实践：使用 user ring buffer 向内核异步发送信息](35-user-ringbuf/README.md)
- [用户空间 eBPF 运行时：深度解析与应用实践](36-userspace-ebpf/README.md)
- [使用 uprobe 追踪 Rust 应用程序](37-uprobe-rust/README.md)
- [借助 eBPF 和 BTF，让用户态也能一次编译、到处运行](38-btf-uprobe/README.md)

# bcc 和 bpftrace 教程与文档

- [BPF Features by Linux Kernel Version](bcc-documents/kernel-versions.md)
- [Kernel Configuration for BPF Features](bcc-documents/kernel_config.md)
- [bcc Reference Guide](bcc-documents/reference_guide.md)
- [Special Filtering](bcc-documents/special_filtering.md)
- [bcc Tutorial](bcc-documents/tutorial.md)
- [bcc Python Developer Tutorial](bcc-documents/tutorial_bcc_python_developer.md)
- [bpftrace Tutorial](bpftrace-tutorial/README.md)
