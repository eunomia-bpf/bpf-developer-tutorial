# BPF 特性的内核配置

## 与 BPF 相关的内核配置

| 功能 | 内核配置 | 描述 |
|:----|:----------|:-----|
| **基础** | CONFIG_BPF_SYSCALL | 启用 bpf() 系统调用 |
|  | CONFIG_BPF_JIT | BPF 程序通常由 BPF 解释器处理。此选项允许内核在加载程序时生成本地代码。这将显著加速 BPF 程序的处理 |
|  | CONFIG_HAVE_BPF_JIT | 启用 BPF 即时编译器 |
|  | CONFIG_HAVE_EBPF_JIT | 扩展 BPF JIT (eBPF) |
|  | CONFIG_HAVE_CBPF_JIT | 经典 BPF JIT (cBPF) |
|  | CONFIG_MODULES | 启用可加载内核模块的构建 |
|  | CONFIG_BPF | BPF VM 解释器 |
|  | CONFIG_BPF_EVENTS | 允许用户将 BPF 程序附加到 kprobe、uprobe 和 tracepoint 事件上 |
|  | CONFIG_PERF_EVENTS | 内核性能事件和计数器 |
|  | CONFIG_HAVE_PERF_EVENTS | 启用性能事件 |
|  | CONFIG_PROFILING | 启用分析器使用的扩展分析支持机制 |
| **BTF** | CONFIG_DEBUG_INFO_BTF | 从 DWARF 调试信息生成去重的 BTF 类型信息 |
| | CONFIG_PAHOLE_HAS_SPLIT_BTF | 为每个选定的内核模块生成 BTF |
| | CONFIG_DEBUG_INFO_BTF_MODULES | 为内核模块生成紧凑的分割 BTF 类型信息 |
| **安全** | CONFIG_BPF_JIT_ALWAYS_ON | 启用 BPF JIT 并删除 BPF 解释器以避免猜测执行 |
| | CONFIG_BPF_UNPRIV_DEFAULT_OFF | 通过设置默认禁用非特权 BPF |
| **Cgroup** | CONFIG_CGROUP_BPF | 支持将 BPF 程序附加到 cgroup 上 |
| **网络** | CONFIG_BPFILTER | 基于 BPF 的数据包过滤框架 (BPFILTER) |
| | CONFIG_BPFILTER_UMH | 使用内嵌的用户模式助手构建 bpfilter 内核模块 |
| | CONFIG_NET_CLS_BPF | 基于可编程 BPF (JIT'ed) 过滤器进行数据包分类的基于 BPF 的分类器的替代方法 || | CONFIG_NET_ACT_BPF | 在数据包上执行BPF代码。BPF代码将决定是否丢弃数据包 |
| | CONFIG_BPF_STREAM_PARSER | 启用此功能，允许使用BPF_MAP_TYPE_SOCKMAP与TCP流解析器配合使用 |
| | CONFIG_LWTUNNEL_BPF | 在路由查找入站和出站数据包后，允许作为下一跳操作运行BPF程序 |
| | CONFIG_NETFILTER_XT_MATCH_BPF | BPF匹配将对每个数据包应用Linux套接字过滤器，并接受过滤器返回非零值的数据包 |
| | CONFIG_IPV6_SEG6_BPF | 为支持BPF seg6local挂钩，添加IPv6 Segement Routing助手 [参考](https://github.com/torvalds/linux/commit/fe94cc290f535709d3c5ebd1e472dfd0aec7ee7) |
| **kprobes** | CONFIG_KPROBE_EVENTS | 允许用户通过ftrace接口动态添加跟踪事件（类似于tracepoints） |
|  | CONFIG_KPROBES | 启用基于kprobes的动态事件 |
|  | CONFIG_HAVE_KPROBES | 检查是否启用了kprobes |
|  | CONFIG_HAVE_REGS_AND_STACK_ACCESS_API | 如果架构支持从pt_regs访问寄存器和堆栈条目所需的API，则应该选择此符号。例如，基于kprobes的事件跟踪器需要此API |
|  | CONFIG_KPROBES_ON_FTRACE | 如果架构支持将pt_regs完全传递给函数跟踪，则在函数跟踪器上有kprobes |
| **kprobe multi** | CONFIG_FPROBE | 启用fprobe以一次性在多个函数上附加探测点 |
| **kprobe override** | CONFIG_BPF_KPROBE_OVERRIDE | 启用BPF程序覆盖kprobed函数 |
| **uprobes** | CONFIG_UPROBE_EVENTS | 启用基于uprobes的动态事件 |
|  | CONFIG_ARCH_SUPPORTS_UPROBES | 架构特定的uprobes支持 |
|  | CONFIG_UPROBES | Uprobes是kprobes的用户空间对应项：它们允许仪器应用程序（如'perf probe'）在用户空间二进制文件和库中建立非侵入性探测点，并在用户空间应用程序触发探测点时执行处理函数。 ||  | CONFIG_MMU | 基于MMU的虚拟化寻址空间支持，通过分页内存管理 |
| **Tracepoints** | CONFIG_TRACEPOINTS | 启用在内核中插入Tracepoints并与问题函数连接 |
|  | CONFIG_HAVE_SYSCALL_TRACEPOINTS | 启用系统调用进入/退出跟踪 |
| **Raw Tracepoints** | Same as Tracepoints | |
| **LSM** | CONFIG_BPF_LSM | 使用BPF程序对安全钩子进行仪器化，实现动态MAC和审计策略 |
| **LIRC** | CONFIG_BPF_LIRC_MODE2 | 允许将BPF程序附加到lirc设备 |
