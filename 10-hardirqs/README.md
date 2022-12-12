## eBPF 入门开发实践指南十：在 eBPF 中使用 kprobe 监测捕获 unlink 系统调用

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践指南的第十篇，在 eBPF 中。
## hardirqs是什么？

```

```
这看起来是一个 BPF（Berkeley Packet Filter）程序。BPF 程序是小型程序，可以直接在 Linux 内核中运行，用于过滤和操纵网络流量。这个特定的程序似乎旨在收集内核中中断处理程序的统计信息。它定义了一些地图（可以在 BPF 程序和内核的其他部分之间共享的数据结构）和两个函数：handle_entry 和 handle_exit。当内核进入和退出中断处理程序时，分别执行这些函数。handle_entry 函数用于跟踪中断处理程序被执行的次数，而 handle_exit 则用于测量中断处理程序中花费的时间。
