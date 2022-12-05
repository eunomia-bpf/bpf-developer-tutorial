## eBPF 入门实践教程：编写 eBPF 程序 Memleak 监控内存泄漏

### 背景

内存泄漏对于一个程序而言是一个很严重的问题。倘若放任一个存在内存泄漏的程序运行，久而久之
系统的内存会慢慢被耗尽，导致程序运行速度显著下降。为了避免这一情况，`memleak`工具被提出。
它可以跟踪并匹配内存分配和释放的请求，并且打印出已经被分配资源而又尚未释放的堆栈信息。

### 实现原理

`memleak` 的实现逻辑非常直观。它在我们常用的动态分配内存的函数接口路径上挂载了ebpf程序，
同时在free上也挂载了ebpf程序。在调用分配内存相关函数时，`memleak` 会记录调用者的pid，分配得到
内存的地址，分配得到的内存大小等基本数据。在free之后，`memeleak`则会去map中删除记录的对应的分配
信息。对于用户态常用的分配函数 `malloc`, `calloc` 等，`memleak`使用了 uporbe 技术实现挂载，对于
内核态的函数，比如 `kmalloc` 等，`memleak` 则使用了现有的 tracepoint 来实现。
`memleak`主要的挂载点为
```c
SEC("uprobe/malloc")

SEC("uretprobe/malloc")

SEC("uprobe/calloc")

SEC("uretprobe/calloc")

SEC("uprobe/realloc")

SEC("uretprobe/realloc")

SEC("uprobe/memalign")

SEC("uretprobe/memalign")

SEC("uprobe/posix_memalign")

SEC("uretprobe/posix_memalign")

SEC("uprobe/valloc")

SEC("uretprobe/valloc")

SEC("uprobe/pvalloc")

SEC("uretprobe/pvalloc")

SEC("uprobe/aligned_alloc")

SEC("uretprobe/aligned_alloc")

SEC("uprobe/free")

SEC("tracepoint/kmem/kmalloc")

SEC("tracepoint/kmem/kfree")


SEC("tracepoint/kmem/kmalloc_node")

SEC("tracepoint/kmem/kmem_cache_alloc")

SEC("tracepoint/kmem/kmem_cache_alloc_node")

SEC("tracepoint/kmem/kmem_cache_free")

SEC("tracepoint/kmem/mm_page_alloc")

SEC("tracepoint/kmem/mm_page_free")

SEC("tracepoint/percpu/percpu_alloc_percpu")

SEC("tracepoint/percpu/percpu_free_percpu")

```

### Eunomia中使用方式


### 总结
`memleak` 实现了对内存分配系列函数的监控追踪，可以避免程序发生严重的内存泄漏事故，对于开发者而言
具有极大的帮助。
