# eBPF 入门实践教程十五：使用 USDT 捕获用户态 Java GC 事件耗时

eBPF (扩展的伯克利数据包过滤器) 是一项强大的网络和性能分析工具，被广泛应用在 Linux 内核上。eBPF 使得开发者能够动态地加载、更新和运行用户定义的代码，而无需重启内核或更改内核源代码。这个特性使得 eBPF 能够提供极高的灵活性和性能，使其在网络和系统性能分析方面具有广泛的应用。此外，eBPF 还支持使用 USDT (用户级静态定义跟踪点) 捕获用户态的应用程序行为。

在我们的 eBPF 入门实践教程系列的这一篇，我们将介绍如何使用 eBPF 和 USDT 来捕获和分析 Java 的垃圾回收 (GC) 事件的耗时。

## USDT 介绍

USDT 是一种在应用程序中插入静态跟踪点的机制，它允许开发者在程序的关键位置插入可用于调试和性能分析的探针。这些探针可以在运行时被 DTrace、SystemTap 或 eBPF 等工具动态激活，从而在不重启应用程序或更改程序代码的情况下，获取程序的内部状态和性能指标。USDT 在很多开源软件，如 MySQL、PostgreSQL、Ruby、Python 和 Node.js 等都有广泛的应用。

### 用户层面的追踪机制：用户级动态跟踪和 USDT

在用户层面进行动态跟踪，即用户级动态跟踪（User-Level Dynamic Tracing）允许我们对任何用户级别的代码进行插桩。比如，我们可以通过在 MySQL 服务器的 `dispatch_command()` 函数上进行插桩，来跟踪服务器的查询请求：

```bash
# ./uprobe 'p:cmd /opt/bin/mysqld:_Z16dispatch_command19enum_server_commandP3THDPcj +0(%dx):string'
Tracing uprobe cmd (p:cmd /opt/bin/mysqld:0x2dbd40 +0(%dx):string). Ctrl-C to end.
  mysqld-2855  [001] d... 19957757.590926: cmd: (0x6dbd40) arg1="show tables"
  mysqld-2855  [001] d... 19957759.703497: cmd: (0x6dbd40) arg1="SELECT * FROM numbers"
[...]
```

这里我们使用了 `uprobe` 工具，它利用了 Linux 的内置功能：ftrace（跟踪器）和 uprobes（用户级动态跟踪，需要较新的 Linux 版本，例如 4.0 左右）。其他的跟踪器，如 perf_events 和 SystemTap，也可以实现此功能。

许多其他的 MySQL 函数也可以被跟踪以获取更多的信息。我们可以列出和计算这些函数的数量：

```bash
# ./uprobe -l /opt/bin/mysqld | more
account_hash_get_key
add_collation
add_compiled_collation
add_plugin_noargs
adjust_time_range
[...]
# ./uprobe -l /opt/bin/mysqld | wc -l
21809
```

这有 21,000 个函数。我们也可以跟踪库函数，甚至是单个的指令偏移。

用户级动态跟踪的能力是非常强大的，它可以解决无数的问题。然而，使用它也有一些困难：需要确定需要跟踪的代码，处理函数参数，以及应对代码的更改。

用户级静态定义跟踪（User-level Statically Defined Tracing, USDT）则可以在某种程度上解决这些问题。USDT 探针（或者称为用户级 "marker"）是开发者在代码的关键位置插入的跟踪宏，提供稳定且已经过文档说明的 API。这使得跟踪工作变得更加简单。

使用 USDT，我们可以简单地跟踪一个名为 `mysql:query__start` 的探针，而不是去跟踪那个名为 `_Z16dispatch_command19enum_server_commandP3THDPcj` 的 C++ 符号，也就是 `dispatch_command()` 函数。当然，我们仍然可以在需要的时候去跟踪 `dispatch_command()` 以及其他 21,000 个 mysqld 函数，但只有当 USDT 探针无法解决问题的时候我们才需要这么做。

在 Linux 中的 USDT，无论是哪种形式的静态跟踪点，其实都已经存在了几十年。它最近由于 Sun 的 DTrace 工具的流行而再次受到关注，这使得许多常见的应用程序，包括 MySQL、PostgreSQL、Node.js、Java 等都加入了 USDT。SystemTap 则开发了一种可以消费这些 DTrace 探针的方式。

你可能正在运行一个已经包含了 USDT 探针的 Linux 应用程序，或者可能需要重新编译（通常是 --enable-dtrace）。你可以使用 `readelf` 来进行检查，例如对于 Node.js：

```bash
# readelf -n node
[...]
Notes at offset 0x00c43058 with length 0x00000494:
  Owner                 Data size   Description
  stapsdt              0x0000003c   NT_STAPSDT (SystemTap probe descriptors)
    Provider: node
    Name: gc__start
    Location: 0x0000000000bf44b4, Base: 0x0000000000f22464, Semaphore: 0x0000000001243028
    Arguments: 4@%esi 4@%edx 8@%rdi
[...]
  stapsdt              0x00000082       NT_STAPSDT (SystemTap probe descriptors)
    Provider: node
    Name: http__client__request
    Location: 0x0000000000bf48ff, Base: 0x0000000000f22464, Semaphore: 0x0000000001243024
    Arguments: 8@%rax 8@%rdx 8@-136(%rbp) -4@-140(%rbp) 8@-72(%rbp) 8@-80(%rbp) -4@-144(%rbp)
[...]
```

这就是使用 --enable-dtrace 重新编译的 node，以及安装了提供 "dtrace" 功能来构建 USDT 支持的 systemtap-sdt-dev 包。这里显示了两个探针：node:gc__start（开始进行垃圾回收）和 node:http__client__request。

在这一点上，你可以使用 SystemTap 或者 LTTng 来跟踪这些探针。然而，内置的 Linux 跟踪器，比如 ftrace 和 perf_events，目前还无法做到这一点（尽管 perf_events 的支持正在开发中）。

USDT 在内核态 eBPF 运行时，也可能产生比较大的性能开销，这时候也可以考虑使用用户态 eBPF 运行时，例如  [bpftime](https://github.com/eunomia-bpf/bpftime)。bpftime 是一个基于 LLVM JIT/AOT 的用户态 eBPF 运行时，它可以在用户态运行 eBPF 程序，和内核态的 eBPF 兼容，避免了内核态和用户态之间的上下文切换，从而提高了 eBPF 程序的执行效率。对于 uprobe 而言，bpftime 的性能开销比 kernel 小一个数量级。

## Java GC 介绍

Java 作为一种高级编程语言，其自动垃圾回收（GC）是其核心特性之一。Java GC 的目标是自动地回收那些不再被程序使用的内存空间，从而减轻程序员在内存管理方面的负担。然而，GC 过程可能会引发应用程序的停顿，对程序的性能和响应时间产生影响。因此，对 Java GC 事件进行监控和分析，对于理解和优化 Java 应用的性能是非常重要的。

在接下来的教程中，我们将演示如何使用 eBPF 和 USDT 来监控和分析 Java GC 事件的耗时，希望这些内容对你在使用 eBPF 进行应用性能分析方面的工作有所帮助。

## eBPF 实现机制

Java GC 的 eBPF 程序分为内核态和用户态两部分，我们会分别介绍这两部分的实现机制。

### 内核态程序

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Chen Tao */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>
#include "javagc.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, uint32_t);
    __type(value, struct data_t);
} data_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, int);
} perf_map SEC(".maps");

__u32 time;

static int gc_start(struct pt_regs *ctx)
{
    struct data_t data = {};

    data.cpu = bpf_get_smp_processor_id();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&data_map, &data.pid, &data, 0);
    return 0;
}

static int gc_end(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct data_t *p;
    __u32 val;

    data.cpu = bpf_get_smp_processor_id();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    p = bpf_map_lookup_elem(&data_map, &data.pid);
    if (!p)
        return 0;

    val = data.ts - p->ts;
    if (val > time) {
        data.ts = val;
        bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }
    bpf_map_delete_elem(&data_map, &data.pid);
    return 0;
}

SEC("usdt")
int handle_gc_start(struct pt_regs *ctx)
{
    return gc_start(ctx);
}

SEC("usdt")
int handle_gc_end(struct pt_regs *ctx)
{
    return gc_end(ctx);
}

SEC("usdt")
int handle_mem_pool_gc_start(struct pt_regs *ctx)
{
    return gc_start(ctx);
}

SEC("usdt")
int handle_mem_pool_gc_end(struct pt_regs *ctx)
{
    return gc_end(ctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

首先，我们定义了两个映射（map）：

- `data_map`：这个 hashmap 存储每个进程 ID 的垃圾收集开始时间。`data_t` 结构体包含进程 ID、CPU ID 和时间戳。
- `perf_map`：这是一个 perf event array，用于将数据发送回用户态程序。

然后，我们有四个处理函数：`gc_start`、`gc_end` 和两个 USDT 处理函数 `handle_mem_pool_gc_start` 和 `handle_mem_pool_gc_end`。这些函数都用 BPF 的 `SEC("usdt")` 宏注解，以便在 Java 进程中捕获到与垃圾收集相关的 USDT 事件。

`gc_start` 函数在垃圾收集开始时被调用。它首先获取当前的 CPU ID、进程 ID 和时间戳，然后将这些数据存入 `data_map`。

`gc_end` 函数在垃圾收集结束时被调用。它执行与 `gc_start` 类似的操作，但是它还从 `data_map` 中检索开始时间，并计算垃圾收集的持续时间。如果持续时间超过了设定的阈值（变量 `time`），那么它将数据发送回用户态程序。

`handle_gc_start` 和 `handle_gc_end` 是针对垃圾收集开始和结束事件的处理函数，它们分别调用了 `gc_start` 和 `gc_end`。

`handle_mem_pool_gc_start` 和 `handle_mem_pool_gc_end` 是针对内存池的垃圾收集开始和结束事件的处理函数，它们也分别调用了 `gc_start` 和 `gc_end`。

最后，我们有一个 `LICENSE` 数组，声明了该 BPF 程序的许可证，这是加载 BPF 程序所必需的。

### 用户态程序

用户态程序的主要目标是加载和运行eBPF程序，以及处理来自内核态程序的数据。它是通过 libbpf 库来完成这些操作的。这里我们省略了一些通用的加载和运行 eBPF 程序的代码，只展示了与 USDT 相关的部分。

第一个函数 `get_jvmso_path` 被用来获取运行的Java虚拟机（JVM）的 `libjvm.so` 库的路径。首先，它打开了 `/proc/<pid>/maps` 文件，该文件包含了进程地址空间的内存映射信息。然后，它在文件中搜索包含 `libjvm.so` 的行，然后复制该行的路径到提供的参数中。

```c
static int get_jvmso_path(char *path)
{
    char mode[16], line[128], buf[64];
    size_t seg_start, seg_end, seg_off;
    FILE *f;
    int i = 0;

    sprintf(buf, "/proc/%d/maps", env.pid);
    f = fopen(buf, "r");
    if (!f)
        return -1;

    while (fscanf(f, "%zx-%zx %s %zx %*s %*d%[^\n]\n",
            &seg_start, &seg_end, mode, &seg_off, line) == 5) {
        i = 0;
        while (isblank(line[i]))
            i++;
        if (strstr(line + i, "libjvm.so")) {
            break;
        }
    }

    strcpy(path, line + i);
    fclose(f);

    return 0;
}
```

接下来，我们看到的是将 eBPF 程序（函数 `handle_gc_start` 和 `handle_gc_end`）附加到Java进程的相关USDT探针上。每个程序都通过调用 `bpf_program__attach_usdt` 函数来实现这一点，该函数的参数包括BPF程序、进程ID、二进制路径以及探针的提供者和名称。如果探针挂载成功，`bpf_program__attach_usdt` 将返回一个链接对象，该对象将存储在skeleton的链接成员中。如果挂载失败，程序将打印错误消息并进行清理。

```c
    skel->links.handle_mem_pool_gc_start = bpf_program__attach_usdt(skel->progs.handle_gc_start, env.pid,
                                    binary_path, "hotspot", "mem__pool__gc__begin", NULL);
    if (!skel->links.handle_mem_pool_gc_start) {
        err = errno;
        fprintf(stderr, "attach usdt mem__pool__gc__begin failed: %s\n", strerror(err));
        goto cleanup;
    }

    skel->links.handle_mem_pool_gc_end = bpf_program__attach_usdt(skel->progs.handle_gc_end, env.pid,
                                binary_path, "hotspot", "mem__pool__gc__end", NULL);
    if (!skel->links.handle_mem_pool_gc_end) {
        err = errno;
        fprintf(stderr, "attach usdt mem__pool__gc__end failed: %s\n", strerror(err));
        goto cleanup;
    }

    skel->links.handle_gc_start = bpf_program__attach_usdt(skel->progs.handle_gc_start, env.pid,
                                    binary_path, "hotspot", "gc__begin", NULL);
    if (!skel->links.handle_gc_start) {
        err = errno;
        fprintf(stderr, "attach usdt gc__begin failed: %s\n", strerror(err));
        goto cleanup;
    }

    skel->links.handle_gc_end = bpf_program__attach_usdt(skel->progs.handle_gc_end, env.pid,
                binary_path, "hotspot", "gc__end", NULL);
    if (!skel->links.handle_gc_end) {
        err = errno;
        fprintf(stderr, "attach usdt gc__end failed: %s\n", strerror(err));
        goto cleanup;
    }
```

最后一个函数 `handle_event` 是一个回调函数，用于处理从perf event array收到的数据。这个函数会被 perf event array 触发，并在每次接收到新的事件时调用。函数首先将数据转换为 `data_t` 结构体，然后将当前时间格式化为字符串，并打印出事件的时间戳、CPU ID、进程 ID，以及垃圾回收的持续时间。

```c
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct data_t *e = (struct data_t *)data;
    struct tm *tm = NULL;
    char ts[16];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    printf("%-8s %-7d %-7d %-7lld\n", ts, e->cpu, e->pid, e->ts/1000);
}
```

## 安装依赖

构建示例需要 clang、libelf 和 zlib。包名在不同的发行版中可能会有所不同。

在 Ubuntu/Debian 上，你需要执行以下命令：

```shell
sudo apt install clang libelf1 libelf-dev zlib1g-dev
```

在 CentOS/Fedora 上，你需要执行以下命令：

```shell
sudo dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

## 编译运行

在对应的目录中，运行 Make 即可编译运行上述代码：

```console
$ make
$ sudo ./javagc -p 12345
Tracing javagc time... Hit Ctrl-C to end.
TIME     CPU     PID     GC TIME
10:00:01 10%     12345   50ms
10:00:02 12%     12345   55ms
10:00:03 9%      12345   47ms
10:00:04 13%     12345   52ms
10:00:05 11%     12345   50ms
```

完整源代码：

- <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/15-javagc>

参考资料：

- <https://www.brendangregg.com/blog/2015-07-03/hacking-linux-usdt-ftrace.html>
- <https://github.com/iovisor/bcc/blob/master/libbpf-tools/javagc.c>

## 总结

通过本篇 eBPF 入门实践教程，我们学习了如何使用 eBPF 和 USDT 动态跟踪和分析 Java 的垃圾回收(GC)事件。我们了解了如何在用户态应用程序中设置 USDT 跟踪点，以及如何编写 eBPF 程序来捕获这些跟踪点的信息，从而更深入地理解和优化 Java GC 的行为和性能。

此外，我们也介绍了一些关于 Java GC、USDT 和 eBPF 的基础知识和实践技巧，这些知识和技巧对于想要在网络和系统性能分析领域深入研究的开发者来说是非常有价值的。

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。

> The original link of this article: <https://eunomia.dev/tutorials/15-javagc>
