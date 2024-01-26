# 借助 eBPF 和 BTF，让用户态也能一次编译、到处运行

在现代 Linux 系统中，eBPF（扩展的 Berkeley Packet Filter）是一项强大而灵活的技术。它允许在内核中运行沙盒化程序，类似于虚拟机环境，为扩展内核功能提供了一种既安全又不会导致系统崩溃或安全风险的方法。

eBPF 中的 “co-re” 代表“一次编译、到处运行”。这是其关键特征之一，用于解决 eBPF 程序在不同内核版本间兼容性的主要挑战。eBPF 的 CO-RE 功能可以实现在不同的内核版本上运行同一 eBPF 程序，而无需重新编译。

利用 eBPF 的 Uprobe 功能，可以追踪用户空间应用程序并访问其内部数据结构。然而，用户空间应用程序的 CO-RE 实践目前尚不完善。本文将介绍一种新方法，利用 CO-RE 为用户空间应用程序确保 eBPF 程序在不同应用版本间的兼容性，从而避免了多次编译的需求。例如，在从加密流量中捕获 SSL/TLS 明文数据时，你或许不需要为每个版本的 OpenSSL 维护一个单独的 eBPF 程序。

为了在用户空间应用程序中实现eBPF的“一次编译、到处运行”(Co-RE)特性，我们需要利用BPF类型格式(BTF)来克服传统eBPF程序的一些限制。这种方法的关键在于为用户空间程序提供与内核类似的类型信息和兼容性支持，从而使得eBPF程序能够更灵活地应对不同版本的用户空间应用和库。

本文是eBPF开发者教程的一部分，详细内容可访问[这里](https://eunomia.dev/tutorials/)。源代码在[GitHub库](https://github.com/eunomia-bpf/bpf-developer-tutorial)中可用。

## 为什么我们需要CO-RE？

- **内核依赖性**：传统的eBPF程序和它们被编译的特定Linux内核版本紧密耦合。这是因为它们依赖于内核的特定内部数据结构和API，这些可能在内核版本间变化。
- **可移植性问题**：如果你想在带有不同内核版本的不同Linux系统上运行一个eBPF程序，你通常需要为每个内核版本重新编译eBPF程序，这是一个麻烦而低效的过程。

### Co-RE的解决方案

- **抽象内核依赖性**：Co-RE使eBPF程序更具可移植性，通过使用BPF类型格式(BTF)和重定位来抽象特定的内核依赖。
- **BPF类型格式（BTF）**：BTF提供了关于内核中数据结构和函数的丰富类型信息。这些元数据允许eBPF程序在运行时理解内核结构的布局。
- **重定位**：编译支持Co-RE的eBPF程序包含在加载时解析的重定位。这些重定位根据运行内核的实际布局和地址调整程序对内核数据结构和函数的引用。

### Co-RE的优点

1. **编写一次，任何地方运行**：编译有Co-RE的eBPF程序可以在不同的内核版本上运行，无需重新编译。这大大简化了在多样环境中部署和维护eBPF程序。
2. **安全和稳定**：Co-RE保持了eBPF的安全性，确保程序不会导致内核崩溃，遵守安全约束。
3. **简单的开发**：开发者不需要关注每个内核版本的具体情况，这简化了eBPF程序的开发。

## 用户空间应用程序CO-RE的问题

eBPF也支持追踪用户空间应用程序。Uprobe是一个用户空间探针，允许对用户空间程序进行动态仪表装置。探针位置包括函数入口、特定偏移和函数返回。

BTF是为内核设计的，生成自vmlinux，它可以帮助eBPF程序方便地兼容不同的内核版本。

但是，用户空间应用程序也需要CO-RE。例如，SSL/TLS uprobe被广泛用于从加密流量中捕获明文数据。它是用用户空间库实现的，如OpenSSL、GnuTLS、NSS等。用户空间应用程序和库也有各种版本，如果我们需要为每个版本编译和维护eBPF程序，那就会很复杂。

下面是一些新的工具和方法来帮助我们为用户空间应用程序启用CO-RE。

## 用户空间程序的BTF

这是一个简单的uprobe例子，它可以捕获用户空间程序的`add_test`函数的调用和参数。你可以在`uprobe.bpf.c`中添加`#define BPF_NO_PRESERVE_ACCESS_INDEX`来确保eBPF程序可以在没有`struct data`的BTF的情况下编译。

```c
#define BPF_NO_GLOBAL_DATA
#define BPF_NO_PRESERVE_ACCESS_INDEX
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct data {
        int a;
        int c;
        int d;
};

SEC("uprobe/examples/btf-base:add_test")
int BPF_UPROBE(add_test, struct data *d)
{
    int a = 0, c = 0;
    bpf_probe_read_user(&a, sizeof(a), &d->a);
    bpf_probe_read_user(&c, sizeof(c), &d->c);
    bpf_printk("add_test(&d) %d + %d = %d\n", a, c,  a + c);
    return a + c;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

然后，我们有两个不同版本的用户空间程序，`examples/btf-base`和`examples/btf-base-new`。两个版本中的struct `data`是不同的。

`examples/btf-base`：

```c
// use a different struct
struct data {
        int a;
        int c;
        int d;
};

int add_test(struct data *d) {
    return d->a + d->c;
}

int main(int argc, char **argv) {
    struct data d = {1, 3, 4};
    printf("add_test(&d) = %d\n", add_test(&d));
    return 0;
}
```

`examples/btf-base-new`：

```c
struct data {
        int a;
        int b;
        int c;
        int d;
};

int add_test(struct data *d) {
    return d->a + d->c;
}

int main(int argc, char **argv) {
    struct data d = {1, 2, 3, 4};
    printf("add_test(&d) = %d\n", add_test(&d));
    return 0;
}
```

我们可以使用pahole和clang来生成每个版本的btf。制作示例并生成btf:

```sh
make -C example # it's like: pahole --btf_encode_detached base.btf btf-base.o
```

然后我们执行eBPF程序和用户空间程序。 对于 `btf-base`：

```sh
sudo ./uprobe examples/btf-base 
```

也是用户空间程序：

```console
$ examples/btf-base
add_test(&d) = 4
```

我们将看到：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe\
           <...>-25458   [000] ...11 27694.081465: bpf_trace_printk: add_test(&d) 1 + 3 = 4
```

对于 `btf-base-new`：

```sh
sudo ./uprobe examples/btf-base-new
```

同时也是用户空间程序：

```console
$ examples/btf-base-new
add_test(&d) = 4
```

但我们可以看到：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe\
           <...>-25809   [001] ...11 27828.314224: bpf_trace_printk: add_test(&d) 1 + 2 = 3
```

结果是不同的，因为两个版本中的struct `data`是不同的。eBPF程序无法与不同版本的用户空间程序兼容。

## 使用用户空间程序的BTF

在`uprobe.bpf.c`中注释掉`#define BPF_NO_PRESERVE_ACCESS_INDEX` ，以确保eBPF程序可以以`struct data`的BTF编译。

```c
#define BPF_NO_GLOBAL_DATA
// #define BPF_NO_PRESERVE_ACCESS_INDEX
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

struct data {
        int a;
        int c;
        int d;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

SEC("uprobe/examples/btf-base:add_test")
int BPF_UPROBE(add_test, struct data *d)
{
    int a = 0, c = 0;
    bpf_probe_read_user(&a, sizeof(a), &d->a);
    bpf_probe_read_user(&c, sizeof(c), &d->c);
    bpf_printk("add_test(&d) %d + %d = %d\n", a, c,  a + c);
    return a + c;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

`struct data`的记录在eBPF程序中被保留下来。然后，我们可以使用 `btf-base.btf`来编译eBPF程序。

将用户btf与内核btf合并，这样我们就有了一个完整的内核和用户空间的btf:

```sh
./merge-btf /sys/kernel/btf/vmlinux examples/base.btf target-base.btf
```

然后我们使用用户空间程序执行eBPF程序。 对于 `btf-base`：

```console
$ sudo ./uprobe examples/btf-base target-base.btf
...
libbpf: prog 'add_test': relo #1: patched insn #4 (ALU/ALU64) imm 0 -> 0
libbpf: prog 'add_test': relo #2: <byte_off> [7] struct data.c (0:1 @ offset 4)
libbpf: prog 'add_test': relo #2: matching candidate #0 <byte_off> [133110] struct data.c (0:1 @ offset 4)
libbpf: prog 'add_test': relo #2: patched insn #11 (ALU/ALU64) imm 4 -> 4
...
```

执行用户空间程序并获取结果：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
[sudo] password for yunwei37: 
           <...>-26740   [001] ...11 28180.156220: bpf_trace_printk: add_test(&d) 1 + 3 = 4
```

还可以对另一个版本的用户空间程序`btf-base-new`做同样的操作:

```console
$ ./merge-btf /sys/kernel/btf/vmlinux examples/base-new.btf target-base-new.btf
$ sudo ./uprobe examples/btf-base-new target-base-new.btf
....
libbpf: sec 'uprobe/examples/btf-base:add_test': found 3 CO-RE relocations
libbpf: CO-RE relocating [2] struct pt_regs: found target candidate [357] struct pt_regs in [vmlinux]
libbpf: prog 'add_test': relo #0: <byte_off> [2] struct pt_regs.di (0:14 @ offset 112)
libbpf: prog 'add_test': relo #0: matching candidate #0 <byte_off> [357] struct pt_regs.di (0:14 @ offset 112)
libbpf: prog 'add_test': relo #0: patched insn #0 (LDX/ST/STX) off 112 -> 112
libbpf: CO-RE relocating [7] struct data: found target candidate [133110] struct data in [vmlinux]
libbpf: prog 'add_test': relo #1: <byte_off> [7] struct data.a (0:0 @ offset 0)
libbpf: prog 'add_test': relo #1: matching candidate #0 <byte_off> [133110] struct data.a (0:0 @ offset 0)
libbpf: prog 'add_test': relo #1: patched insn #4 (ALU/ALU64) imm 0 -> 0
libbpf: prog 'add_test': relo #2: <byte_off> [7] struct data.c (0:1 @ offset 4)
libbpf: prog 'add_test': relo #2: matching candidate #0 <byte_off> [133110] struct data.c (0:2 @ offset 8)
libbpf: prog 'add_test': relo #2: patched insn #11 (ALU/ALU64) imm 4 -> 8
libbpf: elf: symbol address match for 'add_test' in 'examples/btf-base-new': 0x1140
Successfully started! Press Ctrl+C to stop.
```

结果是正确的：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
[sudo] password for yunwei37: 
           <...>-26740   [001] ...11 28180.156220: bpf_trace_printk: add_test(&d) 1 + 3 = 4
```

## 结论

- **灵活性和兼容性**：在用户空间eBPF程序中使用BTF大大增强了它们在不同版本的用户空间应用程序和库之间的灵活性和兼容性。
- **简化了复杂性**：这种方法显著减少了维护不同版本的用户空间应用程序的eBPF程序的复杂性，因为它消除了需要多个程序版本的需要。
- **更广泛的应用**：虽然你的例子关注于SSL/TLS监控，但是这种方法在性能监控、安全和用户空间应用程序的调试等方面有更广泛的应用。

这个示例展示了eBPF在实践中的重要进步，将其强大的功能扩展到更动态地处理用户空间应用程序在Linux环境中。对于处理现代Linux系统复杂性的软件工程师和系统管理员来说，这是一个引人注目的解决方案。

如果你想了解更多关于eBPF知识和实践，你可以访问我们的教程代码库<https://github.com/eunomia-bpf/bpf-developer-tutorial>或者网站<https://eunomia.dev/tutorials/>获得更多示例和完整教程。