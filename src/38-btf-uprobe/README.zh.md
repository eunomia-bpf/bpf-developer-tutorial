# 借助 eBPF 和 BTF，让用户态也能一次编译、到处运行

在现代 Linux 系统中，eBPF（扩展的 Berkeley Packet Filter）是一项强大而灵活的技术。它允许在内核中运行沙盒化程序，类似于虚拟机环境，为扩展内核功能提供了一种既安全又不会导致系统崩溃或安全风险的方法。

eBPF 中的 “co-re” 代表“一次编译、到处运行”。这是其关键特征之一，用于解决 eBPF 程序在不同内核版本间兼容性的主要挑战。eBPF 的 CO-RE 功能可以实现在不同的内核版本上运行同一 eBPF 程序，而无需重新编译。

利用 eBPF 的 Uprobe 功能，可以追踪用户空间应用程序并访问其内部数据结构。然而，用户空间应用程序的 CO-RE 实践目前尚不完善。本文将介绍一种新方法，利用 CO-RE 为用户空间应用程序确保 eBPF 程序在不同应用版本间的兼容性，从而避免了多次编译的需求。例如，在从加密流量中捕获 SSL/TLS 明文数据时，你或许不需要为每个版本的 OpenSSL 维护一个单独的 eBPF 程序。

为了在用户空间应用程序中实现eBPF的“一次编译、到处运行”(Co-RE)特性，我们需要利用BPF类型格式(BTF)来克服传统eBPF程序的一些限制。这种方法的关键在于为用户空间程序提供与内核类似的类型信息和兼容性支持，从而使得eBPF程序能够更灵活地应对不同版本的用户空间应用和库。

本文是eBPF开发者教程的一部分，详细内容可访问[https://eunomia.dev/tutorials/](https://eunomia.dev/tutorials/)。本文完整的代码请查看 <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/38-btf-uprobe> 。

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

BTF是为内核设计的，生成自vmlinux，它可以帮助eBPF程序方便地兼容不同的内核版本。但是，用户空间应用程序也需要CO-RE。例如，SSL/TLS uprobe被广泛用于从加密流量中捕获明文数据。它是用用户空间库实现的，如OpenSSL、GnuTLS、NSS等。用户空间应用程序和库也有各种版本，如果我们需要为每个版本编译和维护eBPF程序，那就会很复杂。

下面是一些新的工具和方法，可以帮助我们为用户空间应用程序启用CO-RE。

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
make -C examples # it's like: pahole --btf_encode_detached base.btf btf-base.o
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

结果是不同的，因为两个版本中的struct `data`是不同的。eBPF程序无法与不同版本的用户空间程序兼容，我们获取到了错误的结构体偏移量，也会导致我们追踪失败。

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

这时，如果未提供用户态的 BTF 信息，会导致验证失败：

```console
# ./uprobe examples/btf-base 
.....
; int BPF_UPROBE(add_test, struct data *d) @ uprobe.bpf.c:23
0: (79) r6 = *(u64 *)(r1 +112)        ; R1=ctx() R6_w=scalar()
1: (b7) r7 = 0                        ; R7_w=0
; int a = 0, c = 0; @ uprobe.bpf.c:25
2: (63) *(u32 *)(r10 -4) = r7         ; R7_w=0 R10=fp0 fp-8=0000????
3: (63) *(u32 *)(r10 -8) = r7         ; R7_w=0 R10=fp0 fp-8=00000
4: <invalid CO-RE relocation>
failed to resolve CO-RE relocation <byte_off> [17] struct data.a (0:0 @ offset 0)
processed 5 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --
libbpf: prog 'add_test': failed to load: -22
libbpf: failed to load object 'uprobe_bpf'
libbpf: failed to load BPF skeleton 'uprobe_bpf': -22
Failed to load and verify BPF skeleton
```

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

我们的 eBPF 追踪程序也几乎不需要进行任何修改，只需要把包含 kernel 和用户态结构体偏移量的 BTF 加载进来即可。这和旧版本内核上没有 btf 信息的使用方式是一样的:

```c
	LIBBPF_OPTS(bpf_object_open_opts , opts,
	);
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	if (argc != 3 && argc != 2) {
		fprintf(stderr, "Usage: %s <example-name> [<external-btf>]\n", argv[0]);
		return 1;
	}
	if (argc == 3)
		opts.btf_custom_path = argv[2];

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = uprobe_bpf__open_opts(&opts);
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
```

实际上，btf 实现重定向需要两个部分，一个是 bpf 程序带的编译时的 btf 信息，一个是内核的 btf 信息。在实际加载 ebpf 程序的时候，libbpf 会根据当前内核上准确的 btf 信息，来修改可能存在错误的 ebpf 指令，确保在不同内核版本上能够兼容。

有趣的是，实际上 libbpf 并不区分这些 btf 信息来自用户态程序还是内核，因此我们只要把用户态的重定向信息一起提供给 libbpf 进行重定向，问题就解决了。

本文的工具和完整的代码在 <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/38-btf-uprobe> 开源。

## 结论

- **灵活性和兼容性**：在用户空间eBPF程序中使用 BTF 大大增强了它们在不同版本的用户空间应用程序和库之间的灵活性和兼容性。
- **简化了复杂性**：这种方法显著减少了维护不同版本的用户空间应用程序的eBPF程序的复杂性，因为它消除了需要多个程序版本的需要。
- **更广泛的应用**：这种方法在性能监控、安全和用户空间应用程序的调试等方面也可能能有更广泛的应用。bpftime（https://github.com/eunomia-bpf/bpftime） 是一个开源的基于 LLVM JIT/AOT 的用户态 eBPF 运行时，它可以在用户态运行 eBPF 程序，和内核态的 eBPF 兼容。它在支持 uprobe、syscall trace 和一般的插件扩展的同时，避免了内核态和用户态之间的上下文切换，从而提高了 uprobe 程序的执行效率。借助 libbpf 和 btf 的支持，bpftime 也可以更加动态的扩展用户态应用程序，实现在不同用户态程序版本之间的兼容性。

这个示例展示了 eBPF 在实践中可以将其强大的 CO-RE 功能扩展到更动态地处理用户空间应用的不同版本变化。

如果你想了解更多关于eBPF知识和实践，你可以访问我们的教程代码库<https://github.com/eunomia-bpf/bpf-developer-tutorial>或者网站<https://eunomia.dev/tutorials/>获得更多示例和完整教程。
