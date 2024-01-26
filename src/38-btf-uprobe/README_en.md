# Expanding eBPF Compile Once, Run Everywhere(CO-RE) to Userspace Compatibility 

> Yusheng 

eBPF, short for extended Berkeley Packet Filter, is a powerful and versatile technology used in modern Linux systems. It allows for the running of sandboxed programs in a virtual machine-like environment within the kernel, providing a safe way to extend the capabilities of the kernel without the risk of crashing the system or compromising security.

Co-RE, standing for 'Compile Once, Run Everywhere', tackles the critical issue of eBPF program compatibility across diverse kernel versions. This feature allows eBPF programs to run on various kernel versions without the need for recompilation, simplifying deployment and maintenance.

With eBPF Uprobe, you can also trace userspace applications and access their internal data structures. However, the  CO-RE is not designed for userspace applications. This blog will introduce how to leverage CO-RE for user-space applications, ensuring eBPF Uprobe programs remain compatible across different application versions without the need for multiple compilations. 

This approach may be particularly beneficial for tracing applications like OpenSSL, where maintaining separate eBPF programs for each version is impractical. With userspace eBPF runtimes like bpftime, you can also expand the CO-RE to more usecases, including extensions, networking, and dynamic patching, providing versatile and efficient solutions.

To implement the Co-RE feature of eBPF in user-space applications, we also need to utilize the BPF Type Format (BTF) to overcome some of the limitations of traditional eBPF programs. The key to this approach lies in providing user-space programs with similar type information and compatibility support as the kernel, thereby enabling eBPF programs to more flexibly handle different versions of user-space applications and libraries.

This article is part of the eBPF Developer Tutorial, and for more detailed content, you can visit [https://eunomia.dev/tutorials/](https://eunomia.dev/tutorials/). The source code is available on the [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/38-btf-uprobe).

## Why we need CO-RE?

- **Kernel Dependencies**: Traditional eBPF programs are tightly coupled with the specific Linux kernel version they are compiled for. This is because they rely on specific internal data structures and kernel APIs which can change between kernel versions.
- **Portability Issues**: If you wanted to run an eBPF program on different Linux systems with different kernel versions, you'd traditionally have to recompile the eBPF program for each kernel version, which is a cumbersome and inefficient process.

### The Co-RE Solution

- **Abstracting Kernel Dependencies**: Co-RE enables eBPF programs to be more portable by abstracting away specific kernel dependencies. This is achieved through the use of BPF Type Format (BTF) and relocations.
- **BPF Type Format (BTF)**: BTF provides rich type information about data structures and functions in the kernel. This metadata allows eBPF programs to understand the layout of kernel structures at runtime.
- **Relocations**: eBPF programs compiled with Co-RE support contain relocations that are resolved at load time. These relocations adjust the program's references to kernel data structures and functions according to the actual layout and addresses in the running kernel.

### Advantages of Co-RE

1. **Write Once, Run Anywhere**: eBPF programs compiled with Co-RE can run on different kernel versions without the need for recompilation. This greatly simplifies the deployment and maintenance of eBPF programs in diverse environments.
2. **Safety and Stability**: Co-RE maintains the safety guarantees of eBPF, ensuring that programs do not crash the kernel and adhere to security constraints.
3. **Ease of Development**: Developers don't need to worry about the specifics of each kernel version, which simplifies the development of eBPF programs.

## Problem: userspace application CO-RE

The eBPF also supports tracing userspace applications. Uprobe is a user-space probe that allows dynamic instrumentation in user-space programs. The probe locations include function entry, specific offsets, and function returns.

The BTF is designed for the kernel and generated from vmlinux, it can help the eBPF program to be easily compatible with different kernel versions.

The userspace application, however, also need CO-RE. For example, the SSL/TLS uprobe is widely used to capture the plaintext data from the encrypted traffic. It is implemented with the userspace library, such as OpenSSL, GnuTLS, NSS, etc. The userspace application and libraries also has different versions, it would be complex if we need to compile and maintain the eBPF program for each version.

Let's see what will happen if CO-RE is not enabled for userspace applications, and how the BTF from userspace applications can solve this.

## No BTF for userspace program

This is a simple uprobe example, it can capture the function call and arguments of the `add_test` function in the userspace program. You can add `#define BPF_NO_PRESERVE_ACCESS_INDEX` in the `uprobe.bpf.c` to make sure the eBPF program can be compiled without BTF for `struct data`.


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

Then, we have two different versions of the userspace program, `examples/btf-base` and `examples/btf-base-new`. The struct `data` is different in the two versions.

`examples/btf-base`:

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

`examples/btf-base-new`:

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

We can use pahole and clang to generate the btf for each version of userspace applications. The pahole tool can simply generate BTF from the debug info: <https://linux.die.net/man/1/pahole>

make examples and generate btf for them:

```sh
make -C example # it's like: pahole --btf_encode_detached base.btf btf-base.o
```

The we execute the eBPF program with the userspace program. for `btf-base`:

```sh
sudo ./uprobe examples/btf-base 
```

And also the userspace program:

```console
$ examples/btf-base
add_test(&d) = 4
```

We will see:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe\
           <...>-25458   [000] ...11 27694.081465: bpf_trace_printk: add_test(&d) 1 + 3 = 4
```

For `btf-base-new`:

```sh
sudo ./uprobe examples/btf-base-new
```

And also the userspace program:

```console
$ examples/btf-base-new
add_test(&d) = 4
```

But we will see:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe\
           <...>-25809   [001] ...11 27828.314224: bpf_trace_printk: add_test(&d) 1 + 2 = 3
```

The result is different, because the struct `data` is different in the two versions. The eBPF program can't be compatible with different versions of the userspace program, so we cannot get the correct information.

## Use BTF for userspace program

Comment the `#define BPF_NO_PRESERVE_ACCESS_INDEX` in the `uprobe.bpf.c` to make sure the eBPF program can be compiled with BTF for `struct data`.

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

The record of `struct data` is preserved in the eBPF program. Then, we can use the `btf-base.btf` to compile the eBPF program.

Merge user btf with kernel btf, so we have a complete btf for the kernel and userspace:

```sh
./merge-btf /sys/kernel/btf/vmlinux examples/base.btf target-base.btf
```

Then we execute the eBPF program with the userspace program. for `btf-base`:

```console
$ sudo ./uprobe examples/btf-base target-base.btf
...
libbpf: prog 'add_test': relo #1: patched insn #4 (ALU/ALU64) imm 0 -> 0
libbpf: prog 'add_test': relo #2: <byte_off> [7] struct data.c (0:1 @ offset 4)
libbpf: prog 'add_test': relo #2: matching candidate #0 <byte_off> [133110] struct data.c (0:1 @ offset 4)
libbpf: prog 'add_test': relo #2: patched insn #11 (ALU/ALU64) imm 4 -> 4
...
```

Execute the userspace program and get result:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
[sudo] password for yunwei37: 
           <...>-26740   [001] ...11 28180.156220: bpf_trace_printk: add_test(&d) 1 + 3 = 4

```

Also, we do the same for another version of the userspace program `btf-base-new`:

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

The result is correct:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
[sudo] password for yunwei37: 
           <...>-26740   [001] ...11 28180.156220: bpf_trace_printk: add_test(&d) 1 + 3 = 4
```

For complete source code, you can visit [https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/38-btf-uprobe](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/38-btf-uprobe) for more details.

The eBPF uprobe tracing program almost doesn't need any modifications. We just need to load the BTF containing the offsets of kernel and user-space structures. This is the same usage as enabling CO-RE on older kernel versions without BTF information:

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

In fact, the BTF implementation for relocation requires two parts: the compile-time BTF information carried by the BPF program, and the BTF information of the kernel when loading the eBPF program. When actually loading the eBPF program, libbpf will modify potentially incorrect eBPF instructions based on the accurate BTF information of the current kernel, ensuring compatibility across different kernel versions.

Interestingly, libbpf does not differentiate whether these BTF information come from user-space programs or the kernel. Therefore, by merging the user-space BTF information with kernel BTF and provide them to libbpf, the problem is solved.

And also, since the relocation is happened in userspace loader(like libbpf), both kernel eBPF runtime and userspace eBPF runtimes(Such as bpftime) can benefit from the CO-RE. bpftime (<https://github.com/eunomia-bpf/bpftime>) is an open-source user-space eBPF runtime based on LLVM JIT/AOT. It enables the execution of eBPF programs in user space, compatible with kernel-space eBPF. While supporting uprobes, syscall trace, and general plugin extensions, it avoids the context switching between kernel and user spaces, thereby enhancing the execution efficiency of uprobe programs. With the support of libbpf and BTF, bpftime can also dynamically extend user-space applications, achieving compatibility across different versions of user-space programs.

For more details about BTF relocation, you may refer to <https://nakryiko.com/posts/bpf-core-reference-guide/>

## Conclusion

- **Flexibility and Compatibility**: The use of BTF in user-space eBPF programs greatly enhances their flexibility and compatibility across different versions of user-space applications and libraries.
- **Reduced Complexity**: This approach significantly reduces the complexity involved in maintaining eBPF programs for different versions of user-space applications, as it eliminates the need for multiple program versions.
- **Potential for Broader Application**: While your example focused on SSL/TLS monitoring, this methodology may has broader applications in performance monitoring, security, and debugging of user-space applications.

This example showcases a significant advancement in the practical application of eBPF, extending its powerful features to more dynamically handle user-space applications in a Linux environment. It's a compelling solution for software engineers and system administrators dealing with the complexities of modern Linux systems.

If you want to learn more about eBPF knowledge and practices, you can visit our tutorial code repository <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> to get more examples and complete tutorials.
