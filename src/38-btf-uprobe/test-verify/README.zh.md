# 使用 BTF 验证用户态 eBPF 扩展

这里我们将展示如何利用用户态应用程序的类型信息，来验证将要访问用户态内存的 eBPF 程序（包括有效或无效的数据结构内存访问、指针访问等），以及如何验证 eBPF 程序在 bpftime 中所访问的伪 ufunc（用户态函数）的资源分配与释放。

这里复用内核 eBPF 验证器来验证用户态 eBPF 扩展；用户态 eBPF 扩展可以是 uprobe 或其他 eBPF 程序，既可以运行在内核空间，也可以运行在 bpftime 中。

## 用法

想要在用户态应用程序上使用 eBPF 程序的应用开发者或扩展使用者需要提供：

1. 用户态应用程序的 BTF 信息。它可以由编译器生成，或从 DWARF 信息获得。
2. 如果 eBPF 程序会访问用户态应用程序的资源分配与释放函数，还需要提供伪 ufunc 信息。

通过复用内核验证器，我们可以提供：

1. CO-RE 重定位：当用户态应用程序存在不同版本、结构体/函数类型发生变化时。
2. 用户态扩展的类型检查与变量访问检查。
3. 内存访问检查，因此无需复制数据。
4. 资源分配与释放函数的访问检查。

## BTF 格式

BTF 是一种包含类型信息的二进制格式。

基础程序位于教程源码树的 [src/38-btf-uprobe/examples](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/38-btf-uprobe/examples) 目录下。它们表示宿主用户态应用程序的不同版本，包括：

- `btf-base`：`btf-base-complete` 的基础版本，其 `struct data` 的类型信息与 [verify-failed-no-btf/uprobe.bpf.c](verify-failed-no-btf/uprobe.bpf.c) 中相同。
- `btf-base-new`：`btf-base` 的新版本，其中 `struct data` 的类型信息与 `btf-base` 以及 [verify-failed-no-btf/uprobe_failed.bpf.c](verify-failed-no-btf/uprobe_failed.bpf.c) 中的不同。我们可以用它来测试 CO-RE 重定位。
- `btf-base-complete`：`btf-base` 的完整版本，包含 eBPF 程序用到的所有类型，以及一个资源分配与释放函数。

在本目录运行 `make -C ../` 生成 BTF 文件。

## 验证结构体数据访问

用户态应用程序拥有类似下面的数据结构

版本 1：

```c
struct data {
    int a;
    int c;
    int d;
};
```

或者

版本 2：

```c
struct data {
    int a;
    int b;
    int c;
    int d;
};
```


### 1.1 不提供用户态应用 BTF 时验证失败

eBPF 程序如下

```c
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
```

如果没有提供用户态应用程序的 BTF，验证将会失败。

```console
$ sudo ./verify-failed-no-btf/uprobe ../examples/btf-base 

libbpf: prog 'add_test': -- BEGIN PROG LOAD LOG --
0: R1=ctx() R10=fp0
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

### 1.2 使用 BTF 验证结构体访问与重定位成功

更多细节参见 [../README.md](../README.md)。

```console
$ sudo ./verify-failed-no-btf/uprobe ../examples/btf-base ../target-base.btf

libbpf: prog 'add_test': relo #0: <byte_off> [2] struct pt_regs.di (0:14 @ offset 112)
libbpf: prog 'add_test': relo #0: matching candidate #0 <byte_off> [88] struct pt_regs.di (0:14 @ offset 112)
libbpf: prog 'add_test': relo #0: patched insn #0 (LDX/ST/STX) off 112 -> 112
libbpf: CO-RE relocating [17] struct data: found target candidate [143229] struct data in [vmlinux]
libbpf: prog 'add_test': relo #1: <byte_off> [17] struct data.a (0:0 @ offset 0)
libbpf: prog 'add_test': relo #1: matching candidate #0 <byte_off> [143229] struct data.a (0:0 @ offset 0)
libbpf: prog 'add_test': relo #1: patched insn #4 (ALU/ALU64) imm 0 -> 0
libbpf: prog 'add_test': relo #2: <byte_off> [17] struct data.c (0:1 @ offset 4)
libbpf: prog 'add_test': relo #2: matching candidate #0 <byte_off> [143229] struct data.c (0:1 @ offset 4)
libbpf: prog 'add_test': relo #2: patched insn #11 (ALU/ALU64) imm 4 -> 4
libbpf: map '.rodata.str1.1': created successfully, fd=3
libbpf: elf: symbol address match for 'add_test' in '../examples/btf-base': 0x1140
Successfully started! Press Ctrl+C to stop.
```

它可以在 BTF 文件中成功找到 `struct data` 的类型信息并通过验证。

### 1.3 访问无效用户态结构体变量时验证失败

eBPF 程序为：

```c
struct data {
    int a;
    int e;
    int d;
};

SEC("uprobe/examples/btf-base:add_test")
int BPF_UPROBE(add_test, struct data *d)
{
	int a = 0, e = 0;
	bpf_probe_read_user(&a, sizeof(a), &d->a);
	bpf_probe_read_user(&e, sizeof(e), &d->e);
	bpf_printk("add_test(&d) %d + %d = %d\n", a, e,  a + e);
	return a + e;
}
```

如果扩展（BPF 程序）访问了无效的用户态结构体变量，验证将会失败。

## 验证内存指针访问

完整示例参见教程源码树中的 `verify-memory-access/` 目录。

数据结构如下：

```c
struct deep_memory_block {
    int a;
    char b[10];
};

struct inner_memory_block {
    int a;
    char b[10];
    struct deep_memory_block *deep;
};

struct data {
        int a;
        int b;
        int c;
        int d;
        // represent a pointer to a memory block
        struct inner_memory_block *inner;
};
```

这里包含通过指针进行的深层内存访问。

### 内层数据结构无需深拷贝即可内存访问成功

eBPF 程序为：

```c
SEC("uprobe/examples/btf-base:add_test")
int BPF_UPROBE(add_test, struct data *d)
{
	int inner_deep_a = BPF_CORE_READ_USER(d, inner, deep, a);
	bpf_printk("inner_deep_a = %d\n", inner_deep_a);
	char* inner_deep_b = BPF_CORE_READ_USER(d, inner, deep, b);
	bpf_printk("inner_deep_b[9] = %c\n", inner_deep_b[9]);
	return 0;
}
```

运行：

```sh
$ sudo ./verify-memory-access/uprobe ../examples/btf-base-complete ../target-base-complete.btf 

libbpf: sec 'uprobe/examples/btf-base:add_test': found 7 CO-RE relocations
libbpf: CO-RE relocating [2] struct pt_regs: found target candidate [88] struct pt_regs in [vmlinux]
libbpf: prog 'add_test': relo #0: <byte_off> [2] struct pt_regs.di (0:14 @ offset 112)
libbpf: prog 'add_test': relo #0: matching candidate #0 <byte_off> [88] struct pt_regs.di (0:14 @ offset 112)
libbpf: prog 'add_test': relo #0: patched insn #0 (LDX/ST/STX) off 112 -> 112
libbpf: CO-RE relocating [17] struct data: found target candidate [143228] struct data in [vmlinux]
libbpf: prog 'add_test': relo #1: <byte_off> [17] struct data.a (0:0 @ offset 0)
libbpf: prog 'add_test': relo #1: matching candidate #0 <byte_off> [143228] struct data.a (0:0 @ offset 0)
libbpf: prog 'add_test': relo #1: patched insn #4 (ALU/ALU64) imm 0 -> 0
libbpf: prog 'add_test': relo #2: <byte_off> [17] struct data.c (0:2 @ offset 8)
libbpf: prog 'add_test': relo #2: matching candidate #0 <byte_off> [143228] struct data.c (0:2 @ offset 8)
libbpf: prog 'add_test': relo #2: patched insn #11 (ALU/ALU64) imm 8 -> 8
libbpf: prog 'add_test': relo #3: <byte_off> [17] struct data.inner (0:4 @ offset 16)
libbpf: prog 'add_test': relo #3: matching candidate #0 <byte_off> [143228] struct data.inner (0:4 @ offset 16)
libbpf: prog 'add_test': relo #3: patched insn #38 (ALU/ALU64) imm 16 -> 16
libbpf: CO-RE relocating [19] struct inner_memory_block: found target candidate [143231] struct inner_memory_block in [vmlinux]
libbpf: prog 'add_test': relo #4: <byte_off> [19] struct inner_memory_block.deep (0:2 @ offset 16)
libbpf: prog 'add_test': relo #4: matching candidate #0 <byte_off> [143231] struct inner_memory_block.deep (0:2 @ offset 16)
libbpf: prog 'add_test': relo #4: patched insn #46 (ALU/ALU64) imm 16 -> 16
libbpf: CO-RE relocating [24] struct deep_memory_block: found target candidate [143234] struct deep_memory_block in [vmlinux]
libbpf: prog 'add_test': relo #5: <byte_off> [24] struct deep_memory_block.a (0:0 @ offset 0)
libbpf: prog 'add_test': relo #5: matching candidate #0 <byte_off> [143234] struct deep_memory_block.a (0:0 @ offset 0)
libbpf: prog 'add_test': relo #5: patched insn #52 (ALU/ALU64) imm 0 -> 0
libbpf: prog 'add_test': relo #6: <byte_off> [24] struct deep_memory_block.b (0:1 @ offset 4)
libbpf: prog 'add_test': relo #6: matching candidate #0 <byte_off> [143234] struct deep_memory_block.b (0:1 @ offset 4)
libbpf: prog 'add_test': relo #6: patched insn #84 (ALU/ALU64) imm 4 -> 4
libbpf: map '.rodata.str1.1': created successfully, fd=3
libbpf: elf: symbol address match for 'add_test' in '../examples/btf-base-complete': 0x1160
Successfully started! Press Ctrl+C to stop.
```

### 内层数据结构因越界访问导致内存访问失败

如果修改 eBPF 程序使其访问越界内存，验证将会失败。

```c
SEC("uprobe/examples/btf-base:add_test")
int BPF_UPROBE(add_test, struct data *d)
{
	int inner_deep_a = BPF_CORE_READ_USER(d, inner, deep, a);
	bpf_printk("inner_deep_a = %d\n", inner_deep_a);
	char* inner_deep_b = BPF_CORE_READ_USER(d, inner, deep, b);
	// memory access out of bounds
	bpf_printk("inner_deep_b[11] = %c\n", inner_deep_b[100]);
	return 0;
}
```

测试：

```c
$ sudo ./verify-memory-access/uprobe_failed ../examples/btf-base-complete ../target-base-complete.btf 
...
; bpf_printk("inner_deep_b[11] = %c\n", inner_deep_b[100]); @ uprobe_failed.bpf.c:44
57: (6b) *(u16 *)(r10 -12) = r1       ; R1_w=2659 R10=fp0 fp-16=??mm?mmm
58: (b7) r1 = 622869792               ; R1_w=0x25203d20
59: (63) *(u32 *)(r10 -16) = r1       ; R1_w=0x25203d20 R10=fp0 fp-16=??mm0x25203d20
60: (18) r1 = 0x5d31315b625f7065      ; R1_w=0x5d31315b625f7065
62: (7b) *(u64 *)(r10 -24) = r1       ; R1_w=0x5d31315b625f7065 R10=fp0 fp-24_w=0x5d31315b625f7065
63: (7b) *(u64 *)(r10 -32) = r8       ; R8=0x65645f72656e6e69 R10=fp0 fp-32_w=0x65645f72656e6e69
64: (73) *(u8 *)(r10 -10) = r9        ; R9=0 R10=fp0 fp-16=?0mmmmmm
65: (71) r3 = *(u8 *)(r10 +68)
invalid read from stack R10 off=68 size=1
processed 63 insns (limit 1000000) max_states_per_insn 0 total_states 3 peak_states 3 mark_read 2
-- END PROG LOAD LOG --
libbpf: prog 'add_test': failed to load: -13
libbpf: failed to load object 'uprobe_failed_bpf'
libbpf: failed to load BPF skeleton 'uprobe_failed_bpf': -13
Failed to load and verify BPF skeleton
```

## 使用伪 ufunc 验证资源分配与释放

完整示例参见教程源码树中的 `verify-resource-allocation/` 目录。

首先，通过内核模块把伪 ufunc 信息提供给内核：

```sh
cd module
make
sudo insmod hello.ko
```

检查内核输出：

```sh
$ sudo dmesg | tail
[83824.574456] Hello, world!
[83824.574952] bpf_kfunc_example: Module loaded successfully
```

伪 ufunc 信息类似：

```c
__bpf_kfunc struct data *my_alloc_data(void)
{
    // here we only use it for verification
    return NULL;
}

__bpf_kfunc void my_free_data(struct data *d)
{
    // here we only use it for verification
    return;
}
/*Auto generated code end*/

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, my_alloc_data, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, my_free_data, KF_RELEASE)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)
```

注意：在前面的方法中，我们只用用户态程序的 BTF 信息来验证 eBPF 程序，因此不需要额外的内核模块。而在这种情况下，内核可能会尝试把伪 kfunc 链接到 eBPF 程序上；如果模块中没有对应的实现，验证将会失败。

并且这只能在用户态运行，因为在内核中运行是没有意义的（"ufunc" 只是一个占位 kfunc，在内核中没有实现）。

### 使用伪 ufunc 信息验证资源分配与释放成功

eBPF 程序类似：

```c
SEC("uprobe/examples/btf-base:add_test")
int BPF_UPROBE(add_test, struct data *d)
{
	struct data *alloced = my_alloc_data();
    if (alloced == NULL) {
        bpf_printk("Failed to allocate data\n");
        return 0;
    }
	my_free_data(alloced);
	return 0;
}
```

然后就可以成功运行：

```console
$ sudo ./verify-resource-allocation/uprobe ../examples/btf-base-complete ../target-base-complete.btf 

libbpf: loaded kernel BTF from '/sys/kernel/btf/vmlinux'
libbpf: extern (func ksym) 'my_alloc_data': resolved to hello [143233]
libbpf: extern (func ksym) 'my_free_data': resolved to hello [143235]
libbpf: map '.rodata.str1.1': created successfully, fd=3
libbpf: elf: symbol address match for 'add_test' in '../examples/btf-base-complete': 0x1160
Successfully started! Press Ctrl+C to stop.
```

### 资源分配与释放验证失败

如果不释放用户态应用程序分配的资源，验证将会失败。

代码：

```c
SEC("uprobe/examples/btf-base:add_test")
int BPF_UPROBE(add_test, struct data *d)
{
	struct data *alloced = my_alloc_data();
    if (alloced == NULL) {
        bpf_printk("Failed to allocate data\n");
        return 0;
    }
	return 0;
}
```

运行：

```console
$ sudo ./verify-resource-allocation/uprobe_failed ../examples/btf-base-complete ../target-base-complete.btf 

0: R1=ctx() R10=fp0
; struct data *alloced = my_alloc_data(); @ uprobe_failed.bpf.c:43
0: (85) call my_alloc_data#143233     ; R0_w=ptr_or_null_data(id=2,ref_obj_id=2) refs=2
; if (alloced == NULL) { @ uprobe_failed.bpf.c:44
1: (55) if r0 != 0x0 goto pc+15 17: R0_w=ptr_data(ref_obj_id=2) R10=fp0 refs=2
17: (b7) r0 = 0                       ; R0_w=0 refs=2
18: (95) exit
Unreleased reference id=2 alloc_insn=0
processed 18 insns (limit 1000000) max_states_per_insn 1 total_states 1 peak_states 1 mark_read 0
-- END PROG LOAD LOG --
libbpf: prog 'add_test': failed to load: -22
libbpf: failed to load object 'uprobe_failed_bpf'
libbpf: failed to load BPF skeleton 'uprobe_failed_bpf': -22
Failed to load and verify BPF skeleton
```

或者，如果没有检查 `my_alloc_data` 的返回值，验证同样会失败，例如：

```c
SEC("uprobe/examples/btf-base:add_test")
int BPF_UPROBE(add_test, struct data *d)
{
	struct data *alloced = my_alloc_data();

	my_free_data(alloced);
	return 0;
}
```

运行：

```console
$ sudo ./verify-resource-allocation/uprobe ../examples/btf-base-complete ../target-base-complete.btf 

libbpf: loaded kernel BTF from '/sys/kernel/btf/vmlinux'
libbpf: extern (func ksym) 'my_alloc_data': resolved to hello [143233]
libbpf: extern (func ksym) 'my_free_data': resolved to hello [143235]
libbpf: prog 'add_test': BPF program load failed: Permission denied
libbpf: prog 'add_test': -- BEGIN PROG LOAD LOG --
0: R1=ctx() R10=fp0
; struct data *alloced = my_alloc_data(); @ uprobe.bpf.c:43
0: (85) call my_alloc_data#143233     ; R0_w=ptr_or_null_data(id=2,ref_obj_id=2) refs=2
; my_free_data(alloced); @ uprobe.bpf.c:45
1: (bf) r1 = r0                       ; R0_w=ptr_or_null_data(id=2,ref_obj_id=2) R1_w=ptr_or_null_data(id=2,ref_obj_id=2) refs=2
2: (85) call my_free_data#143235
Possibly NULL pointer passed to trusted arg0
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --
libbpf: prog 'add_test': failed to load: -13
libbpf: failed to load object 'uprobe_bpf'
libbpf: failed to load BPF skeleton 'uprobe_bpf': -13
Failed to load and verify BPF skeleton
```

### 在用户态运行 ufunc

由于在内核中运行 ufunc 没有意义，所以只能在用户态运行它。

加载带 ufunc 的 eBPF 程序：

```sh
LD_PRELOAD=/home/yunwei37/.bpftime/libbpftime-syscall-server.so ./verify-resource-allocation/uprobe ../examples/btf-base-complete ../target-base-complete.btf 
```

然后运行用户态程序：

```console
# LD_PRELOAD=/home/yunwei37/.bpftime/libbpftime-agent.so ../examples/btf-base-complete

my_alloc_data
my_free_data
```
