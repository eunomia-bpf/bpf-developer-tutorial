# 将 eBPF 的边界拓展：内核模块中的自定义 kfuncs

你是否曾感到 eBPF 的功能受限？也许你遇到过现有的 eBPF 功能无法完成你的目标的情况。可能你需要与内核进行更深入的交互，或者面临标准 eBPF 运行时无法解决的性能问题。如果你曾希望在 eBPF 程序中拥有更多的灵活性和强大功能，本教程将为你提供帮助。

## 引言：通过 kfuncs 打破 eBPF 运行时的限制

**eBPF（扩展伯克利数据包过滤器）** 通过允许开发者在内核中运行受限的程序，彻底改变了 Linux 系统编程。它在网络、安全和可观察性方面带来了革命性的变化，使得无需修改内核源代码或加载传统的内核模块即可实现强大的功能。

然而，尽管 eBPF 非常强大，它也有其局限性：

- **功能差距：** 有时，eBPF 运行时现有的功能无法提供你所需的特定能力。
- **复杂需求：** 某些任务需要更复杂的内核交互，而 eBPF 无法开箱即用地处理这些需求。
- **性能问题：** 在某些情况下，eBPF 运行时的开销会引入延迟，或者在高性能需求下效率不够。

这些挑战源于 **整个 eBPF 运行时** 的限制，而不仅仅是其辅助函数。那么，如何在不更改内核本身的情况下克服这些障碍呢？

引入 **kfuncs（BPF 内核函数）**。通过在内核模块中定义你自己的 kfuncs，你可以将 eBPF 的功能扩展到其默认限制之外。这种方法让你能够：

- **增强功能：** 引入标准 eBPF 运行时中不可用的新操作。
- **自定义行为：** 根据你的具体需求调整内核交互。
- **提升性能：** 通过在内核上下文中直接执行自定义代码来优化关键路径。

最重要的是，你无需修改核心内核，从而保持系统稳定性和代码安全性。

在本教程中，我们将向你展示如何定义自定义 kfuncs，以填补 eBPF 功能中的任何空白。我们将逐步创建一个引入新 kfuncs 的内核模块，并演示如何在你的 eBPF 程序中使用它们。无论你是希望克服性能瓶颈，还是需要 eBPF 运行时未提供的功能，自定义 kfuncs 都能为你的项目解锁新的可能性。

## 理解 kfuncs：将 eBPF 拓展到辅助函数之外

### 什么是 kfuncs？

**BPF 内核函数（kfuncs）** 是 Linux 内核中的专用函数，供 eBPF 程序使用。与标准 eBPF 辅助函数不同，kfuncs 没有稳定的接口，且可能在内核版本之间有所不同。这种可变性意味着使用 kfuncs 的 BPF 程序需要与内核更新同步更新，以保持兼容性和稳定性。

### 为什么使用 kfuncs？

1. **扩展功能：** kfuncs 允许执行标准 eBPF 辅助函数无法完成的操作。
2. **自定义：** 定义针对特定用例的逻辑，增强 eBPF 程序的灵活性。
3. **安全性和稳定性：** 通过将 kfuncs 封装在内核模块中，避免对核心内核的直接修改，保持系统完整性。

### kfuncs 在 eBPF 中的作用

kfuncs 作为 eBPF 程序与更深层内核功能之间的桥梁。它们允许 eBPF 程序执行更复杂的操作，方法是暴露现有内核函数或引入专门为 eBPF 交互设计的新封装。这种集成促进了更深入的内核交互，同时确保 eBPF 程序保持安全和可维护。

需要注意的是，Linux 内核已经包含了大量的 kfuncs。这些内置的 kfuncs 覆盖了广泛的功能，使大多数开发者无需定义新的 kfuncs 就能完成任务。然而，在现有 kfuncs 无法满足特定需求的情况下，定义自定义 kfuncs 就变得必要。本教程将演示如何定义新的 kfuncs 以填补任何空白，确保你的 eBPF 程序能够利用你所需的确切功能。eBPF 还可以扩展到用户空间。在用户空间 eBPF 运行时 [bpftime](https://github.com/eunomia-bpf/bpftime) 中，我们还在实现 ufuncs，它们类似于 kfuncs，但用于扩展用户空间应用程序。

## kfuncs 的概述及其演变

要理解 kfuncs 的重要性，必须了解它们与 eBPF 辅助函数之间的演变关系。

![累计的 Helper 和 kfunc 时间线](https://raw.githubusercontent.com/eunomia-bpf/code-survey/main/imgs/cumulative_helper_kfunc_timeline.png)

**关键要点：**

- **辅助函数的稳定性：** eBPF 辅助函数基本保持稳定，新增内容较少。
- **kfuncs 的快速增长：** kfuncs 的采用和创建显著增加，表明社区对通过 kfuncs 扩展内核交互的兴趣。
- **向更深层内核集成的转变：** 自 2023 年以来，新用例主要利用 kfuncs 影响内核行为，标志着通过 eBPF 进行更深层内核集成的趋势。

这一趋势凸显了社区通过 kfuncs 更深入地与内核集成，推动 eBPF 能力的边界的动力。

## 定义你自己的 kfunc：逐步指南

要利用 kfuncs 的强大功能，你需要在内核模块中定义它们。此过程确保你的自定义函数能够安全地暴露给 eBPF 程序，而无需更改核心内核。

### 编写内核模块

让我们从创建一个定义 kfunc 的简单内核模块开始。这个 kfunc 将执行一个基本的算术操作，作为理解机制的基础。

#### **文件：`hello.c`**

```c
#include <linux/init.h>    // 模块初始化的宏
#include <linux/module.h>  // 加载模块的核心头文件
#include <linux/kernel.h>  // 内核日志宏
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

// 声明 kfunc
__bpf_kfunc u64 bpf_kfunc_call_test(u32 a, u64 b, u32 c, u64 d);

/* 定义 kfunc 函数 */
__bpf_kfunc_start_defs();

__bpf_kfunc u64 bpf_kfunc_call_test(u32 a, u64 b, u32 c, u64 d)
{
    return a + b + c + d;
}

__bpf_kfunc_end_defs();

// 定义 BTF kfunc ID 集合
BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_kfunc_call_test)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

// 注册 kfunc ID 集合
static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

// 模块初始化
static int __init hello_init(void)
{
    int ret;

    printk(KERN_INFO "Hello, world!\n");
    // 注册 BTF kfunc ID 集合
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    if (ret) {
        pr_err("bpf_kfunc_example: 注册 BTF kfunc ID 集合失败\n");
        return ret;
    }
    printk(KERN_INFO "bpf_kfunc_example: 模块加载成功\n");
    return 0;  // 成功
}

// 模块清理
static void __exit hello_exit(void)
{
    // 注销 BTF kfunc ID 集合（根据内核版本可选）
    // unregister_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    printk(KERN_INFO "Goodbye, world!\n");
}

// 定义模块的入口和出口
module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");                 // 许可类型
MODULE_AUTHOR("Your Name");            // 模块作者
MODULE_DESCRIPTION("一个简单的模块");    // 模块描述
MODULE_VERSION("1.0");                 // 模块版本
```

**代码解释：**

- **声明 kfunc：** `__bpf_kfunc` 宏声明了一个 eBPF 程序可以调用的函数。在这里，`bpf_kfunc_call_test` 接受四个参数（`a`、`b`、`c`、`d`），并返回它们的和。
  
- **BTF 定义：** `__bpf_kfunc_start_defs` 和 `__bpf_kfunc_end_defs` 宏标志着 kfunc 定义的开始和结束。`BTF_KFUNCS_START` 及相关宏有助于将 kfuncs 注册到 BPF 类型格式（BTF）中。
  
- **模块初始化：** `hello_init` 函数注册 kfunc ID 集合，使 `bpf_kfunc_call_test` 对 `BPF_PROG_TYPE_KPROBE` 类型的 eBPF 程序可用。
  
- **模块清理：** `hello_exit` 函数确保在模块移除时注销 kfunc ID 集合，保持系统的清洁。

#### **文件：`Makefile`**

```makefile
obj-m += hello.o  # hello.o 是目标

# 启用 BTF 生成
KBUILD_CFLAGS += -g -O2

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

**Makefile 解释：**

- **目标定义：** `obj-m += hello.o` 指定 `hello.o` 是要构建的模块。
  
- **BTF 生成标志：** `KBUILD_CFLAGS += -g -O2` 启用调试信息和优化，以促进 BTF 生成。
  
- **构建命令：**
  - **`all`：** 通过调用内核构建系统编译内核模块。
  - **`clean`：** 清理构建产物。

**注意：** 提供的代码已在 **Linux 内核版本 6.11** 上进行了测试。如果你使用的是较早的版本，可能需要实现一些变通方法，例如引用 `compact.h`。

### 编译内核模块

有了内核模块的源代码和 Makefile 后，按照以下步骤编译模块：

1. **导航到模块目录：**

    ```bash
    cd /path/to/bpf-developer-tutorial/src/43-kfuncs/module/
    ```

2. **编译模块：**

    ```bash
    make
    ```

    该命令将生成一个名为 `hello.ko` 的文件，即编译后的内核模块。

### 加载内核模块

要将编译好的模块插入内核，使用 `insmod` 命令：

```bash
sudo insmod hello.ko
```

### 验证模块加载

加载模块后，通过检查内核日志来验证是否成功插入：

```bash
dmesg | tail
```

**预期输出：**

```txt
[ 1234.5678] Hello, world!
[ 1234.5679] bpf_kfunc_example: 模块加载成功
```

### 移除内核模块

当不再需要该模块时，使用 `rmmod` 命令卸载它：

```bash
sudo rmmod hello
```

**验证移除：**

```bash
dmesg | tail
```

**预期输出：**

```txt
[ 1234.9876] Goodbye, world!
```

## 处理编译错误

在编译过程中，你可能会遇到以下错误：

```txt
Skipping BTF generation for /root/bpf-developer-tutorial/src/43-kfuncs/module/hello.ko due to unavailability of vmlinux
```

**解决方案：**

1. **安装 `dwarves` 包：**

    `dwarves` 包提供了 BTF 生成所需的工具。

    ```sh
    sudo apt install dwarves
    ```

2. **复制 `vmlinux` 文件：**

    确保包含 BTF 信息的 `vmlinux` 文件在构建目录中可用。

    ```sh
    sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/$(uname -r)/build/
    ```

    该命令将 `vmlinux` 文件复制到适当的构建目录中，确保 BTF 生成成功。

本教程的完整代码可以在 GitHub 的链接 <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/43-kfuncs> 中找到。这个代码在 Linux 内核版本 6.11 上进行了测试，其他低版本可能需要一些修改，参考 `compact.h`。

## 在 eBPF 程序中使用自定义 kfunc

有了定义自定义 kfunc 的内核模块后，下一步是创建一个利用该函数的 eBPF 程序。这种交互展示了 kfuncs 引入的增强功能。

### 编写 eBPF 程序

创建一个 eBPF 程序，该程序附加到 `do_unlinkat` 内核函数，并使用自定义的 `bpf_kfunc_call_test` kfunc。

#### **文件：`kfunc.c`**

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int pid_t;

// 声明外部 kfunc
extern u64 bpf_kfunc_call_test(u32 a, u64 b, u32 c, u64 d) __ksym;

// 许可信息
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 附加到 do_unlinkat 内核函数
SEC("kprobe/do_unlinkat")
int handle_kprobe(void *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u64 result = bpf_kfunc_call_test(1, 2, 3, 4);
    bpf_printk("BPF 触发了 do_unlinkat，PID: %d。结果: %lld\n", pid, result);
    return 0;
}
```

**eBPF 代码解释：**

- **外部 kfunc 声明：** `extern` 关键字声明了 `bpf_kfunc_call_test` 函数，使其在 eBPF 程序中可用。
  
- **Kprobe 附加：** `SEC("kprobe/do_unlinkat")` 宏将 eBPF 程序附加到 `do_unlinkat` 内核函数。每当调用 `do_unlinkat` 时，`handle_kprobe` 函数就会执行。
  
- **使用 kfunc：** 在 `handle_kprobe` 中，eBPF 程序调用 `bpf_kfunc_call_test`，传入四个参数（`1, 2, 3, 4`）。结果，即这些数字的和，通过 `bpf_printk` 打印出来，显示 PID 和结果。

### 编译 eBPF 程序

要编译 eBPF 程序，确保你已安装必要的工具，如 `clang` 和 `llvm`。以下是编译程序的方法：

1. **导航到 eBPF 程序目录：**

    ```bash
    cd /path/to/bpf-developer-tutorial/src/43-kfuncs/
    ```

2. **编译 eBPF 程序：**

    ```bash
    make
    ```

### 运行 eBPF 程序

假设你有一个用户空间应用程序或工具来加载和附加 eBPF 程序，你可以执行它以观察 eBPF 程序与自定义 kfunc 之间的交互。

**示例输出：**

```bash
$ sudo ./kfunc
BPF 程序加载并成功附加。按 Ctrl-C 退出。
            node-9523    [004] ...21  7520.587718: bpf_trace_printk: BPF 触发了 do_unlinkat，PID: 9523。结果: 10

        cpptools-11242   [003] ...21  7859.613060: bpf_trace_printk: BPF 触发了 do_unlinkat，PID: 11235。结果: 10

^C
cpptools-11242   [002] ...21  7865.831074: bpf_trace_printk: BPF 触发了 do_unlinkat，PID: 11235。结果: 10
```

**输出解释：**

每当内核中调用 `do_unlinkat` 函数时，eBPF 程序都会打印一条消息，指示进程的 PID 和 kfunc 调用的结果。在此示例中，`1 + 2 + 3 + 4` 的和为 `10`，这在输出中得到了体现。

## 总结与结论

在本教程中，我们深入探讨了通过定义和使用自定义内核函数（kfuncs）来扩展 eBPF 功能。以下是我们涵盖的内容回顾：

- **理解 kfuncs：** 掌握了 kfuncs 的概念及其在增强 eBPF 标准辅助函数方面的作用。
- **定义 kfuncs：** 创建了一个定义自定义 kfunc 的内核模块，确保其能够安全地暴露给 eBPF 程序，而无需更改核心内核。
- **编写使用 kfuncs 的 eBPF 程序：** 开发了一个利用自定义 kfunc 执行特定操作的 eBPF 程序，展示了增强的功能。
- **编译与执行：** 提供了逐步指南，编译、加载和运行内核模块及 eBPF 程序，确保你能在自己的系统上复现设置。
- **错误处理：** 解决了潜在的编译问题，并提供了解决方案，以确保顺利的开发体验。

**关键要点：**

- **克服辅助函数的限制：** kfuncs 填补了标准 eBPF 辅助函数留下的空白，提供了针对特定需求的扩展功能。
- **维护系统稳定性：** 通过将 kfuncs 封装在内核模块中，确保在不进行侵入性内核更改的情况下保持系统稳定性。
- **社区驱动的演变：** kfuncs 的快速增长和采用凸显了 eBPF 社区致力于通过内核级编程推动 eBPF 潜力的决心。
- **利用现有 kfuncs：** 在定义新的 kfuncs 之前，探索内核提供的现有 kfuncs。它们涵盖了广泛的功能，除非绝对必要，否则无需创建自定义函数。

**准备好进一步提升你的 eBPF 技能了吗？** [访问我们的教程仓库](https://github.com/eunomia-bpf/bpf-developer-tutorial)并[探索我们网站上的更多教程](https://eunomia.dev/tutorials/)。深入了解大量示例，深化你的理解，并为动态发展的 eBPF 世界做出贡献！

祝你 eBPF 编程愉快！

## 参考资料

- [BPF 内核函数文档](https://docs.kernel.org/bpf/kfuncs.html)
- [eBPF kfuncs 指南](https://docs.ebpf.io/linux/kfuncs/)

## 额外资源

如果你想了解更多关于 eBPF 的知识和实践，可以访问我们的开源教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或者我们的网站 <https://eunomia.dev/tutorials/>，获取更多示例和完整代码。

## 结论

通过遵循本详尽的教程，你已经掌握了使用自定义 kfuncs 扩展 eBPF 功能的知识。无论你是旨在执行高级内核交互、克服辅助函数的限制，还是增强你的可观察性工具，kfuncs 都提供了你所需的灵活性和强大功能。继续尝试，保持好奇，并为不断发展的 eBPF 领域做出贡献！
