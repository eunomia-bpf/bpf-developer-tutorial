# 超越 eBPF 的极限：在内核模块中定义自定义 kfunc

你是否曾经觉得 eBPF 的能力有限？也许你遇到了现有 eBPF 功能无法实现目标的情况。或许你需要与内核进行更深层次的交互，或者标准 eBPF 运行时无法解决的性能问题。如果你曾经希望在 eBPF 程序中拥有更多的灵活性和强大功能，那么本教程正适合你。

## 引言：添加 `strstr` kfunc 以突破 eBPF 运行时的限制

**eBPF（扩展伯克利包过滤器）** 通过允许开发者在内核中运行受沙箱限制的程序，彻底改变了 Linux 系统编程。它在网络、安全和可观测性方面具有革命性的作用，能够实现强大的功能，而无需修改内核源代码或加载传统的内核模块。

但尽管 eBPF 非常强大，它也并非没有局限性：

- **功能差距：** 有时，eBPF 运行时的现有功能无法提供你所需的特定能力。
- **复杂需求：** 某些任务需要更复杂的内核交互，而 eBPF 无法开箱即用地处理这些需求。
- **性能问题：** 在某些情况下，eBPF 运行时的开销会引入延迟，或者在高性能需求下效率不够。

这些挑战源于**整个 eBPF 运行时的限制**，而不仅仅是其辅助函数。那么，如何在不修改内核本身的情况下克服这些障碍呢？

引入**kfunc（BPF 内核函数）**。通过在内核模块中定义你自己的 kfunc，可以将 eBPF 的能力扩展到默认限制之外。这种方法让你能够：

- **增强功能：** 引入标准 eBPF 运行时中不可用的新操作。
- **定制行为：** 根据你的特定需求定制内核交互。
- **提升性能：** 通过在内核上下文中直接执行自定义代码，优化关键路径。

**在本教程中，我们将特别添加一个 `strstr` kfunc。** 由于 eBPF 的验证器限制，直接在 eBPF 中实现字符串搜索是具有挑战性的，而将其定义为 kfunc 则允许我们安全高效地绕过这些限制，执行更复杂的操作。

最棒的是，你可以在不修改核心内核的情况下实现这一目标，保持系统的稳定性和代码的安全性。

在本教程中，我们将展示如何定义自定义 kfunc 以填补 eBPF 功能的任何空白。我们将逐步讲解如何创建一个引入新 kfunc 的内核模块，并演示如何在 eBPF 程序中使用它们。无论你是希望克服性能瓶颈，还是需要 eBPF 运行时未提供的功能，自定义 kfunc 都能为你的项目解锁新的可能性。

## 理解 kfunc：扩展 eBPF 超越辅助函数

### 什么是 kfunc？

**BPF 内核函数（kfuncs）** 是 Linux 内核中的专用函数，供 eBPF 程序使用。与标准的 eBPF 辅助函数不同，kfuncs 没有稳定的接口，并且在不同的内核版本之间可能有所变化。这种可变性意味着使用 kfuncs 的 BPF 程序需要与内核更新同步更新，以保持兼容性和稳定性。

### 为什么使用 kfuncs？

1. **扩展功能：** kfuncs 允许执行标准 eBPF 辅助函数无法完成的操作。
2. **定制化：** 定义针对特定用例量身定制的逻辑，增强 eBPF 程序的灵活性。
3. **安全与稳定：** 通过将 kfuncs 封装在内核模块中，避免直接修改核心内核，保持系统完整性。

### kfuncs 在 eBPF 中的角色

kfuncs 作为 eBPF 程序与更深层次内核功能之间的桥梁。它们允许 eBPF 程序执行更复杂的操作，通过暴露现有内核函数或引入专为 eBPF 交互设计的新包装函数。这种集成在确保 eBPF 程序保持安全和可维护的同时，促进了更深入的内核交互。

需要注意的是，Linux 内核已经包含了大量的 kfuncs。这些内置的 kfuncs 覆盖了广泛的功能，大多数开发者无需定义新的 kfuncs 就能完成任务。然而，在现有 kfuncs 无法满足特定需求的情况下，定义自定义 kfuncs 就变得必要。本教程将演示如何定义新的 kfuncs 以填补任何空白，确保你的 eBPF 程序能够利用你所需的确切功能。eBPF 也可以扩展到用户空间。在用户空间 eBPF 运行时 [bpftime](https://github.com/eunomia-bpf/bpftime) 中，我们也在实现 ufuncs，它们类似于 kfuncs，但扩展了用户空间应用程序。

## kfuncs 及其演变概述

要理解 kfuncs 的重要性，必须了解它们与 eBPF 辅助函数的演变关系。

![累计辅助函数和 kfunc 时间线](https://raw.githubusercontent.com/eunomia-bpf/code-survey/main/imgs/cumulative_helper_kfunc_timeline.png)

**关键要点：**

- **辅助函数的稳定性：** eBPF 辅助函数保持了高度的稳定性，新增内容较少。
- **kfuncs 的快速增长：** kfuncs 的采用和创建显著增加，表明社区有兴趣通过 kfuncs 扩展内核交互。
- **向更深层次内核集成的转变：** 自 2023 年以来，新的用例主要利用 kfuncs 影响内核行为，显示出通过 kfuncs 实现更深层次内核集成的趋势。

这一趋势凸显了社区通过 kfuncs 更深入地与内核集成，推动 eBPF 能力边界的决心。

## 定义你自己的 kfunc：分步指南

为了利用 kfuncs 的强大功能，你需要在内核模块中定义它们。这个过程确保你的自定义函数能够安全地暴露给 eBPF 程序，而无需修改核心内核。

### 编写内核模块

让我们从创建一个简单的内核模块开始，该模块定义一个 `strstr` kfunc。这个 kfunc 将执行子字符串搜索操作，作为理解机制的基础。

#### **文件：`hello.c`**

```c
#include <linux/init.h>       // 模块初始化宏
#include <linux/module.h>     // 加载模块的核心头文件
#include <linux/kernel.h>     // 内核日志宏
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

/* 声明 kfunc 原型 */
__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz);

/* 开始 kfunc 定义 */
__bpf_kfunc_start_defs();

/* 定义 bpf_strstr kfunc */
__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz)
{
    // 边界情况：如果 substr 为空，返回 0（假设空字符串在开始处找到）
    if (substr__sz == 0)
    {
        return 0;
    }
    // 边界情况：如果子字符串比主字符串长，则无法找到
    if (substr__sz > str__sz)
    {
        return -1; // 返回 -1 表示未找到
    }
    // 遍历主字符串，考虑大小限制
    for (size_t i = 0; i <= str__sz - substr__sz; i++)
    {
        size_t j = 0;
        // 将子字符串与当前主字符串位置进行比较
        while (j < substr__sz && str[i + j] == substr[j])
        {
            j++;
        }
        // 如果整个子字符串都匹配
        if (j == substr__sz)
        {
            return i; // 返回第一次匹配的索引
        }
    }
    // 如果未找到子字符串，返回 -1
    return -1;
}

/* 结束 kfunc 定义 */
__bpf_kfunc_end_defs();

/* 定义 BTF kfuncs ID 集 */
BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_strstr)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

/* 注册 kfunc ID 集 */
static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

/* 模块加载时执行的函数 */
static int __init hello_init(void)
{
    int ret;

    printk(KERN_INFO "Hello, world!\n");
    /* 注册 BPF_PROG_TYPE_KPROBE 的 BTF kfunc ID 集 */
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    if (ret)
    {
        pr_err("bpf_kfunc_example: 注册 BTF kfunc ID 集失败\n");
        return ret;
    }
    printk(KERN_INFO "bpf_kfunc_example: 模块加载成功\n");
    return 0; // 成功返回 0
}

/* 模块卸载时执行的函数 */
static void __exit hello_exit(void)
{
    /* 取消注册 BTF kfunc ID 集 */
    unregister_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    printk(KERN_INFO "再见，世界！\n");
}

/* 定义模块的初始化和退出点的宏 */
module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");                 // 许可证类型（GPL）
MODULE_AUTHOR("Your Name");            // 模块作者
MODULE_DESCRIPTION("一个简单的模块"); // 模块描述
MODULE_VERSION("1.0");                 // 模块版本
```

**代码解释：**

- **声明 kfunc：** `__bpf_kfunc` 宏声明一个 eBPF 程序可以调用的函数。在这里，`bpf_strstr` 执行给定字符串中的子字符串搜索。
  
- **BTF 定义：** `__bpf_kfunc_start_defs` 和 `__bpf_kfunc_end_defs` 宏标示 kfunc 定义的开始和结束。`BTF_KFUNCS_START` 及相关宏帮助将 kfuncs 注册到 BPF 类型格式（BTF）。
  
- **模块初始化：** `hello_init` 函数注册 kfunc ID 集，使 `bpf_strstr` 可用于 `BPF_PROG_TYPE_KPROBE` 类型的 eBPF 程序。
  
- **模块清理：** `hello_exit` 函数确保在模块移除时取消注册 kfunc ID 集，保持系统整洁。

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
  
- **BTF 生成标志：** `KBUILD_CFLAGS += -g -O2` 启用调试信息和优化，便于 BTF 生成。
  
- **构建命令：**
  - **`all`:** 通过调用内核构建系统编译内核模块。
  - **`clean`:** 清理构建产物。

**注意：** 提供的代码在 Linux 内核版本 **6.11** 上进行了测试。如果你使用的是较早的版本，可能需要实现一些变通方法，例如引用 `compact.h`。

### 编译内核模块

在内核模块源代码和 Makefile 就位后，按照以下步骤编译模块：

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

加载模块后，通过检查内核日志验证其是否成功插入：

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
[ 1234.9876] 再见，世界！
```

## 处理编译错误

在编译过程中，可能会遇到以下错误：

```txt
Skipping BTF generation for /root/bpf-developer-tutorial/src/43-kfuncs/module/hello.ko due to unavailability of vmlinux
```

**解决方案：**

1. **安装 `dwarves` 包：**

   `dwarves` 包提供了生成 BTF 所需的工具。

   ```sh
   sudo apt install dwarves
   ```

2. **复制 `vmlinux` 文件：**

   确保包含 BTF 信息的 `vmlinux` 文件在构建目录中可用。

   ```sh
   sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/$(uname -r)/build/
   ```

   该命令将 `vmlinux` 文件复制到适当的构建目录，确保成功生成 BTF。

本教程的完整代码可在 [bpf-developer-tutorial 仓库](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/43-kfuncs) 的 GitHub 上找到。此代码在 Linux 内核版本 6.11 上进行了测试，对于较低版本，可能需要参考 `compact.h` 进行一些修改。

## 在 eBPF 程序中使用自定义 kfunc

有了定义自定义 `strstr` kfunc 的内核模块后，下一步是创建一个利用此函数的 eBPF 程序。此交互展示了 kfuncs 引入的增强功能。

### 编写 eBPF 程序

创建一个附加到 `do_unlinkat` 内核函数并使用自定义 `bpf_strstr` kfunc 的 eBPF 程序。

#### **文件：`kfunc.c`**

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef long long s64;

/* 声明外部 kfunc */
extern int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz) __ksym;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int handle_kprobe(struct pt_regs *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    char str[] = "Hello, world!";
    char substr[] = "wor";
    int result = bpf_strstr(str, sizeof(str) - 1, substr, sizeof(substr) - 1);
    if (result != -1)
    {
        bpf_printk("'%s' found in '%s' at index %d\n", substr, str, result);
    }
    bpf_printk("Hello, world! (pid: %d) bpf_strstr %d\n", pid, result);
    return 0;
}
```

**eBPF 代码解释：**

- **外部 kfunc 声明：** `extern` 关键字声明 `bpf_strstr` 函数，使其在 eBPF 程序中可用。
  
- **Kprobe 附加：** `SEC("kprobe/do_unlinkat")` 宏将 eBPF 程序附加到 `do_unlinkat` 内核函数。每次调用 `do_unlinkat` 时，`handle_kprobe` 函数都会执行。
  
- **使用 kfunc：** 在 `handle_kprobe` 中，eBPF 程序调用 `bpf_strstr`，传入四个参数：
  - `str`: 要搜索的主字符串。
  - `str__sz`: 主字符串的大小。
  - `substr`: 要搜索的子字符串。
  - `substr__sz`: 子字符串的大小。

  结果（子字符串在主字符串中的首次出现索引，或 -1 表示未找到）然后通过 `bpf_printk` 打印，显示 PID 和结果。

**重要提示：** 由于验证器限制，直接在 eBPF 中实现类似 `strstr` 的函数具有挑战性，因为这限制了循环和复杂的内存访问。通过将 `strstr` 实现为 kfunc，我们绕过了这些限制，使得在 eBPF 程序中执行更复杂和高效的字符串操作成为可能。

### 编译 eBPF 程序

要编译 eBPF 程序，确保你已安装必要的工具，如 `clang` 和 `llvm`。以下是编译程序的步骤：

1. **导航到 eBPF 程序目录：**

   ```bash
   cd /path/to/bpf-developer-tutorial/src/43-kfuncs/
   ```

2. **为 eBPF 程序创建一个 `Makefile`：**

   ```makefile
   # 文件：Makefile

   CLANG ?= clang
   LLVM_STRIP ?= llvm-strip
   BPF_TARGET := bpf

   CFLAGS := -O2 -g -target $(BPF_TARGET) -Wall -Werror -I/usr/include

   all: kfunc.o

   kfunc.o: kfunc.c
       $(CLANG) $(CFLAGS) -c $< -o $@

   clean:
       rm -f kfunc.o
   ```

3. **编译 eBPF 程序：**

   ```bash
   make
   ```

   该命令将生成一个名为 `kfunc.o` 的文件，即编译后的 eBPF 对象文件。

### 运行 eBPF 程序

假设你有一个用户空间应用程序或工具来加载和附加 eBPF 程序，你可以执行它以观察 eBPF 程序与自定义 kfunc 之间的交互。

**示例输出：**

```bash
# sudo ./kfunc
BPF 程序已加载并成功附加。按 Ctrl-C 退出。
```

然后，当调用 `do_unlinkat` 函数时（例如，当文件被取消链接时），你可以检查内核日志：

```bash
dmesg | tail
```

**预期输出：**

```txt
[ 1234.5678] 'wor' found in 'Hello, world!' at index 7
[ 1234.5679] Hello, world! (pid: 2075) bpf_strstr 7
```

**输出解释：**

每次内核调用 `do_unlinkat` 函数时，eBPF 程序都会打印一条消息，指示进程的 PID 以及 kfunc 调用的结果。在此示例中，子字符串 `"wor"` 在字符串 `"Hello, world!"` 的索引 `7` 处被找到。

## 总结与结论

在本教程中，我们深入探讨了通过定义和使用自定义内核函数（kfuncs）来扩展 eBPF 的能力。以下是我们涵盖的内容回顾：

- **理解 kfuncs：** 理解了 kfuncs 的概念及其在标准辅助函数之外增强 eBPF 的角色。
- **定义 kfuncs：** 创建了一个内核模块，定义了自定义的 `strstr` kfunc，确保其能够安全地暴露给 eBPF 程序，而无需修改核心内核。
- **编写包含 kfuncs 的 eBPF 程序：** 开发了一个利用自定义 kfunc 的 eBPF 程序，展示了增强的功能。
- **编译与执行：** 提供了逐步指南，编译、加载并运行内核模块和 eBPF 程序，确保你可以在自己的系统上复制设置。
- **错误处理：** 解决了潜在的编译问题，并提供了解决方案，确保顺利的开发体验。

**关键要点：**

- **克服辅助函数的限制：** kfuncs 弥合了标准 eBPF 辅助函数留下的空白，提供了针对特定需求的扩展功能。
- **维护系统稳定性：** 通过将 kfuncs 封装在内核模块中，确保系统稳定性，而无需对内核进行侵入性更改。
- **社区驱动的演变：** kfuncs 的快速增长和采用凸显了 eBPF 社区致力于通过 kfuncs 推动内核级编程可能性的决心。
- **利用现有 kfuncs：** 在定义新的 kfuncs 之前，探索内核提供的现有 kfuncs。它们涵盖了广泛的功能，减少了除非绝对必要，否则无需创建自定义函数的需求。

**准备好进一步提升你的 eBPF 技能了吗？** [访问我们的教程仓库](https://github.com/eunomia-bpf/bpf-developer-tutorial)并[探索我们网站上的更多教程](https://eunomia.dev/tutorials/)。深入丰富的示例，深化你的理解，并为 eBPF 的动态世界做出贡献！

祝你在 eBPF 的旅程中愉快！

## 参考资料

- [BPF 内核函数文档](https://docs.kernel.org/bpf/kfuncs.html)
- [eBPF kfuncs 指南](https://docs.ebpf.io/linux/kfuncs/)

## 附加资源

如果你想了解更多关于 eBPF 的知识和实践，可以访问我们的开源教程代码仓库 [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) 或访问我们的网站 [eunomia.dev/tutorials](https://eunomia.dev/tutorials/) 以获取更多示例和完整代码。
