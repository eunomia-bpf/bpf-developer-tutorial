# eBPF 教程：使用 BPF struct_ops 扩展内核子系统

你是否想过扩展内核行为——比如添加自定义调度器、网络协议或安全策略——却因为编写和维护内核模块的复杂性而望而却步？如果你可以直接用 eBPF 定义这些逻辑，实现动态更新、安全执行和可编程控制，同时无需重新编译内核或担心系统稳定性呢？

这就是 **BPF struct_ops** 的强大之处。它允许 BPF 程序实现内核操作结构体的回调函数，让你能够"插入"自定义逻辑来扩展内核子系统的行为。这已经超越了简单的跟踪或过滤——你现在可以用 BPF 实现核心的内核操作。例如，我们用它在 GPU 驱动中实现了 GPU 调度和内存卸载扩展（参见 [LPC 2024 演讲](https://lpc.events/event/19/contributions/2168/) 和 [gpu_ext 项目](https://github.com/eunomia-bpf/gpu_ext)）。

在本教程中，我们将探讨如何使用 `struct_ops` 来动态地扩展内核子系统的行为。我们不会使用常见的 TCP 拥塞控制示例。相反，我们将采用一种更基础的方法，这种方法反映了与 kfuncs 相似的可扩展性。我们将创建一个自定义的内核模块，该模块定义了一组新的、简单的操作。这个模块将充当一个占位符，为我们的 BPF 程序创建新的附加点。然后，我们将编写一个 BPF 程序来实现这些操作的逻辑。这演示了一种强大的模式：使用一个最小化的内核模块来暴露一个 `struct_ops` 接口，然后使用 BPF 来提供完整、复杂的实现。

> 本教程的完整源代码可以在这里找到：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/struct_ops>

## BPF struct_ops 简介：可编程的内核子系统

### 挑战：安全、动态地扩展内核行为

传统上，向 Linux 内核添加新功能，例如新的文件系统、网络协议或调度器算法，都需要编写内核模块。虽然功能强大，但内核模块也带来了重大的挑战：

- **复杂性：** 内核开发具有陡峭的学习曲线，需要对内核内部有深入的了解。
- **安全性：** 内核模块中的一个错误很容易导致整个系统崩溃。没有沙箱保障。
- **维护性：** 内核模块必须针对不同的内核版本进行维护和重新编译，这与内核的内部 API 产生了紧密的耦合。

eBPF 通过提供一个安全的沙箱环境，传统上在跟踪、网络和安全领域解决了这些问题。然而，大多数 eBPF 程序都附加到现有的钩子（如 tracepoints、kprobes 或 XDP）上并对事件做出反应。它们通常不*实现*内核子系统的核心逻辑。

### 解决方案：用 BPF 实现内核操作

BPF `struct_ops` 填补了这一空白。它允许 BPF 程序实现 `struct_ops` 中的函数——这是内核中一种常见的模式，即一个结构体包含一组操作的函数指针。这些指针不再指向编译到内核或模块中的函数，而是可以指向 BPF 程序。

这是一种范式转变。它不再仅仅是关于观察或过滤；它是关于*实现*。想象一个内核子系统，它定义了一组像 `open`、`read`、`write` 这样的操作。通过 `struct_ops`，你可以编写 BPF 程序来作为这些函数的实现。

这种方法的精神与 **kfuncs** 允许开发者扩展 BPF 功能的方式相似。通过 kfuncs，我们可以在内核模块中定义它们，从而向 BPF 运行时添加自定义的辅助函数。通过 `struct_ops`，我们更进一步：我们为 BPF 程序定义了一整套全新的*附加点*，有效地在内核中创建了一个自定义的、可通过 BPF 编程的子系统。

其好处是巨大的：

- **动态实现**：你可以在不重启内核或应用程序的情况下，动态加载、更新和卸载实现子系统逻辑的 BPF 程序。
- **安全性**：BPF 验证器确保 BPF 程序的运行是安全的，防止了诸如无限循环、越界内存访问和系统崩溃等常见陷阱。
- **灵活性**：逻辑位于 BPF 程序中，可以独立于定义 `struct_ops` 接口的内核模块进行开发和更新。
- **可编程性**：用户空间应用程序可以与 BPF 程序交互并控制它们，从而实现对内核子系统行为的动态配置和控制。

在本教程中，我们将通过一个实际的例子来演示这种模式。我们将从一个定义了新的 `struct_ops` 类型的内核模块开始，然后我们将编写一个 BPF 程序来实现它的功能。

## 内核模块：定义子系统接口

第一步是创建一个内核模块，用以定义我们新的、可通过 BPF 编程的子系统。这个模块本身不需要包含太多逻辑。它的主要作用是定义一个 `struct_ops` 类型并将其注册到内核，从而为 BPF 程序创建一个新的附加点。它还提供了一种触发这些操作的机制，在我们的例子中，这将是一个简单的 proc 文件。

这种方法之所以强大，是因为它将接口定义（在内核模块中）与实现（在 BPF 程序中）分离开来。内核模块是稳定且最小化的，而复杂、动态的逻辑则位于 BPF 程序中，可以随时更新。

### 完整的内核模块：`module/hello.c`

以下是我们的内核模块的完整源代码。它定义了一个名为 `bpf_testmod_ops` 的 `struct_ops`，其中包含三个不同的操作，我们的 BPF 程序稍后将实现这些操作。

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/bpf_verifier.h>

/* 定义我们的自定义 struct_ops 操作 */
struct bpf_testmod_ops {
	int (*test_1)(void);
	int (*test_2)(int a, int b);
	int (*test_3)(const char *buf, int len);
};

/* BPF 程序将实现的全局实例 */
static struct bpf_testmod_ops __rcu *testmod_ops;

/* 用于触发 struct_ops 的 Proc 文件 */
static struct proc_dir_entry *trigger_file;

/* CFI 存根函数 - struct_ops 所需 */
static int bpf_testmod_ops__test_1(void)
{
	return 0;
}

static int bpf_testmod_ops__test_2(int a, int b)
{
	return 0;
}

static int bpf_testmod_ops__test_3(const char *buf, int len)
{
	return 0;
}

/* CFI 存根结构 */
static struct bpf_testmod_ops __bpf_ops_bpf_testmod_ops = {
	.test_1 = bpf_testmod_ops__test_1,
	.test_2 = bpf_testmod_ops__test_2,
	.test_3 = bpf_testmod_ops__test_3,
};

/* BTF 和验证器回调 */
static int bpf_testmod_ops_init(struct btf *btf)
{
	/* 如果需要，初始化 BTF */
	return 0;
}

static bool bpf_testmod_ops_is_valid_access(int off, int size,
					    enum bpf_access_type type,
					    const struct bpf_prog *prog,
					    struct bpf_insn_access_aux *info)
{
	/* 目前允许所有访问 */
	return true;
}

/* 允许在 struct_ops 程序中使用特定的 BPF 辅助函数 */
static const struct bpf_func_proto *
bpf_testmod_ops_get_func_proto(enum bpf_func_id func_id,
			       const struct bpf_prog *prog)
{
	/* 使用基础函数原型，包括 trace_printk 和其他基本辅助函数 */
	return bpf_base_func_proto(func_id, prog);
}

static const struct bpf_verifier_ops bpf_testmod_verifier_ops = {
	.is_valid_access = bpf_testmod_ops_is_valid_access,
	.get_func_proto = bpf_testmod_ops_get_func_proto,
};

static int bpf_testmod_ops_init_member(const struct btf_type *t,
				       const struct btf_member *member,
				       void *kdata, const void *udata)
{
	/* 无需特殊的成员初始化 */
	return 0;
}

/* 注册函数 */
static int bpf_testmod_ops_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_testmod_ops *ops = kdata;
	
	/* 一次只允许一个实例 */
	if (cmpxchg(&testmod_ops, NULL, ops) != NULL)
		return -EEXIST;

	pr_info("bpf_testmod_ops registered\n");
	return 0;
}

/* 注销函数 */
static void bpf_testmod_ops_unreg(void *kdata, struct bpf_link *link)
{
	struct bpf_testmod_ops *ops = kdata;

	if (cmpxchg(&testmod_ops, ops, NULL) != ops) {
		pr_warn("bpf_testmod_ops: unexpected unreg\n");
		return;
	}

	pr_info("bpf_testmod_ops unregistered\n");
}

/* Struct ops 定义 */
static struct bpf_struct_ops bpf_testmod_ops_struct_ops = {
	.verifier_ops = &bpf_testmod_verifier_ops,
	.init = bpf_testmod_ops_init,
	.init_member = bpf_testmod_ops_init_member,
	.reg = bpf_testmod_ops_reg,
	.unreg = bpf_testmod_ops_unreg,
	.cfi_stubs = &__bpf_ops_bpf_testmod_ops,
	.name = "bpf_testmod_ops",
	.owner = THIS_MODULE,
};

/* 用于触发 struct_ops 的 Proc 文件写处理程序 */
static ssize_t trigger_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *pos)
{
	struct bpf_testmod_ops *ops;
	char kbuf[64];
	int ret = 0;
	
	if (count >= sizeof(kbuf))
		count = sizeof(kbuf) - 1;
	
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	
	kbuf[count] = '\0';
	
	rcu_read_lock();
	ops = rcu_dereference(testmod_ops);
	if (ops) {
		pr_info("Calling struct_ops callbacks:\n");
		
		if (ops->test_1) {
			ret = ops->test_1();
			pr_info("test_1() returned: %d\n", ret);
		}
		
		if (ops->test_2) {
			ret = ops->test_2(10, 20);
			pr_info("test_2(10, 20) returned: %d\n", ret);
		}
		
		if (ops->test_3) {
			ops->test_3(kbuf, count);
			pr_info("test_3() called with buffer\n");
		}
	} else {
		pr_info("No struct_ops registered\n");
	}
	rcu_read_unlock();
	
	return count;
}

static const struct proc_ops trigger_proc_ops = {
	.proc_write = trigger_write,
};

static int __init testmod_init(void)
{
	int ret;

	/* 注册 struct_ops */
	ret = register_bpf_struct_ops(&bpf_testmod_ops_struct_ops, bpf_testmod_ops);
	if (ret) {
		pr_err("Failed to register struct_ops: %d\n", ret);
		return ret;
	}

	/* 创建用于触发的 proc 文件 */
	trigger_file = proc_create("bpf_testmod_trigger", 0222, NULL, &trigger_proc_ops);
	if (!trigger_file) {
		/* 注意：此内核版本中没有可用的注销函数 */
		return -ENOMEM;
	}

	pr_info("bpf_testmod loaded with struct_ops support\n");
	return 0;
}

static void __exit testmod_exit(void)
{
	proc_remove(trigger_file);
	/* 注意：struct_ops 的注销在模块卸载时自动发生 */
	pr_info("bpf_testmod unloaded\n");
}

module_init(testmod_init);
module_exit(testmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("eBPF Example");
MODULE_DESCRIPTION("BPF struct_ops test module");
MODULE_VERSION("1.0");
```

### 理解内核模块代码

这个模块可能看起来很复杂，但其结构是合乎逻辑的，并且服务于一个明确的目的：安全地向 BPF 子系统暴露一个新的可编程接口。让我们来分解一下。

首先，我们定义了我们新操作的结构。这是一个包含函数指针的简单 C 结构体。这个 `struct bpf_testmod_ops` 就是我们的 BPF 程序将要实现的接口。每个函数指针都定义了一个 BPF 程序可以填充的“槽”。

```c
struct bpf_testmod_ops {
	int (*test_1)(void);
	int (*test_2)(int a, int b);
	int (*test_3)(const char *buf, int len);
};
```

接下来，我们有核心的 `bpf_struct_ops` 定义。这是一个特殊的内核结构，向 BPF 系统描述了我们新的 `struct_ops` 类型。它是将我们的自定义 `bpf_testmod_ops` 连接到 BPF 基础设施的粘合剂。

```c
static struct bpf_struct_ops bpf_testmod_ops_struct_ops = {
	.verifier_ops = &bpf_testmod_verifier_ops,
	.init = bpf_testmod_ops_init,
	.init_member = bpf_testmod_ops_init_member,
	.reg = bpf_testmod_ops_reg,
	.unreg = bpf_testmod_ops_unreg,
	.cfi_stubs = &__bpf_ops_bpf_testmod_ops,
	.name = "bpf_testmod_ops",
	.owner = THIS_MODULE,
};
```

这个结构体充满了内核将用来管理我们的 `struct_ops` 的回调函数：
- `.reg` 和 `.unreg`：这些是注册和注销回调。当 BPF 程序尝试为 `bpf_testmod_ops` 附加一个实现时，内核会调用 `.reg`。我们的实现使用 `cmpxchg` 来确保一次只有一个 BPF 程序可以被附加。当 BPF 程序分离时，会调用 `.unreg`。
- `.verifier_ops`：这指向一个用于 BPF 验证器的回调结构。它允许我们自定义验证器如何处理附加到此 `struct_ops` 的 BPF 程序。例如，我们可以控制允许哪些辅助函数。在我们的例子中，我们使用 `bpf_base_func_proto` 来允许一组基本的辅助函数，包括对调试有用的 `bpf_printk`。
- `.init` 和 `.init_member`：这些用于 BTF（BPF 类型格式）初始化。内核需要它们来理解我们的 `struct_ops` 的类型和布局。
- `.name` 和 `.owner`：这些标识了我们的 `struct_ops` 并将其与我们的模块绑定，确保正确的引用计数，以便在 BPF 程序仍然附加时模块不会被卸载。

模块的 `testmod_init` 函数是魔法开始的地方。它调用 `register_bpf_struct_ops`，传入我们的定义。这使得内核意识到新的 `bpf_testmod_ops` 类型，从这一点开始，BPF 程序就可以以它为目标。

最后，为了使其可演示，该模块在 proc 文件系统中创建了一个文件：`/proc/bpf_testmod_trigger`。当用户空间程序向此文件写入时，`trigger_write` 函数被调用。此函数检查是否有 BPF 程序为 `testmod_ops` 注册了实现。如果有，它会调用函数指针（`test_1`、`test_2`、`test_3`），这将执行我们 BPF 程序中的代码。这提供了一种从用户空间调用 BPF 实现的操作的简单方法。使用 RCU（`rcu_read_lock`、`rcu_dereference`）确保即使 `testmod_ops` 指针正在被并发更新，我们也可以安全地访问它。

## BPF 程序：实现操作

内核模块定义了*什么*（`bpf_testmod_ops` 接口）之后，我们现在可以编写一个 BPF 程序来定义*如何*（这些操作的实际实现）。这个 BPF 程序将包含在从内核调用 `test_1`、`test_2` 和 `test_3` 函数时执行的逻辑。

### 完整的 BPF 程序：`struct_ops.bpf.c`

该程序为 `bpf_testmod_ops` 中的函数指针提供了具体的实现。

```c
/* SPDX-License-Identifier: GPL-2.0 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "module/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

/* 实现 struct_ops 回调 */
SEC("struct_ops/test_1")
int BPF_PROG(bpf_testmod_test_1)
{
	bpf_printk("BPF test_1 called!\n");
	return 42;
}

SEC("struct_ops/test_2")
int BPF_PROG(bpf_testmod_test_2, int a, int b)
{
	int result = a + b;
	bpf_printk("BPF test_2 called: %d + %d = %d\n", a, b, result);
	return result;
}

SEC("struct_ops/test_3")
int BPF_PROG(bpf_testmod_test_3, const char *buf, int len)
{
	char read_buf[64] = {0};
	int read_len = len < sizeof(read_buf) ? len : sizeof(read_buf) - 1;

	bpf_printk("BPF test_3 called with buffer length %d\n", len);

	/* 使用 bpf_probe_read_kernel 安全地从内核缓冲区读取 */
	if (buf && read_len > 0) {
		long ret = bpf_probe_read_kernel(read_buf, read_len, buf);
		if (ret == 0) {
			/* 成功读取缓冲区 - 打印前几个字符 */
			bpf_printk("Buffer content: '%c%c%c%c'\n",
				   read_buf[0], read_buf[1], read_buf[2], read_buf[3]);
			bpf_printk("Full buffer: %s\n", read_buf);
		} else {
			bpf_printk("Failed to read buffer, ret=%ld\n", ret);
		}
	}

	return len;
}

/* 定义 struct_ops map */
SEC(".struct_ops")
struct bpf_testmod_ops testmod_ops = {
	.test_1 = (void *)bpf_testmod_test_1,
	.test_2 = (void *)bpf_testmod_test_2,
	.test_3 = (void *)bpf_testmod_test_3,
};
```

### 理解 BPF 代码

BPF 代码非常直观，这证明了 `struct_ops` 抽象的强大功能。

BPF 程序中的每个函数都对应于内核模块 `bpf_testmod_ops` 结构中定义的一个操作。其奥秘在于 `SEC` 注解：
- `SEC("struct_ops/test_1")`：这告诉 BPF 加载器，`bpf_testmod_test_1` 程序是 `struct_ops` 操作的一个实现。斜杠后的名称虽然没有严格要求必须与函数名匹配，但这是一个很好的约定。关键部分是 `struct_ops` 前缀。

实现本身很简单：
- `bpf_testmod_test_1`：此函数不接受任何参数，使用 `bpf_printk`向内核跟踪日志打印一条消息，并返回整数 `42`。
- `bpf_testmod_test_2`：此函数接受两个整数 `a` 和 `b`，计算它们的和，打印操作和结果，并返回总和。
- `bpf_testmod_test_3`：此函数演示了如何处理来自用户空间的数据。它接收一个字符缓冲区及其长度。它使用 `bpf_probe_read_kernel` 安全地将内核模块传递的缓冲区中的数据复制到 BPF 栈上的本地缓冲区中。这是一项至关重要的安全措施，因为 BPF 程序不能直接访问任意的内核内存指针。读取后，它会打印内容。

最后一部分是 `struct_ops` map 本身：

```c
SEC(".struct_ops")
struct bpf_testmod_ops testmod_ops = {
	.test_1 = (void *)bpf_testmod_test_1,
	.test_2 = (void *)bpf_testmod_test_2,
	.test_3 = (void *)bpf_testmod_test_3,
};
```

这是将所有部分链接在一起最关键的一环。
- `SEC(".struct_ops")`：这个特殊的节将下面的数据结构标识为 `struct_ops` map。
- `struct bpf_testmod_ops testmod_ops`：我们声明一个名为 `testmod_ops` 的变量，其类型为 `struct bpf_testmod_ops`。这个变量的**名称很重要**。它必须与内核模块中 `bpf_struct_ops` 定义中的 `name` 字段匹配（`.name = "bpf_testmod_ops"`）。`libbpf` 就是通过这种方式知道这个 BPF 程序打算实现哪个内核 `struct_ops`。
- 该结构通过将 BPF 程序（`bpf_testmod_test_1` 等）分配给相应的函数指针来初始化。这将我们的 BPF 函数映射到 `struct_ops` 接口中的“槽”。

当用户空间加载器附加这个 `struct_ops` 时，`libbpf` 和内核会协同工作，找到由我们的内核模块注册的 `bpf_testmod_ops`，并将这些 BPF 程序链接为其实现。

## 用户空间加载器：附加和触发

最后一个组件是用户空间程序。它的工作是加载 BPF 程序，将其附加到内核模块定义的 `struct_ops` 上，然后触发这些操作，以证明一切正常。

### 完整的用户空间程序：`struct_ops.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "struct_ops.skel.h"

static volatile bool exiting = false;

void handle_signal(int sig) {
    exiting = true;
}

static int trigger_struct_ops(const char *message) {
    int fd, ret;
    
    fd = open("/proc/bpf_testmod_trigger", O_WRONLY);
    if (fd < 0) {
        perror("open /proc/bpf_testmod_trigger");
        return -1;
    }
    
    ret = write(fd, message, strlen(message));
    if (ret < 0) {
        perror("write");
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    struct struct_ops_bpf *skel;
    struct bpf_link *link;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* 打开 BPF 应用程序 */
    skel = struct_ops_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* 加载 BPF 程序 */
    err = struct_ops_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* 注册 struct_ops */
    link = bpf_map__attach_struct_ops(skel->maps.testmod_ops);
    if (!link) {
        fprintf(stderr, "Failed to attach struct_ops\n");
        err = -1;
        goto cleanup;
    }

    printf("Successfully loaded and attached BPF struct_ops!\n");
    printf("Triggering struct_ops callbacks...\n");
    
    /* 通过写入 proc 文件触发 struct_ops */
    if (trigger_struct_ops("Hello from userspace!") < 0) {
        printf("Failed to trigger struct_ops - is the kernel module loaded?\n");
        printf("Load it with: sudo insmod module/hello.ko\n");
    } else {
        printf("Triggered struct_ops successfully! Check dmesg for output.\n");
    }
    
    printf("\nPress Ctrl-C to exit...\n");

    /* 主循环 - 定期触发 */
    while (!exiting) {
        sleep(2);
        if (!exiting && trigger_struct_ops("Periodic trigger") == 0) {
            printf("Triggered struct_ops again...\n");
        }
    }

    printf("\nDetaching struct_ops...\n");
    bpf_link__destroy(link);

cleanup:
    struct_ops_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
```

### 理解用户空间代码

用户空间代码编排了整个过程。
1.  **信号处理**：它为 `SIGINT` 和 `SIGTERM` 设置了信号处理程序，以实现优雅退出。这对于 `struct_ops` 至关重要，因为我们需要确保 BPF 程序被正确分离。

2.  **打开和加载**：它使用标准的 `libbpf` 骨架 API 来打开和加载 BPF 应用程序（`struct_ops_bpf__open()` 和 `struct_ops_bpf__load()`）。这将 BPF 程序和 `struct_ops` map 加载到内核中。

3.  **附加 `struct_ops`**：关键步骤是附加：
    ```c
    link = bpf_map__attach_struct_ops(skel->maps.testmod_ops);
    ```
    这个 `libbpf` 函数完成了繁重的工作。它从我们的 BPF 骨架中获取 `struct_ops` map（`skel->maps.testmod_ops`），并请求内核将其链接到相应的 `struct_ops` 定义（通过名称 "bpf_testmod_ops" 找到）。如果成功，我们模块中的内核 `reg` 回调将被执行，内核中的函数指针现在将指向我们的 BPF 程序。该函数返回一个 `bpf_link`，代表活动的附加。

4.  **触发**：`trigger_struct_ops` 函数只是打开 `/proc/bpf_testmod_trigger` 文件并向其写入一条消息。此操作会调用我们内核模块中的 `trigger_write` 处理程序，该处理程序又会调用 BPF 实现的操作。

5.  **清理**：当用户按下 Ctrl-C 时，`exiting` 标志被设置，循环终止，并调用 `bpf_link__destroy(link)`。这是附加步骤的对应操作。它分离 BPF 程序，导致内核调用我们模块中的 `unreg` 回调。这会清理链接并递减模块的引用计数，使其能够被干净地卸载。如果跳过此步骤（例如，通过 `-9` 杀死进程），模块将保持“使用中”状态，直到内核的垃圾回收清理了该链接，这可能需要一些时间。

## 编译和执行

现在我们已经拥有了所有三个组件——内核模块、BPF 程序和用户空间加载器——让我们编译并运行这个例子，看看 `struct_ops` 的实际效果。

### 1. 编译内核模块

首先，进入 `module` 目录并编译内核模块。这需要为你的当前内核版本安装内核头文件。

```bash
cd module
make
cd ..
```

这将生成一个 `hello.ko` 文件，即我们编译好的内核模块。

### 2. 加载内核模块

使用 `insmod` 将模块加载到内核中。这将注册我们的 `bpf_testmod_ops` struct_ops 类型，并创建 `/proc/bpf_testmod_trigger` 文件。

```bash
sudo insmod module/hello.ko
```

你可以通过检查内核日志来验证模块是否已成功加载：

```bash
dmesg | tail -n 1
```

你应该会看到类似 `bpf_testmod loaded with struct_ops support` 的消息。

### 3. 编译并运行 eBPF 应用程序

接下来，编译并运行用户空间加载器，这也会编译 BPF 程序。

```bash
make
sudo ./struct_ops
```

运行后，用户空间应用程序将：
1.  加载 BPF 程序。
2.  将 BPF 实现附加到 `bpf_testmod_ops` struct_ops。
3.  向 `/proc/bpf_testmod_trigger` 写入数据以调用 BPF 函数。

你应该会在终端中看到类似以下的输出：

```
Successfully loaded and attached BPF struct_ops!
Triggering struct_ops callbacks...
Triggered struct_ops successfully! Check dmesg for output.

Press Ctrl-C to exit...
Triggered struct_ops again...
```

### 4. 检查内核日志中的 BPF 输出

在用户空间程序运行时，打开另一个终端并观察内核日志，以查看我们 BPF 程序的输出。

```bash
sudo dmesg -w
```

每次向 proc 文件写入数据时，你都会看到由 BPF 程序通过 `bpf_printk` 打印的消息：

```
[ ... ] bpf_testmod_ops registered
[ ... ] Calling struct_ops callbacks:
[ ... ] BPF test_1 called!
[ ... ] test_1() returned: 42
[ ... ] BPF test_2 called: 10 + 20 = 30
[ ... ] test_2(10, 20) returned: 30
[ ... ] BPF test_3 called with buffer length 21
[ ... ] Buffer content: 'Hell'
[ ... ] Full buffer: Hello from userspace!
[ ... ] test_3() called with buffer
```

此输出证实了来自内核模块的调用被正确地分派到了我们的 BPF 程序。

### 5. 清理

完成后，在运行 `./struct_ops` 的终端中按 `Ctrl-C`。程序将优雅地分离 BPF 链接。然后，你可以卸载内核模块。

```bash
sudo rmmod hello
```

最后，清理构建产物：

```bash
make clean
cd module
make clean
```

**关于卸载模块的说明**：优雅地停止用户空间程序非常重要。它确保 `bpf_link__destroy()` 被调用，从而允许内核模块的引用计数递减。如果用户空间进程被突然杀死（例如，使用 `kill -9`），内核模块可能会保持“使用中”状态，`rmmod` 将会失败，直到 BPF 链接被内核垃圾回收，这可能需要一些时间。

## 常见问题排查

在处理像 `struct_ops` 这样涉及内核模块、BTF 和 BPF 验证器的高级功能时，你可能会遇到一些棘手的问题。本节根据本示例的开发过程，涵盖了常见问题及其解决方案。

### 问题 1：未能找到 `struct_ops` 的 BTF 信息

**症状：** 用户空间加载器失败，并显示类似以下的错误：

```
libbpf: failed to find BTF info for struct_ops/bpf_testmod_ops
Failed to attach struct_ops
```

**根本原因：** 此错误意味着内核模块（`hello.ko`）编译时没有包含必需的 BTF（BPF 类型格式）信息。BPF 系统依赖 BTF 来理解模块中定义的结构和类型，这对于将 BPF 程序链接到 `struct_ops`至关重要。

**解决方案：**

1.  **确保带有 BTF 的 `vmlinux` 可用：** 内核构建系统需要访问与你正在运行的内核相对应的 `vmlinux` 文件，以便为外部模块生成 BTF。此文件通常默认不可用。你可能需要从 `/sys/kernel/btf/vmlinux` 复制它，或从你的内核源码构建它。构建系统查找的一个常见位置是 `/lib/modules/$(uname -r)/build/vmlinux`。

2.  **确保 `pahole` 是最新的：** BTF 的生成依赖于 `pahole` 工具（`dwarves` 软件包的一部分）。旧版本的 `pahole` 可能缺少现代 BTF 生成所需的功能。请确保你的 `pahole` 版本为 v1.16 或更高。如果你发行版中的版本太旧，你可能需要从源码编译它。

3.  **重新编译模块：** 确保依赖项满足后，重新编译内核模块。本示例的 `Makefile` 已经包含了 `-g` 标志，该标志指示编译器生成调试信息，`pahole` 使用这些信息来创建 BTF。

你可以使用 `readelf` 来验证你的模块中是否存在 BTF 信息：

```bash
readelf -S module/hello.ko | grep .BTF
```

你应该会看到名为 `.BTF` 和 `.BTF.ext` 的节，表明 BTF 数据已被嵌入。

### 问题 2：加载模块时发生内核崩溃

**症状：** 在你运行 `sudo insmod hello.ko` 后，系统立即崩溃（内核崩溃）。`dmesg` 日志可能会显示在 `register_bpf_struct_ops` 内部发生了 `NULL pointer dereference`（空指针解引用）。

**根本原因：** 内核的 `struct_ops` 注册逻辑期望 `bpf_struct_ops` 结构中的某些回调指针为非空。在较旧的内核版本或某些配置中，如果缺少像 `.verifier_ops`、`.init` 或 `.init_member` 这样的回调，内核可能会解引用一个空指针，从而导致崩溃。内核的代码并不总是执行防御性的空指针检查。

**解决方案：** 始终在你的 `bpf_struct_ops` 定义中提供所有必需的回调，即使它们只是空函数。

```c
// 在 module/hello.c 中
static const struct bpf_verifier_ops bpf_testmod_verifier_ops = {
    .is_valid_access = bpf_testmod_ops_is_valid_access,
    .get_func_proto = bpf_testmod_ops_get_func_proto,
};

static struct bpf_struct_ops bpf_testmod_ops_struct_ops = {
	.verifier_ops = &bpf_testmod_verifier_ops,  // 必需
	.init = bpf_testmod_ops_init,              // 必需
	.init_member = bpf_testmod_ops_init_member, // 必需
	.reg = bpf_testmod_ops_reg,
	.unreg = bpf_testmod_ops_unreg,
	/* ... */
};
```

通过显式定义这些回调，你可以防止内核尝试调用一个空函数指针。

### 问题 3：BPF 程序加载失败，错误为“无效参数”

**症状：** 用户空间加载器失败，并显示一个错误，指示某个 BPF 辅助函数不被允许。

```
libbpf: prog 'bpf_testmod_test_1': BPF program load failed: Invalid argument
program of this type cannot use helper bpf_trace_printk#6
```

**根本原因：** 类型为 `struct_ops` 的 BPF 程序在与跟踪程序（如 kprobes 或 tracepoints）不同的内核上下文中运行。因此，它们受到一套不同且通常更严格的允许使用的辅助函数的限制。`bpf_trace_printk` 辅助函数（`bpf_printk` 是其宏）是一个跟踪辅助函数，在 `struct_ops` 程序中默认是不允许的。

**解决方案：** 虽然默认情况下不能使用 `bpf_printk`，但你可以为你的 `struct_ops` 类型显式地允许它。这可以在内核模块中通过在你的 `bpf_verifier_ops` 中实现 `.get_func_proto` 回调来完成。

```c
// 在 module/hello.c 中
static const struct bpf_func_proto *
bpf_testmod_ops_get_func_proto(enum bpf_func_id func_id,
			       const struct bpf_prog *prog)
{
	/* 使用基础函数原型，它包括 trace_printk 和其他基本辅助函数 */
	return bpf_base_func_proto(func_id, prog);
}

static const struct bpf_verifier_ops bpf_testmod_verifier_ops = {
	.is_valid_access = bpf_testmod_ops_is_valid_access,
	.get_func_proto = bpf_testmod_ops_get_func_proto, // 添加此行
};
```

`bpf_base_func_proto` 函数提供了一组通用的、基本的辅助函数的访问权限，包括 `bpf_trace_printk`。通过将其添加到我们的验证器操作中，我们告诉 BPF 验证器，附加到 `bpf_testmod_ops` 的程序被允许使用这些辅助函数。这使得使用 `bpf_printk` 进行调试成为可能。

## 总结

在本教程中，我们通过超越常见的示例，探索了 BPF `struct_ops` 的强大功能。我们演示了一种强大的内核扩展模式：创建一个最小化的内核模块来定义一个新的、可通过 BPF 编程的子系统接口，然后在安全、可更新的 BPF 程序中提供完整、复杂的实现。这种方法结合了内核模块的可扩展性与 eBPF 的安全性和灵活性。

我们看到了内核模块如何注册一个 `struct_ops` 类型，BPF 程序如何实现所需的函数，以及用户空间加载器如何附加此实现并触发其执行。这种架构为在 BPF 中实现广泛的内核级功能打开了大门，从自定义网络协议和安全策略到新的文件系统行为，所有这些都可以在保持系统稳定性的同时，避免重新编译内核的需要。

> 如果你想更深入地研究 eBPF，请查看我们的教程库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- **`struct_ops` 的内核源码**：其实现可以在 Linux 源码树的 `kernel/bpf/bpf_struct_ops.c` 中找到。
- **`struct_ops` 的内核测试模块**：官方的内核自测试模块提供了一个参考实现：`tools/testing/selftests/bpf/test_kmods/bpf_testmod.c`。
- **BPF 文档**：内核源码中的官方 BPF 文档：[https://www.kernel.org/doc/html/latest/bpf/](https://www.kernel.org/doc/html/latest/bpf/)
