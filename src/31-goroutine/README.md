# eBPF 实践教程：使用 eBPF 跟踪 Go 协程状态

Go 是 Google 创建的一种广受欢迎的编程语言，以其强大的并发模型而著称。Go 语言的一个重要特点是协程（goroutine）的使用——这些协程是轻量级、由 Go 运行时管理的线程，使得编写并发程序变得非常简单。然而，在实时环境中理解和跟踪这些协程的执行状态，尤其是在调试复杂系统时，可能会面临很大的挑战。

这时我们可以利用 eBPF（扩展伯克利包过滤器）技术。eBPF 最初设计用于网络数据包过滤，但随着时间的推移，eBPF 已经发展成为一个强大的工具，用于跟踪和监控系统行为。通过使用 eBPF，我们可以深入到内核，收集有关 Go 程序运行时行为的数据，包括协程的状态。本文将探讨如何使用 eBPF 跟踪 Go 程序中的协程状态转换。

## 背景：协程与 eBPF

### 协程

协程是 Go 语言的核心特性之一，它提供了一种简单而高效的并发处理方式。与传统的线程不同，协程由 Go 运行时管理，而不是由操作系统管理，因此更加轻量化。协程可以在以下几种状态之间进行转换：

- **RUNNABLE（可运行）**：协程已准备好运行。
- **RUNNING（运行中）**：协程正在执行中。
- **WAITING（等待）**：协程正在等待某个事件（如 I/O 或定时器）。
- **DEAD（终止）**：协程执行完毕并已终止。

理解这些状态以及协程之间的状态转换对于诊断性能问题、确保 Go 程序的高效运行至关重要。

### eBPF

eBPF 是一种强大的技术，它允许开发人员在不修改内核源代码或加载内核模块的情况下，在 Linux 内核中运行自定义程序。eBPF 最初用于数据包过滤，但现在已扩展为一种多功能工具，广泛应用于性能监控、安全和调试。

通过编写 eBPF 程序，开发人员可以跟踪各种系统事件，包括系统调用、网络事件和进程执行。在本文中，我们将重点介绍如何使用 eBPF 跟踪 Go 程序中协程的状态转换。

## eBPF 内核代码

现在，让我们深入探讨实现该跟踪功能的 eBPF 内核代码。

```c
#include <vmlinux.h>
#include "goroutine.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define GOID_OFFSET 0x98

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("uprobe/./go-server-http/main:runtime.casgstatus")
int uprobe_runtime_casgstatus(struct pt_regs *ctx) {
  int newval = ctx->cx;
  void *gp = ctx->ax;
  struct goroutine_execute_data *data;
  u64 goid;
  if (bpf_probe_read_user(&goid, sizeof(goid), gp + GOID_OFFSET) == 0) {
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
    if (data) {
      u64 pid_tgid = bpf_get_current_pid_tgid();
      data->pid = pid_tgid;
      data->tgid = pid_tgid >> 32;
      data->goid = goid;
      data->state = newval;
      bpf_ringbuf_submit(data, 0);
    }
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

1. **头文件**：代码首先包含了必要的头文件，如 `vmlinux.h`（提供内核定义）和 `bpf_helpers.h`（提供 eBPF 程序的辅助函数）。
2. **GOID_OFFSET**：`goid` 字段的偏移量被硬编码为 `0x98`，这是特定于所跟踪的 Go 版本和程序的。此偏移量在不同的 Go 版本或程序中可能有所不同。
3. **环形缓冲区映射**：定义了一个 BPF 环形缓冲区映射，用于存储协程的执行数据。这个缓冲区允许内核高效地将信息传递到用户空间。
4. **Uprobe**：该 eBPF 程序的核心是一个附加到 Go 程序中 `runtime.casgstatus` 函数的 uprobe（用户级探针）。该函数负责改变协程的状态，因此非常适合用来拦截和跟踪状态转换。
5. **读取协程 ID**：`bpf_probe_read_user` 函数从用户空间内存中读取协程 ID（`goid`），使用的是预定义的偏移量。
6. **提交数据**：如果成功读取了协程 ID，则数据会与进程 ID、线程组 ID 以及协程的新状态一起存储在环形缓冲区中。随后，这些数据会提交到用户空间以供分析。

## 运行程序

要运行此跟踪程序，请按照以下步骤操作：

1. **编译 eBPF 代码**：使用类似 `ecc`（eBPF 编译集合）这样的编译器编译 eBPF 程序，并生成一个可以由 eBPF 加载器加载的包。

    ```bash
    ecc goroutine.bpf.c goroutine.h
    ```

2. **运行 eBPF 程序**：使用 eBPF 加载器运行编译后的 eBPF 程序。

    ```bash
    ecli-rs run package.json
    ```

3. **输出**：程序将输出协程的状态转换及其 `goid`、`pid` 和 `tgid`。以下是一个示例输出：

    ```console
    TIME     STATE       GOID   PID    TGID   
    21:00:47 DEAD(6)     0      2542844 2542844
    21:00:47 RUNNABLE(1) 0      2542844 2542844
    21:00:47 RUNNING(2)  1      2542844 2542844
    21:00:47 WAITING(4)  2      2542847 2542844
    ```

完整代码可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/31-goroutine> 找到。

如果你想了解更多关于 eBPF 的知识和实践，你可以访问我们的教程代码库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/tutorials/> 获取更多示例和完整教程。

内核模式 eBPF 运行时的 `Uprobe` 可能会带来较大的性能开销。在这种情况下，你也可以考虑使用用户模式的 eBPF 运行时，例如 [bpftime](https://github.com/eunomia-bpf/bpftime)。bpftime 是基于 LLVM JIT/AOT 的用户模式 eBPF 运行时，它可以在用户模式下运行 eBPF 程序，并且在处理 `uprobe` 时比内核模式 eBPF 更快。

### 结论

使用 eBPF 跟踪协程状态可以深入了解 Go 程序的执行情况，尤其是在传统调试工具可能无法胜任的生产环境中。通过利用 eBPF，开发人员可以监控和诊断性能问题，确保 Go 应用程序高效运行。

请注意，本 eBPF 程序中使用的偏移量是特定于所跟踪的 Go 版本和程序的。随着 Go 的发展，这些偏移量可能会发生变化，需要对 eBPF 代码进行更新。

在未来的探索中，我们可以将这种方法扩展到跟踪 Go 程序或其他语言的其他方面，展示 eBPF 在现代软件开发中的多功能性和强大作用。
