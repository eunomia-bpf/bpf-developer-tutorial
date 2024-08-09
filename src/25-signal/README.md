# eBPF 入门实践教程：用 bpf_send_signal 发送信号终止恶意进程

eBPF (扩展的伯克利数据包过滤器) 是 Linux 内核的一种革命性技术，允许用户在内核空间执行自定义程序，而不需要修改内核源代码或加载任何内核模块。这使得开发人员可以非常灵活地对 Linux 系统进行观测、修改和控制。

本文介绍了如何使用 eBPF 的 bpf_send_signal 功能，向指定的进程发送信号进行干预。本文完整的源代码和更多的教程文档，请参考 <https://github.com/eunomia-bpf/bpf-developer-tutorial>

## 使用场景

**1. 性能分析:**  
在现代软件生态系统中，优化应用程序的性能是开发人员和系统管理员的一个核心任务。当应用程序，如 hhvm，出现运行缓慢或资源利用率异常高时，它可能会对整个系统产生不利影响。因此，定位这些性能瓶颈并及时解决是至关重要的。

**2. 异常检测与响应:**  
任何运行在生产环境中的系统都可能面临各种异常情况，从简单的资源泄露到复杂的恶意软件攻击。在这些情况下，系统需要能够迅速、准确地检测到这些异常，并采取适当的应对措施。

**3. 动态系统管理:**  
随着云计算和微服务架构的普及，能够根据当前系统状态动态调整资源配置和应用行为已经成为了一个关键需求。例如，根据流量波动自动扩容或缩容，或者在检测到系统过热时降低 CPU 频率。

### 现有方案的不足

为了满足上述使用场景的需求，传统的技术方法如下：

- 安装一个 bpf 程序，该程序会持续监视系统，同时对一个 map 进行轮询。
- 当某个事件触发了 bpf 程序中定义的特定条件时，它会将相关数据写入此 map。
- 接着，外部分析工具会从该 map 中读取数据，并根据读取到的信息向目标进程发送信号。

尽管这种方法在很多场景中都是可行的，但它存在一个主要的缺陷：从事件发生到外部工具响应的时间延迟可能相对较大。这种延迟可能会影响到事件的响应速度，从而使得性能分析的结果不准确或者在面对恶意活动时无法及时作出反应。

### 新方案的优势

为了克服传统方法的这些限制，Linux 内核提供了 `bpf_send_signal` 和 `bpf_send_signal_thread` 这两个 helper 函数。

这两个函数带来的主要优势包括：

**1. 实时响应:**  
通过直接从内核空间发送信号，避免了用户空间的额外开销，这确保了信号能够在事件发生后立即被发送，大大减少了延迟。

**2. 准确性:**  
得益于减少的延迟，现在我们可以获得更准确的系统状态快照，这对于性能分析和异常检测尤其重要。

**3. 灵活性:**  
这些新的 helper 函数为开发人员提供了更多的灵活性，他们可以根据不同的使用场景和需求来自定义信号的发送逻辑，从而更精确地控制和管理系统行为。

## 内核态代码分析

在现代操作系统中，一种常见的安全策略是监控和控制进程之间的交互。尤其在Linux系统中，`ptrace` 系统调用是一个强大的工具，它允许一个进程观察和控制另一个进程的执行，并修改其寄存器和内存。这使得它成为了调试和跟踪工具（如 `strace` 和 `gdb`）的主要机制。然而，恶意的 `ptrace` 使用也可能导致安全隐患。

这个程序的目标是在内核态监控 `ptrace` 的调用，当满足特定的条件时，它会发送一个 `SIGKILL` 信号终止调用进程。此外，为了调试或审计目的，该程序会记录这种干预并将相关信息发送到用户空间。

## 代码分析

### 1. 数据结构定义 (`signal.h`)

signal.h

```c
// Simple message structure to get events from eBPF Programs
// in the kernel to user space
#define TASK_COMM_LEN 16
struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    bool success;
};
```

这部分定义了一个简单的消息结构，用于从内核的 eBPF 程序传递事件到用户空间。结构包括进程ID、命令名和一个标记是否成功发送信号的布尔值。

### 2. eBPF 程序 (`signal.bpf.c`)

signal.bpf.c

```c
// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Ringbuffer Map to pass messages from kernel to user
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Optional Target Parent PID
const volatile int target_ppid = 0;

SEC("tp/syscalls/sys_enter_ptrace")
int bpf_dos(struct trace_event_raw_sys_enter *ctx)
{
    long ret = 0;
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;

    // if target_ppid is 0 then we target all pids
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid) {
            return 0;
        }
    }

    // Send signal. 9 == SIGKILL
    ret = bpf_send_signal(9);

    // Log event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}
```

- **许可证声明**

  声明了程序的许可证为 "Dual BSD/GPL"，这是为了满足 Linux 内核对 eBPF 程序的许可要求。

- **Ringbuffer Map**

  这是一个 ring buffer 类型的 map，允许 eBPF 程序在内核空间产生的消息被用户空间程序高效地读取。

- **目标父进程ID**

  `target_ppid` 是一个可选的父进程ID，用于限制哪些进程受到影响。如果它被设置为非零值，只有与其匹配的进程才会被目标。

- **主函数 `bpf_dos`**

  - **进程检查**  
    程序首先获取当前进程的ID。如果设置了 `target_ppid`，它还会获取当前进程的父进程ID并进行比较。如果两者不匹配，则直接返回。

  - **发送信号**  
    使用 `bpf_send_signal(9)` 来发送 `SIGKILL` 信号。这将终止调用 `ptrace` 的进程。

  - **记录事件**  
    使用 ring buffer map 记录这个事件。这包括了是否成功发送信号、进程ID以及进程的命令名。

总结：这个 eBPF 程序提供了一个方法，允许系统管理员或安全团队在内核级别监控和干预 `ptrace` 调用，提供了一个对抗潜在恶意活动或误操作的额外层次。

## 编译运行

eunomia-bpf 是一个结合 Wasm 的开源 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。可以参考 <https://github.com/eunomia-bpf/eunomia-bpf> 下载和安装 ecc 编译工具链和 ecli 运行时。我们使用 eunomia-bpf 编译运行这个例子。

编译：

```bash
./ecc signal.bpf.c signal.h
```

使用方式：

```console
$ sudo ./ecli package.json
TIME     PID    COMM   SUCCESS
```

这个程序会对任何试图使用 `ptrace` 系统调用的程序，例如 `strace`，发出 `SIG_KILL` 信号。
一旦 eBPF 程序开始运行，你可以通过运行以下命令进行测试：

```bash
$ strace /bin/whoami
Killed
```

原先的 console 中会输出：

```txt
INFO [bpf_loader_lib::skeleton] Running ebpf program...
TIME     PID    COMM   SUCCESS 
13:54:45  8857  strace true
```

完整的源代码可以参考：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/25-signal>

## 总结

通过这个实例，我们深入了解了如何将 eBPF 程序与用户态程序相结合，实现对系统调用的监控和干预。eBPF 提供了一种在内核空间执行程序的机制，这种技术不仅限于监控，还可用于性能优化、安全防御、系统诊断等多种场景。对于开发者来说，这为Linux系统的性能调优和故障排查提供了一种强大且灵活的工具。

最后，如果您对 eBPF 技术感兴趣，并希望进一步了解和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 和教程网站 <https://eunomia.dev/zh/tutorials/。>

## 参考资料

- <https://github.com/pathtofile/bad-bpf>
- <https://www.mail-archive.com/netdev@vger.kernel.org/msg296358.html>
