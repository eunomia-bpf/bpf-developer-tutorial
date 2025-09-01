# eBPF 入门实践教程十二：使用 eBPF 程序 profile 进行性能分析

本教程将指导您使用 eBPF 程序和 Rust 实现进行性能分析。我们将利用内核中的 perf 机制，学习如何捕获函数的执行时间以及如何查看性能数据。

本实现使用 libbpf-rs（libbpf 的 Rust 封装）以及 blazesym 进行符号解析。perf 是 Linux 内核中的性能分析工具，允许用户测量和分析内核及用户空间程序的性能，以及获取对应的调用堆栈。它利用内核中的硬件计数器和软件事件来收集性能数据。

## eBPF 工具：profile 性能分析示例

`profile` 工具基于 eBPF 实现，利用 Linux 内核中的 perf 事件进行性能分析。`profile` 工具会定期对每个处理器进行采样，以便捕获内核函数和用户空间函数的执行。

在栈回溯信息中，工具会显示函数调用的内存地址，这是最原始的位置信息。通过符号解析，这些地址会被转换为对应的函数名称，让开发者能够直接识别是哪个函数在执行。更进一步，如果调试信息可用，工具还能提供源代码文件名称和具体的行号，精确定位到代码的具体位置。这种从地址到符号，再到源代码位置的完整信息链，为开发人员提供了全方位的性能分析视角。

这些详细的信息有助于开发人员快速定位性能瓶颈和优化代码。通过分析哪些函数被频繁调用，哪些代码路径消耗了最多的 CPU 时间，开发者可以有针对性地进行优化。更进一步，这些栈回溯信息可以被转换成火焰图格式，通过可视化的方式直观展示程序的执行热点，让性能问题一目了然。

在本示例中，可以通过 Rust 和 Cargo 编译运行：

**前提条件：**
- 安装 Rust 和 Cargo（参考 [Cargo 手册](https://rustwiki.org/en/cargo/getting-started/installation.html)）
- 安装 Clang 和开发库

```console
$ git submodule update --init --recursive
$ sudo apt install clang libelf1 libelf-dev zlib1g-dev
$ make
$ sudo ./profile
```

**示例输出：**
```console
[1756723652.366364804] COMM: node (pid=285503) @ CPU 64
No Kernel Stack
Userspace:
0x0072e2a97f4be0: v8::internal::Scanner::Next() @ 0x15f47c0+0x420
0x0072e2a97d9051: v8::internal::ParserBase<v8::internal::PreParser>::ParseBlock(...) @ 0x15d8fc0+0x91
0x0072e2a97d6df0: v8::internal::ParserBase<v8::internal::PreParser>::ParseStatement(...) @ 0x15d6ce0+0x110
...

[1756723657.337170411] COMM: qemu-system-x86 (pid=4166437) @ CPU 70
Kernel:
0xffffffff95f403d5: _raw_spin_lock_irq @ 0xffffffff95f403b0+0x25
0xffffffff94e2b6d8: __flush_work @ 0xffffffff94e2b630+0xa8
0xffffffff94e2ba5c: flush_work @ 0xffffffff94e2ba40+0x1c
0xffffffff95852672: tty_buffer_flush_work @ 0xffffffff95852660+0x12
...
Userspace:
0x005849a7fbbd33: qemu_poll_ns @ 0xc63c4c+0xe7 /home/victoryang00/CXLMemSim/lib/qemu/build/../util/qemu-timer.c:347:1
0x005849a7fb64d7: os_host_main_loop_wait @ 0xc5e473+0x64 /home/victoryang00/CXLMemSim/lib/qemu/build/../util/main-loop.c:305:11
...
```

该工具提供详细的堆栈跟踪和符号解析，包括函数名、偏移量以及可用时的源文件位置。

## 实现原理

profile 工具由两个部分组成，内核态中的 eBPF 程序和用户态中的 `profile` 符号处理程序。`profile` 符号处理程序负责加载 eBPF 程序，以及处理 eBPF 程序输出的数据。

### 内核态部分

内核态 eBPF 程序的实现逻辑主要是借助 perf event，对程序的堆栈进行定时采样，从而捕获程序的执行流程。

```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "profile.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("perf_event")
int profile(void *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    int cpu_id = bpf_get_smp_processor_id();
    struct stacktrace_event *event;
    int cp;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 1;

    event->pid = pid;
    event->cpu_id = cpu_id;
    event->timestamp = bpf_ktime_get_ns();  // 捕获时间戳

    if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
        event->comm[0] = 0;

    event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

    event->ustack_sz = 
        bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

    bpf_ringbuf_submit(event, 0);

    return 0;
}
```

接下来，我们将重点讲解内核态代码的关键部分。

1. 定义 eBPF maps `events`：

    ```c

    struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
    } events SEC(".maps");
    ```

    这里定义了一个类型为 `BPF_MAP_TYPE_RINGBUF` 的 eBPF  maps 。Ring Buffer 是一种高性能的循环缓冲区，用于在内核和用户空间之间传输数据。`max_entries` 设置了 Ring Buffer 的最大大小。

2. 定义 `perf_event` eBPF 程序：

    ```c
    SEC("perf_event")
    int profile(void *ctx)
    ```

    这里定义了一个名为 `profile` 的 eBPF 程序，它将在 perf 事件触发时执行。

3. 获取进程 ID 和 CPU ID：

    ```c
    int pid = bpf_get_current_pid_tgid() >> 32;
    int cpu_id = bpf_get_smp_processor_id();
    ```

    `bpf_get_current_pid_tgid()` 函数返回当前进程的 PID 和 TID，通过右移 32 位，我们得到 PID。`bpf_get_smp_processor_id()` 函数返回当前 CPU 的 ID。

4. 预留 Ring Buffer 空间：

    ```c
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 1;
    ```

    通过 `bpf_ringbuf_reserve()` 函数预留 Ring Buffer 空间，用于存储采集的栈信息。若预留失败，返回错误.

5. 获取当前进程名：

    ```c

    if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
        event->comm[0] = 0;
    ```

    使用 `bpf_get_current_comm()` 函数获取当前进程名并将其存储到 `event->comm`。

6. 获取时间戳：

    ```c
    event->timestamp = bpf_ktime_get_ns();
    ```

    使用 `bpf_ktime_get_ns()` 函数获取内核时间戳（以纳秒为单位）。

7. 获取内核栈信息：

    ```c
    event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);
    ```

    使用 `bpf_get_stack()` 函数获取内核栈信息。将结果存储在 `event->kstack`，并将其大小存储在 `event->kstack_sz`。

8. 获取用户空间栈信息：

    ```c
    event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);
    ```

    同样使用 `bpf_get_stack()` 函数，但传递 `BPF_F_USER_STACK` 标志以获取用户空间栈信息。将结果存储在 `event->ustack`，并将其大小存储在 `event->ustack_sz`。

9. 将事件提交到 Ring Buffer：

    ```c
    bpf_ringbuf_submit(event, 0);
    ```

    最后，使用 `bpf_ringbuf_submit()` 函数将事件提交到 Ring Buffer，以便用户空间程序可以读取和处理。

    这个内核态 eBPF 程序通过定期采样程序的内核栈和用户空间栈来捕获程序的执行流程。这些数据将存储在 Ring Buffer 中，以便用户态的 `profile` 程序能读取。

### 用户态部分（Rust 实现）

用户空间部分使用 Rust 实现，利用 libbpf-rs 和 blazesym 库来处理 eBPF 程序的加载、管理和数据处理。整个用户态程序的架构分为几个核心模块：主程序入口负责参数解析和整体流程控制，perf 模块处理性能事件的设置和管理，event 模块负责事件数据的处理和符号解析，syscall 模块封装了底层的系统调用接口。这种模块化的设计使得代码结构清晰，易于维护和扩展。

**主入口点（src/main.rs）：**

主程序是整个工具的入口点，负责协调各个模块的工作。它首先解析命令行参数，根据用户指定的选项配置采样频率、事件类型等参数。然后初始化 BPF 程序，设置性能监控事件，并启动事件循环来持续处理来自内核的性能数据。程序使用了 Rust 的所有权系统来确保资源的正确管理，在程序退出时自动清理所有分配的资源。
```rust
use clap::Parser;
use libbpf_rs::PerfBufferBuilder;
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
struct Args {
    #[arg(short = 'f', default_value = "50")]
    /// 采样频率
    freq: u64,
    
    #[arg(long, action = clap::ArgAction::SetTrue)]
    /// 使用软件事件触发
    sw_event: bool,
    
    #[arg(short, long)]
    /// 按 PID 过滤（可选）
    pid: Option<i32>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // 初始化日志系统
    let filter = EnvFilter::from_default_env();
    fmt().with_env_filter(filter).init();
    
    // 设置 perf 事件并附加 BPF 程序
    let mut skel_builder = ProfileSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    
    // 在所有 CPU 上附加 perf 事件
    for cpu in online_cpus()? {
        let perf_fd = perf_event_open(cpu, args.pid, args.freq, args.sw_event)?;
        skel.progs().profile().attach_perf_event(perf_fd)?;
    }
    
    // 处理来自 ring buffer 的事件
    let mut builder = PerfBufferBuilder::new(skel.maps().events());
    builder.add_callback(handle_event);
    let perf_buffer = builder.build()?;
    
    loop {
        perf_buffer.poll(Duration::from_millis(100))?;
    }
}
```

`perf_event_open` 这个函数是一个对 perf_event_open 系统调用的封装。它接收一个 perf_event_attr 结构体指针，用于指定 perf event 的类型和属性。pid 参数用于指定要监控的进程 ID（-1 表示监控所有进程），cpu 参数用于指定要监控的 CPU。group_fd 参数用于将 perf event 分组，这里我们使用 -1，表示不需要分组。flags 参数用于设置一些标志，这里我们使用 PERF_FLAG_FD_CLOEXEC 以确保在执行 exec 系列系统调用时关闭文件描述符。

在 main 函数中：

```c
for (cpu = 0; cpu < num_cpus; cpu++) {
    // ...
}
```

这个循环针对每个在线 CPU 设置 perf event 并附加 eBPF 程序。首先，它会检查当前 CPU 是否在线，如果不在线则跳过。然后，使用 perf_event_open() 函数为当前 CPU 设置 perf event，并将返回的文件描述符存储在 pefds 数组中。最后，使用 bpf_program__attach_perf_event() 函数将 eBPF 程序附加到 perf event。links 数组用于存储每个 CPU 上的 BPF 链接，以便在程序结束时销毁它们。

通过这种方式，用户态程序为每个在线 CPU 设置 perf event，并将 eBPF 程序附加到这些 perf event 上，从而实现对系统中所有在线 CPU 的监控。

**事件处理和符号解析（src/event.rs）：**

事件处理模块是整个性能分析工具的核心组件之一。它负责接收来自内核的原始事件数据，进行必要的转换和解析，最终输出人类可读的性能信息。这个模块的设计考虑了多种输出格式的需求，既支持标准的详细输出，也支持适合生成火焰图的折叠格式输出。模块中的时间戳转换逻辑将内核的单调时间戳转换为 Unix 时间戳，使得输出更容易理解和分析。符号解析功能则将原始的内存地址转换为函数名和源代码位置，大大提高了性能数据的可读性和实用性。
```rust
use blazesym::{Addr, Pid, Source, Symbolizer};
use std::time::{Duration, SystemTime};

pub struct Event {
    pub timestamp: SystemTime,
    pub pid: i32,
    pub cpu_id: u32,
    pub comm: String,
    pub kstack: Vec<u64>,
    pub ustack: Vec<u64>,
}

impl Event {
    pub fn symbolize_and_print(&self, symbolizer: &Symbolizer) {
        println!("[{:?}] COMM: {} (pid={}) @ CPU {}",
                 self.timestamp, self.comm, self.pid, self.cpu_id);
        
        // 符号化内核栈
        if !self.kstack.is_empty() {
            println!("Kernel:");
            let src = Source::Kernel(Default::default());
            let syms = symbolizer.symbolize(&src, &self.kstack).unwrap();
            print_stack_trace(&self.kstack, &syms);
        } else {
            println!("No Kernel Stack");
        }
        
        // 符号化用户栈
        if !self.ustack.is_empty() {
            println!("Userspace:");
            let src = Source::Process(Pid::from(self.pid as u32));
            let syms = symbolizer.symbolize(&src, &self.ustack).unwrap();
            print_stack_trace(&self.ustack, &syms);
        } else {
            println!("No Userspace Stack");
        }
    }
}

fn print_stack_trace(addrs: &[u64], symbols: &[Vec<blazesym::SymbolInfo>]) {
    for (addr, syms) in addrs.iter().zip(symbols.iter()) {
        if syms.is_empty() {
            println!("0x{:016x}: <no-symbol>", addr);
        } else {
            for sym in syms {
                if let Some(name) = &sym.name {
                    if let Some(file) = &sym.file_name {
                        println!("0x{:016x}: {} @ 0x{:x}+0x{:x} {}:{}",
                                addr, name, sym.addr, addr - sym.addr,
                                file, sym.line_no.unwrap_or(0));
                    } else {
                        println!("0x{:016x}: {} @ 0x{:x}+0x{:x}",
                                addr, name, sym.addr, addr - sym.addr);
                    }
                } else {
                    println!("0x{:016x}: <unknown>", addr);
                }
            }
        }
    }
}
```

**Rust 实现的主要特性：**

Rust 实现通过类型系统提供强类型安全，有效防止了 C 语言中常见的内存安全问题，如缓冲区溢出、空指针解引用等。这种安全性保证让开发者能够专注于业务逻辑而不必担心底层的内存管理问题。

符号解析是性能分析工具的核心功能之一。本实现集成了 blazesym 库，它能够高效地将内存地址转换为可读的函数名和源代码位置。blazesym 支持 DWARF 调试信息的解析，这意味着即使是经过优化的二进制文件，也能获得准确的源文件路径和行号信息。这对于定位性能瓶颈的具体代码位置至关重要。

错误处理方面，Rust 的 `Result` 类型提供了显式的错误处理机制。每个可能失败的操作都返回 Result 类型，强制开发者处理潜在的错误情况。这种设计避免了未处理错误导致的程序崩溃，提高了工具的稳定性和可靠性。

日志系统使用了 `tracing` crate，它提供了结构化的日志记录能力。通过环境变量或命令行参数，用户可以动态调整日志级别，从 WARN、INFO、DEBUG 到 TRACE，方便在不同场景下获取适当详细程度的诊断信息。这种灵活性对于调试和问题排查非常有用。

命令行界面通过 `clap` 库实现，提供了直观的参数解析和帮助信息生成。用户可以通过 `-f` 参数调整采样频率，使用 `--sw-event` 在虚拟机等不支持硬件性能计数器的环境中切换到软件事件，通过 `-p` 参数过滤特定进程，以及使用 `-E` 参数输出适合生成火焰图的扩展格式。


这种集成方法结合了 eBPF 的性能与 Rust 的安全性和表达力，提供了一个强大的系统性能分析工具。


### 总结

本实现展示了如何将 eBPF 的高性能监控能力与 Rust 的安全性和表达力相结合，创建一个强大而可靠的性能分析工具。通过这个例子，您可以了解到 eBPF 在性能分析方面的强大功能，以及如何使用现代系统编程语言来构建 eBPF 工具。

如果您希望学习更多关于 eBPF 的知识和实践，请查阅 eunomia-bpf 的官方文档：<https://github.com/eunomia-bpf/eunomia-bpf> 。您还可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。

接下来的教程将进一步探讨 eBPF 的高级特性，我们会继续分享更多有关 eBPF 开发实践的内容，帮助您更好地理解和掌握 eBPF 技术，希望这些内容对您在 eBPF 开发道路上的学习和实践有所帮助。
