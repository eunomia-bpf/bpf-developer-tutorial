# eBPF Tutorial by Example 12: Using eBPF Program Profile for Performance Analysis

This tutorial will guide you on using eBPF programs for performance analysis with a Rust implementation. We will leverage the perf mechanism in the kernel to learn how to capture the execution time of functions and view performance data.

This implementation uses libbpf-rs, a Rust wrapper around libbpf, along with blazesym for symbol resolution. Perf is a performance analysis tool in the Linux kernel that allows users to measure and analyze the performance of kernel and user space programs, as well as obtain corresponding call stacks. It collects performance data using hardware counters and software events in the kernel.

## eBPF Tool: profile Performance Analysis Example

The `profile` tool is implemented based on eBPF and utilizes the perf events in the Linux kernel for performance analysis. The `profile` tool periodically samples each processor to capture the execution of kernel and user space functions.

In the stack trace information, the tool displays the memory addresses of function calls, which represent the most primitive location information. Through symbol resolution, these addresses are converted to corresponding function names, allowing developers to directly identify which functions are being executed. Furthermore, when debug information is available, the tool can provide source code file names and specific line numbers, pinpointing the exact location in the code. This complete information chain from addresses to symbols to source code locations provides developers with a comprehensive perspective for performance analysis.

This detailed information helps developers quickly locate performance bottlenecks and optimize code. By analyzing which functions are frequently called and which code paths consume the most CPU time, developers can perform targeted optimizations. Additionally, this stack trace information can be converted into flame graph format, providing a visual representation of program execution hotspots that makes performance issues immediately apparent.

In this example, you can compile and run it with Rust and Cargo:

**Prerequisites:**
- Rust and Cargo installed (see ["The Cargo Book"](https://rustwiki.org/en/cargo/getting-started/installation.html))
- Clang and development libraries

```console
$ git submodule update --init --recursive
$ sudo apt install clang libelf1 libelf-dev zlib1g-dev
$ make
$ sudo ./profile
```

**Sample Output:**
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

The tool provides detailed stack traces with symbol resolution, including function names, offsets, and source file locations when available.

## Implementation Principle

The `profile` tool consists of two parts: the eBPF program in kernel space and the `profile` symbol handling program in user space. The `profile` symbol handling program is responsible for loading the eBPF program and processing the data outputted by the eBPF program.

### Kernel Space Part

The implementation logic of the eBPF program in kernel space mainly relies on perf events to periodically sample the stack of the program, thereby capturing its execution flow.

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
    event->timestamp = bpf_ktime_get_ns();  // Capture timestamp

    if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
        event->comm[0] = 0;

    event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

    event->ustack_sz = 
        bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

    bpf_ringbuf_submit(event, 0);

    return 0;
}
```

The header file `profile.h` defines the event structure:

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PROFILE_H_
#define __PROFILE_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct stacktrace_event {
    __u32 pid;
    __u32 cpu_id;
    __u64 timestamp;  // Kernel timestamp in nanoseconds
    char comm[TASK_COMM_LEN];
    __s32 kstack_sz;
    __s32 ustack_sz;
    stack_trace_t kstack;
    stack_trace_t ustack;
};

#endif /* __PROFILE_H_ */
```

Next, we will focus on the key part of the kernel code.

1. Define eBPF maps `events`:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");
```

Here, a eBPF maps of type `BPF_MAP_TYPE_RINGBUF` is defined. The Ring Buffer is a high-performance circular buffer used to transfer data between the kernel and user space. `max_entries` sets the maximum size of the Ring Buffer.

2. Define `perf_event` eBPF program:

```c
SEC("perf_event")
int profile(void *ctx)
```

Here, a eBPF program named `profile` is defined, which will be executed when a perf event is triggered.

3. Get process ID and CPU ID:

```c
int pid = bpf_get_current_pid_tgid() >> 32;
int cpu_id = bpf_get_smp_processor_id();
```

The function `bpf_get_current_pid_tgid()` returns the PID and TID of the current process. By right shifting 32 bits, we get the PID. The function `bpf_get_smp_processor_id()` returns the ID of the current CPU.

4. Reserve space in the Ring Buffer:

```c
event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
if (!event)
    return 1;
```

Use the `bpf_ringbuf_reserve()` function to reserve space in the Ring Buffer for storing the collected stack information. If the reservation fails, return an error.

5. Get the current process name:

```c

if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
    event->comm[0] = 0;
```

Use the `bpf_get_current_comm()` function to get the current process name and store it in `event->comm`.

6. Get kernel stack information:

```c

event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);
```

Use the `bpf_get_stack()` function to get kernel stack information. Store the result in `event->kstack` and the size in `event->kstack_sz`.

7. Get user space stack information:

```c
event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);
```

Using the `bpf_get_stack()` function with the `BPF_F_USER_STACK` flag retrieves information about the user space stack. Store the result in `event->ustack` and its size in `event->ustack_sz`.

8. Submit the event to the Ring Buffer:

```c
    bpf_ringbuf_submit(event, 0);
```

Finally, use the `bpf_ringbuf_submit()` function to submit the event to the Ring Buffer for the user space program to read and process.

This kernel mode eBPF program captures the program's execution flow by sampling the kernel stack and user space stack of the program periodically. These data are stored in the Ring Buffer for the user mode `profile` program to read.

### User Mode Section (Rust Implementation)

The user-space portion is implemented in Rust using libbpf-rs and blazesym. The main components include:

**Main Entry Point (src/main.rs):**
```rust
use std::mem::MaybeUninit;
use std::time::Duration;
use clap::{ArgAction, Parser};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};

mod profile {
    include!(concat!(env!("OUT_DIR"), "/profile.skel.rs"));
}
mod syscall;
mod event;
mod perf;

use profile::*;

#[derive(Parser, Debug)]
struct Args {
    /// Sampling frequency
    #[arg(short, default_value_t = 50)]
    freq: u64,
    
    /// Increase verbosity (can be supplied multiple times)
    #[arg(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
    verbosity: u8,
    
    /// Use software event for triggering stack trace capture
    #[arg(long = "sw-event")]
    sw_event: bool,
    
    /// Filter by PID (optional)
    #[arg(short = 'p', long = "pid")]
    pid: Option<i32>,
    
    /// Output in extended folded format
    #[arg(short = 'E', long = "fold-extend")]
    fold_extend: bool,
}

fn main() -> Result<(), libbpf_rs::Error> {
    let args = Args::parse();
    
    // Set up logging based on verbosity
    let level = match args.verbosity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };
    
    // Initialize BPF skeleton
    let skel_builder = ProfileSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let skel = open_skel.load()?;
    
    // Set up perf events and attach BPF program
    let pefds = perf::init_perf_monitor(args.freq, args.sw_event, args.pid)?;
    let _links = perf::attach_perf_event(&pefds, &skel.progs.profile);
    
    // Set up ring buffer with event handler
    let mut builder = libbpf_rs::RingBufferBuilder::new();
    let output_format = if args.fold_extend {
        event::OutputFormat::FoldedExtended
    } else {
        event::OutputFormat::Standard
    };
    
    let event_handler = event::EventHandler::new(output_format);
    builder.add(&skel.maps.events, move |data| {
        event_handler.handle(data)
    })?;
    
    let ringbuf = builder.build()?;
    while ringbuf.poll(Duration::MAX).is_ok() {}
    
    perf::close_perf_events(pefds)?;
    Ok(())
}
```

The `perf_event_open` function is a wrapper for the perf_event_open system call. It takes a pointer to a perf_event_attr structure to specify the type and attributes of the perf event. The pid parameter is used to specify the process ID to monitor (-1 for monitoring all processes), and the cpu parameter is used to specify the CPU to monitor. The group_fd parameter is used to group perf events, and we use -1 here to indicate no grouping is needed. The flags parameter is used to set some flags, and we use PERF_FLAG_FD_CLOEXEC to ensure file descriptors are closed when executing exec series system calls.

In the main function:

```c
for (cpu = 0; cpu < num_cpus; cpu++) {
    // ...
}
```

This loop sets up perf events and attaches eBPF programs for each online CPU. Firstly, it checks if the current CPU is online and skips if it's not. Then, it uses the perf_event_open() function to set up perf events for the current CPU and stores the returned file descriptor in the pefds array. Finally, it attaches the eBPF program to the perf event using the bpf_program__attach_perf_event() function. The links array is used to store the BPF links for each CPU so that they can be destroyed when the program ends.By doing so, user-mode programs set perf events for each online CPU and attach eBPF programs to these perf events to monitor all online CPUs in the system.

**Event Processing and Symbol Resolution (src/event.rs):**
```rust
use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};
use blazesym::symbolize;
use nix::sys::sysinfo;

pub const MAX_STACK_DEPTH: usize = 128;
pub const TASK_COMM_LEN: usize = 16;

// A Rust version of stacktrace_event in profile.h
#[repr(C)]
pub struct StacktraceEvent {
    pub pid: u32,
    pub cpu_id: u32,
    pub timestamp: u64,  // Kernel timestamp in nanoseconds
    pub comm: [u8; TASK_COMM_LEN],
    pub kstack_size: i32,
    pub ustack_size: i32,
    pub kstack: [u64; MAX_STACK_DEPTH],
    pub ustack: [u64; MAX_STACK_DEPTH],
}

pub enum OutputFormat {
    Standard,
    FoldedExtended,  // For flame graph generation
}

pub struct EventHandler {
    symbolizer: symbolize::Symbolizer,
    format: OutputFormat,
    boot_time_ns: u64,  // System boot time for timestamp conversion
}

impl EventHandler {
    pub fn new(format: OutputFormat) -> Self {
        let boot_time_ns = Self::get_boot_time_ns();
        Self {
            symbolizer: symbolize::Symbolizer::new(),
            format,
            boot_time_ns,
        }
    }
    
    fn get_boot_time_ns() -> u64 {
        // Calculate boot time from current time minus uptime
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before Unix epoch");
        let now_ns = now.as_nanos() as u64;
        
        let info = sysinfo::sysinfo().expect("Failed to get sysinfo");
        let uptime_ns = (info.uptime().as_secs_f64() * 1_000_000_000.0) as u64;
        
        now_ns - uptime_ns
    }
    
    pub fn handle(&self, data: &[u8]) -> ::std::os::raw::c_int {
        let event = unsafe { &*(data.as_ptr() as *const StacktraceEvent) };
        
        if event.kstack_size <= 0 && event.ustack_size <= 0 {
            return 1;
        }
        
        match self.format {
            OutputFormat::Standard => self.handle_standard(event),
            OutputFormat::FoldedExtended => self.handle_folded_extended(event),
        }
        
        0
    }
    
    fn handle_standard(&self, event: &StacktraceEvent) {
        let comm = std::str::from_utf8(&event.comm)
            .unwrap_or("<unknown>")
            .trim_end_matches('\0');
        
        // Convert kernel timestamp to Unix timestamp
        let unix_timestamp_ns = event.timestamp + self.boot_time_ns;
        let timestamp_sec = unix_timestamp_ns / 1_000_000_000;
        let timestamp_nsec = unix_timestamp_ns % 1_000_000_000;
        
        println!("[{}.{:09}] COMM: {} (pid={}) @ CPU {}", 
                 timestamp_sec, timestamp_nsec, comm, event.pid, event.cpu_id);
        
        // Process and symbolize stacks...
        // (implementation continues with symbolization logic)
    }
}
```

**Key Features of the Rust Implementation:**

The Rust implementation provides strong type safety through its type system, effectively preventing memory safety issues that are common in C, such as buffer overflows and null pointer dereferences. This safety guarantee allows developers to focus on business logic without worrying about low-level memory management issues.

Symbol resolution is a core feature of performance analysis tools. This implementation integrates the blazesym library, which efficiently converts memory addresses into readable function names and source code locations. Blazesym supports DWARF debug information parsing, meaning that even optimized binaries can provide accurate source file paths and line number information. This capability is crucial for pinpointing the exact code locations of performance bottlenecks.

For error handling, Rust's `Result` type provides an explicit error handling mechanism. Every operation that might fail returns a Result type, forcing developers to handle potential error conditions. This design prevents unhandled errors from causing program crashes, improving the tool's stability and reliability.

The logging system uses the `tracing` crate, which provides structured logging capabilities. Through environment variables or command-line arguments, users can dynamically adjust the log level from WARN, INFO, DEBUG to TRACE, making it convenient to obtain appropriate levels of diagnostic information in different scenarios. This flexibility is very useful for debugging and troubleshooting.

The command-line interface is implemented through the `clap` library, providing intuitive argument parsing and help message generation. Users can adjust the sampling frequency with the `-f` parameter, switch to software events using `--sw-event` in environments like virtual machines that don't support hardware performance counters, filter specific processes with the `-p` parameter, and output in an extended format suitable for flame graph generation using the `-E` parameter.

This integrated approach combines the performance of eBPF with the safety and expressiveness of Rust, providing a robust profiling tool for system performance analysis.

### Summary

Through this introductory tutorial on eBPF, we have learned how to use eBPF programs for performance analysis. In this process, we explained in detail how to create eBPF programs, monitor process performance, and retrieve data from the ring buffer for analyzing stack traces. We also learned how to use the `perf_event_open()` function to set up performance monitoring and attach BPF programs to performance events. In this tutorial, we also demonstrated how to write eBPF programs to capture the kernel and userspace stack information of processes in order to analyze program performance bottlenecks. With this example, you can understand the powerful features of eBPF in performance analysis.

If you want to learn more about eBPF knowledge and practices, please refer to the official documentation of eunomia-bpf: <https://github.com/eunomia-bpf/eunomia-bpf>. You can also visit our tutorial code repository <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials.

The next tutorial will further explore advanced features of eBPF. We will continue to share more content about eBPF development practices to help you better understand and master eBPF technology. We hope these contents will be helpful for your learning and practice on the eBPF development journey.

> The original link of this article: <https://eunomia.dev/tutorials/12-profile>
