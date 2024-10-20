# eBPF Tutorial by Example 15: Capturing User-Space Java GC Duration Using USDT

eBPF (Extended Berkeley Packet Filter) is a powerful network and performance analysis tool widely used in the Linux kernel. eBPF allows developers to dynamically load, update, and run user-defined code without the need to restart the kernel or modify the kernel source code. This feature provides eBPF with high flexibility and performance, making it widely applicable in network and system performance analysis. Furthermore, eBPF also supports capturing user-space application behavior using User-Level Statically Defined Tracing (USDT).

In this article of our eBPF Tutorial by Example series, we will explore how to use eBPF and USDT to capture and analyze the duration of Java garbage collection (GC) events.

## Introduction to USDT

USDT is a mechanism for inserting static tracepoints into applications, allowing developers to insert probes at critical points in the program for debugging and performance analysis purposes. These probes can be dynamically activated at runtime by tools such as DTrace, SystemTap, or eBPF, allowing access to the program's internal state and performance metrics without the need to restart the application or modify the program code. USDT is widely used in many open-source software applications such as MySQL, PostgreSQL, Ruby, Python, and Node.js.

### User-Level Tracing Mechanism: User-Level Dynamic Tracing and USDT

User-Level Dynamic Tracing allows us to instrument any user-level code by placing probes. For example, we can trace query requests in a MySQL server by placing a probe on the `dispatch_command()` function:

```bash
# ./uprobe 'p:cmd /opt/bin/mysqld:_Z16dispatch_command19enum_server_commandP3THDPcj +0(%dx):string'
Tracing uprobe cmd (p:cmd /opt/bin/mysqld:0x2dbd40 +0(%dx):string). Ctrl-C to end.
  mysqld-2855  [001] d... 19957757.590926: cmd: (0x6dbd40) arg1="show tables"
  mysqld-2855  [001] d... 19957759.703497: cmd: (0x6dbd40) arg1="SELECT * FROM numbers"
[...]
```

Here, we use the `uprobe` tool, which leverages Linux's built-in functionalities: ftrace (tracing framework) and uprobes (User-Level Dynamic Tracing, requires a relatively new Linux version, around 4.0 or later). Other tracing frameworks such as perf_events and SystemTap can also achieve this functionality.

Many other MySQL functions can be traced to obtain more information. We can list and count the number of these functions:

```bash
# ./uprobe -l /opt/bin/mysqld | more
account_hash_get_key
add_collation
add_compiled_collation
add_plugin_noargs
adjust_time_range
[...]
# ./uprobe -l /opt/bin/mysqld | wc -l
21809
```

There are 21,000 functions here. We can also trace library functions or even individual instruction offsets.

User-Level Dynamic Tracing capability is very powerful and can solve numerous problems. However, using it also has some challenges: identifying the code to trace, handling function parameters, and dealing with code modifications.

User-Level Statically Defined Tracing (USDT) can address some of these challenges. USDT probes (or "markers" at the user level) are trace macros inserted at critical positions in the code, providing a stable and well-documented API. This makes the tracing work simpler.

With USDT, we can easily trace a probe called `mysql:query__start` instead of tracing the C++ symbol `_Z16dispatch_command19enum_server_commandP3THDPcj`, which is the `dispatch_command()` function. Of course, we can still trace `dispatch_command()` and the other 21,000 mysqld functions when needed, but only when USDT probes cannot solve the problem.In Linux, USDT (User Statically Defined Tracing) has actually existed in various forms for decades. It has recently gained attention again due to the popularity of Sun's DTrace tool, which has led to many common applications, including MySQL, PostgreSQL, Node.js, Java, etc., adding USDT support. SystemTap has developed a way to consume these DTrace probes.

You may be running a Linux application that already includes USDT probes, or you may need to recompile it (usually with --enable-dtrace). You can use `readelf` to check, for example, for Node.js:

```bash
# readelf -n node
[...]
Notes at offset 0x00c43058 with length 0x00000494:
  Owner                 Data size   Description
  stapsdt              0x0000003c   NT_STAPSDT (SystemTap probe descriptors)
    Provider: node
    Name: gc__start
    Location: 0x0000000000bf44b4, Base: 0x0000000000f22464, Semaphore: 0x0000000001243028
    Arguments: 4@%esi 4@%edx 8@%rdi
[...]
  stapsdt              0x00000082       NT_STAPSDT (SystemTap probe descriptors)
    Provider: node
    Name: http__client__request
    Location: 0x0000000000bf48ff, Base: 0x0000000000f22464, Semaphore: 0x0000000001243024
    Arguments: 8@%rax 8@%rdx 8@-136(%rbp) -4@-140(%rbp) 8@-72(%rbp) 8@-80(%rbp) -4@-144(%rbp)
[...]
```

This is a Node.js recompiled with --enable-dtrace and installed with the systemtap-sdt-dev package that provides "dtrace" functionality to support USDT. Here are two probes displayed: node:gc__start (garbage collection start) and node:http__client__request.

At this point, you can use SystemTap or LTTng to trace these probes. However, built-in Linux tracers like ftrace and perf_events currently cannot do this (although perf_events support is under development).

## Introduction to Java GC

Java, as a high-level programming language, has automatic garbage collection (GC) as one of its core features. The goal of Java GC is to automatically reclaim memory space that is no longer used by the program, thereby relieving programmers of the burden of memory management. However, the GC process may cause application pauses, which can impact program performance and response time. Therefore, monitoring and analyzing Java GC events are essential for understanding and optimizing the performance of Java applications.

In the following tutorial, we will demonstrate how to use eBPF and USDT to monitor and analyze the duration of Java GC events. We hope this content will be helpful to you in your work with eBPF for application performance analysis.

USDT in kernel mode eBPF runtime may also cause relatively large performance overhead. In this case, you can also consider using user mode eBPF runtime, such as [bpftime](https://github.com/eunomia-bpf/bpftime). bpftime is a user mode eBPF runtime based on LLVM JIT/AOT. It can run eBPF programs in user mode and is compatible with kernel mode eBPF, avoiding context switching between kernel mode and user mode, thereby improving the execution efficiency of eBPF programs by 10 times.

## eBPF Implementation Mechanism

The eBPF program for Java GC is divided into two parts: kernel space and user space. We will introduce the implementation mechanisms of these two parts separately.

### Kernel Space Program

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Chen Tao */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>
#include "javagc.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, uint32_t);
    __type(value, struct data_t);
} data_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY)
    __type(key, int);
    __type(value, int);
} perf_map SEC(".maps");

__u32 time;

static int gc_start(struct pt_regs *ctx)
{
    struct data_t data = {};

    data.cpu = bpf_get_smp_processor_id();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&data_map, &data.pid, &data, 0);
    return 0;
}

static int gc_end(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct data_t *p;
    __u32 val;

    data.cpu = bpf_get_smp_processor_id();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    p = bpf_map_lookup_elem(&data_map, &data.pid);
    if (!p)
        return 0;

    val = data.ts - p->ts;
    if (val > time) {
        data.ts = val;
        bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }
    bpf_map_delete_elem(&data_map, &data.pid);
    return 0;
}

SEC("usdt")
int handle_gc_start(struct pt_regs *ctx)
{
    return gc_start(ctx);
}

SEC("usdt")
int handle_gc_end(struct pt_regs *ctx)
{
    return gc_end(ctx);
}

SEC("usdt")
int handle_mem_pool_gc_start(struct pt_regs *ctx)
{
    return gc_start(ctx);
}

SEC("usdt")
int handle_mem_pool_gc_end(struct pt_regs *ctx)
{
    return gc_end(ctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

First, we define two maps:

- `data_map`: This hashmap stores the start time of garbage collection for each process ID. The `data_t` structure contains the process ID, CPU ID, and timestamp.
- `perf_map`: This is a perf event array used to send data back to the user-space program.

Then, we have four handler functions: `gc_start`, `gc_end`, and two USDT handler functions `handle_mem_pool_gc_start` and `handle_mem_pool_gc_end`. These functions are all annotated with the BPF `SEC("usdt")` macro to capture USDT events related to garbage collection in a Java process.

The `gc_start` function is called when garbage collection starts. It first gets the current CPU ID, process ID, and timestamp, and then stores this data in `data_map`.

The `gc_end` function is called when garbage collection ends. It performs similar operations as `gc_start`, but it also retrieves the start time from `data_map` and calculates the duration of garbage collection. If the duration exceeds a set threshold (`time` variable), it sends the data back to the user-space program.

`handle_gc_start` and `handle_gc_end` are handler functions for the garbage collection start and end events, respectively, and they call `gc_start` and `gc_end`, respectively.

`handle_mem_pool_gc_start` and `handle_mem_pool_gc_end` are handler functions for the garbage collection start and end events in the memory pool, and they also call `gc_start` and `gc_end`, respectively.Finally, we have a `LICENSE` array that declares the license of the BPF program, which is required for loading the BPF program.

### User-space Program

The main goal of the user-space program is to load and run eBPF programs, as well as process data from the kernel-space program. This is achieved through the use of the libbpf library. Here, we are omitting some common code for loading and running eBPF programs and only showing the parts related to USDT.

The first function `get_jvmso_path` is used to obtain the path of the `libjvm.so` library for the running Java Virtual Machine (JVM). First, it opens the `/proc/<pid>/maps` file, which contains the memory mapping information of the process address space. Then, it searches for the line that contains `libjvm.so` in the file and copies the path of that line to the provided argument.

```c
static int get_jvmso_path(char *path)
{
    char mode[16], line[128], buf[64];
    size_t seg_start, seg_end, seg_off;
    FILE *f;
    int i = 0;

    sprintf(buf, "/proc/%d/maps", env.pid);
    f = fopen(buf, "r");
    if (!f)
        return -1;

    while (fscanf(f, "%zx-%zx %s %zx %*s %*d%[^\n]\n",
            &seg_start, &seg_end, mode, &seg_off, line) == 5) {
        i = 0;
        while (isblank(line[i]))
            i++;
        if (strstr(line + i, "libjvm.so")) {
            break;
        }
    }

    strcpy(path, line + i);
    fclose(f);

    return 0;
}
```

Next, we see the attachment of the eBPF programs (`handle_gc_start` and `handle_gc_end`) to the relevant USDT probes in the Java process. Each program achieves this by calling the `bpf_program__attach_usdt` function, which takes as parameters the BPF program, the process ID, the binary path, and the provider and name of the probe. If the probe is successfully attached, `bpf_program__attach_usdt` will return a link object, which is stored in the skeleton's link member. If the attachment fails, the program will print an error message and perform cleanup.

```c
    skel->links.handle_mem_pool_gc_start = bpf_program__attach_usdt(skel->progs.handle_gc_start, env.pid,
                                    binary_path, "hotspot", "mem__pool__gc__begin", NULL);
    if (!skel->links.handle_mem_pool_gc_start) {
        err = errno;
        fprintf(stderr, "attach usdt mem__pool__gc__begin failed: %s\n", strerror(err));
        goto cleanup;
    }

    skel->links.handle_mem_pool_gc_end = bpf_program__attach_usdt(skel->progs.handle_gc_end, env.pid,
                                binary_path, "hotspot", "mem__pool__gc__end", NULL);
    if (!skel->links.handle_mem_pool_gc_end) {
        err = errno;
        fprintf(stderr, "attach usdt mem__pool__gc__end failed: %s\n", strerror(err));
        goto cleanup;
    }

    skel->links.handle_gc_start = bpf_program__attach_usdt(skel->progs.handle_gc_start, env.pid,
binary_path, "hotspot", "gc__begin", NULL);
    if (!skel->links.handle_gc_start) {
        err = errno;
        fprintf(stderr, "attach usdt gc__begin failed: %s\n", strerror(err));
        goto cleanup;
    }

    skel->links.handle_gc_end = bpf_program__attach_usdt(skel->progs.handle_gc_end, env.pid,
                binary_path, "hotspot", "gc__end", NULL);
    if (!skel->links.handle_gc_end) {
        err = errno;
        fprintf(stderr, "attach usdt gc__end failed: %s\n", strerror(err));
        goto cleanup;
    }
```

The last function `handle_event` is a callback function used to handle data received from the perf event array. This function is triggered by the perf event array and is called each time a new event is received. The function first converts the data to a `data_t` structure, then formats the current time as a string, and finally prints the timestamp, CPU ID, process ID, and duration of the garbage collection.

```c
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct data_t *e = (struct data_t *)data;
    struct tm *tm = NULL;
    char ts[16];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    printf("%-8s %-7d %-7d %-7lld\n", ts, e->cpu, e->pid, e->ts/1000);
}
```

## Installing Dependencies

To build the example, you need clang, libelf, and zlib. The package names may vary with different distributions.

On Ubuntu/Debian, run the following command:

```shell
sudo apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, run the following command:

```shell
sudo dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

## Compiling and Running

In the corresponding directory, run Make to compile and run the code:

```console
$ make
$ sudo ./javagc -p 12345
Tracing javagc time... Hit Ctrl-C to end.
TIME     CPU     PID     GC TIME
10:00:01 10%     12345   50ms
10:00:02 12%     12345   55ms
10:00:03 9%      12345   47ms
10:00:04 13%     12345   52ms
10:00:05 11%     12345   50ms
```

Complete source code:

- <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/15-javagc>

References:

- <https://www.brendangregg.com/blog/2015-07-03/hacking-linux-usdt-ftrace.html>
- <https://github.com/iovisor/bcc/blob/master/libbpf-tools/javagc.c>

Summary.Through this introductory eBPF tutorial, we have learned how to use eBPF and USDT for dynamic tracing and analysis of Java garbage collection (GC) events. We have understood how to set USDT tracepoints in user space applications and how to write eBPF programs to capture information from these tracepoints, thereby gaining a deeper understanding and optimizing the behavior and performance of Java GC.

Additionally, we have also introduced some basic knowledge and practical techniques related to Java GC, USDT, and eBPF. This knowledge and skills are valuable for developers who want to delve into the field of network and system performance analysis.

If you would like to learn more about eBPF knowledge and practices, you can visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> to get more examples and the complete tutorial.
