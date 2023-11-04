# eBPF 入门开发实践教程十一：在 eBPF 中使用 libbpf 开发用户态程序并跟踪 exec() 和 exit() 系统调用

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

在本教程中，我们将了解内核态和用户态的 eBPF 程序是如何协同工作的。我们还将学习如何使用原生的 libbpf 开发用户态程序，将 eBPF 应用打包为可执行文件，实现跨内核版本分发。

## libbpf 库，以及为什么需要使用它

libbpf 是一个 C 语言库，伴随内核版本分发，用于辅助 eBPF 程序的加载和运行。它提供了用于与 eBPF 系统交互的一组 C API，使开发者能够更轻松地编写用户态程序来加载和管理 eBPF 程序。这些用户态程序通常用于分析、监控或优化系统性能。

使用 libbpf 库有以下优势：

- 它简化了 eBPF 程序的加载、更新和运行过程。
- 它提供了一组易于使用的 API，使开发者能够专注于编写核心逻辑，而不是处理底层细节。
- 它能够确保与内核中的 eBPF 子系统的兼容性，降低了维护成本。

同时，libbpf 和 BTF（BPF Type Format）都是 eBPF 生态系统的重要组成部分。它们各自在实现跨内核版本兼容方面发挥着关键作用。BTF（BPF Type Format）是一种元数据格式，用于描述 eBPF 程序中的类型信息。BTF 的主要目的是提供一种结构化的方式，以描述内核中的数据结构，以便 eBPF 程序可以更轻松地访问和操作它们。

BTF 在实现跨内核版本兼容方面的关键作用如下：

- BTF 允许 eBPF 程序访问内核数据结构的详细类型信息，而无需对特定内核版本进行硬编码。这使得 eBPF 程序可以适应不同版本的内核，从而实现跨内核版本兼容。
- 通过使用 BPF CO-RE（Compile Once, Run Everywhere）技术，eBPF 程序可以利用 BTF 在编译时解析内核数据结构的类型信息，进而生成可以在不同内核版本上运行的 eBPF 程序。

结合 libbpf 和 BTF，eBPF 程序可以在各种不同版本的内核上运行，而无需为每个内核版本单独编译。这极大地提高了 eBPF 生态系统的可移植性和兼容性，降低了开发和维护的难度。

## 什么是 bootstrap

Bootstrap 是一个使用 libbpf 的完整应用，它利用 eBPF 程序来跟踪内核中的 exec() 系统调用（通过 SEC("tp/sched/sched_process_exec") handle_exec BPF 程序），这主要对应于新进程的创建（不包括 fork() 部分）。此外，它还跟踪进程的 exit() 系统调用（通过 SEC("tp/sched/sched_process_exit") handle_exit BPF 程序），以了解每个进程何时退出。

这两个 BPF 程序共同工作，允许捕获关于新进程的有趣信息，例如二进制文件的文件名，以及测量进程的生命周期，并在进程结束时收集有趣的统计信息，例如退出代码或消耗的资源量等。这是深入了解内核内部并观察事物如何真正运作的良好起点。

Bootstrap 还使用 argp API（libc 的一部分）进行命令行参数解析，使得用户可以通过命令行选项配置应用行为。这种方式提供了灵活性，让用户能够根据实际需求自定义程序行为。虽然这些功能使用 eunomia-bpf 工具也可以实现，但是这里我们使用 libbpf 可以在用户态提供更高的可扩展性，不过也带来了不少额外的复杂度。

## Bootstrap

Bootstrap 分为两个部分：内核态和用户态。内核态部分是一个 eBPF 程序，它跟踪 exec() 和 exit() 系统调用。用户态部分是一个 C 语言程序，它使用 libbpf 库来加载和运行内核态程序，并处理从内核态程序收集的数据。

### 内核态 eBPF 程序 bootstrap.bpf.c

```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
} exec_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    unsigned fname_off;
    struct event *e;
    pid_t pid;
    u64 ts;

    /* remember time exec() was executed for this PID */
    pid = bpf_get_current_pid_tgid() >> 32;
    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

    /* don't emit exec events when minimum duration is specified */
    if (min_duration_ns)
        return 0;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task();

    e->exit_event = false;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    /* successfully submit it to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, tid;
    u64 id, ts, *start_ts, duration_ns = 0;
    
    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    /* if we recorded start of the process, calculate lifetime duration */
    start_ts = bpf_map_lookup_elem(&exec_start, &pid);
    if (start_ts)
        duration_ns = bpf_ktime_get_ns() - *start_ts;
    else if (min_duration_ns)
        return 0;
    bpf_map_delete_elem(&exec_start, &pid);

    /* if process didn't live long enough, return early */
    if (min_duration_ns && duration_ns < min_duration_ns)
        return 0;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task();

    e->exit_event = true;
    e->duration_ns = duration_ns;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

这段代码是一个内核态 eBPF 程序（bootstrap.bpf.c），主要用于跟踪 exec() 和 exit() 系统调用。它通过 eBPF 程序捕获进程的创建和退出事件，并将相关信息发送到用户态程序进行处理。下面是对代码的详细解释。

首先，我们引入所需的头文件，定义 eBPF 程序的许可证以及两个 eBPF maps：exec_start 和 rb。exec_start 是一个哈希类型的 eBPF map，用于存储进程开始执行时的时间戳。rb 是一个环形缓冲区类型的 eBPF map，用于存储捕获的事件数据，并将其发送到用户态程序。

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
} exec_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;
```

接下来，我们定义了一个名为 handle_exec 的 eBPF 程序，它会在进程执行 exec() 系统调用时触发。首先，我们从当前进程中获取 PID，记录进程开始执行的时间戳，然后将其存储在 exec_start map 中。

```c
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    // ...
    pid = bpf_get_current_pid_tgid() >> 32;
    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

    // ...
}
```

然后，我们从环形缓冲区 map rb 中预留一个事件结构，并填充相关数据，如进程 ID、父进程 ID、进程名等。之后，我们将这些数据发送到用户态程序进行处理。

```c
    // reserve sample from BPF ringbuf
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // fill out the sample with data
    task = (struct task_struct *)bpf_get_current_task();

    e->exit_event = false;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    // successfully submit it to user-space for post-processing
    bpf_ringbuf_submit(e, 0);
    return 0;
```

最后，我们定义了一个名为 handle_exit 的 eBPF 程序，它会在进程执行 exit() 系统调用时触发。首先，我们从当前进程中获取 PID 和 TID（线程 ID）。如果 PID 和 TID 不相等，说明这是一个线程退出，我们将忽略此事件。

```c
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
    // ...
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    // ...
}
```

接着，我们查找之前存储在 exec_start map 中的进程开始执行的时间戳。如果找到了时间戳，我们将计算进程的生命周期（持续时间），然后从 exec_start map 中删除该记录。如果未找到时间戳且指定了最小持续时间，则直接返回。

```c
    // if we recorded start of the process, calculate lifetime duration
    start_ts = bpf_map_lookup_elem(&exec_start, &pid);
    if (start_ts)
        duration_ns = bpf_ktime_get_ns() - *start_ts;
    else if (min_duration_ns)
        return 0;
    bpf_map_delete_elem(&exec_start, &pid);

    // if process didn't live long enough, return early
    if (min_duration_ns && duration_ns < min_duration_ns)
        return 0;
```

然后，我们从环形缓冲区 map rb 中预留一个事件结构，并填充相关数据，如进程 ID、父进程 ID、进程名、进程持续时间等。最后，我们将这些数据发送到用户态程序进行处理。

```c
    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task();

    e->exit_event = true;
    e->duration_ns = duration_ns;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

这样，当进程执行 exec() 或 exit() 系统调用时，我们的 eBPF 程序会捕获相应的事件，并将详细信息发送到用户态程序进行后续处理。这使得我们可以轻松地监控进程的创建和退出，并获取有关进程的详细信息。

除此之外，在 bootstrap.h 中，我们还定义了和用户态交互的数据结构：

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
    int pid;
    int ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    bool exit_event;
};

#endif /* __BOOTSTRAP_H */
```

### 用户态，bootstrap.c

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"

static struct env {
    bool verbose;
    long min_duration_ms;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF bootstrap demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'v':
        env.verbose = true;
        break;
    case 'd':
        errno = 0;
        env.min_duration_ms = strtol(arg, NULL, 10);
        if (errno || env.min_duration_ms <= 0) {
            fprintf(stderr, "Invalid duration: %s\n", arg);
            argp_usage(state);
        }
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    if (e->exit_event) {
        printf("%-8s %-5s %-16s %-7d %-7d [%u]",
               ts, "EXIT", e->comm, e->pid, e->ppid, e->exit_code);
        if (e->duration_ns)
            printf(" (%llums)", e->duration_ns / 1000000);
        printf("\n");
    } else {
        printf("%-8s %-5s %-16s %-7d %-7d %s\n",
               ts, "EXEC", e->comm, e->pid, e->ppid, e->filename);
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct bootstrap_bpf *skel;
    int err;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
    skel = bootstrap_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Parameterize BPF code with minimum duration parameter */
    skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

    /* Load & verify BPF programs */
    err = bootstrap_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = bootstrap_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Process events */
    printf("%-8s %-5s %-16s %-7s %-7s %s\n",
           "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    /* Clean up */
    ring_buffer__free(rb);
    bootstrap_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
```

这个用户态程序主要用于加载、验证、附加 eBPF 程序，以及接收 eBPF 程序收集的事件数据，并将其打印出来。我们将分析一些关键部分。

首先，我们定义了一个 env 结构，用于存储命令行参数：

```c
static struct env {
    bool verbose;
    long min_duration_ms;
} env;
```

接下来，我们使用 argp 库来解析命令行参数：

```c
static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    // ...
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};
```

main() 函数中，首先解析命令行参数，然后设置 libbpf 的打印回调函数 libbpf_print_fn，以便在需要时输出调试信息：

```c
err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
if (err)
    return err;

libbpf_set_print(libbpf_print_fn);
```

接下来，我们打开 eBPF 脚手架（skeleton）文件，将最小持续时间参数传递给 eBPF 程序，并加载和附加 eBPF 程序：

```c
skel = bootstrap_bpf__open();
if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
}

skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

err = bootstrap_bpf__load(skel);
if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
}

err = bootstrap_bpf__attach(skel);
if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
}
```

然后，我们创建一个环形缓冲区（ring buffer），用于接收 eBPF 程序发送的事件数据：

```c
rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
}
```

handle_event() 函数会处理从 eBPF 程序收到的事件。根据事件类型（进程执行或退出），它会提取并打印事件信息，如时间戳、进程名、进程 ID、父进程 ID、文件名或退出代码等。

最后，我们使用 ring_buffer__poll() 函数轮询环形缓冲区，处理收到的事件数据：

```c
while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    // ...
}
```

当程序收到 SIGINT 或 SIGTERM 信号时，它会最后完成清理、退出操作，关闭和卸载 eBPF 程序：

```c
cleanup:
 /* Clean up */
 ring_buffer__free(rb);
 bootstrap_bpf__destroy(skel);

 return err < 0 ? -err : 0;
}
```

## 安装依赖

构建示例需要 clang、libelf 和 zlib。包名在不同的发行版中可能会有所不同。

在 Ubuntu/Debian 上，你需要执行以下命令：

```shell
sudo apt install clang libelf1 libelf-dev zlib1g-dev
```

在 CentOS/Fedora 上，你需要执行以下命令：

```shell
sudo dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

## 编译运行

编译运行上述代码：

```console
$ git submodule update --init --recursive
$ make
  BPF      .output/bootstrap.bpf.o
  GEN-SKEL .output/bootstrap.skel.h
  CC       .output/bootstrap.o
  BINARY   bootstrap
$ sudo ./bootstrap 
[sudo] password for yunwei: 
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
03:16:41 EXEC  sh               110688  80168   /bin/sh
03:16:41 EXEC  which            110689  110688  /usr/bin/which
03:16:41 EXIT  which            110689  110688  [0] (0ms)
03:16:41 EXIT  sh               110688  80168   [0] (0ms)
03:16:41 EXEC  sh               110690  80168   /bin/sh
03:16:41 EXEC  ps               110691  110690  /usr/bin/ps
03:16:41 EXIT  ps               110691  110690  [0] (49ms)
03:16:41 EXIT  sh               110690  80168   [0] (51ms)
```

## 总结

通过这个实例，我们了解了如何将 eBPF 程序与用户态程序结合使用。这种结合为开发者提供了一个强大的工具集，可以实现跨内核和用户空间的高效数据收集和处理。通过使用 eBPF 和 libbpf，您可以构建更高效、可扩展和安全的监控和性能分析工具。

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。
