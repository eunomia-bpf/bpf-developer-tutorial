# eBPF Tutorial by Example 11: Develop User-Space Programs with libbpf and Trace exec() and exit()

eBPF (Extended Berkeley Packet Filter) is a powerful network and performance analysis tool on the Linux kernel. It allows developers to dynamically load, update, and run user-defined code during kernel runtime.

In this tutorial, we will learn how kernel-space and user-space eBPF programs work together. We will also learn how to use the native libbpf to develop user-space programs, package eBPF applications into executable files, and distribute them across different kernel versions.

## The libbpf Library and Why We Need to Use It

libbpf is a C language library that is distributed with the kernel version to assist in loading and running eBPF programs. It provides a set of C APIs for interacting with the eBPF system, allowing developers to write user-space programs more easily to load and manage eBPF programs. These user-space programs are typically used for system performance analysis, monitoring, or optimization.

There are several advantages to using the libbpf library:

- It simplifies the process of loading, updating, and running eBPF programs.
- It provides a set of easy-to-use APIs, allowing developers to focus on writing core logic instead of dealing with low-level details.
- It ensures compatibility with the eBPF subsystem in the kernel, reducing maintenance costs.

At the same time, libbpf and BTF (BPF Type Format) are important components of the eBPF ecosystem. They play critical roles in achieving compatibility across different kernel versions. BTF is a metadata format used to describe type information in eBPF programs. The primary purpose of BTF is to provide a structured way to describe data structures in the kernel so that eBPF programs can access and manipulate them more easily.

The key roles of BTF in achieving compatibility across different kernel versions are as follows:

- BTF allows eBPF programs to access detailed type information of kernel data structures without hardcoding specific kernel versions. This enables eBPF programs to adapt to different kernel versions, achieving compatibility across kernel versions.
- By using BPF CO-RE (Compile Once, Run Everywhere) technology, eBPF programs can leverage BTF to parse the type information of kernel data structures during compilation, thereby generating eBPF programs that can run on different kernel versions.

By combining libbpf and BTF, eBPF programs can run on various kernel versions without the need for separate compilation for each kernel version. This greatly improves the portability and compatibility of the eBPF ecosystem and reduces the difficulty of development and maintenance.

## What is Bootstrap

Bootstrap is a complete application that utilizes libbpf. It uses eBPF programs to trace the exec() system call in the kernel (handled by the SEC("tp/sched/sched_process_exec") handle_exec BPF program), which mainly corresponds to the creation of new processes (excluding the fork() part). In addition, it also traces the exit() system call of processes (handled by the SEC("tp/sched/sched_process_exit") handle_exit BPF program) to understand when each process exits.

These two BPF programs work together to capture interesting information about new processes, such as the file name of the binary and measure the lifecycle of processes. They also collect interesting statistics, such as exit codes or resource consumption, when a process exits. This is a good starting point to gain a deeper understanding of the inner workings of the kernel and observe how things actually operate.

Bootstrap also uses the argp API (part of libc) for command-line argument parsing, allowing users to configure the behavior of the application through command-line options. This provides flexibility and allows users to customize the program behavior according to their specific needs. While these functionalities can also be achieved using the eunomia-bpf tool, using libbpf here provides higher scalability in user space at the cost of additional complexity.

## Bootstrap

Bootstrap consists of two parts: kernel space and user space. The kernel space part is an eBPF program that traces the exec() and exit() system calls. The user space part is a C language program that uses the libbpf library to load and run the kernel space program and process the data collected from the kernel space program.

### Kernel-space eBPF Program bootstrap.bpf.c

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
    if (start_ts)duration_ns = bpf_ktime_get_ns() - *start_ts;
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

This code is a kernel-level eBPF program (`bootstrap.bpf.c`) used to trace `exec()` and `exit()` system calls. It captures process creation and exit events using an eBPF program and sends the relevant information to a user-space program for processing. Below is a detailed explanation of the code.

First, we include the necessary headers and define the license for the eBPF program. We also define two eBPF maps: `exec_start` and `rb`. `exec_start` is a hash type eBPF map used to store the timestamp when a process starts executing. `rb` is a ring buffer type eBPF map used to store captured event data and send it to the user-space program.

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

Next, we define an eBPF program named `handle_exec` which is triggered when a process executes the `exec()` system call. First, we retrieve the PID from the current process, record the timestamp when the process starts executing, and store it in the `exec_start` map.

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

Then, we reserve an event structure from the circular buffer map `rb` and fill in the relevant data, such as the process ID, parent process ID, and process name. Afterwards, we send this data to the user-mode program for processing.

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

Finally, we define an eBPF program named `handle_exit` that will be triggered when a process executes the `exit()` system call. First, we retrieve the PID and TID (thread ID) from the current process. If the PID and TID are not equal, it means that this is a thread exit, and we will ignore this event.

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

Next, we look up the timestamp of when the process started execution, which was previously stored in the `exec_start` map. If a timestamp is found, we calculate the process's lifetime duration and then remove the record from the `exec_start` map. If a timestamp is not found and a minimum duration is specified, we return directly.

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

Then, we reserve an event structure from the circular buffer map `rb` and fill in the relevant data, such as the process ID, parent process ID, process name, and process duration. Finally, we send this data to the user-mode program for processing.

```c
    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task();

    e->exit_event = true;
    e->duration_ns = duration_ns;```
e->pid = pid;
e->ppid = BPF_CORE_READ(task, real_parent, tgid);
e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
bpf_get_current_comm(&e->comm, sizeof(e->comm));

/* send data to user-space for post-processing */
bpf_ringbuf_submit(e, 0);
return 0;
}
```

This way, when a process executes the exec() or exit() system calls, our eBPF program captures the corresponding events and sends detailed information to the user space program for further processing. This allows us to easily monitor process creation and termination and obtain detailed information about the processes.

In addition, in the bootstrap.h file, we also define the data structures for interaction with user space:

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

### User space, bootstrap.c

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

This user-level program is mainly used to load, verify, attach eBPF programs, and receive event data collected by eBPF programs and print it out. We will analyze some key parts.

First, we define an env structure to store command line arguments:

```c
static struct env {
    bool verbose;
    long min_duration_ms;
} env;
```

Next, we use the argp library to parse command line arguments:

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

In the main() function, we first parse the command line arguments, and then set the libbpf print callback function libbpf_print_fn to output debug information when needed:

```c
err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
if (err)
    return err;
libbpf_set_print(libbpf_print_fn);
```

Next, we open the eBPF skeleton file, pass the minimum duration parameter to the eBPF program, and load and attach the eBPF program:

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

Then, we create a ring buffer to receive event data sent by the eBPF program:

```c
rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
}
```

The handle_event() function handles events received from the eBPF program. Depending on the event type (process execution or exit), it extracts and prints event information such as timestamp, process name, process ID, parent process ID, file name, or exit code.

Finally, we use the ring_buffer__poll() function to poll the ring buffer and process the received event data:

```c
while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    // ...
}
```

When the program receives the SIGINT or SIGTERM signal, it completes the final cleanup and exit operations, and closes and unloads the eBPF program:

```c
cleanup:
 /* Clean up */
 ring_buffer__free(rb);
 bootstrap_bpf__destroy(skel);

 return err < 0 ? -err : 0;
}
```

## Dependency Installation

Building the example requires clang, libelf, and zlib. The package names may vary in different distributions.

On Ubuntu/Debian, you need to execute the following command:

```shell
sudo apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need to execute the following command:

```shell
sudo dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

## Compile and Run

Compile and run the above code:

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
03:16:41 EXIT  sh               110688  80168   [0] (0ms)".
```

The complete source code can be found at <https://github.com/eunomia-bpf/bpf-developer-tutorial>

## Summary

Through this example, we have learned how to combine eBPF programs with user-space programs. This combination provides developers with a powerful toolkit for efficient data collection and processing across the kernel and user space. By using eBPF and libbpf, you can build more efficient, scalable, and secure monitoring and performance analysis tools.

In the following tutorials, we will continue to explore the advanced features of eBPF and share more about eBPF development practices. Through continuous learning and practice, you will have a better understanding and mastery of eBPF technology and apply it to solve real-world problems.

If you would like to learn more about eBPF knowledge and practices, please refer to the official documentation of eunomia-bpf: <https://github.com/eunomia-bpf/eunomia-bpf>. You can also visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials.

## Reference

- [Building BPF applications with libbpf-bootstrap](https://nakryiko.com/posts/libbpf-bootstrap/)
- <https://github.com/libbpf/libbpf-bootstrap>

> The original link of this article: <https://eunomia.dev/tutorials/11-bootstrap>
