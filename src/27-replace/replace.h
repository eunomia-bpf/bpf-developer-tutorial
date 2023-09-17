// SPDX-License-Identifier: BSD-3-Clause
#ifndef BAD_BPF_COMMON_H
#define BAD_BPF_COMMON_H

// These are used by a number of
// different programs to sync eBPF Tail Call
// login between user space and kernel
#define PROG_00 0
#define PROG_01 1
#define PROG_02 2

// Used when replacing text
#define FILENAME_LEN_MAX 50
#define TEXT_LEN_MAX 20

// Simple message structure to get events from eBPF Programs
// in the kernel to user spcae
#define TASK_COMM_LEN 16
#define LOCAL_BUFF_SIZE 64
#define loop_size 64
#define text_len_max 20

struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    bool success;
};

#endif  // BAD_BPF_COMMON_H
