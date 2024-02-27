// SPDX-License-Identifier: BSD-3-Clause
#ifndef BAD_BPF_COMMON_H
#define BAD_BPF_COMMON_H

// Simple message structure to get events from eBPF Programs
// in the kernel to user spcae
#define TASK_COMM_LEN 16
#define MAX_PID_LEN 16

// These are used by a number of
// different programs to sync eBPF Tail Call
// login between user space and kernel
#define PROG_00 0
#define PROG_01 1
#define PROG_02 2

struct event
{
    int pid;
    char comm[TASK_COMM_LEN];
    bool success;
};

#endif // BAD_BPF_COMMON_H
