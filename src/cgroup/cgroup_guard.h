// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef __CGROUP_GUARD_H
#define __CGROUP_GUARD_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define SYSCTL_NAME_LEN 64

enum event_type {
    EVENT_CONNECT4 = 1,
    EVENT_DEVICE   = 2,
    EVENT_SYSCTL   = 3,
};

struct event {
    __u64 ts_ns;
    __u32 pid;
    __u32 type;
    char comm[TASK_COMM_LEN];

    union {
        struct {
            __u32 daddr;  /* IPv4, network order */
            __u16 dport;  /* host order */
            __u16 proto;  /* e.g. 6 for TCP */
        } connect4;

        struct {
            __u32 major;
            __u32 minor;
            __u32 access_type;
        } device;

        struct {
            __u32 write;
            char name[SYSCTL_NAME_LEN];
        } sysctl;
    };
};

#endif /* __CGROUP_GUARD_H */
