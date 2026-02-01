// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 eunomia-bpf
#ifndef __DYNPTR_TC_H
#define __DYNPTR_TC_H

/* Use types that work in both BPF and userspace contexts */
#ifdef __BPF__
/* BPF side uses vmlinux types */
#else
/* Userspace side uses standard types */
#include <linux/types.h>
#endif

#define MAX_SNAPLEN 64

struct dynptr_cfg {
    __u16 blocked_port;   /* 0 = disable blocking */
    __u16 _pad1;

    __u32 snap_len;       /* TCP payload snapshot length */
    __u8  enable_ringbuf; /* 1: output events to ringbuf */
    __u8  _pad2[3];
};

/* Fixed header + variable payload (flex array) */
struct event_hdr {
    __u64 ts_ns;

    __u32 ifindex;
    __u32 pkt_len;

    __be32 saddr;
    __be32 daddr;

    __u16 sport;
    __u16 dport;

    __u8  drop;     /* 1: packet was dropped */
    __u8  _pad1;
    __u16 snap_len; /* actual snapshot length (<= MAX_SNAPLEN) */

    __u8  payload[]; /* follows immediately after the struct */
};

#endif /* __DYNPTR_TC_H */
