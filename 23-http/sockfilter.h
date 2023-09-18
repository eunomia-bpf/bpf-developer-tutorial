// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#ifndef __SOCKFILTER_H
#define __SOCKFILTER_H

#define MAX_BUF_SIZE 64

struct so_event {
	__be32 src_addr;
	__be32 dst_addr;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	__u32 ip_proto;
	__u32 pkt_type;
	__u32 ifindex;
	__u32 payload_length;
    __u8 payload[MAX_BUF_SIZE];
};

#endif /* __SOCKFILTER_H */
