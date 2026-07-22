/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TC_FLOW_INDEX_H
#define __TC_FLOW_INDEX_H

#define FLOW_COMM_LEN 16

struct flow_key {
	unsigned int source_ip;
	unsigned int destination_ip;
	unsigned short source_port;
	unsigned short destination_port;
	unsigned char protocol;
	unsigned char padding[3];
};

struct flow_snapshot {
	unsigned long long packets;
	unsigned long long bytes;
	unsigned long long last_seen_ns;
	struct flow_key key;
	unsigned int found;
	char comm[FLOW_COMM_LEN];
};

struct flow_cursor {
	unsigned long long bytes;
	unsigned long long packets;
	struct flow_key key;
	unsigned int valid;
};

#endif /* __TC_FLOW_INDEX_H */
