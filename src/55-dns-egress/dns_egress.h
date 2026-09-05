/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __DNS_EGRESS_H
#define __DNS_EGRESS_H

#define DNS_QNAME_MAX 64

enum dns_egress_event_type {
	DNS_LEARNED = 1,
	DNS_ALLOWED = 2,
	DNS_DENIED = 3,
	DNS_EXPIRED = 4,
};

struct dns_header {
	unsigned short id;
	unsigned short flags;
	unsigned short questions;
	unsigned short answers;
	unsigned short authorities;
	unsigned short additionals;
} __attribute__((packed));

struct dns_question {
	unsigned short type;
	unsigned short class;
} __attribute__((packed));

struct dns_a_answer {
	unsigned short name;
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short address_length;
	unsigned int address;
} __attribute__((packed));

struct dns_egress_event {
	unsigned long long timestamp_ns;
	unsigned long long expires_ns;
	unsigned int type;
	unsigned int pid;
	unsigned int ip4;
	unsigned int ttl_seconds;
};

#endif /* __DNS_EGRESS_H */
