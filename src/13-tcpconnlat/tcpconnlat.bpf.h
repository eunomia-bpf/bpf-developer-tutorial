/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCPCONNLAT_H
#define __TCPCONNLAT_H

#define TASK_COMM_LEN	16

struct event {
	// union {
		unsigned int saddr_v4;
		unsigned char saddr_v6[16];
	// };
	// union {
		unsigned int daddr_v4;
		unsigned char daddr_v6[16];
	// };
	char comm[TASK_COMM_LEN];
	unsigned long long delta_us;
	unsigned long long ts_us;
	unsigned int tgid;
	int af;
	unsigned short lport;
	unsigned short dport;
};


#endif /* __TCPCONNLAT_H_ */
