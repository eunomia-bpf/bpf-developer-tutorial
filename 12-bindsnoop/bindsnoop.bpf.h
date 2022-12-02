/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BINDSNOOP_H
#define __BINDSNOOP_H

#define TASK_COMM_LEN	16

struct bind_event {
	unsigned __int128 addr;
	unsigned long long ts_us;
	unsigned int pid;
	unsigned int bound_dev_if;
	int ret;
	unsigned short port;
	unsigned short proto;
	unsigned char opts;
	unsigned char ver;
	char task[TASK_COMM_LEN];
};

union bind_options {
	unsigned char data;
	struct {
		unsigned char freebind : 1;
		unsigned char transparent : 1;
		unsigned char bind_address_no_port : 1;
		unsigned char reuseaddress : 1;
		unsigned char reuseport : 1;
	} fields;
};

#endif /* __BINDSNOOP_H */
