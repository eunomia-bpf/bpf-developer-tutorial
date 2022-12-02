/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OPENSNOOP_H
#define __OPENSNOOP_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define INVALID_UID ((uid_t)-1)

// used for export event
struct event {
	/* user terminology for pid: */
	unsigned long long ts;
	int pid;
	int uid;
	int ret;
	int flags;
	char comm[TASK_COMM_LEN];
	char fname[NAME_MAX];
};

#endif /* __OPENSNOOP_H */