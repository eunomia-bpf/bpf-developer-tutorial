/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#define TASK_COMM_LEN 16

struct event {
	int pid;
	int ppid;
	int uid;
	int retval;
	bool is_exit;
	char comm[TASK_COMM_LEN];
};

#endif /* __EXECSNOOP_H */


