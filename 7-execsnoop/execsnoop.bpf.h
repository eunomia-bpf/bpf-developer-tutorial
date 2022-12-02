/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#define ARGSIZE  128
#define TASK_COMM_LEN 16
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define INVALID_UID ((uid_t)-1)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

struct event {
	int pid;
	int ppid;
	int uid;
	int retval;
	int args_count;
	unsigned int args_size;
	char comm[TASK_COMM_LEN];
	char args[FULL_MAX_ARGS_ARR];
};

#endif /* __EXECSNOOP_H */


