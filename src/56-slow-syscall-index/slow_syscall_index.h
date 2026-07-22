/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SLOW_SYSCALL_INDEX_H
#define __SLOW_SYSCALL_INDEX_H

#define SLOW_SYSCALL_COMM_LEN 16

struct slow_syscall_event {
	unsigned long long timestamp_ns;
	unsigned long long duration_ns;
	long long return_value;
	unsigned int tgid;
	unsigned int tid;
	unsigned int syscall_id;
	char comm[SLOW_SYSCALL_COMM_LEN];
};

#endif /* __SLOW_SYSCALL_INDEX_H */
