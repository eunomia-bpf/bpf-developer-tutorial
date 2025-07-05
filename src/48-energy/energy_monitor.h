// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef __ENERGY_MONITOR_H
#define __ENERGY_MONITOR_H

#define TASK_COMM_LEN 16

struct energy_event {
	__u64 ts;
	__u32 cpu;
	__u32 pid;
	__u64 runtime_ns;
	char comm[TASK_COMM_LEN];
};

#endif /* __ENERGY_MONITOR_H */