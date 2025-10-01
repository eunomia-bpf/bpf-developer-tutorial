// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef __ENERGY_MONITOR_H
#define __ENERGY_MONITOR_H

#define TASK_COMM_LEN 16
#define MAX_CPUS 256

struct energy_event {
	__u64 ts;
	__u32 cpu;
	__u32 pid;
	__u64 runtime_ns;
	char comm[TASK_COMM_LEN];
};

// RAPL energy domains
enum rapl_domain {
	RAPL_PKG = 0,   // Package domain (entire CPU socket)
	RAPL_CORE,      // Core domain (CPU cores only)
	RAPL_UNCORE,    // Uncore domain (integrated GPU, memory controller)
	RAPL_DRAM,      // DRAM domain (memory)
	RAPL_PSYS,      // Platform domain (entire SoC)
	RAPL_MAX_DOMAINS
};

#endif /* __ENERGY_MONITOR_H */