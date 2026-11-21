/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OOM_WATCH_H
#define __OOM_WATCH_H

#define OOM_RECLAIM_BUCKETS 20
#define OOM_STACK_DEPTH 127

enum oom_watch_event_type {
	OOM_VICTIM_MARKED = 1,
	OOM_VICTIM_EXITED = 2,
};

struct reclaim_profile {
	unsigned long long begin_count;
	unsigned long long end_count;
	unsigned long long reclaimed_pages;
	unsigned long long cross_cgroup_reclaims;
	unsigned long long last_reclaim_ns;
	unsigned long long total_reclaim_ns;
	unsigned long long maximum_reclaim_ns;
	unsigned long long stack_samples;
	unsigned long long stack_failures;
	unsigned long long latency_slots[OOM_RECLAIM_BUCKETS];
};

struct reclaim_stack_key {
	unsigned long long cgroup_id;
	signed int stack_id;
	unsigned int padding;
};

struct reclaim_stack_profile {
	unsigned long long samples;
	unsigned long long total_ns;
	unsigned long long maximum_ns;
	unsigned long long reclaimed_pages;
};

struct oom_watch_event {
	unsigned long long timestamp_ns;
	unsigned long long cgroup_id;
	struct reclaim_profile profile;
	unsigned long long total_vm_kb;
	unsigned long long anon_rss_kb;
	unsigned long long file_rss_kb;
	unsigned int type;
	unsigned int victim_pid;
	unsigned int victim_tid;
	unsigned int triggering_tgid;
	signed int exit_code;
	char comm[16];
};

#endif /* __OOM_WATCH_H */
