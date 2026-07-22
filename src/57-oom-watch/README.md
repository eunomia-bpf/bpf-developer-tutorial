# eBPF Tutorial by Example: OOM Victim Monitoring with Reclaim Profiling

When the kernel kills a process due to memory pressure, how do you know which cgroup was under stress and how hard it was fighting to reclaim memory before the OOM killer stepped in? This tutorial builds a tool that tracks memory reclaim activity per cgroup and captures detailed context when the OOM killer selects a victim.

> Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/57-oom-watch>

## eBPF and OOM Tracepoints

eBPF lets verified programs run at Linux kernel hooks and send selected state to user space. This tutorial uses the `oom/mark_victim` tracepoint to capture when the OOM killer selects a victim, and `mm_vmscan_memcg_reclaim_begin/end` tracepoints to track memory reclaim activity. Linux 7.1 added the target `mem_cgroup` to these vmscan tracepoints, which lets the BPF program attribute reclaim to the memory cgroup being scanned instead of the task that happened to trigger it. Victim lookup uses the `bpf_task_from_pid()` kfunc introduced in Linux 6.2, while ordinary tracepoint programs gained tracing-kfunc access in Linux 6.12. The vmscan tracepoint change is the newest dependency, so this implementation requires Linux 7.1 or later.

## How the Implementation Works

The tool tracks two phases of the OOM lifecycle. Before any OOM event, the kernel attempts memory reclaim. We count reclaim cycles per memory cgroup, track how many pages were reclaimed, and note when reclaim was triggered from a different cgroup (cross-cgroup reclaim). When the OOM killer selects a victim, we capture the victim's memory statistics, link it to the accumulated reclaim profile, and track the victim until it exits.

## Header File

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OOM_WATCH_H
#define __OOM_WATCH_H

enum oom_watch_event_type {
	OOM_VICTIM_MARKED = 1,
	OOM_VICTIM_EXITED = 2,
};

struct oom_watch_event {
	unsigned long long timestamp_ns;
	unsigned long long cgroup_id;
	unsigned long long reclaim_begin_count;
	unsigned long long reclaim_end_count;
	unsigned long long reclaimed_pages;
	unsigned long long cross_cgroup_reclaims;
	unsigned long long last_reclaim_ns;
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
```

The header defines the event structure sent to user space. Each event includes the cgroup ID, reclaim statistics (begin/end counts, pages reclaimed, cross-cgroup reclaims), victim memory statistics from the tracepoint, and exit code when the victim terminates.

## BPF Program

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "oom_watch.h"

char LICENSE[] SEC("license") = "GPL";

const volatile __u64 target_cgroup_id;

extern struct task_struct *bpf_task_from_pid(__s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *task) __ksym;

struct reclaim_profile {
	__u64 begin_count;
	__u64 end_count;
	__u64 reclaimed_pages;
	__u64 cross_cgroup_reclaims;
	__u64 last_reclaim_ns;
};

struct victim_state {
	__u64 cgroup_id;
	__u32 triggering_tgid;
	__u32 victim_tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct reclaim_profile);
} profiles SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct victim_state);
} victims SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

__u64 dropped_victim_states;

static __always_inline bool selected_cgroup(__u64 cgroup_id)
{
	return !target_cgroup_id || cgroup_id == target_cgroup_id;
}

static __always_inline __u64 victim_task_info(__u32 victim_pid,
					      __u32 *victim_tgid)
{
	struct task_struct *task;
	__u64 cgroup_id = 0;

	task = bpf_task_from_pid(victim_pid);
	if (!task)
		return 0;
	cgroup_id = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id);
	*victim_tgid = BPF_CORE_READ(task, tgid);
	bpf_task_release(task);
	return cgroup_id;
}

static __always_inline __u64 memcg_cgroup_id(struct mem_cgroup *memcg)
{
	struct cgroup *cgroup;

	cgroup = BPF_CORE_READ(memcg, css.cgroup);
	if (!cgroup)
		return 0;
	return BPF_CORE_READ(cgroup, kn, id);
}

static __always_inline struct reclaim_profile *get_profile(__u64 cgroup_id)
{
	struct reclaim_profile initial = {};
	struct reclaim_profile *profile;

	profile = bpf_map_lookup_elem(&profiles, &cgroup_id);
	if (profile)
		return profile;
	bpf_map_update_elem(&profiles, &cgroup_id, &initial, BPF_NOEXIST);
	return bpf_map_lookup_elem(&profiles, &cgroup_id);
}

SEC("tp_btf/mm_vmscan_memcg_reclaim_begin")
int BPF_PROG(track_reclaim_begin, gfp_t gfp_flags, int order,
	     struct mem_cgroup *memcg)
{
	struct reclaim_profile *profile;
	__u64 cgroup_id = memcg_cgroup_id(memcg);

	(void)gfp_flags;
	(void)order;
	if (!selected_cgroup(cgroup_id))
		return 0;
	profile = get_profile(cgroup_id);
	if (!profile)
		return 0;
	__sync_fetch_and_add(&profile->begin_count, 1);
	if (bpf_get_current_cgroup_id() != cgroup_id)
		__sync_fetch_and_add(&profile->cross_cgroup_reclaims, 1);
	profile->last_reclaim_ns = bpf_ktime_get_ns();
	return 0;
}

SEC("tp_btf/mm_vmscan_memcg_reclaim_end")
int BPF_PROG(track_reclaim_end, unsigned long reclaimed,
	     struct mem_cgroup *memcg)
{
	struct reclaim_profile *profile;
	__u64 cgroup_id = memcg_cgroup_id(memcg);

	if (!selected_cgroup(cgroup_id))
		return 0;
	profile = get_profile(cgroup_id);
	if (!profile)
		return 0;
	__sync_fetch_and_add(&profile->end_count, 1);
	__sync_fetch_and_add(&profile->reclaimed_pages, reclaimed);
	profile->last_reclaim_ns = bpf_ktime_get_ns();
	return 0;
}

SEC("tracepoint/oom/mark_victim")
int capture_oom_victim(struct trace_event_raw_mark_victim *ctx)
{
	struct reclaim_profile *profile;
	struct victim_state victim;
	struct oom_watch_event *event;
	__u64 cgroup_id;
	__u32 victim_pid = ctx->pid;
	__u32 victim_tgid = 0;

	cgroup_id = victim_task_info(victim_pid, &victim_tgid);
	if (!victim_tgid || !selected_cgroup(cgroup_id))
		return 0;
	victim.cgroup_id = cgroup_id;
	victim.triggering_tgid = bpf_get_current_pid_tgid() >> 32;
	victim.victim_tgid = victim_tgid;
	if (bpf_map_update_elem(&victims, &victim_pid, &victim, BPF_ANY)) {
		__sync_fetch_and_add(&dropped_victim_states, 1);
		return 0;
	}

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;
	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_ns = bpf_ktime_get_ns();
	event->cgroup_id = cgroup_id;
	event->type = OOM_VICTIM_MARKED;
	event->victim_pid = victim_tgid;
	event->victim_tid = victim_pid;
	event->triggering_tgid = victim.triggering_tgid;
	event->total_vm_kb = ctx->total_vm;
	event->anon_rss_kb = ctx->anon_rss;
	event->file_rss_kb = ctx->file_rss;
	bpf_probe_read_kernel_str(event->comm, sizeof(event->comm),
				  (void *)ctx + (ctx->__data_loc_comm & 0xffff));

	profile = bpf_map_lookup_elem(&profiles, &cgroup_id);
	if (profile) {
		event->reclaim_begin_count = profile->begin_count;
		event->reclaim_end_count = profile->end_count;
		event->reclaimed_pages = profile->reclaimed_pages;
		event->cross_cgroup_reclaims = profile->cross_cgroup_reclaims;
		event->last_reclaim_ns = profile->last_reclaim_ns;
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int capture_victim_exit(void *ctx)
{
	struct victim_state *victim;
	struct task_struct *task;
	struct oom_watch_event *event;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;

	(void)ctx;
	victim = bpf_map_lookup_elem(&victims, &tid);
	if (!victim)
		return 0;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		event->timestamp_ns = bpf_ktime_get_ns();
		event->cgroup_id = victim->cgroup_id;
		event->type = OOM_VICTIM_EXITED;
		event->victim_pid = victim->victim_tgid;
		event->victim_tid = tid;
		event->triggering_tgid = victim->triggering_tgid;
		task = (struct task_struct *)bpf_get_current_task_btf();
		event->exit_code = BPF_CORE_READ(task, exit_code);
		bpf_get_current_comm(event->comm, sizeof(event->comm));
		bpf_ringbuf_submit(event, 0);
	}
	bpf_map_delete_elem(&victims, &tid);
	return 0;
}
```

The BPF program uses `bpf_task_from_pid()` kfunc to look up the victim task from its PID. This kfunc was introduced in Linux 6.2 and returns a referenced pointer that must be released with `bpf_task_release()`. `BPF_PROG_TYPE_TRACEPOINT` programs gained access to tracing kfuncs in Linux 6.12. The reclaim callbacks also consume the target `mem_cgroup` argument added to vmscan tracepoints in Linux 7.1, which sets the minimum kernel version for the complete tool.

The `track_reclaim_begin` and `track_reclaim_end` functions attach to memcg reclaim tracepoints. They count reclaim cycles and track cross-cgroup reclaims (when a task in one cgroup triggers reclaim in another cgroup's memory space).

The `capture_oom_victim` function runs when the OOM killer selects a victim. It uses `bpf_task_from_pid()` to get the victim's cgroup ID and TGID, stores victim state for exit tracking, and sends an event with memory statistics and accumulated reclaim profile.

The `capture_victim_exit` function tracks when the victim actually exits, confirming the kill completed and reporting the exit signal.

## User Space Program

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "oom_watch.h"
#include "oom_watch.skel.h"

struct options {
	const char *cgroup_path;
	unsigned int duration_seconds;
	bool demo;
};

static volatile sig_atomic_t stop;
static int victim_events;
static int exit_events;
static unsigned long long observed_cgroup_id;
static unsigned int observed_victim_pid;
static unsigned int observed_victim_tid;
static unsigned long long observed_reclaims;
static unsigned long long observed_cross_cgroup_reclaims;

struct allocation_context {
	int ready_fd;
	int continue_fd;
};

static struct allocation_context allocation_context;

static void handle_signal(int signal_number)
{
	(void)signal_number;
	stop = 1;
}

static unsigned long long monotonic_ns(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static int write_text(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t length = strlen(text);
	int err = 0;

	if (fd < 0)
		return -1;
	if (write(fd, text, length) != length)
		err = -1;
	close(fd);
	return err;
}

static int memory_controller_enabled(bool *enabled)
{
	char controllers[4096];
	ssize_t length;
	int fd;

	fd = open("/sys/fs/cgroup/cgroup.subtree_control",
		  O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	length = read(fd, controllers, sizeof(controllers) - 1);
	close(fd);
	if (length < 0)
		return -1;
	controllers[length] = '\0';
	*enabled = strstr(controllers, "memory") != NULL;
	return 0;
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct oom_watch_event *event = data;

	(void)ctx;
	if (size != sizeof(*event))
		return 0;
	if (event->type == OOM_VICTIM_MARKED) {
		victim_events++;
		observed_cgroup_id = event->cgroup_id;
		observed_victim_pid = event->victim_pid;
		observed_reclaims = event->reclaim_begin_count;
		observed_victim_tid = event->victim_tid;
		observed_cross_cgroup_reclaims = event->cross_cgroup_reclaims;
		printf("event=oom-victim pid=%u tid=%u comm=%s trigger_pid=%u cgroup_id=%llu "
		       "anon_rss_kb=%llu file_rss_kb=%llu total_vm_kb=%llu "
		       "reclaim_cycles=%llu cross_cgroup_reclaims=%llu "
		       "reclaimed_pages=%llu\n",
		       event->victim_pid, event->victim_tid, event->comm,
		       event->triggering_tgid,
		       (unsigned long long)event->cgroup_id,
		       (unsigned long long)event->anon_rss_kb,
		       (unsigned long long)event->file_rss_kb,
		       (unsigned long long)event->total_vm_kb,
		       (unsigned long long)event->reclaim_begin_count,
		       (unsigned long long)event->cross_cgroup_reclaims,
		       (unsigned long long)event->reclaimed_pages);
	} else if (event->type == OOM_VICTIM_EXITED) {
		exit_events++;
		printf("event=victim-exit pid=%u tid=%u cgroup_id=%llu exit_code=%d\n",
		       event->victim_pid, event->victim_tid,
		       (unsigned long long)event->cgroup_id, event->exit_code);
	}
	return 0;
}

static int parse_uint(const char *text, unsigned int *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !*text || *end || parsed > 86400)
		return -1;
	*value = parsed;
	return 0;
}

static void usage(const char *program)
{
	printf("Usage: %s [--cgroup PATH] [--duration SEC]\n"
	       "       %s --demo\n", program, program);
}

static int parse_options(int argc, char **argv, struct options *options)
{
	static const struct option long_options[] = {
		{ "cgroup", required_argument, NULL, 'c' },
		{ "duration", required_argument, NULL, 'd' },
		{ "demo", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "c:d:Dh", long_options,
				     NULL)) != -1) {
		switch (option) {
		case 'c': options->cgroup_path = optarg; break;
		case 'd':
			if (parse_uint(optarg, &options->duration_seconds))
				return -1;
			break;
		case 'D': options->demo = true; break;
		case 'h': usage(argv[0]); exit(0);
		default: return -1;
		}
	}
	return optind == argc && !(options->demo && options->cgroup_path) ? 0 : -1;
}

static void *allocation_worker(void *argument)
{
	struct allocation_context *context = argument;
	size_t first_stage = 24 * 1024 * 1024;
	size_t length = 128 * 1024 * 1024;
	unsigned char *memory;
	char byte = 'x';

	memory = mmap(NULL, length, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (memory == MAP_FAILED)
		_exit(4);
	for (size_t offset = 0; offset < first_stage; offset += 4096)
		memory[offset] = 0xa5;
	if (write(context->ready_fd, &byte, 1) != 1 ||
	    read(context->continue_fd, &byte, 1) != 1)
		_exit(5);
	for (size_t offset = first_stage; offset < length; offset += 4096)
		memory[offset] = 0xa5;
	_exit(6);
}

static void allocate_until_killed(const char *cgroup_path, int ready_fd,
				  int continue_fd)
{
	char procs_path[512];
	char pid_text[32];
	pthread_t worker;

	snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path);
	snprintf(pid_text, sizeof(pid_text), "%d", getpid());
	if (write_text(procs_path, pid_text))
		_exit(3);
	allocation_context.ready_fd = ready_fd;
	allocation_context.continue_fd = continue_fd;
	if (pthread_create(&worker, NULL, allocation_worker,
			   &allocation_context))
		_exit(4);
	pthread_detach(worker);
	pthread_exit(NULL);
}

static int configure_demo_cgroup(const char *path, bool *created,
				 bool *enabled_by_demo)
{
	bool memory_enabled;
	char file[512];

	if (memory_controller_enabled(&memory_enabled))
		return -1;
	if (!memory_enabled) {
		if (write_text("/sys/fs/cgroup/cgroup.subtree_control", "+memory"))
			return -1;
		*enabled_by_demo = true;
	}
	if (mkdir(path, 0755))
		return -1;
	*created = true;
	snprintf(file, sizeof(file), "%s/memory.max", path);
	if (write_text(file, "33554432"))
		return -1;
	snprintf(file, sizeof(file), "%s/memory.swap.max", path);
	if (write_text(file, "0"))
		return -1;
	snprintf(file, sizeof(file), "%s/memory.oom.group", path);
	return write_text(file, "1");
}

static int trigger_cross_cgroup_reclaim(const char *cgroup_path)
{
	char reclaim_path[512];

	snprintf(reclaim_path, sizeof(reclaim_path), "%s/memory.reclaim",
		 cgroup_path);
	if (!write_text(reclaim_path, "8388608") || errno == EAGAIN)
		return 0;
	return -1;
}

int main(int argc, char **argv)
{
	struct options options = {};
	struct oom_watch_bpf *skel = NULL;
	struct ring_buffer *ring = NULL;
	char demo_cgroup_path[256];
	unsigned long long deadline = 0;
	struct stat cgroup_stat = {};
	const char *selected_path = NULL;
	pid_t child = -1;
	int ready_pipe[2] = { -1, -1 };
	int continue_pipe[2] = { -1, -1 };
	int status = 0;
	int err = 1;
	bool demo_cgroup_created = false;
	bool memory_enabled_by_demo = false;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (parse_options(argc, argv, &options)) {
		usage(argv[0]);
		return 2;
	}
	if (options.demo) {
		snprintf(demo_cgroup_path, sizeof(demo_cgroup_path),
			 "/sys/fs/cgroup/ebpf-oom-watch-%d", getpid());
		if (configure_demo_cgroup(demo_cgroup_path,
					  &demo_cgroup_created,
					  &memory_enabled_by_demo)) {
			fprintf(stderr, "failed to configure demo memory cgroup: %s\n",
				strerror(errno));
			goto cleanup;
		}
		selected_path = demo_cgroup_path;
	} else {
		selected_path = options.cgroup_path;
	}
	if (selected_path && stat(selected_path, &cgroup_stat)) {
		fprintf(stderr, "failed to stat cgroup %s: %s\n", selected_path,
			strerror(errno));
		goto cleanup;
	}

	skel = oom_watch_bpf__open();
	if (!skel)
		goto cleanup;
	skel->rodata->target_cgroup_id = selected_path ? cgroup_stat.st_ino : 0;
	if (oom_watch_bpf__load(skel) || oom_watch_bpf__attach(skel)) {
		fprintf(stderr, "failed to load and attach OOM watcher\n");
		goto cleanup;
	}
	ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
				NULL, NULL);
	if (!ring)
		goto cleanup;

	if (selected_path)
		printf("oom-watch tracing cgroup=%s cgroup_id=%llu\n",
		       selected_path, (unsigned long long)cgroup_stat.st_ino);
	else
		printf("oom-watch tracing all cgroups\n");

	if (options.demo) {
		struct pollfd ready = { .events = POLLIN };
		struct timespec leader_exit_delay = { .tv_nsec = 100000000 };
		char byte = 'x';

		if (pipe(ready_pipe) || pipe(continue_pipe))
			goto cleanup;
		child = fork();
		if (child < 0)
			goto cleanup;
		if (!child) {
			close(ready_pipe[0]);
			close(continue_pipe[1]);
			allocate_until_killed(selected_path, ready_pipe[1],
					      continue_pipe[0]);
		}
		close(ready_pipe[1]); ready_pipe[1] = -1;
		close(continue_pipe[0]); continue_pipe[0] = -1;
		ready.fd = ready_pipe[0];
		if (poll(&ready, 1, 5000) != 1 ||
		    read(ready_pipe[0], &byte, 1) != 1 ||
		    trigger_cross_cgroup_reclaim(selected_path))
			goto cleanup;
		nanosleep(&leader_exit_delay, NULL);
		if (write(continue_pipe[1], &byte, 1) != 1)
			goto cleanup;
		close(ready_pipe[0]); ready_pipe[0] = -1;
		close(continue_pipe[1]); continue_pipe[1] = -1;

		for (int i = 0; i < 200; i++) {
			pid_t waited;

			ring_buffer__poll(ring, 50);
			waited = waitpid(child, &status, WNOHANG);
			if (waited == child) {
				child = -1;
				break;
			}
		}
		for (int i = 0; i < 10 && exit_events < 1; i++)
			ring_buffer__poll(ring, 50);

		printf("demo workload signaled=%d signal=%d\n",
		       WIFSIGNALED(status),
		       WIFSIGNALED(status) ? WTERMSIG(status) : 0);
		if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL ||
		    victim_events != 1 || exit_events != 1 ||
		    observed_cgroup_id != (unsigned long long)cgroup_stat.st_ino ||
		    !observed_victim_pid || !observed_victim_tid ||
		    observed_victim_pid == observed_victim_tid ||
		    !observed_reclaims || !observed_cross_cgroup_reclaims ||
		    skel->bss->dropped_victim_states)
			goto cleanup;
		printf("demo result=matched-profile-to-victim\n");
	} else {
		signal(SIGINT, handle_signal);
		signal(SIGTERM, handle_signal);
		if (options.duration_seconds)
			deadline = monotonic_ns() +
				   (unsigned long long)options.duration_seconds *
				   1000000000ULL;
		while (!stop && (!deadline || monotonic_ns() < deadline)) {
			int poll_result = ring_buffer__poll(ring, 100);

			if (poll_result < 0 && poll_result != -EINTR) {
				fprintf(stderr, "ring buffer poll failed: %d\n",
					poll_result);
				goto cleanup;
			}
		}
	}
	printf("dropped_victim_states=%llu\n",
	       (unsigned long long)skel->bss->dropped_victim_states);
	err = 0;

cleanup:
	if (child > 0) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
	}
	for (size_t i = 0; i < 2; i++) {
		if (ready_pipe[i] >= 0) close(ready_pipe[i]);
		if (continue_pipe[i] >= 0) close(continue_pipe[i]);
	}
	ring_buffer__free(ring);
	oom_watch_bpf__destroy(skel);
	if (demo_cgroup_created && rmdir(demo_cgroup_path) && !err)
		err = 1;
	if (memory_enabled_by_demo &&
	    write_text("/sys/fs/cgroup/cgroup.subtree_control", "-memory") &&
	    !err)
		err = 1;
	return err;
}
```

The user space program creates events for OOM victims and their exits. In demo mode, it creates a memory-limited cgroup (32MB), forks a child that joins the cgroup and allocates memory until killed, and triggers cross-cgroup reclaim to generate reclaim profile data before the OOM.

## Compilation and Execution

Build the tool:

```bash
cd src/57-oom-watch
make
```

Run with cgroup filtering:

```bash
sudo ./oom_watch --cgroup /sys/fs/cgroup/my-service
```

Or watch all OOM events:

```bash
sudo ./oom_watch --duration 60
```

Run the built-in demo:

```bash
sudo ./oom_watch --demo
```

Example output:

```text
oom-watch tracing cgroup=/sys/fs/cgroup/ebpf-oom-watch-1246 cgroup_id=28
event=oom-victim pid=1257 tid=1258 comm=oom_watch trigger_pid=1257 cgroup_id=28 anon_rss_kb=32820 file_rss_kb=1576 total_vm_kb=144200 reclaim_cycles=43 cross_cgroup_reclaims=21 reclaimed_pages=40
event=victim-exit pid=1257 tid=1258 cgroup_id=28 exit_code=9
demo workload signaled=1 signal=9
demo result=matched-profile-to-victim
dropped_victim_states=0
```

## Requirements

| Requirement | Details |
|-------------|---------|
| Kernel | Linux 7.1+ (target memcg in vmscan tracepoints) |
| Config | `CONFIG_BPF_SYSCALL`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_MEMCG` |
| Privileges | Root |
| cgroup | cgroup v2 with memory controller enabled |

## Understanding the Output

The victim event includes:

- **pid/tid**: TGID and TID of the victim (may differ for multithreaded processes)
- **trigger_pid**: The process whose allocation triggered the OOM killer
- **anon_rss_kb/file_rss_kb/total_vm_kb**: Memory statistics from the tracepoint
- **reclaim_cycles**: How many reclaim attempts occurred in this cgroup
- **cross_cgroup_reclaims**: Reclaims triggered by other cgroups
- **reclaimed_pages**: Total pages reclaimed before OOM

The reclaim counters accumulate from the time tracing starts. The `dropped_victim_states` counter records victim states that could not be inserted into the 1024-entry map.

## Summary

`oom-watch` joins three moments that are usually inspected separately: memory cgroup reclaim, OOM victim selection, and the victim's eventual exit. The resulting event preserves both TGID and TID, adds the victim's memory footprint, and carries the reclaim profile that accumulated while the tool was tracing.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [BPF kfuncs documentation](https://docs.kernel.org/6.2/bpf/kfuncs.html)
- [OOM tracepoints](https://github.com/torvalds/linux/blob/master/include/trace/events/oom.h)
- [vmscan tracepoints](https://github.com/torvalds/linux/blob/master/include/trace/events/vmscan.h)
- [cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [Tracepoint kfunc access commit](https://github.com/torvalds/linux/commit/bc638d8cb5be813d4eeb9f63cce52caaa18f3960)
- [vmscan memcg attribution commit](https://github.com/torvalds/linux/commit/874a0a566ede40f3d6062cae8fe1022e616edd1a)
