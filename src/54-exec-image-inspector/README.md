# eBPF Tutorial by Example: Inspect the Executable Image After exec

A launcher receives one command, but the kernel may install a different executable image. A shell script starts an interpreter, a wrapper selects another binary, and a runtime can call `exec` more than once. During an incident, the original command string does not always tell you what finally ran.

This tutorial builds `exec_image_inspector`, a command runner that observes one child at the `bprm_committed_creds` LSM hook. It reports the installed executable path and decodes the ELF class, byte order, type, and machine. The example also shows why a file read that may fault cannot stay in this non-sleepable hook.

The solution uses BPF task work. The hook records the exec and schedules a callback for the current task. That callback runs in a sleepable context, reacquires the installed executable file, reads it through a file-backed dynptr, and sends the result to user space. By the end, you will have a complete pattern for moving a small file inspection across that context boundary.

The complete implementation is in [`exec_image_inspector.h`](./exec_image_inspector.h), [`bpf_experimental.h`](./bpf_experimental.h), [`exec_image_inspector.bpf.c`](./exec_image_inspector.bpf.c), and [`exec_image_inspector.c`](./exec_image_inspector.c). The [`Makefile`](./Makefile), [exec fixture](./tests/exec_fixture.c), and [integration test](./tests/test_exec_image_inspector.py) provide the build and reproducible cold-page cases.

## Why the hook cannot read every file page

`bprm_committed_creds` runs after the new executable credentials have been committed. At that point, `bprm->file` identifies the image involved in this exec, which makes the hook useful for observing what the task installed rather than only what a launcher requested.

The hook is not sleepable. A file-backed dynptr can read data that is already available, but this program cannot fault a missing file page into memory from that context. Cached bytes may work, so a direct read does not fail for every file or offset. The test fixture creates a cold page to make the boundary reproducible.

BPF task work provides the second half of the design. `bpf_task_work_schedule_signal()` associates a callback with the current task. The callback can sleep, obtain the task's current executable file with `bpf_get_task_exe_file()`, and use the file dynptr helpers there.

The tool observes one child created by its own loader. It is not a system-wide exec daemon. This narrow scope lets the loader know the target TGID before attachment and keeps one task-work slot sufficient for the example.

## Follow one exec from command to event

The full flow has six steps:

1. User space forks the target command, but the child waits on a pipe before `execvp`.
2. The loader writes the child's TGID and optional probe offset into BPF read-only data. It loads the skeleton, attaches the LSM program, and creates the ring-buffer reader.
3. The parent releases the pipe. The child calls `execvp`, and `lsm/bprm_committed_creds` matches the selected TGID after the new credentials are committed.
4. The hook optionally tries a direct file read, stores that result, and schedules `inspect_executable` with BPF task work.
5. The callback reacquires the task's installed executable file, resolves its path, reads the ELF header and optional marker through a file dynptr, and emits one ring-buffer event.
6. User space polls while it reaps the child. A final drain collects later exec events from the same child before the loader frees the ring buffer and destroys the BPF skeleton.

Blocking the child closes a short-lived-command race. Loading BPF before forking would also avoid a missed exec, but it would require a separate launch protocol to discover and control the target. The pipe keeps the example self-contained.

## Complete source code

The shared header defines the ring-buffer event and final statistics used on both sides.

<!-- BEGIN FULL SOURCE: src/54-exec-image-inspector/exec_image_inspector.h -->
```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EXEC_IMAGE_INSPECTOR_H
#define __EXEC_IMAGE_INSPECTOR_H

#define EXEC_COMM_LEN 16
#define EXEC_PATH_LEN 256
#define EXEC_PROBE_LEN 8

struct exec_event {
	unsigned int pid;
	unsigned int tgid;
	unsigned char is_elf;
	unsigned char elf_class;
	unsigned char elf_data;
	unsigned char reserved;
	unsigned short elf_type;
	unsigned short elf_machine;
	int header_error;
	int path_error;
	int direct_probe_error;
	int deferred_probe_error;
	unsigned long long latency_ns;
	unsigned long long probe_offset;
	char comm[EXEC_COMM_LEN];
	char path[EXEC_PATH_LEN];
	unsigned char probe_bytes[EXEC_PROBE_LEN];
};

struct inspector_stats {
	unsigned long long matched;
	unsigned long long scheduled;
	unsigned long long schedule_errors;
	unsigned long long callbacks;
	unsigned long long header_errors;
	unsigned long long path_errors;
	unsigned long long direct_probes;
	unsigned long long direct_probe_errors;
	unsigned long long deferred_probes;
	unsigned long long deferred_probe_errors;
	unsigned long long dropped;
};

#endif /* __EXEC_IMAGE_INSPECTOR_H */
```
<!-- END FULL SOURCE -->

Linux 6.18 and 6.19 added the task-work and file-dynptr interfaces used here. The repository's generated UAPI and BTF headers predate them, so this lesson keeps the missing declarations local.

<!-- BEGIN FULL SOURCE: src/54-exec-image-inspector/bpf_experimental.h -->
```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EXEC_IMAGE_INSPECTOR_BPF_EXPERIMENTAL_H
#define __EXEC_IMAGE_INSPECTOR_BPF_EXPERIMENTAL_H

/*
 * These Linux 6.18/6.19 declarations are not present in the repository's
 * older generated UAPI and vmlinux headers. Keep them local until those
 * vendored headers are regenerated.
 */
struct bpf_task_work {
	__u64 opaque;
} __attribute__((aligned(8)));

typedef int (*bpf_task_work_callback_t)(struct bpf_map *map, void *key,
					void *value);

extern int bpf_task_work_schedule_signal(struct task_struct *task,
					 struct bpf_task_work *work,
					 void *map__map,
					 bpf_task_work_callback_t callback) __ksym;
extern struct file *bpf_get_task_exe_file(struct task_struct *task) __ksym;
extern void bpf_put_file(struct file *file) __ksym;
extern int bpf_path_d_path(const struct path *path, char *buf,
			   __u64 buf__sz) __ksym;
extern int bpf_dynptr_from_file(struct file *file, __u32 flags,
				struct bpf_dynptr *ptr__uninit) __ksym;
extern int bpf_dynptr_file_discard(struct bpf_dynptr *dynptr) __ksym;

#endif /* __EXEC_IMAGE_INSPECTOR_BPF_EXPERIMENTAL_H */
```
<!-- END FULL SOURCE -->

The kernel-mode program filters one TGID, schedules task work, reads the installed image, decodes the ELF header, and emits the event.

<!-- BEGIN FULL SOURCE: src/54-exec-image-inspector/exec_image_inspector.bpf.c -->
```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"
#include "exec_image_inspector.h"

char LICENSE[] SEC("license") = "GPL";

#define ENOENT 2

#define EI_CLASS 4
#define EI_DATA 5
#define ELFCLASS32 1
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

const volatile __u32 target_tgid;
const volatile __u32 probe_offset;

struct inspector_stats stats;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct exec_work {
	__u64 scheduled_ns;
	int direct_probe_error;
	struct bpf_task_work work;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_work);
} pending SEC(".maps");

static __u16 read_elf_u16(const unsigned char *header, int offset, __u8 data)
{
	if (data == ELFDATA2MSB)
		return ((__u16)header[offset] << 8) | header[offset + 1];
	return header[offset] | ((__u16)header[offset + 1] << 8);
}

static int probe_file_without_sleep(struct file *file)
{
	unsigned char sample[EXEC_PROBE_LEN];
	struct bpf_dynptr dynptr;
	int err;

	if (!probe_offset)
		return 0;

	__sync_fetch_and_add(&stats.direct_probes, 1);
	if (!file) {
		err = -ENOENT;
		goto record;
	}

	err = bpf_dynptr_from_file(file, 0, &dynptr);
	if (err) {
		bpf_dynptr_file_discard(&dynptr);
		goto record;
	}

	err = bpf_dynptr_read(sample, sizeof(sample), &dynptr, probe_offset, 0);
	bpf_dynptr_file_discard(&dynptr);

record:
	if (err)
		__sync_fetch_and_add(&stats.direct_probe_errors, 1);
	return err;
}

static int inspect_executable(struct bpf_map *map, void *key, void *value)
{
	unsigned char header[64] = {};
	struct exec_work *work = value;
	struct exec_event event = {};
	struct task_struct *task;
	struct bpf_dynptr dynptr;
	struct file *file;
	__u64 pid_tgid;
	int err;

	(void)map;
	(void)key;
	__sync_fetch_and_add(&stats.callbacks, 1);

	pid_tgid = bpf_get_current_pid_tgid();
	event.pid = (__u32)pid_tgid;
	event.tgid = pid_tgid >> 32;
	event.latency_ns = bpf_ktime_get_ns() - work->scheduled_ns;
	event.direct_probe_error = work->direct_probe_error;
	event.probe_offset = probe_offset;
	bpf_get_current_comm(event.comm, sizeof(event.comm));

	task = bpf_get_current_task_btf();
	file = bpf_get_task_exe_file(task);
	if (!file) {
		event.header_error = -ENOENT;
		__sync_fetch_and_add(&stats.header_errors, 1);
		if (probe_offset) {
			event.deferred_probe_error = -ENOENT;
			__sync_fetch_and_add(&stats.deferred_probes, 1);
			__sync_fetch_and_add(&stats.deferred_probe_errors, 1);
		}
		goto emit;
	}

	err = bpf_path_d_path(&file->f_path, event.path, sizeof(event.path));
	if (err < 0) {
		event.path_error = err;
		__sync_fetch_and_add(&stats.path_errors, 1);
	}

	err = bpf_dynptr_from_file(file, 0, &dynptr);
	if (err) {
		bpf_dynptr_file_discard(&dynptr);
		event.header_error = err;
		__sync_fetch_and_add(&stats.header_errors, 1);
		if (probe_offset) {
			event.deferred_probe_error = err;
			__sync_fetch_and_add(&stats.deferred_probes, 1);
			__sync_fetch_and_add(&stats.deferred_probe_errors, 1);
		}
		goto put_file;
	}

	err = bpf_dynptr_read(header, sizeof(header), &dynptr, 0, 0);
	if (err) {
		event.header_error = err;
		__sync_fetch_and_add(&stats.header_errors, 1);
	}

	if (probe_offset) {
		__sync_fetch_and_add(&stats.deferred_probes, 1);
		err = bpf_dynptr_read(event.probe_bytes, sizeof(event.probe_bytes),
				      &dynptr, probe_offset, 0);
		event.deferred_probe_error = err;
		if (err)
			__sync_fetch_and_add(&stats.deferred_probe_errors, 1);
	}
	bpf_dynptr_file_discard(&dynptr);

	if (!event.header_error && header[0] == 0x7f && header[1] == 'E' &&
	    header[2] == 'L' && header[3] == 'F') {
		event.is_elf = 1;
		event.elf_class = header[EI_CLASS];
		event.elf_data = header[EI_DATA];
		event.elf_type = read_elf_u16(header, 16, event.elf_data);
		event.elf_machine = read_elf_u16(header, 18, event.elf_data);
	}

put_file:
	bpf_put_file(file);
emit:
	if (bpf_ringbuf_output(&events, &event, sizeof(event), 0))
		__sync_fetch_and_add(&stats.dropped, 1);
	return 0;
}

SEC("lsm/bprm_committed_creds")
void BPF_PROG(schedule_exec_inspection, struct linux_binprm *bprm)
{
	struct task_struct *task;
	struct exec_work *work;
	__u64 pid_tgid;
	__u32 key = 0, tgid;
	int err;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = pid_tgid >> 32;
	if (target_tgid && tgid != target_tgid)
		return;

	__sync_fetch_and_add(&stats.matched, 1);
	work = bpf_map_lookup_elem(&pending, &key);
	if (!work) {
		__sync_fetch_and_add(&stats.schedule_errors, 1);
		return;
	}

	work->scheduled_ns = bpf_ktime_get_ns();
	work->direct_probe_error = probe_file_without_sleep(bprm->file);
	task = bpf_get_current_task_btf();
	err = bpf_task_work_schedule_signal(task, &work->work, &pending,
					    inspect_executable);
	if (err) {
		__sync_fetch_and_add(&stats.schedule_errors, 1);
		return;
	}
	__sync_fetch_and_add(&stats.scheduled, 1);
}
```
<!-- END FULL SOURCE -->

The user-space program parses the command, coordinates the blocked child, loads BPF, formats events, enforces the timeout, and cleans up.

<!-- BEGIN FULL SOURCE: src/54-exec-image-inspector/exec_image_inspector.c -->
```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "exec_image_inspector.h"
#include "exec_image_inspector.skel.h"

struct environment {
	unsigned long long probe_offset;
	unsigned int timeout_ms;
	bool verbose;
	char **command;
};

struct child_process {
	pid_t pid;
	int release_fd;
	bool released;
	bool reaped;
	int status;
};

struct event_context {
	unsigned int seen;
};

static struct environment env = {
	.timeout_ms = 5000,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s [--probe-offset BYTES] [--timeout-ms MS] [--verbose] "
		"-- COMMAND [ARG...]\n\n"
		"Inspect the executable image installed by one command.\n\n"
		"Options:\n"
		"  -p, --probe-offset BYTES  also compare direct/deferred file reads\n"
		"  -t, --timeout-ms MS       bound the command, 100-60000 "
		"(default: 5000)\n"
		"  -v, --verbose             print libbpf diagnostics\n"
		"  -h, --help                show this help\n",
		program);
}

static int parse_u64(const char *value, unsigned long long maximum,
			     unsigned long long *result)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(value, &end, 10);
	if (errno || end == value || *end || parsed > maximum)
		return -EINVAL;
	*result = parsed;
	return 0;
}

static int parse_probe_offset(const char *value)
{
	unsigned long long parsed;

	if (parse_u64(value, UINT_MAX - EXEC_PROBE_LEN, &parsed)) {
		fprintf(stderr, "invalid probe offset: %s\n", value);
		return -EINVAL;
	}
	env.probe_offset = parsed;
	return 0;
}

static int parse_timeout(const char *value)
{
	unsigned long long parsed;

	if (parse_u64(value, 60000, &parsed) || parsed < 100) {
		fprintf(stderr, "invalid timeout in milliseconds: %s\n", value);
		return -EINVAL;
	}
	env.timeout_ms = parsed;
	return 0;
}

static int parse_option(int option, const char *program)
{
	switch (option) {
	case 'p':
		return parse_probe_offset(optarg);
	case 't':
		return parse_timeout(optarg);
	case 'v':
		env.verbose = true;
		return 0;
	case 'h':
		usage(program);
		exit(0);
	default:
		return -EINVAL;
	}
}

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "probe-offset", required_argument, NULL, 'p' },
		{ "timeout-ms", required_argument, NULL, 't' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int error, option;

	while ((option = getopt_long(argc, argv, "+p:t:vh", options, NULL)) != -1) {
		error = parse_option(option, argv[0]);
		if (error)
			return error;
	}

	if (optind == argc) {
		fprintf(stderr, "COMMAND is required\n");
		return -EINVAL;
	}
	env.command = &argv[optind];
	return 0;
}

static long long monotonic_milliseconds(void)
{
	struct timespec timestamp;

	if (clock_gettime(CLOCK_MONOTONIC, &timestamp))
		return -errno;
	return timestamp.tv_sec * 1000LL + timestamp.tv_nsec / 1000000;
}

static int start_blocked_child(struct child_process *child)
{
	int pipe_fds[2];
	pid_t pid;

	if (pipe(pipe_fds))
		return -errno;

	pid = fork();
	if (pid < 0) {
		int error = -errno;

		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return error;
	}

	if (pid == 0) {
		char release;
		ssize_t count;

		close(pipe_fds[1]);
		do {
			count = read(pipe_fds[0], &release, sizeof(release));
		} while (count < 0 && errno == EINTR);
		close(pipe_fds[0]);
		if (count != sizeof(release))
			_exit(126);

		/* Intentional argv execution; no shell parses the supplied arguments. */
		execvp(env.command[0], env.command); /* Flawfinder: ignore */
		fprintf(stderr, "failed to execute %s: %s\n", env.command[0],
			strerror(errno));
		_exit(127);
	}

	close(pipe_fds[0]);
	child->pid = pid;
	child->release_fd = pipe_fds[1];
	return 0;
}

static int release_child(struct child_process *child)
{
	char release = 1;
	ssize_t count;

	do {
		count = write(child->release_fd, &release, sizeof(release));
	} while (count < 0 && errno == EINTR);
	close(child->release_fd);
	child->release_fd = -1;
	if (count != sizeof(release))
		return count < 0 ? -errno : -EIO;
	child->released = true;
	return 0;
}

static int child_exit_code(int status)
{
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);
	return 125;
}

static int reap_child(struct child_process *child, int options)
{
	pid_t result;

	if (child->reaped)
		return 1;
	do {
		result = waitpid(child->pid, &child->status, options);
	} while (result < 0 && errno == EINTR);
	if (result < 0)
		return -errno;
	if (result == 0)
		return 0;
	child->reaped = true;
	return 1;
}

static int drain_events(struct ring_buffer *ring_buffer)
{
	int error;

	for (;;) {
		error = ring_buffer__poll(ring_buffer, 0);
		if (error == -EINTR)
			continue;
		if (error < 0) {
			fprintf(stderr, "ring-buffer drain failed: %s\n",
				strerror(-error));
			return error;
		}
		if (!error)
			return 0;
	}
}

static const char *elf_class_name(unsigned char value)
{
	switch (value) {
	case 1:
		return "ELF32";
	case 2:
		return "ELF64";
	default:
		return "UNKNOWN";
	}
}

static const char *elf_data_name(unsigned char value)
{
	switch (value) {
	case 1:
		return "LSB";
	case 2:
		return "MSB";
	default:
		return "UNKNOWN";
	}
}

static const char *elf_type_name(unsigned short value)
{
	switch (value) {
	case 2:
		return "ET_EXEC";
	case 3:
		return "ET_DYN";
	default:
		return "OTHER";
	}
}

static const char *elf_machine_name(unsigned short value)
{
	switch (value) {
	case 3:
		return "EM_386";
	case 62:
		return "EM_X86_64";
	case 183:
		return "EM_AARCH64";
	default:
		return "OTHER";
	}
}

static int handle_event(void *context, void *data, size_t size)
{
	const struct exec_event *event = data;
	struct event_context *events = context;
	unsigned int index;

	if (size < sizeof(*event)) {
		fprintf(stderr, "short ring-buffer event: %zu bytes\n", size);
		return 0;
	}

	events->seen++;
	printf("EXEC pid=%u tgid=%u comm=%.*s path=%.*s is_elf=%u "
	       "class=%s endian=%s type=%s(%u) machine=%s(%u) "
	       "header_error=%d path_error=%d latency_us=%llu\n",
	       event->pid, event->tgid, EXEC_COMM_LEN, event->comm,
	       EXEC_PATH_LEN, event->path, event->is_elf,
	       elf_class_name(event->elf_class), elf_data_name(event->elf_data),
	       elf_type_name(event->elf_type), event->elf_type,
	       elf_machine_name(event->elf_machine), event->elf_machine,
	       event->header_error, event->path_error,
	       event->latency_ns / 1000);

	if (event->probe_offset) {
		printf("PROBE offset=%llu direct_error=%d deferred_error=%d bytes=",
		       event->probe_offset, event->direct_probe_error,
		       event->deferred_probe_error);
		for (index = 0; index < EXEC_PROBE_LEN; index++)
			printf("%02x", event->probe_bytes[index]);
		putchar('\n');
	}
	fflush(stdout);
	return 0;
}

static void stop_child(struct child_process *child)
{
	if (child->reaped || child->pid <= 0)
		return;
	if (!child->released && child->release_fd >= 0) {
		close(child->release_fd);
		child->release_fd = -1;
	} else {
		kill(child->pid, SIGKILL);
	}
	(void)reap_child(child, 0);
}

static int setup_inspector(const struct child_process *child,
			   struct event_context *events,
			   struct exec_image_inspector_bpf **skeleton,
			   struct ring_buffer **ring_buffer)
{
	struct exec_image_inspector_bpf *skel;
	struct ring_buffer *ring;
	int error;

	skel = exec_image_inspector_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return -ENOMEM;
	}
	*skeleton = skel;
	skel->rodata->target_tgid = child->pid;
	skel->rodata->probe_offset = env.probe_offset;

	error = exec_image_inspector_bpf__load(skel);
	if (error) {
		fprintf(stderr, "failed to load BPF object: %s\n", strerror(-error));
		return error;
	}
	error = exec_image_inspector_bpf__attach(skel);
	if (error) {
		fprintf(stderr, "failed to attach bprm_committed_creds LSM hook: %s\n",
			strerror(-error));
		return error;
	}

	ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
				events, NULL);
	if (!ring) {
		fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
		return errno ? -errno : -ENOMEM;
	}
	*ring_buffer = ring;
	return 0;
}

static int reap_timed_out_child(struct child_process *child)
{
	int error;

	if (child->reaped)
		return 0;

	fprintf(stderr, "command exceeded timeout; sending SIGKILL\n");
	kill(child->pid, SIGKILL);
	error = reap_child(child, 0);
	if (error < 0) {
		fprintf(stderr, "waitpid after timeout failed: %s\n",
			strerror(-error));
		return error;
	}
	return 0;
}

static int wait_for_command(struct ring_buffer *ring_buffer,
			    struct child_process *child,
			    const struct event_context *events)
{
	long long deadline, now;
	int error;

	printf("READY target_tgid=%d probe_offset=%llu timeout_ms=%u command=%s\n",
	       child->pid, env.probe_offset, env.timeout_ms, env.command[0]);
	fflush(stdout);
	error = release_child(child);
	if (error) {
		fprintf(stderr, "failed to release command process: %s\n",
			strerror(-error));
		return error;
	}

	now = monotonic_milliseconds();
	if (now < 0) {
		fprintf(stderr, "failed to read monotonic clock: %s\n",
			strerror((int)-now));
		return (int)now;
	}
	deadline = now + env.timeout_ms;

	for (;;) {
		error = ring_buffer__poll(ring_buffer, 50);
		if (error == -EINTR)
			continue;
		if (error < 0) {
			fprintf(stderr, "ring-buffer poll failed: %s\n", strerror(-error));
			return error;
		}

		error = reap_child(child, WNOHANG);
		if (error < 0) {
			fprintf(stderr, "waitpid failed: %s\n", strerror(-error));
			return error;
		}
		if (child->reaped && events->seen)
			break;

		now = monotonic_milliseconds();
		if (now < 0)
			return (int)now;
		if (now >= deadline)
			break;
		if (child->reaped && !events->seen)
			continue;
	}

	error = reap_timed_out_child(child);
	if (error)
		return error;
	error = drain_events(ring_buffer);
	if (error)
		return error;
	return child_exit_code(child->status);
}

static int report_result(const struct exec_image_inspector_bpf *skel,
			 const struct event_context *events, int command_exit)
{
	struct inspector_stats final_stats = skel->bss->stats;

	printf("SUMMARY matched=%llu scheduled=%llu schedule_errors=%llu "
	       "callbacks=%llu header_errors=%llu path_errors=%llu "
	       "direct_probes=%llu direct_probe_errors=%llu "
	       "deferred_probes=%llu deferred_probe_errors=%llu dropped=%llu "
	       "events=%u command_exit=%d\n",
	       final_stats.matched, final_stats.scheduled,
	       final_stats.schedule_errors, final_stats.callbacks,
	       final_stats.header_errors, final_stats.path_errors,
	       final_stats.direct_probes, final_stats.direct_probe_errors,
	       final_stats.deferred_probes, final_stats.deferred_probe_errors,
	       final_stats.dropped, events->seen, command_exit);

	if (!events->seen) {
		fprintf(stderr, "no executable image event was observed\n");
		return 1;
	}
	if (command_exit) {
		fprintf(stderr, "command exited with status %d\n", command_exit);
		return command_exit;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct exec_image_inspector_bpf *skel = NULL;
	struct child_process child = { .release_fd = -1 };
	struct event_context events = {};
	struct ring_buffer *ring_buffer = NULL;
	int command_exit, error, result = 1;

	error = parse_args(argc, argv);
	if (error) {
		usage(argv[0]);
		return 2;
	}

	libbpf_set_print(libbpf_print_fn);
	error = start_blocked_child(&child);
	if (error) {
		fprintf(stderr, "failed to create command process: %s\n",
			strerror(-error));
		return 1;
	}

	error = setup_inspector(&child, &events, &skel, &ring_buffer);
	if (error)
		goto cleanup;
	command_exit = wait_for_command(ring_buffer, &child, &events);
	if (command_exit < 0)
		goto cleanup;
	result = report_result(skel, &events, command_exit);

cleanup:
	stop_child(&child);
	ring_buffer__free(ring_buffer);
	exec_image_inspector_bpf__destroy(skel);
	return result;
}
```
<!-- END FULL SOURCE -->

## Schedule the read from a non-sleepable hook

`schedule_exec_inspection` starts by comparing the current TGID with `target_tgid`. The loader sets that read-only value before load, so unrelated execs return immediately. A matching call increments `matched` and looks up key zero in the one-entry `pending` ARRAY map.

The map value is `struct exec_work`. It contains `scheduled_ns`, the direct probe result, and the `struct bpf_task_work` storage. One invocation observes one child, so one slot is enough. Execs by that child are sequential because the task-work callback runs for the task before it can return to user space and call exec again. A service that handles concurrent tasks would need per-task storage, admission limits, and a policy for tasks that never run the callback.

When `--probe-offset` is present, `probe_file_without_sleep` creates a file-backed dynptr from `bprm->file` and tries to read eight bytes. The fixture's [`create_probe_image()`](./tests/test_exec_image_inspector.py) places `EIPROBE!` on an evicted page more than 4 MiB into the copied executable. That direct access returns `-EFAULT` in the verified run. Cached data could succeed, which is why ordinary image inspection leaves the probe disabled.

The hook stores the timestamp and direct result before calling `bpf_task_work_schedule_signal`. It passes the current task, the work storage, the map, and `inspect_executable`. The kernel holds the references needed for the callback, so the program does not defer a raw `struct file *` from `bprm`.

## Reacquire and read the installed image

`inspect_executable` runs for the task in a sleepable context. It records callback latency for diagnostics, fills the PID, TGID, command name, and direct-probe result, then calls `bpf_get_task_exe_file()` for the image installed on the task.

That kfunc returns a referenced `struct file`. Every successful acquisition must end with `bpf_put_file()`. The callback resolves the path with `bpf_path_d_path` and creates a dynptr with `bpf_dynptr_from_file`. The file dynptr also owns internal state, so every creation path calls `bpf_dynptr_file_discard()`, including the helper's failure path required by this API.

The callback reads only a 64-byte header plus the optional eight-byte marker. It does not scan the whole executable. After a successful header read, the program checks the first four bytes for the ELF magic. Only a matching header is decoded into `EI_CLASS`, `EI_DATA`, `e_type`, and `e_machine`, with both little-endian and big-endian 16-bit values handled.

User space turns common values into names such as `ELF64`, `LSB`, `ET_DYN`, and `EM_X86_64`, while retaining the original numeric type and machine values. Header, path, direct-probe, and deferred-probe failures stay in the event instead of being hidden.

## The loader closes exec and cleanup races

`start_blocked_child` forks before BPF setup, but the child waits for one byte on a pipe. The parent already knows the child PID, which is also its TGID here, and can set `target_tgid` before loading the object. If setup fails, cleanup closes the unreleased pipe and reaps the child without executing the target.

After attachment, `release_child` lets `execvp` run. The call receives an argv vector directly, and no shell parses those arguments. `wait_for_command()` polls the ring buffer, checks `waitpid(WNOHANG)`, and stops when the child is reaped with at least one event or the deadline arrives.

A child may install more than one image. The integration case runs `/bin/sh -c 'exec /bin/true'`, which produces one event for the shell and another for `/bin/true`. After reaping, `drain_events` empties the ring buffer so the final image event is not lost. The test requires two matches, two scheduled callbacks, two completed callbacks, two events, and `/usr/bin/true` as the last resolved path.

When a command exceeds `--timeout-ms`, `reap_timed_out_child` sends SIGKILL and waits for it. Normal completion and every handled error path free the ring buffer and destroy the skeleton, which detaches the LSM link. The tool creates no bpffs pin or persistent link.

The command's exit status remains visible. Receiving an exec event does not turn a failed command into success. Per-event inspection failures remain visible in fields such as `header_error` and `path_error`, but those fields do not by themselves turn a successful command into a nonzero loader exit. The loader has no external SIGINT or SIGTERM handler, so a released child may continue if an outside signal terminates the loader.

## Compilation and execution

Build the lesson on the host without loading BPF:

```bash
git submodule update --init --recursive
make -C src/54-exec-image-inspector clean
make -C src/54-exec-image-inspector -j2
```

Run the integration test only inside a disposable Linux 6.19 or newer guest. Before running it, satisfy the [runtime requirements](#runtime-requirements) and confirm that `bpf` appears in the active LSM list. Both `make test` and direct execution attach a BPF LSM program, so they are not host validation commands.

```bash
cd src/54-exec-image-inspector
sudo make test
```

Repository CI compiles this lesson without loading it. Runtime proof came from the reused `bpf-benchmark` KVM guest running `7.0.0-rc2+`. Exact kernel provenance appears with the runtime requirements below.

The captured session starts with KVM guest provenance, followed by the integration-test harness and tool output:

```text
guest_kernel=7.0.0-rc2+
guest_identity=uid=0(root) gid=0(root) groups=0(root)
TEST-MISSING matched=0 events=0 command_exit=127
TEST-TIMEOUT matched=1 callbacks=1 events=1 command_exit=137
TEST-REEXEC matched=2 callbacks=2 events=2 command_exit=0 final_path=/usr/bin/true
READY target_tgid=1265 probe_offset=4214784 timeout_ms=3000 command=/tmp/exec-image-inspector-sxm3lumw/exec_fixture_image
EXEC pid=1265 tgid=1265 comm=exec_fixture_im path=/tmp/exec-image-inspector-sxm3lumw/exec_fixture_image is_elf=1 class=ELF64 endian=LSB type=ET_DYN(3) machine=EM_X86_64(62) header_error=0 path_error=0 latency_us=37
PROBE offset=4214784 direct_error=-14 deferred_error=0 bytes=454950524f424521
exec fixture completed
SUMMARY matched=1 scheduled=1 schedule_errors=0 callbacks=1 header_errors=0 path_errors=0 direct_probes=1 direct_probe_errors=1 deferred_probes=1 deferred_probe_errors=0 dropped=0 events=1 command_exit=0
PASS: missing-command, timeout cleanup, re-exec drain, ELF decode, and deferred file read succeeded
```

PID, TGID, temporary path, callback latency, and the fixture's probe offset can change after another build or run. The latency is diagnostic output, not a benchmark or overhead measurement.

The main `EXEC` line identifies the installed image and its ELF header. The fixture flushed and evicted the page containing its appended marker before exec. The direct hook read returned `-EFAULT` (`-14`), while the task-work callback returned `454950524f424521`, the hexadecimal bytes for `EIPROBE!`.

The three test lines before `READY` cover important boundaries. A missing command exits with status 127 and never reaches the committed-exec hook, so the test waits only for its 500 ms deadline and sees no event. The timeout case produces an exec event, exceeds its 200 ms test deadline, and is reaped after SIGKILL with status 137. The re-exec case drains both installed-image events and confirms `/usr/bin/true` appears last.

To inspect another command in a suitable guest, omit the fixture-only probe offset:

```bash
sudo ./exec_image_inspector --timeout-ms 3000 -- /bin/true
```

The CLI syntax is:

```text
exec_image_inspector [--probe-offset BYTES] [--timeout-ms MS] [--verbose] -- COMMAND [ARG...]
```

- `--timeout-ms` accepts 100 through 60000 ms and defaults to 5000 ms. The loader kills and reaps the command after the deadline.
- `--probe-offset` compares a direct and deferred eight-byte read. Ordinary inspection does not need it. The fixture calculates a valid marker offset and creates the cold-page condition.
- `--verbose` prints libbpf diagnostics for load or attach debugging.
- `--` explicitly ends inspector option parsing. Every later argument belongs to the observed command.

An ordinary run without `--probe-offset` prints `READY`, one or more `EXEC` lines, and `SUMMARY`. It does not print a `PROBE` line.

## Runtime requirements

| Requirement | Value | Reason |
| --- | --- | --- |
| Linux kernel | 6.19 or newer | BPF task work arrived in 6.18, while file-backed dynptr support arrived in 6.19 |
| Kernel configuration | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_LSM=y`, `CONFIG_SECURITY=y`, `CONFIG_DEBUG_INFO_BTF=y` | Loads a BTF-enabled BPF LSM program |
| Active LSM list | `bpf` appears in `/sys/kernel/security/lsm` | `CONFIG_BPF_LSM=y` does not activate BPF LSM at boot by itself |
| Privilege | Root | Loads and attaches the BPF LSM program |
| Tested architecture | x86_64 | The deterministic ELF assertions currently expect x86-64 |
| Tested tooling | Repository-pinned bpftool `3be8ac3` with nested libbpf `fc064eb` | Builds the BPF object and generated skeleton used by this lesson |
| Hardware | None | The fixture needs no accelerator or special device |

For the captured run, the kernel source worktree was clean at commit `a03114efd0720dff230388f7e160e427e54ea31b`. The kernel image SHA-256 was `760150dd317a5c05e58d35928bd70c399f41838f3be3ac643f3f3a3af4340b88`, and the config SHA-256 was `82f63944a9ddd0bc3b0a60c3e6ebbe3e9900f2eefad7d3872793bb98b3cc68fe`.

The local [`bpf_experimental.h`](./bpf_experimental.h) is temporary compatibility glue for the repository's older generated `vmlinux.h` and UAPI headers. It can be removed after those vendored headers include the required kfunc declarations.

Inside the guest, check the active LSM list with:

```bash
cat /sys/kernel/security/lsm
```

If `bpf` is absent, append it to the guest's existing comma-separated `lsm=` kernel command-line value. Change `lsm=<existing-list>` to `lsm=<existing-list>,bpf` without removing other LSMs. Otherwise the attach step fails. Keep this boot change inside the disposable guest.

## Scope and limitations

- The loader observes one child that it creates. It does not monitor every exec on the system.
- A later exec by the same child produces another `EXEC` line. The loader drains queued events after reaping, and the last line identifies the last image observed before exit.
- The tool reports an executable image and a compact ELF header. It does not verify signatures, classify malware, or enforce an allowlist.
- The event stores at most 256 path bytes and 16 command-name bytes. A longer path can set `path_error`, and the command name can be truncated.
- For a script, the installed executable may be the interpreter rather than the script path. The output answers which image the task installed, not every input file consumed by the launch chain.
- The cold-page fixture demonstrates why deferred file I/O matters. It does not prove that every direct file read fails.
- The single map slot fits the one-child CLI. A concurrent service needs per-task state, admission limits, and recovery for tasks that never execute the callback.
- The KVM run is a functional test. Its callback latency is not a benchmark or an overhead estimate.
- Runtime behavior was exercised on x86_64. Other architectures need their own fixture assertions and KVM coverage.
- The loader has no external SIGINT or SIGTERM handler. Its BPF link closes if the loader is terminated, but an already released child may continue and must be managed by the caller.
- Timeout cleanup sends SIGKILL only to the direct child. It does not kill a process group, so descendants created by that child may outlive the timeout.

## Summary

This example separates two moments that an exec-aware tool often confuses. The LSM hook identifies the committed exec but cannot fault in arbitrary file pages, while BPF task work provides a sleepable callback that can reacquire and inspect the installed image. The blocked-child handshake, bounded command runner, final ring-buffer drain, and explicit resource release turn those kernel features into a reproducible one-command tool without pretending to be a full audit service.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [BPF task-work plumbing](https://github.com/torvalds/linux/commit/5c8fd7e2b5b0a527cf88740da122166695382a78)
- [`bpf_task_work_schedule_signal()` kfunc](https://github.com/torvalds/linux/commit/38aa7003e369802f81a078f6673d10d97013f04f)
- [File-backed dynptr plumbing](https://github.com/torvalds/linux/commit/8d8771dc03e48300e80b43744dd3c320ccaf746a)
- [File dynptr kfuncs and helpers](https://github.com/torvalds/linux/commit/e3e36edb1b8f0e6975c68acd2e1202ec0397fd75)
- [Sleepable file-dynptr dispatch](https://github.com/torvalds/linux/commit/2c52e8943a437af6093d8b0f0920f1764f0e5f64)
- [Kernel kfunc documentation](https://github.com/torvalds/linux/blob/v7.1/Documentation/bpf/kfuncs.rst)
- [File-reader BPF selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/file_reader.c)
- [BPF task-work selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/task_work.c)
