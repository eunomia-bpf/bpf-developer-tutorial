# eBPF Tutorial: Inspecting the Executable Image After exec

Imagine a container running a series of nested wrapper scripts. What you see from `ps` or `/proc` is `/usr/bin/wrapper.sh --config /etc/app.conf`, but the actual business logic might be a Python interpreter or some dynamically linked binary three layers deep. When troubleshooting, you need to know which executable image the kernel finally installed, what architecture it targets, and what byte order it uses - not just the command-line arguments.

This tutorial shows how to achieve this using BPF task work and file-backed dynptr. The tool attaches an LSM hook to observe the `bprm_committed_creds` moment, schedules a task work callback for the target process after credentials are committed, and that callback runs in a sleepable context to reacquire the installed executable file, resolve its path, read the ELF header, and send the results to user space through a ring buffer.

> Complete source: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/54-exec-image-inspector>

## Why BPF task work and file dynptr are needed

Traditional approaches to inspecting executable files all have significant limitations.

The most straightforward idea is to read the `/proc/<pid>/exe` symlink, but this requires the process to still be alive. Short-lived processes may have already exited before you can read it. Furthermore, `/proc` access happens in user space, creating a race window with the kernel's exec event - the same process might have already executed `execve` multiple times.

Using a tracepoint or kprobe to observe `sched_process_exec` can capture exec events, but these hooks run in a non-sleepable context. You can obtain the file path, but if you need to read file contents to verify the ELF header or check embedded metadata, you run into a problem: the file-backed dynptr's `bpf_dynptr_read` triggers a page fault when target bytes are on a cold page, and page faults require sleep to complete. BPF programs in a non-sleepable context cannot wait for I/O.

BPF task work solves this problem. Linux 6.18 introduced the `bpf_task_work_schedule_signal` kfunc, which allows a BPF program to schedule a callback for a target task. The kernel executes this callback in a safe sleepable context. Linux 6.19 introduced file-backed dynptr, providing verifier-tracked file data access. Combining these two features, you can identify the target process in an LSM hook, record a timestamp, and schedule task work. The callback then runs in a sleepable context where it can reacquire the task's installed executable file, read content from any offset through the dynptr (including cold pages), and finally send the complete inspection results to user space.

This is the design philosophy behind `exec_image_inspector`: the LSM hook selects the child process and schedules task work, while the sleepable callback performs the actual file reading and parsing.

## How BPF task work and file dynptr work

BPF task work is a deferred execution mechanism. When you call `bpf_task_work_schedule_signal(task, work, map, callback)` in a BPF program, the kernel associates the callback with the specified task. The callback does not execute immediately - it runs at a safe point before that task returns to user space, where the context allows sleeping.

`struct bpf_task_work` is an opaque 64-byte structure. The BPF program only needs to allocate storage for it; the kernel manages its internal state. This tool uses a single-element ARRAY map to store `struct exec_work`, which contains the `bpf_task_work` storage, a scheduling timestamp, and direct probe results.

File-backed dynptr provides a verifier-tracked file data access interface. `bpf_dynptr_from_file(file, flags, dynptr)` creates a dynptr from a file, and `bpf_dynptr_read(dst, len, dynptr, offset, flags)` reads content at the specified offset. The dynptr holds internal state, so every path that creates a dynptr must call `bpf_dynptr_file_discard` to release it, including failure branches.

In a non-sleepable context, the dynptr can only read content already in the page cache; accessing a cold page returns `-EFAULT`. In a sleepable context, the dynptr can trigger page fault operations and wait for I/O to complete. This is precisely the value of the task work callback.

## Overall tool flow

After user space starts, it forks the target command, but the child process blocks waiting for a release signal on a pipe. This way the parent knows the child's PID (which is also the TGID) before the child executes `execvp`, and can write this value into the BPF program's read-only data section as a filter condition. Blocking the child eliminates the attach race with short-lived commands and keeps the example self-contained.

The parent opens the BPF skeleton, sets `target_tgid` and the optional `probe_offset`, loads and attaches the LSM program, creates a ring buffer reader, then writes a release byte to the pipe to let the child execute `execvp`.

After the child executes exec, the `lsm/bprm_committed_creds` hook triggers when credentials are committed. The BPF program compares the current TGID with `target_tgid` and returns immediately if they do not match. After matching the target, the program records a scheduling timestamp, optionally attempts a direct read in the current context if `--probe-offset` is set (to verify the cold page scenario), then calls `bpf_task_work_schedule_signal` to schedule the callback.

The callback `inspect_executable` runs in that task's sleepable context. It calls `bpf_get_task_exe_file` to obtain the task's currently installed executable file (returning a referenced `struct file` that must be released with `bpf_put_file`), resolves the path with `bpf_path_d_path`, and reads the 64-byte ELF header plus the optional marker location using the file dynptr. After a successful read, it parses the ELF magic, class, data, type, and machine fields. Finally, it packages all the information into a ring buffer event and sends it to user space.

User space alternates between polling the ring buffer and checking child process status with `waitpid(WNOHANG)`. The loop ends when the child is reaped and at least one event is received, or when the timeout is reached. The same child might install multiple images in succession (for example, `/bin/sh -c 'exec /bin/true'`), so after the child is reaped, `drain_events` performs a zero-timeout poll to collect any remaining events in the ring buffer.

![Exec image inspector data flow](https://github.com/eunomia-bpf/bpf-developer-tutorial/raw/main/src/54-exec-image-inspector/exec-image-flow.png)

## Code implementation

This tool consists of four files: a shared header defining event and statistics structures, a compatibility header declaring new kernel kfuncs, a BPF program implementing the hook and callback, and a user-space loader managing the lifecycle.

### Shared header

`exec_image_inspector.h` defines the ring buffer event structure and statistics structure shared between BPF and user space.

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

`exec_event` contains all the information needed to inspect one exec: PID, TGID, process name, path, ELF parsing results, probe results, callback latency, and various error codes. `inspector_stats` accumulates match, schedule, callback, error, and drop counts; user space reads the BSS section at the end and reports the statistics.

### Compatibility declarations

Linux 6.18 introduced BPF task work, and 6.19 introduced file-backed dynptr. The repository's currently generated UAPI and BTF headers predate these features, so this tool places the missing declarations in a local header `bpf_experimental.h`.

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

This file declares kfuncs including `bpf_task_work_schedule_signal`, `bpf_get_task_exe_file`, `bpf_put_file`, `bpf_path_d_path`, `bpf_dynptr_from_file`, and `bpf_dynptr_file_discard`. This file can be removed once the repository's integrated vmlinux headers include these declarations.

### BPF program

`exec_image_inspector.bpf.c` implements the LSM hook and task work callback.

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

The program entry point is the `schedule_exec_inspection` function declared with `SEC("lsm/bprm_committed_creds")`. The `bprm_committed_creds` hook runs after the new executable's credentials have been committed, at which point `bprm->file` points to the image involved in this exec. This hook itself is non-sleepable, but we can identify the target process here and schedule task work.

The two `const volatile` variables `target_tgid` and `probe_offset` are in the `.rodata` section. User space writes values after `open()` but before `load()`, and the verifier treats them as compile-time constants. The program first compares the current TGID with `target_tgid`, returning immediately if they do not match to avoid observing unrelated process execs.

After matching the target, the program looks up key 0 from the single-element `pending` ARRAY map to obtain `struct exec_work`. This structure stores the scheduling timestamp, direct probe result, and `struct bpf_task_work` storage. This tool observes only one child process per invocation, so one slot is sufficient. When `--probe-offset` is set, `probe_file_without_sleep` attempts to read 8 bytes from the specified location in `bprm->file` in the current non-sleepable context. The test program places the marker on a cold page to verify that direct reads return `-EFAULT` in this scenario.

After the hook saves the timestamp and direct read result, it calls `bpf_task_work_schedule_signal`, passing the current task, work storage, map pointer, and the `inspect_executable` callback function pointer. The kernel holds the references needed for callback execution, and the callback will run in a sleepable context before that task returns to user space.

`inspect_executable` is the task work callback function, with signature `int callback(struct bpf_map *map, void *key, void *value)`. It first calculates callback latency (current time minus scheduling timestamp) for diagnostics, then fills PID, TGID, process name, and direct probe result into the event structure. It then calls `bpf_get_task_exe_file` to obtain the task's installed executable file. This kfunc returns a referenced `struct file`; every successful acquisition must be released with `bpf_put_file`.

The callback first resolves the file path with `bpf_path_d_path`, then creates a dynptr with `bpf_dynptr_from_file`. Since we are now in a sleepable context, `bpf_dynptr_read` can trigger page fault operations and wait for I/O to complete. The callback only reads a 64-byte ELF header and an optional 8-byte marker. After a successful header read, the program checks the 4-byte ELF magic `\x7fELF`, then parses `EI_CLASS` (32-bit or 64-bit), `EI_DATA` (little-endian or big-endian), `e_type` (executable or shared object), and `e_machine` (architecture). The `read_elf_u16` helper function correctly parses 16-bit fields according to byte order.

Every path that creates a dynptr must call `bpf_dynptr_file_discard` to release its internal state, including branches where the helper fails. Finally, `bpf_ringbuf_output` sends the event to user space; the `dropped` counter is incremented if sending fails.

### User-space loader

`exec_image_inspector.c` handles command-line parsing, coordinates the blocked child, loads BPF, formats events, and cleans up resources.

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

The loader's flow centers on the blocked child handshake. `start_blocked_child` forks before BPF setup, but the child blocks on a pipe read. The parent already knows the child PID at this point and can write it to `rodata->target_tgid` after opening the skeleton. After attachment, `release_child` writes one byte to the pipe to let the child continue with `execvp`. This handshake eliminates the attach race with short-lived commands.

The `setup_inspector` function opens the skeleton, sets read-only data, loads and attaches the BPF program, and creates the ring buffer reader. Error messages on load failure indicate possible causes to help users troubleshoot kernel version or configuration issues.

`wait_for_command` is the main loop. It first prints a `READY` line indicating the tool is ready, then releases the child, sets a timeout deadline, and enters the poll loop. The loop alternates between calling `ring_buffer__poll` to receive events and `waitpid(WNOHANG)` to check child status. The loop exits when the child is reaped and at least one event is received, or when the timeout is reached. After timeout, `reap_timed_out_child` sends SIGKILL to the child and waits for it to exit.

The same child may install multiple images in succession. For example, running `/bin/sh -c 'exec /bin/true'` causes the shell to exec itself first, then exec `/bin/true`. After the child is reaped, `drain_events` uses zero-timeout poll to collect any remaining events in the ring buffer, ensuring the last image event also reaches user space.

`handle_event` parses ring buffer events and prints formatted output. It converts ELF numeric values to readable names like `ELF64`, `LSB`, `ET_DYN`, `EM_X86_64`, while preserving original values. When `--probe-offset` is set, it also prints a `PROBE` line showing probe results.

## Compilation and execution

Build from source:

```bash
git submodule update --init --recursive
make -C src/54-exec-image-inspector clean
make -C src/54-exec-image-inspector -j2
```

The integration test requires Linux 6.19 or newer. Before running, confirm that `bpf` appears in the active LSM list:

```bash
cat /sys/kernel/security/lsm
```

To add `bpf`, change `lsm=<existing-list>` to `lsm=<existing-list>,bpf` in the kernel boot parameters.

Run tests:

```bash
cd src/54-exec-image-inspector
sudo make test
```

Repository CI only compiles this lesson. Runtime behavior was functionally tested on x86_64 with kernel `7.0.0-rc2+`. The following session output shows the test harness and tool output:

```text
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

The first three test records cover important boundaries: a missing command exits with status 127, at which point the committed-exec hook has not yet triggered, so `matched=0` and `events=0`; the timeout case produces an exec event then exceeds the test deadline, is terminated by SIGKILL, and reaped with status 137; the successive exec case drains two image events and confirms `/usr/bin/true` appears last.

The `EXEC` line shows the installed image and ELF header parsing results. The test program flushes and evicts the marker page before exec, so the direct read in the hook returns `-EFAULT` (`-14`), while the task-work callback successfully returns `454950524f424521` (the hexadecimal bytes for `EIPROBE!`). This verifies that non-sleepable context cannot read cold pages, while sleepable context can.

To inspect other commands, omit the test-program-specific probe offset:

```bash
sudo ./exec_image_inspector --timeout-ms 3000 -- /bin/true
```

Command-line format:

```text
exec_image_inspector [--probe-offset BYTES] [--timeout-ms MS] [--verbose] -- COMMAND [ARG...]
```

`--timeout-ms` accepts 100 to 60000 milliseconds, default is 5000 milliseconds; the loader terminates and reaps the command after the deadline. `--probe-offset` compares 8-byte direct and deferred reads at the specified location, used to verify cold page scenarios. `--verbose` outputs libbpf diagnostics for troubleshooting load or attach issues. `--` explicitly ends inspector option parsing; all subsequent arguments belong to the observed command.

### Environment requirements

| Requirement | Details |
|---|---|
| Kernel version | Linux 6.19+ (BPF task work introduced in 6.18, file-backed dynptr introduced in 6.19) |
| Kernel configuration | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_LSM=y`, `CONFIG_SECURITY=y`, `CONFIG_DEBUG_INFO_BTF=y` |
| Active LSM | `/sys/kernel/security/lsm` contains `bpf` |
| Architecture | Tested on x86_64 |
| Privilege | root |

## Scope

This tool observes one direct child that it creates, and a single map slot is sufficient for this CLI scenario. To extend it to concurrent services, you could allocate per-task state, set admission limits, and reclaim pending callbacks. Timeout cleanup sends SIGKILL to the child; callers can add process-group management and external signal handling to cover more complex scenarios.

## Summary

This tutorial demonstrates how to use BPF task work and file-backed dynptr to inspect the executable image actually installed after exec. Compared to reading `/proc/<pid>/exe` or obtaining paths in tracepoints, this approach can read file contents in a sleepable context, even when target bytes are on cold pages.

The core idea of this tool is to separate the moment of identifying the target process (non-sleepable LSM hook) from the moment of reading file contents (sleepable task work callback). The blocked-child handshake eliminates attach races, bounded command execution and final drain ensure all events reach user space, and explicit resource release guarantees complete cleanup. These kernel features combine into a reproducible single-command tool while leaving room for extension to concurrent scenarios.

> If you want to learn more about eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [BPF task-work plumbing](https://github.com/torvalds/linux/commit/5c8fd7e2b5b0a527cf88740da122166695382a78)
- [bpf_task_work_schedule_signal kfunc](https://github.com/torvalds/linux/commit/38aa7003e369802f81a078f6673d10d97013f04f)
- [File-backed dynptr plumbing](https://github.com/torvalds/linux/commit/8d8771dc03e48300e80b43744dd3c320ccaf746a)
- [File dynptr kfuncs and helpers](https://github.com/torvalds/linux/commit/e3e36edb1b8f0e6975c68acd2e1202ec0397fd75)
- [Sleepable file-dynptr dispatch](https://github.com/torvalds/linux/commit/2c52e8943a437af6093d8b0f0920f1764f0e5f64)
- [Kernel kfunc documentation](https://github.com/torvalds/linux/blob/v7.1/Documentation/bpf/kfuncs.rst)
- [File-reader BPF selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/file_reader.c)
- [BPF task-work selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/task_work.c)
