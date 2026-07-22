# eBPF Tutorial: Inspecting the Executable Image After exec

When a process calls `execve`, the kernel replaces its memory image with a new executable. But which executable, exactly? If the command line says `/usr/bin/wrapper.sh --config /etc/app.conf`, the actual running code might be a Python interpreter or a compiled binary launched three layers deep through wrapper scripts. Security tools, container runtimes, and troubleshooting utilities all need to know what the kernel *actually* installed, not just what the user typed.

This tutorial builds a tool that captures that information at the kernel level. It hooks the moment credentials are committed after exec, schedules a deferred callback, then reads the installed executable's ELF header and reports the architecture, byte order, and file type. Along the way, it demonstrates two recent kernel features (BPF task work and file dynptr) that together solve a problem traditional eBPF approaches cannot.

> Complete source: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/54-exec-image-inspector>

## The problem: reading file content from eBPF

Why would a security tool need to read the executable's content rather than just its path? Because the path alone does not identify what code will run. A hash of the executable's content can verify it matches a known-good binary. Embedded signatures or certificates can prove provenance. Specific byte patterns at known offsets can identify packing, obfuscation, or tampering. None of this information is available from the path; you must read the file's bytes. Doing so from eBPF, at the exact moment of exec, eliminates the race window that plagues user-space approaches.

The most direct approach to inspecting an executable is reading `/proc/<pid>/exe`, but this only works if the process is still alive. Short-lived processes exit before you can read them. Even if you catch them in time, the `/proc` filesystem is accessed from user space, creating a race window: by the time you read the symlink, the process might have called `execve` again.

Tracepoints and kprobes can hook `sched_process_exec` to observe exec events synchronously, but these hooks run in what the kernel calls a **non-sleepable context**. This matters because of how Linux manages file data in memory.

When you read from a file, the kernel first checks whether the requested bytes are already in the **page cache**, a memory region that caches recently-accessed file data. If they are, the read completes immediately. If they are not (a **cold page**), the kernel must issue I/O to the storage device, and the calling context must **sleep** while waiting for that I/O to complete.

BPF programs attached to tracepoints and kprobes cannot sleep. They run with interrupts potentially disabled and locks held; sleeping would deadlock the system. If a BPF program tries to read file content and encounters a cold page, the read fails with `-EFAULT` instead of waiting for I/O.

This creates a fundamental limitation: you can observe exec events, but you cannot reliably read the executable's content to verify its ELF header or check embedded metadata.

## The solution: BPF task work and file dynptr

Linux 6.18 introduced **BPF task work**, a mechanism that lets a BPF program schedule a callback to run later in a safe, sleepable context. The callback executes before the target task returns to user space, at a point where the kernel permits sleeping.

Linux 6.19 introduced **file dynptr**, which provides verifier-tracked access to file data. A dynptr (dynamic pointer) is a BPF abstraction that tracks a pointer's bounds at verification time; the file variant wraps file I/O operations so the verifier can ensure memory safety.

Combining these features, the design becomes:

1. Attach an LSM hook to `bprm_committed_creds`, which fires after exec installs the new credentials
2. In the hook (non-sleepable), identify the target process and schedule a task work callback
3. The callback runs in a sleepable context, where it can access the installed executable, read content from any offset (including cold pages), and send results to user space

This separation (identify the target in a non-sleepable hook, do the heavy lifting in a sleepable callback) is the key insight.

## How BPF task work operates

When you call `bpf_task_work_schedule_signal(task, work, map, callback)`, the kernel associates your callback with the specified task. The callback does not run immediately; it runs later, at a safe point before that task returns to user space.

The `struct bpf_task_work` is an opaque structure that the kernel uses to track the scheduled callback. Your BPF program allocates storage for it but does not interpret its contents. This tool uses a single-element ARRAY map to hold `struct exec_work`, which contains the `bpf_task_work` storage plus fields for timestamps and intermediate results.

The callback signature is `int callback(struct bpf_map *map, void *key, void *value)`. The `value` parameter points to the map element containing your `bpf_task_work`, so you can pass data from the scheduling hook to the callback through surrounding fields.

## How file dynptr operates

A dynptr wraps a pointer with bounds information that the BPF verifier can track. For file dynptrs:

- `bpf_dynptr_from_file(file, flags, dynptr)` creates a dynptr from a file
- `bpf_dynptr_read(dst, len, dynptr, offset, flags)` reads content at the specified offset
- `bpf_dynptr_file_discard(dynptr)` releases the dynptr's internal state

Every path that creates a dynptr, including error paths, must call `bpf_dynptr_file_discard` to release it. Failing to do so leaks internal resources.

In a non-sleepable context, `bpf_dynptr_read` only succeeds if the target bytes are already in the page cache. Accessing a cold page returns `-EFAULT`. In a sleepable context, the same call can trigger page fault handling and wait for I/O, so it succeeds even for cold pages. This difference is why task work matters: the callback runs in a sleepable context where file reads work reliably.

## Tool architecture

The user-space program forks a child process, but holds the child blocked on a pipe before it calls `execvp`. This gives the parent time to:

1. Note the child's PID (which becomes its TGID, thread group ID)
2. Open the BPF skeleton and write the target TGID into read-only data
3. Load and attach the BPF program
4. Create a ring buffer reader

Only then does the parent release the child by writing to the pipe. This handshake eliminates a race condition: without it, a fast-exiting command might finish before the BPF program attaches.

When the child calls `execvp`, the `lsm/bprm_committed_creds` hook fires. The BPF program compares the current TGID with the configured target; if they match, it records a timestamp and schedules a task work callback.

The callback (`inspect_executable`) runs in the child's sleepable context. It:

1. Calls `bpf_get_task_exe_file` to get the installed executable (returning a referenced `struct file` that must be released with `bpf_put_file`)
2. Resolves the path with `bpf_path_d_path`
3. Creates a file dynptr and reads the 64-byte ELF header
4. Parses ELF fields: magic number, class (32/64-bit), data (endianness), type (executable vs shared object), and machine (architecture)
5. Sends an event through the ring buffer

User space polls the ring buffer while also checking whether the child has exited. A single child might exec multiple times (for example, `/bin/sh -c 'exec /bin/true'` first execs the shell, then execs `/bin/true`), so after the child exits, the tool drains any remaining events from the ring buffer.

![Exec image inspector data flow](https://github.com/eunomia-bpf/bpf-developer-tutorial/raw/main/src/54-exec-image-inspector/exec-image-flow.png)

## Code walkthrough

The implementation spans four files: a shared header, a compatibility header for new kernel interfaces, the BPF program, and the user-space loader.

### Shared header

`exec_image_inspector.h` defines structures shared between BPF and user space:

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

`exec_event` carries everything needed to report one exec: process identifiers, the resolved path, ELF metadata, and error codes. `inspector_stats` accumulates counters that user space reads from the BSS section at exit to report success and failure rates.

### Compatibility header

The repository's vendored vmlinux headers predate Linux 6.18/6.19, so `bpf_experimental.h` declares the new interfaces locally:

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

These declarations use `__ksym` to mark them as kernel symbols resolved at load time. Once the repository's vmlinux headers are regenerated from a 6.19+ kernel, this file can be removed.

### BPF program

`exec_image_inspector.bpf.c` implements the LSM hook and the task work callback:

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

The entry point is `schedule_exec_inspection`, declared with `SEC("lsm/bprm_committed_creds")`. This LSM hook fires after the new executable's credentials have been installed, so `bprm->file` points to the file being executed. The hook itself is non-sleepable, but it can identify the target and schedule the deferred work.

The two `const volatile` variables (`target_tgid` and `probe_offset`) live in the `.rodata` section. User space writes values between `open()` and `load()`, and the verifier treats them as compile-time constants for optimization.

When the target matches, the program looks up `struct exec_work` from the single-element `pending` ARRAY map. This structure holds the `bpf_task_work` storage plus a timestamp and optional direct-probe result. A single slot suffices because this tool observes one child process per invocation.

The optional `--probe-offset` flag makes the tool attempt a direct read in the non-sleepable hook via `probe_file_without_sleep`. The test suite uses this to verify that reading a cold page fails with `-EFAULT` in the non-sleepable context but succeeds in the sleepable callback.

After saving the timestamp and direct-probe result, the hook calls `bpf_task_work_schedule_signal`. The kernel holds the references needed to execute the callback later.

The callback `inspect_executable` calculates latency for diagnostics, then acquires the executable file with `bpf_get_task_exe_file`. This returns a referenced `struct file` that must be released with `bpf_put_file`. The callback resolves the path, creates a file dynptr, reads the 64-byte ELF header, and parses it. The `read_elf_u16` helper handles endianness: ELF files declare their byte order in the header, and multi-byte fields must be read accordingly.

Every path that creates a dynptr, success or failure, must call `bpf_dynptr_file_discard`. Finally, `bpf_ringbuf_output` sends the event to user space.

### User-space loader

`exec_image_inspector.c` coordinates the child process, loads BPF, receives events, and reports results:

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

The core technique is the blocked-child handshake. `start_blocked_child` forks before BPF setup, but the child blocks on a pipe read. The parent notes the child's PID, opens the skeleton, writes `target_tgid`, loads and attaches, creates the ring buffer, and only then calls `release_child` to write to the pipe and let the child proceed to `execvp`.

`wait_for_command` is the main loop. It prints a `READY` line, releases the child, then alternates between polling the ring buffer and checking whether the child has exited. The loop ends when the child is reaped and at least one event has arrived, or when the timeout expires. After timeout, `reap_timed_out_child` sends SIGKILL and waits.

A single exec might trigger multiple events if the command itself execs (for example, `/bin/sh -c 'exec /bin/true'`). After the child exits, `drain_events` does a zero-timeout poll to collect any remaining events.

`handle_event` formats the output, translating numeric ELF values to readable names while preserving the raw values for scripting.

## Building and running

Build from source:

```bash
git submodule update --init --recursive
make -C src/54-exec-image-inspector clean
make -C src/54-exec-image-inspector -j2
```

The test suite requires Linux 6.19 or newer with the BPF LSM active. Check that `bpf` appears in the LSM list:

```bash
cat /sys/kernel/security/lsm
```

If `bpf` is missing, add it to the kernel command line: change `lsm=<existing-list>` to `lsm=<existing-list>,bpf` in your bootloader configuration.

Run the tests:

```bash
cd src/54-exec-image-inspector
sudo make test
```

The repository CI only compiles this lesson. Runtime behavior was functionally tested on x86_64 with kernel `7.0.0-rc2+`. Sample output:

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

The first three test lines cover boundary conditions:

- **TEST-MISSING**: A nonexistent command exits with status 127. The LSM hook never fires because exec fails before credentials are committed, so `matched=0` and `events=0`.
- **TEST-TIMEOUT**: The command runs too long, gets SIGKILL, and is reaped with status 137 (128 + 9). One exec event was observed.
- **TEST-REEXEC**: A shell command that uses `exec` internally produces two events, and the final path is `/usr/bin/true`.

The `EXEC` line shows the installed image and parsed ELF fields. The `PROBE` line demonstrates the sleepable-context difference: the test writes a marker (`EIPROBE!`) to a page, flushes and evicts it from the page cache, then execs. The direct read in the non-sleepable hook returns `-EFAULT` (`-14`) because the page is cold. The deferred read in the sleepable callback succeeds, returning the marker bytes as hex (`454950524f424521`).

To inspect a simple command:

```bash
sudo ./exec_image_inspector --timeout-ms 3000 -- /bin/true
```

Command-line format:

```text
exec_image_inspector [--probe-offset BYTES] [--timeout-ms MS] [--verbose] -- COMMAND [ARG...]
```

- `--timeout-ms`: 100 to 60000 milliseconds (default 5000). The tool kills and reaps the command after this deadline.
- `--probe-offset`: Read 8 bytes at this offset both in the hook (direct) and in the callback (deferred), to verify the cold-page difference.
- `--verbose`: Print libbpf diagnostic messages.
- `--`: Separates inspector options from the command to run.

### Requirements

| Requirement | Details |
|---|---|
| Kernel version | Linux 6.19+ (BPF task work introduced in 6.18, file dynptr in 6.19) |
| Kernel configuration | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_LSM=y`, `CONFIG_SECURITY=y`, `CONFIG_DEBUG_INFO_BTF=y` |
| Active LSM | `/sys/kernel/security/lsm` must contain `bpf` |
| Architecture | Tested on x86_64 |
| Privileges | root |

## Limitations and extensions

This tool observes one direct child per invocation, using a single map slot. For concurrent services, you would allocate per-task state, implement admission limits, and handle callback reclamation. Timeout cleanup sends SIGKILL to the child only; callers needing process-group management or external signal handling would add those features.

## Summary

This tutorial demonstrates how to combine BPF task work and file dynptr to inspect the executable image actually installed by exec. The key insight is separating two moments: identifying the target (in a non-sleepable LSM hook) and reading file content (in a sleepable task work callback). This lets eBPF programs read file data reliably, even when the target bytes are not in the page cache.

The blocked-child handshake eliminates attach races, bounded execution ensures cleanup, and the final drain captures all events. Together, these techniques produce a reproducible single-command tool while leaving room for extension.

> To learn more about eBPF, visit our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or <https://eunomia.dev/tutorials/>.

## References

- [BPF task-work plumbing](https://github.com/torvalds/linux/commit/5c8fd7e2b5b0a527cf88740da122166695382a78)
- [bpf_task_work_schedule_signal kfunc](https://github.com/torvalds/linux/commit/38aa7003e369802f81a078f6673d10d97013f04f)
- [File-backed dynptr plumbing](https://github.com/torvalds/linux/commit/8d8771dc03e48300e80b43744dd3c320ccaf746a)
- [File dynptr kfuncs and helpers](https://github.com/torvalds/linux/commit/e3e36edb1b8f0e6975c68acd2e1202ec0397fd75)
- [Sleepable file-dynptr dispatch](https://github.com/torvalds/linux/commit/2c52e8943a437af6093d8b0f0920f1764f0e5f64)
- [Kernel kfunc documentation](https://github.com/torvalds/linux/blob/v7.1/Documentation/bpf/kfuncs.rst)
- [File-reader BPF selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/file_reader.c)
- [BPF task-work selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/task_work.c)
