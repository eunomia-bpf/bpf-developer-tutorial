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

1. Attach an LSM hook to `bprm_committed_creds`, which fires after each successful exec installs the new credentials
2. In the hook (non-sleepable), create per-exec state and schedule a task work callback
3. The callback runs in a sleepable context, where it can access the installed executable, read content from any offset (including cold pages), and send results to user space

This separation (admit the exec in a non-sleepable hook, do the heavy lifting in a sleepable callback) is the key insight.

## How BPF task work operates

When you call `bpf_task_work_schedule_signal(task, work, map, callback)`, the kernel associates your callback with the specified task. The callback does not run immediately; it runs later, at a safe point before that task returns to user space.

The `struct bpf_task_work` is an opaque structure that the kernel uses to track the scheduled callback. Your BPF program allocates storage for it but does not interpret its contents. This tool uses a HASH map keyed by `pid_tgid`; each `struct exec_work` value contains the `bpf_task_work` storage plus fields for timestamps and intermediate results. Separate keys allow concurrent execs to remain independent.

The callback signature is `int callback(struct bpf_map *map, void *key, void *value)`. The `value` parameter points to the map element containing your `bpf_task_work`, so you can pass data from the scheduling hook to the callback through surrounding fields.

## How file dynptr operates

A dynptr wraps a pointer with bounds information that the BPF verifier can track. For file dynptrs:

- `bpf_dynptr_from_file(file, flags, dynptr)` creates a dynptr from a file
- `bpf_dynptr_read(dst, len, dynptr, offset, flags)` reads content at the specified offset
- `bpf_dynptr_file_discard(dynptr)` releases the dynptr's internal state

Every path that creates a dynptr, including error paths, must call `bpf_dynptr_file_discard` to release it. Failing to do so leaks internal resources.

In a non-sleepable context, `bpf_dynptr_read` only succeeds if the target bytes are already in the page cache. Accessing a cold page returns `-EFAULT`. In a sleepable context, the same call can trigger page fault handling and wait for I/O, so it succeeds even for cold pages. This difference is why task work matters: the callback runs in a sleepable context where file reads work reliably.

## Tool architecture

The user-space program loads and attaches the BPF program, creates a ring buffer reader, and prints `READY scope=system-wide`. It then remains active until SIGINT or SIGTERM, so workloads can start independently after readiness instead of being launched through a special child-command interface.

For every successful exec after `READY`, the `lsm/bprm_committed_creds` hook inserts one `exec_work` value into the `pending` HASH map under the current `pid_tgid`, records a timestamp, and schedules a task work callback. Failed insertions or scheduling attempts are counted and clean up the map entry.

The callback (`inspect_executable`) runs later in the execing task's sleepable context. It:

1. Calls `bpf_get_task_exe_file` to get the installed executable (returning a referenced `struct file` that must be released with `bpf_put_file`)
2. Resolves the path with `bpf_path_d_path`
3. Creates a file dynptr and reads the 64-byte ELF header
4. Parses ELF fields: magic number, class (32/64-bit), data (endianness), type (executable vs shared object), and machine (architecture)
5. Sends an event through the ring buffer

User space polls the ring buffer until a signal arrives. Shutdown first detaches the LSM program to stop admitting new execs, waits until `completed >= scheduled`, drains remaining events, prints stable counters, and only then destroys the skeleton. This ordering prevents queued callbacks from outliving their maps or ring buffer.

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
	unsigned long long completed;
	unsigned long long header_errors;
	unsigned long long path_errors;
	unsigned long long direct_probes;
	unsigned long long direct_probe_errors;
	unsigned long long deferred_probes;
	unsigned long long deferred_probe_errors;
	unsigned long long dropped;
	unsigned long long cleanup_errors;
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
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 4096);
	__type(key, __u64);
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

static __always_inline void record_header_error(struct exec_event *event, int err)
{
	event->header_error = err;
	__sync_fetch_and_add(&stats.header_errors, 1);
}

static __always_inline void record_deferred_probe(struct exec_event *event,
						   int err)
{
	if (!probe_offset)
		return;

	event->deferred_probe_error = err;
	__sync_fetch_and_add(&stats.deferred_probes, 1);
	if (err)
		__sync_fetch_and_add(&stats.deferred_probe_errors, 1);
}

static __always_inline void parse_elf_header(const unsigned char *header,
					     struct exec_event *event)
{
	if (event->header_error || header[0] != 0x7f || header[1] != 'E' ||
	    header[2] != 'L' || header[3] != 'F')
		return;

	event->is_elf = 1;
	event->elf_class = header[EI_CLASS];
	event->elf_data = header[EI_DATA];
	event->elf_type = read_elf_u16(header, 16, event->elf_data);
	event->elf_machine = read_elf_u16(header, 18, event->elf_data);
}

static __always_inline void inspect_file(struct file *file,
					 struct exec_event *event)
{
	unsigned char header[64] = {};
	struct bpf_dynptr dynptr;
	int err;

	err = bpf_path_d_path(&file->f_path, event->path, sizeof(event->path));
	if (err < 0) {
		event->path_error = err;
		__sync_fetch_and_add(&stats.path_errors, 1);
	}

	err = bpf_dynptr_from_file(file, 0, &dynptr);
	if (err) {
		bpf_dynptr_file_discard(&dynptr);
		record_header_error(event, err);
		record_deferred_probe(event, err);
		return;
	}

	err = bpf_dynptr_read(header, sizeof(header), &dynptr, 0, 0);
	if (err)
		record_header_error(event, err);

	if (probe_offset) {
		err = bpf_dynptr_read(event->probe_bytes,
				      sizeof(event->probe_bytes),
				      &dynptr, probe_offset, 0);
		record_deferred_probe(event, err);
	}
	bpf_dynptr_file_discard(&dynptr);
	parse_elf_header(header, event);
}

static int inspect_executable(struct bpf_map *map, void *key, void *value)
{
	struct exec_work *work = value;
	struct exec_event event = {};
	struct task_struct *task;
	struct file *file;
	__u64 pid_tgid;

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
		record_header_error(&event, -ENOENT);
		record_deferred_probe(&event, -ENOENT);
		goto emit;
	}

	inspect_file(file, &event);
	bpf_put_file(file);
emit:
	if (bpf_ringbuf_output(&events, &event, sizeof(event), 0))
		__sync_fetch_and_add(&stats.dropped, 1);
	if (bpf_map_delete_elem(map, key))
		__sync_fetch_and_add(&stats.cleanup_errors, 1);
	__sync_fetch_and_add(&stats.completed, 1);
	return 0;
}

SEC("lsm/bprm_committed_creds")
void BPF_PROG(schedule_exec_inspection, struct linux_binprm *bprm)
{
	struct task_struct *task;
	struct exec_work empty_work = {};
	struct exec_work *work;
	__u64 pid_tgid;
	__u64 key;
	int err;

	pid_tgid = bpf_get_current_pid_tgid();
	key = pid_tgid;
	__sync_fetch_and_add(&stats.matched, 1);
	err = bpf_map_update_elem(&pending, &key, &empty_work, BPF_NOEXIST);
	if (err) {
		__sync_fetch_and_add(&stats.schedule_errors, 1);
		return;
	}
	work = bpf_map_lookup_elem(&pending, &key);
	if (!work) {
		__sync_fetch_and_add(&stats.schedule_errors, 1);
		if (bpf_map_delete_elem(&pending, &key))
			__sync_fetch_and_add(&stats.cleanup_errors, 1);
		return;
	}

	work->scheduled_ns = bpf_ktime_get_ns();
	work->direct_probe_error = probe_file_without_sleep(bprm->file);
	task = bpf_get_current_task_btf();
	err = bpf_task_work_schedule_signal(task, &work->work, &pending,
					    inspect_executable);
	if (err) {
		__sync_fetch_and_add(&stats.schedule_errors, 1);
		if (bpf_map_delete_elem(&pending, &key))
			__sync_fetch_and_add(&stats.cleanup_errors, 1);
		return;
	}
	__sync_fetch_and_add(&stats.scheduled, 1);
}
```

The entry point is `schedule_exec_inspection`, declared with `SEC("lsm/bprm_committed_creds")`. This LSM hook fires after the new executable's credentials have been installed, so `bprm->file` points to the file being executed. The hook itself is non-sleepable, but it can admit the exec and schedule the deferred work.

The optional `probe_offset` variable lives in `.rodata`. User space writes it between `open()` and `load()`, and the verifier treats it as a compile-time constant for optimization.

For each exec, the program inserts a zeroed `struct exec_work` into the `pending` HASH map with `BPF_NOEXIST`, keyed by `pid_tgid`, then looks it up to fill the timestamp and optional direct-probe result. The callback deletes that exact key. This supports concurrent execs without sharing one task-work slot.

The optional `--probe-offset` flag makes the tool attempt a direct read in the non-sleepable hook via `probe_file_without_sleep`. The test suite uses this to verify that reading a cold page fails with `-EFAULT` in the non-sleepable context but succeeds in the sleepable callback.

After saving the timestamp and direct-probe result, the hook calls `bpf_task_work_schedule_signal`. The kernel holds the references needed to execute the callback later. Every insert, lookup, or scheduling failure is counted, and every path that created pending state deletes it.

The callback `inspect_executable` calculates latency for diagnostics, then acquires the executable file with `bpf_get_task_exe_file`. This returns a referenced `struct file` that must be released with `bpf_put_file`. The callback resolves the path, creates a file dynptr, reads the 64-byte ELF header, and parses it. The `read_elf_u16` helper handles endianness: ELF files declare their byte order in the header, and multi-byte fields must be read accordingly.

Every path that creates a dynptr, success or failure, must call `bpf_dynptr_file_discard`. Finally, `bpf_ringbuf_output` sends the event to user space, the callback deletes its pending entry, and `completed` is incremented so shutdown can wait for finished work rather than merely scheduled work.

### User-space loader

`exec_image_inspector.c` loads BPF, receives events continuously, handles signals, and reports results:

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "exec_image_inspector.h"
#include "exec_image_inspector.skel.h"

struct environment {
	unsigned long long probe_offset;
	bool verbose;
};

struct event_context {
	unsigned long long seen;
};

static struct environment env;
static volatile sig_atomic_t exiting;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
		"Usage: %s [--probe-offset BYTES] [--verbose]\n\n"
		"Continuously inspect executable images installed by exec.\n"
		"Press Ctrl-C to stop and print a summary.\n\n"
		"Options:\n"
		"  -p, --probe-offset BYTES  compare reads at a positive offset\n"
		"  -v, --verbose             print libbpf diagnostics\n"
		"  -h, --help                show this help\n",
		program);
}

static int parse_probe_offset(const char *value)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(value, &end, 10);
	if (errno || end == value || *end || !parsed ||
	    parsed > UINT_MAX - EXEC_PROBE_LEN) {
		fprintf(stderr, "invalid probe offset: %s\n", value);
		return -EINVAL;
	}
	env.probe_offset = parsed;
	return 0;
}

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "probe-offset", required_argument, NULL, 'p' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "+p:vh", options, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (parse_probe_offset(optarg))
				return -EINVAL;
			break;
		case 'v':
			env.verbose = true;
			break;
		case 'h':
			usage(stdout, argv[0]);
			exit(0);
		default:
			return -EINVAL;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "unexpected argument: %s\n", argv[optind]);
		return -EINVAL;
	}
	return 0;
}

static void handle_signal(int signal_number)
{
	(void)signal_number;
	exiting = 1;
}

static int install_signal_handlers(void)
{
	struct sigaction action = {
		.sa_handler = handle_signal,
	};

	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL))
		return -errno;
	return 0;
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

static int setup_inspector(struct event_context *events,
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
	skel->rodata->probe_offset = env.probe_offset;

	error = exec_image_inspector_bpf__load(skel);
	if (error) {
		fprintf(stderr,
			"failed to load BPF object: %s\n"
			"This monitor requires Linux 6.19+, BTF, BPF JIT, "
			"CONFIG_BPF_LSM=y, and an active bpf LSM.\n"
			"Check the active list with: cat /sys/kernel/security/lsm\n",
			strerror(-error));
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

static int monitor_execs(struct ring_buffer *ring_buffer)
{
	int error;

	printf("READY scope=system-wide probe_offset=%llu\n", env.probe_offset);
	fflush(stdout);
	while (!exiting) {
		error = ring_buffer__poll(ring_buffer, 100);
		if (error == -EINTR)
			continue;
		if (error < 0) {
			fprintf(stderr, "ring-buffer poll failed: %s\n", strerror(-error));
			return error;
		}
	}
	return 0;
}

static int drain_pending_events(struct ring_buffer *ring_buffer,
				const struct exec_image_inspector_bpf *skel)
{
	int attempts, error;

	for (attempts = 0; attempts < 10; attempts++) {
		if (skel->bss->stats.completed >= skel->bss->stats.scheduled)
			return drain_events(ring_buffer);
		error = ring_buffer__poll(ring_buffer, 100);
		if (error == -EINTR)
			continue;
		if (error < 0) {
			fprintf(stderr, "ring-buffer shutdown poll failed: %s\n",
				strerror(-error));
			return error;
		}
	}

	fprintf(stderr, "timed out waiting for %llu scheduled callbacks\n",
		skel->bss->stats.scheduled - skel->bss->stats.completed);
	return -ETIMEDOUT;
}

static void report_result(const struct exec_image_inspector_bpf *skel,
			  const struct event_context *events)
{
	struct inspector_stats final_stats = skel->bss->stats;

	printf("SUMMARY matched=%llu scheduled=%llu schedule_errors=%llu "
	       "callbacks=%llu completed=%llu header_errors=%llu path_errors=%llu "
	       "direct_probes=%llu direct_probe_errors=%llu "
	       "deferred_probes=%llu deferred_probe_errors=%llu dropped=%llu "
	       "cleanup_errors=%llu events=%llu\n",
	       final_stats.matched, final_stats.scheduled,
	       final_stats.schedule_errors, final_stats.callbacks,
	       final_stats.completed, final_stats.header_errors,
	       final_stats.path_errors,
	       final_stats.direct_probes, final_stats.direct_probe_errors,
	       final_stats.deferred_probes, final_stats.deferred_probe_errors,
	       final_stats.dropped, final_stats.cleanup_errors, events->seen);
}

int main(int argc, char **argv)
{
	struct exec_image_inspector_bpf *skel = NULL;
	struct event_context events = {};
	struct ring_buffer *ring_buffer = NULL;
	int error, result = 1;

	error = parse_args(argc, argv);
	if (error) {
		usage(stderr, argv[0]);
		return 2;
	}
	error = install_signal_handlers();
	if (error) {
		fprintf(stderr, "failed to install signal handlers: %s\n",
			strerror(-error));
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	error = setup_inspector(&events, &skel, &ring_buffer);
	if (error)
		goto cleanup;
	error = monitor_execs(ring_buffer);
	exec_image_inspector_bpf__detach(skel);
	if (!error)
		error = drain_pending_events(ring_buffer, skel);
	report_result(skel, &events);
	if (!error)
		result = 0;

cleanup:
	ring_buffer__free(ring_buffer);
	exec_image_inspector_bpf__destroy(skel);
	return result;
}
```

`setup_inspector` opens, configures, loads, and attaches the skeleton before creating the ring buffer. `monitor_execs` prints `READY`, then polls until SIGINT or SIGTERM. There is no required timeout and no `-- COMMAND` child-launch mode.

On shutdown, `main` detaches first. `drain_pending_events` then waits in bounded 100 ms polls for `completed` to catch up with `scheduled`, drains the ring buffer, and reports all counters before resources are destroyed.

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

The repository CI compiles this lesson. Runtime behavior was also functionally tested in the tutorial KVM on x86_64 with kernel `7.2.0-rc4`. A shortened sample is:

```text
TEST-CONTINUOUS workers=16 matched=18 callbacks=18 events=18
READY scope=system-wide probe_offset=4214784
EXEC pid=... tgid=... comm=exec_fixture_im path=/tmp/.../exec_fixture_image is_elf=1 class=ELF64 endian=LSB type=ET_DYN(3) machine=EM_X86_64(62) header_error=0 path_error=0 latency_us=...
PROBE offset=4214784 direct_error=-14 deferred_error=0 bytes=454950524f424521
SUMMARY matched=18 scheduled=18 schedule_errors=0 callbacks=18 completed=18 header_errors=0 path_errors=0 direct_probes=18 direct_probe_errors=18 deferred_probes=18 deferred_probe_errors=2 dropped=0 cleanup_errors=0 events=18
PASS: persistent monitoring, concurrent execs, signal cleanup, ELF decode, and deferred file reads succeeded
```

The test starts the monitor, waits for `READY`, launches 16 fixture processes concurrently plus a shell that re-execs `/bin/true`, and stops the monitor with SIGINT. It checks `scheduled == callbacks == completed == events`, with zero scheduling, drop, or cleanup errors. It also verifies that the obsolete `--timeout-ms` and `-- COMMAND` interface is rejected.

The `EXEC` line shows the installed image and parsed ELF fields. The `PROBE` line demonstrates the sleepable-context difference: the test writes a marker (`EIPROBE!`) to a page, flushes and evicts it from the page cache, then execs. The direct read in the non-sleepable hook returns `-EFAULT` (`-14`) because the page is cold. The deferred read in the sleepable callback succeeds, returning the marker bytes as hex (`454950524f424521`).

To monitor subsequent execs system-wide:

```bash
sudo ./exec_image_inspector
```

Command-line format:

```text
exec_image_inspector [--probe-offset BYTES] [--verbose]
```

- `--probe-offset`: Read 8 bytes at this offset both in the hook (direct) and in the callback (deferred), to verify the cold-page difference.
- `--verbose`: Print libbpf diagnostic messages.
- Ctrl-C or SIGTERM: Stop admission, wait for scheduled callbacks, drain events, print `SUMMARY`, and unload.

### Requirements

| Requirement | Details |
|---|---|
| Kernel version | Linux 6.19+ (BPF task work introduced in 6.18, file dynptr in 6.19) |
| Kernel configuration | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_LSM=y`, `CONFIG_SECURITY=y`, `CONFIG_DEBUG_INFO_BTF=y` |
| Active LSM | `/sys/kernel/security/lsm` must contain `bpf` |
| Architecture | Tested on x86_64 |
| Privileges | root |

## Limitations and extensions

This tool observes successful execs system-wide after `READY`. The pending HASH map supports up to 4096 concurrent `pid_tgid` keys; insertion or scheduling pressure is visible in `schedule_errors`. Shutdown waits for callbacks for about one second before returning an error rather than destroying live callback state silently. `--probe-offset` is an advanced diagnostic for comparing cold-page behavior, not a workload filter.

## Summary

This tutorial demonstrates how to combine BPF task work and file dynptr to inspect the executable image actually installed by exec. The key insight is separating two moments: admitting an exec (in a non-sleepable LSM hook) and reading file content (in a sleepable task work callback). This lets eBPF programs read file data reliably, even when the target bytes are not in the page cache.

The persistent monitor exposes a natural `READY` boundary for independent workloads. Detach-before-drain shutdown, per-exec pending state, and completed-work accounting keep concurrent callbacks safe while preserving the original task-work and file-dynptr lesson.

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
