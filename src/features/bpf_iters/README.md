# eBPF Tutorial by Example: BPF Iterators for Kernel Data Export

Ever tried monitoring hundreds of processes and ended up parsing thousands of `/proc` files just to find the few you care about? Or needed custom formatted kernel data but didn't want to modify the kernel itself? Traditional `/proc` filesystem access is slow, inflexible, and forces you to process tons of data in userspace even when you only need a small filtered subset.

This is what **BPF Iterators** solve. Introduced in Linux kernel 5.8, iterators let you traverse kernel data structures directly from BPF programs, apply filters in-kernel, and output exactly the data you need in any format you want. In this tutorial, we'll build a dual-mode iterator that shows kernel stack traces and open file descriptors for processes, with in-kernel filtering by process name - dramatically faster than parsing `/proc`.

## Introduction to BPF Iterators: The /proc Replacement

### The Problem: /proc is Slow and Rigid

Traditional Linux monitoring revolves around the `/proc` filesystem. Need to see what processes are doing? Read `/proc/*/stack`. Want open files? Parse `/proc/*/fd/*`. This works, but it's painfully inefficient when you're monitoring systems at scale or need specific filtered views of kernel data.

The performance problem is systemic. Every `/proc` access requires a syscall, kernel mode transition, text formatting, data copy to userspace, and then you parse that text back into structures. If you want stack traces for all "bash" processes among 1000 total processes, you still read all 1000 `/proc/*/stack` files and filter in userspace. That's 1000 syscalls, 1000 text parsing operations, and megabytes of data transferred just to find a handful of matches.

Format inflexibility compounds the problem. The kernel chooses what data to show and how to format it. Want stack traces with custom annotations? Too bad, you get the kernel's fixed format. Need to aggregate data across processes? Parse everything in userspace. The `/proc` interface is designed for human consumption, not programmatic filtering and analysis.

Here's what traditional monitoring looks like:

```bash
# Find stack traces for all bash processes
for pid in $(pgrep bash); do
  echo "=== PID $pid ==="
  cat /proc/$pid/stack
done
```

This spawns `pgrep` as a subprocess, makes a syscall per matching PID to read stack files, parses text output, and does all filtering in userspace. Simple to write, horrible for performance.

### The Solution: Programmable In-Kernel Iteration

BPF iterators flip the model. Instead of pulling all data to userspace for processing, you push your processing logic into the kernel where the data lives. An iterator is a BPF program attached to a kernel data structure traversal that gets called for each element. The kernel walks tasks, files, or sockets, invokes your BPF program with each element's context, and your code decides what to output and how to format it.

The architecture is elegant. You write a BPF program marked `SEC("iter/task")` or `SEC("iter/task_file")` that receives each task or file during iteration. Inside this program, you have direct access to kernel struct fields, can filter based on any criteria using normal C logic, and use `BPF_SEQ_PRINTF()` to format output exactly as needed. The kernel handles the iteration mechanics while your code focuses purely on filtering and formatting.

When userspace reads from the iterator file descriptor, the magic happens entirely in the kernel. The kernel walks the task list, calls your BPF program for each task passing the task_struct pointer. Your program checks if the task name matches your filter - if not, it returns 0 immediately with no output. If it matches, your program extracts the stack trace and formats it to a seq_file. All this happens in kernel context before any data crosses to userspace.

The benefits are transformative. **In-kernel filtering** means only relevant data crosses the kernel boundary, eliminating wasted work. **Custom formats** let you output binary, JSON, CSV, whatever your tools need. **Single read operation** replaces thousands of individual `/proc` file accesses. **Zero parsing** because you formatted the data correctly in the kernel. **Composability** works with standard Unix tools since iterator output comes through a normal file descriptor.

### Iterator Types and Capabilities

The kernel provides iterators for many subsystems. **Task iterators** (`iter/task`) walk all tasks giving you access to process state, credentials, resource usage, and parent-child relationships. **File iterators** (`iter/task_file`) traverse open file descriptors showing files, sockets, pipes, and other fd types. **Network iterators** (`iter/tcp`, `iter/udp`) walk active network connections with full socket state. **BPF object iterators** (`iter/bpf_map`, `iter/bpf_prog`) enumerate loaded BPF programs and maps for introspection.

Our tutorial focuses on task and task_file iterators because they solve common monitoring needs and demonstrate core concepts applicable to all iterator types.

## Implementation: Dual-Mode Task Iterator

Let's build a complete example demonstrating two iterator types in one tool. We'll create a program that can show either kernel stack traces or open file descriptors for processes, with optional filtering by process name.

### Complete BPF Program: task_stack.bpf.c

```c
// SPDX-License-Identifier: GPL-2.0
/* Kernel task stack and file descriptor iterator */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define MAX_STACK_TRACE_DEPTH   64
unsigned long entries[MAX_STACK_TRACE_DEPTH] = {};
#define SIZE_OF_ULONG (sizeof(unsigned long))

/* Filter: only show stacks for tasks with this name (empty = show all) */
char target_comm[16] = "";
__u32 stacks_shown = 0;
__u32 files_shown = 0;

/* Task stack iterator */
SEC("iter/task")
int dump_task_stack(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	long i, retlen;
	int match = 1;

	if (task == (void *)0) {
		/* End of iteration - print summary */
		if (stacks_shown > 0) {
			BPF_SEQ_PRINTF(seq, "\n=== Summary: %u task stacks shown ===\n",
				       stacks_shown);
		}
		return 0;
	}

	/* Filter by task name if specified */
	if (target_comm[0] != '\0') {
		match = 0;
		for (i = 0; i < 16; i++) {
			if (task->comm[i] != target_comm[i])
				break;
			if (task->comm[i] == '\0') {
				match = 1;
				break;
			}
		}
		if (!match)
			return 0;
	}

	/* Get kernel stack trace for this task */
	retlen = bpf_get_task_stack(task, entries,
				    MAX_STACK_TRACE_DEPTH * SIZE_OF_ULONG, 0);
	if (retlen < 0)
		return 0;

	stacks_shown++;

	/* Print task info and stack trace */
	BPF_SEQ_PRINTF(seq, "=== Task: %s (pid=%u, tgid=%u) ===\n",
		       task->comm, task->pid, task->tgid);
	BPF_SEQ_PRINTF(seq, "Stack depth: %u frames\n", retlen / SIZE_OF_ULONG);

	for (i = 0; i < MAX_STACK_TRACE_DEPTH; i++) {
		if (retlen > i * SIZE_OF_ULONG)
			BPF_SEQ_PRINTF(seq, "  [%2ld] %pB\n", i, (void *)entries[i]);
	}
	BPF_SEQ_PRINTF(seq, "\n");

	return 0;
}

/* Task file descriptor iterator */
SEC("iter/task_file")
int dump_task_file(struct bpf_iter__task_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	__u32 fd = ctx->fd;
	long i;
	int match = 1;

	if (task == (void *)0 || file == (void *)0) {
		if (files_shown > 0 && ctx->meta->seq_num > 0) {
			BPF_SEQ_PRINTF(seq, "\n=== Summary: %u file descriptors shown ===\n",
				       files_shown);
		}
		return 0;
	}

	/* Filter by task name if specified */
	if (target_comm[0] != '\0') {
		match = 0;
		for (i = 0; i < 16; i++) {
			if (task->comm[i] != target_comm[i])
				break;
			if (task->comm[i] == '\0') {
				match = 1;
				break;
			}
		}
		if (!match)
			return 0;
	}

	if (ctx->meta->seq_num == 0) {
		BPF_SEQ_PRINTF(seq, "%-16s %8s %8s %6s %s\n",
			       "COMM", "TGID", "PID", "FD", "FILE_OPS");
	}

	files_shown++;

	BPF_SEQ_PRINTF(seq, "%-16s %8d %8d %6d 0x%lx\n",
		       task->comm, task->tgid, task->pid, fd,
		       (long)file->f_op);

	return 0;
}
```

### Understanding the BPF Code

The program implements two separate iterators sharing common filtering logic. The `SEC("iter/task")` annotation registers `dump_task_stack` as a task iterator - the kernel will call this function once for each task in the system. The context structure `bpf_iter__task` provides three critical pieces: the `meta` field containing iteration metadata and the seq_file for output, the `task` pointer to the current task_struct, and a NULL task pointer when iteration finishes so you can print summaries.

The task stack iterator shows in-kernel filtering in action. When `task` is NULL, we've reached the end of iteration and can print summary statistics showing how many tasks matched our filter. For each task, we first apply filtering by comparing `task->comm` (the process name) against `target_comm`. We can't use standard library functions like `strcmp()` in BPF, so we manually loop through characters comparing byte by byte. If the names don't match and filtering is enabled, we immediately return 0 with no output - this task is skipped entirely in the kernel without crossing to userspace.

Once a task passes filtering, we extract its kernel stack trace using `bpf_get_task_stack()`. This BPF helper captures up to 64 stack frames into our `entries` array, returning the number of bytes written. We format the output using `BPF_SEQ_PRINTF()` which writes to the kernel's seq_file infrastructure. The special `%pB` format specifier symbolizes kernel addresses, turning raw pointers into human-readable function names like `schedule+0x42/0x100`. This makes stack traces immediately useful for debugging.

The file descriptor iterator demonstrates a different iterator type. `SEC("iter/task_file")` tells the kernel to call this function for every open file descriptor across all tasks. The context provides `task`, `file` (the kernel's struct file pointer), and `fd` (the numeric file descriptor). We apply the same task name filtering, then format output as a table. Using `ctx->meta->seq_num` to detect the first output lets us print column headers exactly once.

Notice how filtering happens before any expensive operations. We check the task name first, and only if it matches do we extract stack traces or format file information. This minimizes work in the kernel fast path - non-matching tasks are rejected with just a string comparison, no memory allocation, no formatting, no output.

### Complete User-Space Program: task_stack.c

```c
// SPDX-License-Identifier: GPL-2.0
/* Userspace program for task stack and file iterator */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "task_stack.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void run_iterator(const char *name, struct bpf_program *prog)
{
	struct bpf_link *link;
	int iter_fd, len;
	char buf[8192];

	link = bpf_program__attach_iter(prog, NULL);
	if (!link) {
		fprintf(stderr, "Failed to attach %s iterator\n", name);
		return;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		fprintf(stderr, "Failed to create %s iterator: %d\n", name, iter_fd);
		bpf_link__destroy(link);
		return;
	}

	while ((len = read(iter_fd, buf, sizeof(buf) - 1)) > 0) {
		buf[len] = '\0';
		printf("%s", buf);
	}

	close(iter_fd);
	bpf_link__destroy(link);
}

int main(int argc, char **argv)
{
	struct task_stack_bpf *skel;
	int err;
	int show_files = 0;

	libbpf_set_print(libbpf_print_fn);

	/* Parse arguments */
	if (argc > 1 && strcmp(argv[1], "--files") == 0) {
		show_files = 1;
		argc--;
		argv++;
	}

	/* Open BPF application */
	skel = task_stack_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Configure filter before loading */
	if (argc > 1) {
		strncpy(skel->bss->target_comm, argv[1], sizeof(skel->bss->target_comm) - 1);
		printf("Filtering for tasks matching: %s\n\n", argv[1]);
	} else {
		printf("Usage: %s [--files] [comm]\n", argv[0]);
		printf("  --files    Show open file descriptors instead of stacks\n");
		printf("  comm       Filter by process name\n\n");
	}

	/* Load BPF program */
	err = task_stack_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	if (show_files) {
		printf("=== BPF Task File Descriptor Iterator ===\n\n");
		run_iterator("task_file", skel->progs.dump_task_file);
	} else {
		printf("=== BPF Task Stack Iterator ===\n\n");
		run_iterator("task", skel->progs.dump_task_stack);
	}

cleanup:
	task_stack_bpf__destroy(skel);
	return err;
}
```

### Understanding the User-Space Code

The userspace program showcases how simple iterator usage is once you understand the pattern. The `run_iterator()` function encapsulates the three-step iterator lifecycle. First, `bpf_program__attach_iter()` attaches the BPF program to the iterator infrastructure, registering it to be called during iteration. Second, `bpf_iter_create()` creates a file descriptor representing an iterator instance. Third, simple `read()` calls consume the iterator output.

Here's what makes this powerful: when you read from the iterator fd, the kernel transparently starts walking tasks or files. For each element, it calls your BPF program passing the element's context. Your BPF code filters and formats output to a seq_file buffer. The kernel accumulates this output and returns it through the read() call. From userspace's perspective, it's just reading a file - all the iteration, filtering, and formatting complexity is hidden in the kernel.

The main function handles mode selection and configuration. We parse command-line arguments to determine whether to show stacks or files, and what process name to filter for. Critically, we set `skel->bss->target_comm` before loading the BPF program. This writes the filter string into the BPF program's global data section, making it visible to kernel code when the program runs. This is how we pass configuration from userspace to kernel without complex communication channels.

After loading, we select which iterator to run based on the `--files` flag. Both iterators use the same filtering logic, but produce different output - one shows stack traces, the other shows file descriptors. The shared filtering code demonstrates how BPF programs can implement reusable logic across different iterator types.

## Compilation and Execution

Navigate to the bpf_iters directory and build:

```bash
cd /home/yunwei37/workspace/bpf-developer-tutorial/src/features/bpf_iters
make
```

The Makefile compiles the BPF program with BTF support and generates a skeleton header containing the compiled bytecode embedded in C structures. This skeleton API makes BPF program loading trivial.

Show kernel stack traces for all systemd processes:

```bash
sudo ./task_stack systemd
```

Expected output:

```
Filtering for tasks matching: systemd

=== BPF Task Stack Iterator ===

=== Task: systemd (pid=1, tgid=1) ===
Stack depth: 6 frames
  [ 0] ep_poll+0x447/0x460
  [ 1] do_epoll_wait+0xc3/0xe0
  [ 2] __x64_sys_epoll_wait+0x6d/0x110
  [ 3] x64_sys_call+0x19b1/0x2310
  [ 4] do_syscall_64+0x7e/0x170
  [ 5] entry_SYSCALL_64_after_hwframe+0x76/0x7e

=== Summary: 1 task stacks shown ===
```

Show open file descriptors for bash processes:

```bash
sudo ./task_stack --files bash
```

Expected output:

```
Filtering for tasks matching: bash

=== BPF Task File Descriptor Iterator ===

COMM                 TGID      PID     FD FILE_OPS
bash                12345    12345      0 0xffffffff81e3c6e0
bash                12345    12345      1 0xffffffff81e3c6e0
bash                12345    12345      2 0xffffffff81e3c6e0
bash                12345    12345    255 0xffffffff82145dc0

=== Summary: 4 file descriptors shown ===
```

Run without filtering to see all tasks:

```bash
sudo ./task_stack
```

This shows stacks for every task in the system. On a typical desktop, this might display hundreds of tasks. Notice how fast it runs compared to parsing `/proc/*/stack` for all processes - the iterator is dramatically more efficient.

## When to Use BPF Iterators vs /proc

Choose **BPF iterators** when you need filtered kernel data without userspace processing overhead, custom output formats that don't match `/proc` text, performance-critical monitoring that runs frequently, or integration with BPF-based observability infrastructure. Iterators excel when you're monitoring many entities but only care about a subset, or when you need to aggregate and transform data in the kernel.

Choose **/proc** when you need simple one-off queries, are debugging or prototyping where development speed matters more than runtime performance, want maximum portability across kernel versions (iterators require relatively recent kernels), or run in restricted environments where you can't load BPF programs.

The fundamental trade-off is processing location. Iterators push filtering and formatting into the kernel for efficiency and flexibility, while `/proc` keeps the kernel simple and does all processing in userspace. For production monitoring of complex systems, iterators usually win due to their performance benefits and programming flexibility.

## Summary and Next Steps

BPF iterators revolutionize how we export kernel data by enabling programmable, filtered iteration directly from BPF code. Instead of repeatedly reading and parsing `/proc` files, you write a BPF program that iterates kernel structures in-kernel, applies filtering at the source, and formats output exactly as needed. This eliminates massive overhead from syscalls, mode transitions, and userspace parsing while providing complete flexibility in output format.

Our dual-mode iterator demonstrates both task and file iteration, showing how one BPF program can export multiple views of kernel data with shared filtering logic. The kernel handles complex iteration mechanics while your BPF code focuses purely on filtering and formatting. Iterators integrate seamlessly with standard Unix tools through their file descriptor interface, making them composable building blocks for sophisticated monitoring pipelines.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- **BPF Iterator Documentation:** <https://docs.kernel.org/bpf/bpf_iterators.html>
- **Kernel Iterator Selftests:** Linux kernel tree `tools/testing/selftests/bpf/*iter*.c`
- **Tutorial Repository:** <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/bpf_iters>
- **libbpf Iterator API:** <https://github.com/libbpf/libbpf>
- **BPF Helpers Manual:** <https://man7.org/linux/man-pages/man7/bpf-helpers.7.html>

Examples adapted from Linux kernel BPF selftests with educational enhancements. Requires Linux kernel 5.8+ for iterator support, BTF enabled, and libbpf. Complete source code available in the tutorial repository.
