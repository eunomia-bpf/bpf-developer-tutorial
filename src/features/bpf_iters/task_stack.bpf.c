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
