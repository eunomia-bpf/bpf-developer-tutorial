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
