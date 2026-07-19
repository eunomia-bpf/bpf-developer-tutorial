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
