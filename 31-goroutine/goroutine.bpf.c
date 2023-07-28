/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2022- The Yunshan Networks Authors.
 * 
 * Modify from https://github.com/deepflowio/deepflow
 * By Yusheng Zheng <1067852565@qq.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define NAME(N)  __##N

#define HASH_ENTRIES_MAX 40960
#define MAX_SYSTEM_THREADS 40960

struct sched_comm_fork_ctx {
	__u64 __pad_0;
	char parent_comm[16];
	__u32 parent_pid;
	char child_comm[16];
	__u32 child_pid;
};

struct sched_comm_exit_ctx {
	__u64 __pad_0;          /*     0     8 */
	char comm[16];          /*     offset:8;       size:16 */
	pid_t pid;        	/*     offset:24;      size:4  */
	int prio;		/*     offset:28;      size:4  */
};

// struct ebpf_proc_info -> offsets[]  arrays index.
enum offsets_index {
	OFFSET_IDX_GOID_RUNTIME_G,
	OFFSET_IDX_CONN_TLS_CONN,
	OFFSET_IDX_SYSFD_POLL_FD,
	OFFSET_IDX_CONN_HTTP2_SERVER_CONN,
	OFFSET_IDX_TCONN_HTTP2_CLIENT_CONN,
	OFFSET_IDX_CC_HTTP2_CLIENT_CONN_READ_LOOP,
	OFFSET_IDX_CONN_GRPC_HTTP2_CLIENT,
	OFFSET_IDX_CONN_GRPC_HTTP2_SERVER,
	OFFSET_IDX_FRAMER_GRPC_TRANSPORT_LOOPY_WRITER,
	OFFSET_IDX_WRITER_GRPC_TRANSPORT_FRAMER,
	OFFSET_IDX_CONN_GRPC_TRANSPORT_BUFWRITER,
	OFFSET_IDX_SIDE_GRPC_TRANSPORT_LOOPY_WRITER,
	OFFSET_IDX_FIELDS_HTTP2_META_HEADERS_FRAME,
	OFFSET_IDX_STREAM_HTTP2_CLIENT_CONN,
	OFFSET_IDX_STREAM_ID_HTTP2_FRAME_HEADER,
	OFFSET_IDX_MAX,
};

// Store the ebpf_proc_info to eBPF Map.
struct ebpf_proc_info {
	__u32 version;
	__u16 offsets[OFFSET_IDX_MAX];
	
	// In golang, itab represents type, and in interface, struct is represented
	// by the address of itab. We use itab to judge the structure type, and 
	// find the fd representing the connection after multiple jumps. These
	// types are not available in Go ELF files without a symbol table.
	// Go 用 itab 表示类型, 在 interface 中通过 itab 确定具体的 struct, 并根据
	// struct 找到表示连接的 fd.
	__u64 net_TCPConn_itab;
	__u64 crypto_tls_Conn_itab; // TLS_HTTP1,TLS_HTTP2
	__u64 credentials_syscallConn_itab; // gRPC
};

#define GO_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))

// Go implements a new way of passing function arguments and results using 
// registers instead of the stack. We need the go version and the computer
// architecture to determine the parameter locations
static __inline bool is_register_based_call(struct ebpf_proc_info *info)
{
#if defined(__x86_64__)
	// https://go.dev/doc/go1.17
	return info->version >= GO_VERSION(1, 17, 0);
#elif defined(__aarch64__)
	// https://groups.google.com/g/golang-checkins/c/SO9OmZYkOXU
	return info->version >= GO_VERSION(1, 18, 0);
#else
_Pragma("error \"Must specify a BPF target arch\"");
#endif
}

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
};

// Process ID and coroutine ID, marking the coroutine in the system
struct go_key {
	__u32 tgid;
	__u64 goid;
} __attribute__((packed));

// The mapping of coroutines to ancestors, the map is updated when a new
// coroutine is created
// key : current gorouting (struct go_key)
// value : ancerstor goid
struct bpf_map_def SEC("maps") go_ancerstor_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct go_key),
	.value_size = sizeof(__u64),
	.max_entries = HASH_ENTRIES_MAX,
};

// Used to determine the timeout, as a termination condition for finding
// ancestors.
// key : current gorouting (struct go_key)
// value: timestamp when the data was inserted into the map
struct bpf_map_def SEC("maps") go_rw_ts_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct go_key),
	.value_size = sizeof(__u64),
	.max_entries = HASH_ENTRIES_MAX,
};

/*
 * The binary executable file offset of the GO process
 * key: pid
 * value: struct ebpf_proc_info
 */
struct bpf_map_def SEC("maps") proc_info_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(struct ebpf_proc_info),
	.max_entries = HASH_ENTRIES_MAX,
};

// Pass data between coroutine entry and exit functions
struct go_newproc_caller {
	__u64 goid;
	void *sp; // stack pointer
} __attribute__((packed));

struct bpf_map_def SEC("maps") pid_tgid_callerid_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct go_newproc_caller),
	.max_entries = HASH_ENTRIES_MAX,
};

/*
 * Goroutines Map
 * key: {tgid, pid}
 * value: goroutine ID
 */
struct bpf_map_def SEC("maps") goroutines_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u64),
	.max_entries = MAX_SYSTEM_THREADS,
};

SEC("uprobe/runtime.execute")
int runtime_execute(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &tgid);
	if (!info) {
		return 0;
	}
	int offset_g_goid = info->offsets[OFFSET_IDX_GOID_RUNTIME_G];
	if (offset_g_goid < 0) {
		return 0;
	}

	void *g_ptr;

	if (is_register_based_call(info)) {
		g_ptr = (void *)PT_GO_REGS_PARM1(ctx);
	} else {
		bpf_probe_read(&g_ptr, sizeof(g_ptr), (void *)(PT_REGS_SP(ctx) + 8));
	}

	__s64 goid = 0;
	bpf_probe_read(&goid, sizeof(goid), g_ptr + offset_g_goid);
	bpf_map_update_elem(&goroutines_map, &pid_tgid, &goid, BPF_ANY);

	return 0;
}

// This function creates a new go coroutine, and the parent and child 
// coroutine numbers are in the parameters and return values ​​respectively.
// Pass the function parameters through pid_tgid_callerid_map
//
// go 1.15 ~ 1.17: func newproc1(fn *funcval, argp unsafe.Pointer, narg int32, callergp *g, callerpc uintptr) *g
// go1.18+ :func newproc1(fn *funcval, callergp *g, callerpc uintptr) *g
SEC("uprobe/enter_runtime.newproc1")
int enter_runtime_newproc1(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	struct ebpf_proc_info *info =
		bpf_map_lookup_elem(&proc_info_map, &tgid);
	if (!info) {
		return 0;
	}

	// go less than 1.15 cannot get parent-child coroutine relationship
	// ~ go1.14: func newproc1(fn *funcval, argp unsafe.Pointer, narg int32, callergp *g, callerpc uintptr)
	if (info->version < GO_VERSION(1, 15, 0)) {
		return 0;
	}

	int offset_g_goid = info->offsets[OFFSET_IDX_GOID_RUNTIME_G];
	if (offset_g_goid < 0) {
		return 0;
	}

	void *g_ptr;
	if (is_register_based_call(info)) {
		// https://github.com/golang/go/commit/8e5304f7298a0eef48e4796017c51b4d9aeb52b5
		if (info->version >= GO_VERSION(1, 18, 0)) {
			g_ptr = (void *)PT_GO_REGS_PARM2(ctx);
		} else {
			g_ptr = (void *)PT_GO_REGS_PARM4(ctx);
		}
	} else {
		if (info->version >= GO_VERSION(1, 18, 0)) {
			bpf_probe_read(&g_ptr, sizeof(g_ptr),
				       (void *)(PT_REGS_SP(ctx) + 16));
		} else {
			bpf_probe_read(&g_ptr, sizeof(g_ptr),
				       (void *)(PT_REGS_SP(ctx) + 32));
		}
	}

	__s64 goid = 0;
	bpf_probe_read(&goid, sizeof(goid), g_ptr + offset_g_goid);
	if (!goid) {
		return 0;
	}

	struct go_newproc_caller caller = {
		.goid = goid,
		.sp = (void *)PT_REGS_SP(ctx),
	};
	bpf_map_update_elem(&pid_tgid_callerid_map, &pid_tgid, &caller,
			    BPF_ANY);
	return 0;
}

// The mapping relationship between parent and child coroutines is stored in go_ancerstor_map
//
// go 1.15 ~ 1.17: func newproc1(fn *funcval, argp unsafe.Pointer, narg int32, callergp *g, callerpc uintptr) *g
// go1.18+ :func newproc1(fn *funcval, callergp *g, callerpc uintptr) *g
SEC("uprobe/exit_runtime.newproc1")
int exit_runtime_newproc1(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	struct ebpf_proc_info *info =
		bpf_map_lookup_elem(&proc_info_map, &tgid);
	if (!info) {
		return 0;
	}

	if(info->version < GO_VERSION(1, 15, 0)){
		return 0;
	}

	int offset_g_goid = info->offsets[OFFSET_IDX_GOID_RUNTIME_G];
	if (offset_g_goid < 0) {
		return 0;
	}

	struct go_newproc_caller *caller =
		bpf_map_lookup_elem(&pid_tgid_callerid_map, &pid_tgid);
	if (!caller) {
		return 0;
	}

	void *g_ptr;
	if (is_register_based_call(info)) {
		g_ptr = (void *)PT_GO_REGS_PARM1(ctx);
	} else {
		if (info->version >= GO_VERSION(1, 18, 0)) {
			bpf_probe_read(&g_ptr, sizeof(g_ptr), caller->sp + 32);
		} else {
			bpf_probe_read(&g_ptr, sizeof(g_ptr), caller->sp + 48);
		}
	}

	__s64 goid = 0;
	bpf_probe_read(&goid, sizeof(goid), g_ptr + offset_g_goid);
	if (!goid) {
		bpf_map_delete_elem(&pid_tgid_callerid_map, &pid_tgid);
		return 0;
	}

	struct go_key key = { .tgid = tgid, .goid = goid };
	goid = caller->goid;
	bpf_map_update_elem(&go_ancerstor_map, &key, &goid, BPF_ANY);

	bpf_map_delete_elem(&pid_tgid_callerid_map, &pid_tgid);
	return 0;
}

// /sys/kernel/debug/tracing/events/sched/sched_process_exit/format
SEC("tracepoint/sched/sched_process_exit")
int bpf_func_sched_process_exit(struct sched_comm_exit_ctx *ctx)
{
	pid_t pid, tid;
	__u64 id;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (__u32)id;

	// If is a process, clear proc_info_map element and submit event.
	if (pid == tid) {
		bpf_map_delete_elem(&proc_info_map, &pid);
		struct process_event_t data;
		data.pid = pid;
		data.meta.event_type = EVENT_TYPE_PROC_EXIT;
		bpf_get_current_comm(data.name, sizeof(data.name));
		// int ret = bpf_perf_event_output(ctx, &NAME(socket_data),
		// 				BPF_F_CURRENT_CPU, &data,
		// 				sizeof(data));

		// if (ret) {
		// 	bpf_debug
		// 	    ("bpf_func_sched_process_exit event output failed: %d\n",
		// 	     ret);
		// }
	}

	bpf_map_delete_elem(&goroutines_map, &id);
	return 0;
}

// /sys/kernel/debug/tracing/events/sched/sched_process_fork/format
SEC("tracepoint/sched/sched_process_fork")
int bpf_func_sched_process_fork(struct sched_comm_fork_ctx *ctx)
{
	struct process_event_t data;

	data.meta.event_type = EVENT_TYPE_PROC_EXEC;
	data.pid = ctx->child_pid;
	bpf_get_current_comm(data.name, sizeof(data.name));
	// int ret = bpf_perf_event_output(ctx, &NAME(socket_data),
	// 				BPF_F_CURRENT_CPU, &data, sizeof(data));

	// if (ret) {
	// 	bpf_debug(
	// 		"bpf_func_sys_exit_execve event output() failed: %d\n",
	// 		ret);
	// }
	return 0;
}
