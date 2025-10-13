// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Python Stack Profiler - Capture Python interpreter stacks with eBPF
 * Based on oncputime by Eunseon Lee
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "python-stack.h"

#define EEXIST 17

const volatile bool kernel_stacks_only = false;
const volatile bool user_stacks_only = false;
const volatile bool include_idle = false;
const volatile bool filter_by_pid = false;
const volatile bool filter_by_tid = false;
const volatile bool python_only = true; // Only trace Python processes

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_PID_NR);
} pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_TID_NR);
} tids SEC(".maps");

// Store Python thread state pointers for each thread
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32); // tid
	__type(value, u64); // PyThreadState pointer
	__uint(max_entries, 1024);
} python_thread_states SEC(".maps");

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
	void *val;
	int err;

	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;

	err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
	if (err && err != -EEXIST)
		return 0;

	return bpf_map_lookup_elem(map, key);
}

// Read a Python string object (PyUnicodeObject or PyBytesObject)
static __always_inline int read_python_string(void *str_obj, char *buf, int buf_size)
{
	if (!str_obj || !buf || buf_size <= 0)
		return -1;

	// Try to read as PyUnicodeObject (Python 3)
	struct PyUnicodeObject unicode_obj;
	if (bpf_probe_read_user(&unicode_obj, sizeof(unicode_obj), str_obj) == 0) {
		// Check if it's an ASCII compact string (most common case)
		if (unicode_obj.state.compact && unicode_obj.state.ascii) {
			// For compact ASCII strings, data immediately follows the struct
			void *data_ptr = (void *)str_obj + sizeof(struct PyUnicodeObject);
			int len = unicode_obj.length < (buf_size - 1) ?
				  unicode_obj.length : (buf_size - 1);

			if (bpf_probe_read_user_str(buf, len + 1, data_ptr) > 0)
				return 0;
		}
	}

	// Fallback: Try to read as PyBytesObject (Python 2 style or bytes in Python 3)
	struct PyBytesObject bytes_obj;
	if (bpf_probe_read_user(&bytes_obj, sizeof(bytes_obj), str_obj) == 0) {
		void *data_ptr = (void *)str_obj +
				 __builtin_offsetof(struct PyBytesObject, ob_sval);
		int len = bytes_obj.ob_base.ob_size < (buf_size - 1) ?
			  bytes_obj.ob_base.ob_size : (buf_size - 1);

		if (bpf_probe_read_user_str(buf, len + 1, data_ptr) > 0)
			return 0;
	}

	return -1;
}

// Walk Python frame chain and extract stack information
static __always_inline int get_python_stack(struct PyFrameObject *frame,
					    struct python_stack *stack)
{
	struct PyFrameObject current_frame;
	struct PyCodeObject code_obj;
	int depth = 0;

	#pragma unroll
	for (int i = 0; i < MAX_STACK_DEPTH; i++) {
		if (!frame)
			break;

		// Read the frame object
		if (bpf_probe_read_user(&current_frame, sizeof(current_frame), frame) != 0)
			break;

		// Read the code object
		if (!current_frame.f_code)
			break;

		if (bpf_probe_read_user(&code_obj, sizeof(code_obj),
					current_frame.f_code) != 0)
			break;

		// Extract function name
		if (read_python_string(code_obj.co_name,
				      stack->frames[depth].function_name,
				      FUNCTION_NAME_LEN) != 0) {
			__builtin_memcpy(stack->frames[depth].function_name,
					"<unknown>", 10);
		}

		// Extract filename
		if (read_python_string(code_obj.co_filename,
				      stack->frames[depth].file_name,
				      FILE_NAME_LEN) != 0) {
			__builtin_memcpy(stack->frames[depth].file_name,
					"<unknown>", 10);
		}

		// Extract line number
		stack->frames[depth].line_number = current_frame.f_lineno;

		depth++;
		frame = current_frame.f_back;
	}

	stack->depth = depth;
	return depth;
}

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
	u64 *valp;
	static const u64 zero;
	struct key_t key = {};
	u64 id;
	u32 pid;
	u32 tid;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = id;

	if (!include_idle && tid == 0)
		return 0;

	if (filter_by_pid && !bpf_map_lookup_elem(&pids, &pid))
		return 0;

	if (filter_by_tid && !bpf_map_lookup_elem(&tids, &tid))
		return 0;

	key.pid = pid;
	bpf_get_current_comm(&key.name, sizeof(key.name));

	// Get native stacks
	if (user_stacks_only)
		key.kern_stack_id = -1;
	else
		key.kern_stack_id = bpf_get_stackid(&ctx->regs, &stackmap, 0);

	if (kernel_stacks_only)
		key.user_stack_id = -1;
	else
		key.user_stack_id = bpf_get_stackid(&ctx->regs, &stackmap,
						    BPF_F_USER_STACK);

	// Try to get Python stack
	// Note: This is a simplified approach. In reality, you'd need to:
	// 1. Find the PyThreadState for this thread (via TLS or global state)
	// 2. This requires knowing Python's thread state location, which varies
	// For now, we initialize an empty Python stack
	key.py_stack.depth = 0;

	// TODO: Implement Python thread state discovery
	// This would typically involve:
	// - Finding libpython.so in process memory
	// - Locating _PyThreadState_Current or similar
	// - Reading the thread state for this TID
	// - Walking the frame chain

	u64 *thread_state_ptr = bpf_map_lookup_elem(&python_thread_states, &tid);
	if (thread_state_ptr && *thread_state_ptr != 0) {
		struct PyThreadState thread_state;
		if (bpf_probe_read_user(&thread_state, sizeof(thread_state),
					(void *)*thread_state_ptr) == 0) {
			if (thread_state.frame) {
				get_python_stack(thread_state.frame, &key.py_stack);
			}
		}
	}

	valp = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (valp)
		__sync_fetch_and_add(valp, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
