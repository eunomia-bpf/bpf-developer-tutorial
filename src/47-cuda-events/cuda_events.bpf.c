// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cuda_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* CUDA library path is defined via build system now */
#ifndef CUDA_LIB_PATH
#define CUDA_LIB_PATH "/usr/local/cuda/lib64/libcudart.so"
#endif

/* Helper function to prepare and submit an event */
static inline int submit_event(enum cuda_event_type type, bool is_return)
{
    struct event *e;
    
    /* Reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    
    /* Fill common fields */
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = type;
    e->is_return = is_return;
    
    /* Submit to user-space for processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Helper function for malloc event */
static inline int submit_malloc_event(size_t size, bool is_return, int ret_val)
{
    struct event *e;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = CUDA_EVENT_MALLOC;
    e->is_return = is_return;
    
    if (is_return) {
        e->ret_val = ret_val;
    } else {
        e->mem.size = size;
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Helper function for free event */
static inline int submit_free_event(void *ptr, bool is_return, int ret_val)
{
    struct event *e;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = CUDA_EVENT_FREE;
    e->is_return = is_return;
    
    if (is_return) {
        e->ret_val = ret_val;
    } else {
        e->free_data.ptr = ptr;
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Helper function for memcpy event */
static inline int submit_memcpy_event(size_t size, int kind, bool is_return, int ret_val)
{
    struct event *e;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = CUDA_EVENT_MEMCPY;
    e->is_return = is_return;
    
    if (is_return) {
        e->ret_val = ret_val;
    } else {
        e->memcpy_data.size = size;
        e->memcpy_data.kind = kind;
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Helper for kernel launch */
static inline int submit_launch_event(void *func, bool is_return, int ret_val)
{
    struct event *e;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = CUDA_EVENT_LAUNCH_KERNEL;
    e->is_return = is_return;
    
    if (is_return) {
        e->ret_val = ret_val;
    } else {
        e->launch.func = func;
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Helper for device operations */
static inline int submit_device_event(enum cuda_event_type type, int device, bool is_return, int ret_val)
{
    struct event *e;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = type;
    e->is_return = is_return;
    
    if (is_return) {
        e->ret_val = ret_val;
    } else if (type == CUDA_EVENT_SET_DEVICE) {
        e->device.device = device;
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Helper for stream/event operations */
static inline int submit_handle_event(enum cuda_event_type type, void *handle, bool is_return, int ret_val)
{
    struct event *e;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = type;
    e->is_return = is_return;
    
    if (is_return) {
        e->ret_val = ret_val;
    } else if (handle) {
        e->handle.handle = handle;
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Uprobe handlers for CUDA functions */

/* Format of uprobe section definition supporting auto-attach:
 * u[ret]probe/binary:function[+offset]
 */

/* Memory allocation/free operations */
SEC("uprobe")
int BPF_KPROBE(cuda_malloc_enter, void **ptr, size_t size)
{
    return submit_malloc_event(size, false, 0);
}

SEC("uretprobe")
int BPF_KRETPROBE(cuda_malloc_exit, int ret)
{
    return submit_malloc_event(0, true, ret);
}

SEC("uprobe")
int BPF_KPROBE(cuda_free_enter, void *ptr)
{
    return submit_free_event(ptr, false, 0);
}

SEC("uretprobe")
int BPF_KRETPROBE(cuda_free_exit, int ret)
{
    return submit_free_event(0, true, ret);
}

/* Memory copy */
SEC("uprobe")
int BPF_KPROBE(cuda_memcpy_enter, void *dst, const void *src, size_t size, int kind)
{
    return submit_memcpy_event(size, kind, false, 0);
}

SEC("uretprobe")
int BPF_KRETPROBE(cuda_memcpy_exit, int ret)
{
    return submit_memcpy_event(0, 0, true, ret);
}

/* Kernel launch */
SEC("uprobe")
int BPF_KPROBE(cuda_launch_kernel_enter, const void *func)
{
    return submit_launch_event((void*)func, false, 0);
}

SEC("uretprobe")
int BPF_KRETPROBE(cuda_launch_kernel_exit, int ret)
{
    return submit_launch_event(0, true, ret);
}

/* Stream operations */
SEC("uprobe")
int BPF_KPROBE(cuda_stream_create_enter)
{
    return submit_handle_event(CUDA_EVENT_STREAM_CREATE, NULL, false, 0);
}

SEC("uretprobe")
int BPF_KRETPROBE(cuda_stream_create_exit, int ret)
{
    return submit_handle_event(CUDA_EVENT_STREAM_CREATE, NULL, true, ret);
}

SEC("uprobe")
int BPF_KPROBE(cuda_stream_sync_enter, void *stream)
{
    return submit_handle_event(CUDA_EVENT_STREAM_SYNC, stream, false, 0);
}

SEC("uretprobe")
int BPF_KRETPROBE(cuda_stream_sync_exit, int ret)
{
    return submit_handle_event(CUDA_EVENT_STREAM_SYNC, NULL, true, ret);
}

/* Device management */
SEC("uprobe")
int BPF_KPROBE(cuda_get_device_enter)
{
    return submit_device_event(CUDA_EVENT_GET_DEVICE, 0, false, 0);
}

SEC("uretprobe")
int BPF_KRETPROBE(cuda_get_device_exit, int ret)
{
    return submit_device_event(CUDA_EVENT_GET_DEVICE, 0, true, ret);
}

SEC("uprobe")
int BPF_KPROBE(cuda_set_device_enter, int device)
{
    return submit_device_event(CUDA_EVENT_SET_DEVICE, device, false, 0);
}

SEC("uretprobe")
int BPF_KRETPROBE(cuda_set_device_exit, int ret)
{
    return submit_device_event(CUDA_EVENT_SET_DEVICE, 0, true, ret);
}

/* Event operations */
SEC("uprobe")
int BPF_KPROBE(cuda_event_create_enter)
{
    return submit_handle_event(CUDA_EVENT_EVENT_CREATE, NULL, false, 0);
}

SEC("uretprobe")
int BPF_KRETPROBE(cuda_event_create_exit, int ret)
{
    return submit_handle_event(CUDA_EVENT_EVENT_CREATE, NULL, true, ret);
}

SEC("uprobe")
int BPF_KPROBE(cuda_event_record_enter, void *event)
{
    return submit_handle_event(CUDA_EVENT_EVENT_RECORD, event, false, 0);
}

SEC("uretprobe")
int BPF_KRETPROBE(cuda_event_record_exit, int ret)
{
    return submit_handle_event(CUDA_EVENT_EVENT_RECORD, NULL, true, ret);
}

SEC("uprobe")
int BPF_KPROBE(cuda_event_sync_enter, void *event)
{
    return submit_handle_event(CUDA_EVENT_EVENT_SYNC, event, false, 0);
}

SEC("uretprobe")
int BPF_KRETPROBE(cuda_event_sync_exit, int ret)
{
    return submit_handle_event(CUDA_EVENT_EVENT_SYNC, NULL, true, ret);
}