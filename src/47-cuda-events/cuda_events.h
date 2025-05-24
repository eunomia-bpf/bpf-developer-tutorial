/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __CUDA_EVENTS_H
#define __CUDA_EVENTS_H

#define TASK_COMM_LEN 16
#define MAX_FUNC_NAME_LEN 32
#define MAX_DETAILS_LEN 64

enum cuda_event_type {
    CUDA_EVENT_MALLOC = 0,
    CUDA_EVENT_FREE,
    CUDA_EVENT_MEMCPY,
    CUDA_EVENT_LAUNCH_KERNEL,
    CUDA_EVENT_STREAM_CREATE,
    CUDA_EVENT_STREAM_SYNC,
    CUDA_EVENT_GET_DEVICE,
    CUDA_EVENT_SET_DEVICE,
    CUDA_EVENT_EVENT_CREATE,
    CUDA_EVENT_EVENT_RECORD,
    CUDA_EVENT_EVENT_SYNC
};

struct event {
    /* Common fields */
    int pid;                  /* Process ID */
    char comm[TASK_COMM_LEN]; /* Process name */
    enum cuda_event_type type;/* Type of CUDA event */
    
    /* Event-specific data */
    union {
        struct {
            size_t size;      /* Size for malloc/memcpy */
        } mem;
        
        struct {
            void *ptr;        /* Pointer for free */
        } free_data;
        
        struct {
            size_t size;      /* Size for memcpy */
            int kind;         /* Kind of memcpy */
        } memcpy_data;
        
        struct {
            void *func;       /* Function pointer for kernel launch */
        } launch;
        
        struct {
            int device;       /* Device ID for set_device */
        } device;
        
        struct {
            void *handle;     /* Handle for stream/event operations */
        } handle;
    };
    
    /* Return value (for return probes) */
    int ret_val;
    bool is_return;           /* True if this is from a return probe */
    
    char details[MAX_DETAILS_LEN]; /* Additional details as string */
};

#endif /* __CUDA_EVENTS_H */ 