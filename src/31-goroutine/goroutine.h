#ifndef EBPF_EXAMPLE_GOROUTINE_H
#define EBPF_EXAMPLE_GOROUTINE_H


enum {
	/*
	 * 0 ~ 16 for L7 socket event (struct socket_data_buffer),
	 * indicates the number of socket data in socket_data_buffer.
	 */

	/*
	 * For event registrion
	 */
	EVENT_TYPE_MIN = 1 << 5,
	EVENT_TYPE_PROC_EXEC = 1 << 5,
	EVENT_TYPE_PROC_EXIT = 1 << 6
	// Add new event type here.
};

// Description Provides basic information about an event 
struct event_meta {
	__u32 event_type;
};

// Process execution or exit event data 
struct process_event_t {
	struct event_meta meta;
	__u32 pid; // process ID
	__u8 name[TASK_COMM_LEN]; // process name
};


#endif
