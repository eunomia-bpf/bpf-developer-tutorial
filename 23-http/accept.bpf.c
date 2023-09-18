#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "accept.h"

struct conn_id_t
{
    u32 pid;
    int fd;
    __u64 tsid;
};

struct conn_info_t
{
    struct conn_id_t conn_id;
    __s64 wr_bytes;
    __s64 rd_bytes;
    bool is_http;
};

// A struct describing the event that we send to the user mode upon a new connection.
struct socket_open_event_t
{
    // The time of the event.
    u64 timestamp_ns;

    // A unique ID for the connection.
    struct conn_id_t conn_id;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, __u64);
    __type(value, struct conn_info_t);
} conn_info_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct accept_args_t
{
    struct sockaddr_in *addr;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct accept_args_t);
} active_accept_args_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_accept")
int sys_enter_accept(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();

    struct accept_args_t accept_args = {};
    accept_args.addr = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[1]);
    bpf_map_update_elem(&active_accept_args_map, &id, &accept_args, BPF_ANY);
    bpf_printk("enter_accept accept_args.addr: %llx\n", accept_args.addr);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit *ctx)
{

    u64 id = bpf_get_current_pid_tgid();

    struct accept_args_t *args =
        bpf_map_lookup_elem(&active_accept_args_map, &id);
    if (args == NULL)
    {
        return 0;
    }
    bpf_printk("exit_accept accept_args.addr: %llx\n", args->addr);
    int ret_fd = (int)BPF_CORE_READ(ctx, ret);
    if (ret_fd <= 0)
    {
        return 0;
    }

    struct conn_info_t conn_info = {};

    u32 pid = id >> 32;
    conn_info.conn_id.pid = pid;
    conn_info.conn_id.fd = ret_fd;
    conn_info.conn_id.tsid = bpf_ktime_get_ns();

    __u64 pid_fd = ((__u64)pid << 32) | (u32)ret_fd;
    bpf_map_update_elem(&conn_info_map, &pid_fd, &conn_info, BPF_ANY);

    struct socket_data_event_t open_event = {};
    open_event.timestamp_ns = bpf_ktime_get_ns();
    open_event.pid = conn_info.conn_id.pid;
    open_event.fd = conn_info.conn_id.fd;
    open_event.is_connection = true;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &open_event, sizeof(struct socket_data_event_t));

    bpf_map_delete_elem(&active_accept_args_map, &id);
}

struct data_args_t
{
    __s32 fd;
    const char *buf;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct data_args_t);
} active_read_args_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();

    struct data_args_t read_args = {};
    read_args.fd = (int)BPF_CORE_READ(ctx, args[0]);
    read_args.buf = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);

    return 0;
}

static inline bool is_http_connection(const char *line_buffer, u64 bytes_count)
{
    if (bytes_count < 6)
    {
        return 0;
    }
    if (bpf_strncmp(line_buffer, 3, "GET") != 0 && bpf_strncmp(line_buffer, 4, "POST") != 0 && bpf_strncmp(line_buffer, 3, "PUT") != 0 && bpf_strncmp(line_buffer, 6, "DELETE") != 0 && bpf_strncmp(line_buffer, 4, "HTTP") != 0)
    {
        return 0;
    }
    return 1;
}

static inline void process_data(struct trace_event_raw_sys_exit *ctx,
                                u64 id, const struct data_args_t *args, u64 bytes_count)
{
    if (args->buf == NULL)
    {
        return;
    }

    u32 pid = id >> 32;
    u64 pid_fd = ((u64)pid << 32) | (u64)args->fd;
    struct conn_info_t *conn_info = bpf_map_lookup_elem(&conn_info_map, &pid_fd);
    if (conn_info == NULL)
    {
        return;
    }
    if (args->buf == NULL)
    {
        return;
    }
    char line_buffer[7];
    bpf_probe_read_kernel(line_buffer, 7, args->buf);
    if (is_http_connection(line_buffer, bytes_count))
    {
        u32 kZero = 0;
        struct socket_data_event_t event = {};

        event.timestamp_ns = bpf_ktime_get_ns();
        event.is_connection = false;
        event.pid = conn_info->conn_id.pid;
        event.fd = conn_info->conn_id.fd;
        unsigned int read_size = bytes_count > MAX_MSG_SIZE ? MAX_MSG_SIZE : bytes_count;
        bpf_probe_read_kernel(&event.msg, read_size, args->buf);

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &event, sizeof(struct socket_data_event_t));
    }
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    u64 bytes_count = (u64)BPF_CORE_READ(ctx, ret);
    if (bytes_count <= 0)
    {
        return 0;
    }
    u64 id = bpf_get_current_pid_tgid();
    struct data_args_t *read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
    if (read_args != NULL)
    {
        process_data(ctx, id, read_args, bytes_count);
    }

    bpf_map_delete_elem(&active_read_args_map, &id);

    return 0;
}

char _license[] SEC("license") = "GPL";
