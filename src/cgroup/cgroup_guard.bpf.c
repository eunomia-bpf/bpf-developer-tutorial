// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* cgroup_guard.bpf.c - cgroup eBPF policy guard
 *
 * This program demonstrates three types of cgroup eBPF hooks:
 * 1. cgroup/connect4 - TCP connection filtering
 * 2. cgroup/dev - Device access control
 * 3. cgroup/sysctl - Sysctl read/write control
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "cgroup_guard.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ===== Configurable options: set by userspace before load ===== */
#define IPPROTO_TCP 6

const volatile __u16 blocked_tcp_dport = 0;                   /* host order */
const volatile __u32 blocked_dev_major = 0;
const volatile __u32 blocked_dev_minor = 0;
const volatile char denied_sysctl_name[SYSCTL_NAME_LEN] = {}; /* NUL-terminated */

/* ===== ringbuf: send denied events to userspace ===== */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16MB */
} events SEC(".maps");

static __always_inline void fill_common(struct event *e, __u32 type)
{
    e->ts_ns = bpf_ktime_get_ns();
    e->type = type;
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* Compare two strings, return 1 if equal, 0 if not
 * Note: b is volatile to handle const volatile rodata arrays correctly */
static __always_inline int str_eq(const char *a, const volatile char *b, int max_len)
{
#pragma unroll
    for (int i = 0; i < SYSCTL_NAME_LEN; i++) {
        char ca = a[i];
        char cb = b[i];
        if (ca != cb)
            return 0;
        if (ca == '\0')
            return 1;
    }
    return 1;
}

/* ===== 1) Network: block TCP connect4 to specified port =====
 * ctx: struct bpf_sock_addr
 * user_ip4/user_port: network byte order (need conversion)
 *
 * Return semantics:
 * - return 1: allow
 * - return 0: deny (userspace gets EPERM)
 */
SEC("cgroup/connect4")
int cg_connect4(struct bpf_sock_addr *ctx)
{
    if (blocked_tcp_dport == 0)
        return 1;

    if (ctx->protocol != IPPROTO_TCP)
        return 1;

    __u16 dport = bpf_ntohs((__u16)ctx->user_port);
    if (dport != blocked_tcp_dport)
        return 1;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        fill_common(e, EVENT_CONNECT4);
        e->connect4.daddr = ctx->user_ip4; /* network order */
        e->connect4.dport = dport;         /* host order */
        e->connect4.proto = ctx->protocol;
        bpf_ringbuf_submit(e, 0);
    }

    return 0; /* deny -> userspace gets EPERM on connect */
}

/* ===== 2) Device: block access to specified major:minor =====
 * ctx: struct bpf_cgroup_dev_ctx { access_type, major, minor }
 *
 * Return semantics:
 * - return 0: deny (userspace gets EPERM)
 * - return non-zero: allow
 */
SEC("cgroup/dev")
int cg_dev(struct bpf_cgroup_dev_ctx *ctx)
{
    if (blocked_dev_major == 0 && blocked_dev_minor == 0)
        return 1;

    if (ctx->major != blocked_dev_major || ctx->minor != blocked_dev_minor)
        return 1;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        fill_common(e, EVENT_DEVICE);
        e->device.major = ctx->major;
        e->device.minor = ctx->minor;
        e->device.access_type = ctx->access_type;
        bpf_ringbuf_submit(e, 0);
    }

    return 0; /* deny -> -EPERM */
}

/* ===== 3) Sysctl: block reading specified sysctl =====
 * ctx: struct bpf_sysctl
 * Use bpf_sysctl_get_name() to get name
 *
 * Return semantics:
 * - return 0: reject
 * - return 1: proceed
 * If return 0, userspace read/write returns -1 with errno=EPERM
 */
SEC("cgroup/sysctl")
int cg_sysctl(struct bpf_sysctl *ctx)
{
    char name[SYSCTL_NAME_LEN];
    int ret = bpf_sysctl_get_name(ctx, name, sizeof(name), 0);
    if (ret < 0)
        return 1;

    if (denied_sysctl_name[0] == '\0')
        return 1;

    /* Only deny reads, allow writes (safer for testing) */
    if (ctx->write)
        return 1;

    if (!str_eq(name, denied_sysctl_name, SYSCTL_NAME_LEN))
        return 1;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        fill_common(e, EVENT_SYSCTL);
        e->sysctl.write = ctx->write;
#pragma unroll
        for (int i = 0; i < SYSCTL_NAME_LEN; i++) {
            e->sysctl.name[i] = name[i];
            if (name[i] == '\0')
                break;
        }
        bpf_ringbuf_submit(e, 0);
    }

    return 0; /* deny -> -EPERM */
}
