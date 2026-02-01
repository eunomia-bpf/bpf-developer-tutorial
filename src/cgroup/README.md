# eBPF Tutorial: cgroup-based Policy Control

Do you need to enforce network access control on containers or specific process groups without affecting the entire system? Or do you need to restrict certain processes from accessing specific devices while allowing others to use them normally? Traditional iptables and device permissions are global, making fine-grained per-process-group control impossible.

This is the problem **cgroup eBPF** solves. By attaching eBPF programs to cgroups (control groups), you can implement policy control based on process membership—only processes belonging to a specific cgroup are affected. This enables container isolation, multi-tenant security, and sandbox environments. In this tutorial, we'll build a complete "policy guard" program that demonstrates TCP connection filtering, device access control, and sysctl read restrictions—three types of cgroup eBPF usage.

## What is cgroup eBPF?

The core idea of cgroup eBPF is simple: attach an eBPF program to a cgroup, and all processes in that cgroup will be controlled by this program. Unlike XDP/tc which filter traffic by network interface, cgroup eBPF filters by process membership—put a container in a cgroup, attach a policy program, and that container's network access, device access, and sysctl reads/writes are all under your control. Processes in other cgroups are completely unaffected.

This model is perfect for container and multi-tenant scenarios. Kubernetes NetworkPolicy uses cgroup eBPF under the hood. You can also use it for device isolation (e.g., restricting which containers can access GPUs), security sandboxes (preventing reads of sensitive sysctls), and more. When a cgroup eBPF program denies an operation, userspace syscalls return `EPERM` (Operation not permitted).

## cgroup eBPF Hook Points

### 1. `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` - Socket Address Hooks

Triggered on socket address syscalls (bind/connect/sendmsg/recvmsg):

| Hook | Section Name | Description |
|------|--------------|-------------|
| IPv4 bind | `cgroup/bind4` | Filter bind() calls |
| IPv6 bind | `cgroup/bind6` | Filter bind() calls |
| IPv4 connect | `cgroup/connect4` | Filter connect() calls |
| IPv6 connect | `cgroup/connect6` | Filter connect() calls |
| UDP sendmsg | `cgroup/sendmsg4`, `cgroup/sendmsg6` | Filter UDP sends |
| UDP recvmsg | `cgroup/recvmsg4`, `cgroup/recvmsg6` | Filter UDP receives |
| Unix connect | `cgroup/connect_unix` | Filter Unix socket connect |

**Context**: `struct bpf_sock_addr` - contains `user_ip4`, `user_port` (network byte order)

**Return semantics**: `return 1` = allow, `return 0` = deny (EPERM)

### 2. `BPF_PROG_TYPE_CGROUP_DEVICE` - Device Access Control

| Hook | Section Name | Description |
|------|--------------|-------------|
| Device access | `cgroup/dev` | Filter device open/read/write/mknod |

**Context**: `struct bpf_cgroup_dev_ctx` - contains `major`, `minor`, `access_type`

**Return semantics**: `return 0` = deny (EPERM), non-zero = allow

### 3. `BPF_PROG_TYPE_CGROUP_SYSCTL` - Sysctl Access Control

| Hook | Section Name | Description |
|------|--------------|-------------|
| Sysctl access | `cgroup/sysctl` | Filter /proc/sys reads/writes |

**Context**: `struct bpf_sysctl` - use `bpf_sysctl_get_name()` to get sysctl name

**Return semantics**: `return 0` = reject (EPERM), `return 1` = proceed

### 4. Other cgroup Hooks

- `cgroup_skb/ingress`, `cgroup_skb/egress` - Packet-level filtering
- `cgroup/getsockopt`, `cgroup/setsockopt` - Socket option filtering
- `cgroup/sock_create`, `cgroup/sock_release` - Socket lifecycle
- `sockops` - TCP-level optimization (attached via `BPF_CGROUP_SOCK_OPS`)

## This Tutorial: cgroup Policy Guard

We implement a single eBPF object with three programs:

1. **Network (TCP)**: Block `connect()` to a specified destination port
2. **Device**: Block access to a specified `major:minor` device
3. **Sysctl**: Block reading a specified sysctl (read-only, safer for testing)

Events are sent to userspace via ringbuf for observability.

## Implementation

### Shared Header: cgroup_guard.h

This header defines data structures shared between kernel and userspace:

```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef __CGROUP_GUARD_H
#define __CGROUP_GUARD_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define SYSCTL_NAME_LEN 64

enum event_type {
    EVENT_CONNECT4 = 1,
    EVENT_DEVICE   = 2,
    EVENT_SYSCTL   = 3,
};

struct event {
    __u64 ts_ns;
    __u32 pid;
    __u32 type;
    char comm[TASK_COMM_LEN];

    union {
        struct {
            __u32 daddr;  /* IPv4, network order */
            __u16 dport;  /* host order */
            __u16 proto;  /* e.g. 6 for TCP */
        } connect4;

        struct {
            __u32 major;
            __u32 minor;
            __u32 access_type;
        } device;

        struct {
            __u32 write;
            char name[SYSCTL_NAME_LEN];
        } sysctl;
    };
};

#endif /* __CGROUP_GUARD_H */
```

The `event` structure uses a union to store type-specific data for different events, saving space while maintaining a unified event format.

### eBPF Program: cgroup_guard.bpf.c

```c
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
```

#### Understanding the BPF Code

The overall logic of this program is clear: three cgroup hooks handle network connections, device access, and sysctl reads/writes respectively. Each hook follows the same workflow—check if the current operation matches the configured blocking rule, report an event via ringbuf and return 0 (deny) if it matches, otherwise return 1 (allow).

The `cg_connect4` function uses `SEC("cgroup/connect4")` to attach at IPv4 connection time. There's an important detail here: `ctx->user_port` is in network byte order (big-endian), while our configured port is in host byte order, so we must convert with `bpf_ntohs()` before comparing. If the destination port matches our configured `blocked_tcp_dport`, the program returns 0, and the userspace `connect()` call fails with `EPERM`.

The `cg_dev` function handles device access. Its context `struct bpf_cgroup_dev_ctx` contains three key fields: `major` and `minor` identify the device (e.g., `/dev/null` is 1:3), and `access_type` indicates the access type (read/write/mknod). We simply compare whether major:minor matches the configured values.

The `cg_sysctl` function intercepts sysctl reads/writes under `/proc/sys/`. It uses `bpf_sysctl_get_name()` to get the sysctl name, in path format like `kernel/hostname` (slash-separated, not dots). We only block reads, allowing writes—this is safer for testing and won't accidentally change system configuration.

The configuration options at the top of the program are declared as `const volatile`. This is the standard CO-RE (Compile Once, Run Everywhere) pattern: these values are defaults (0 or empty string) at compile time, and userspace sets the actual values via `skel->rodata->` before `load()`. This allows a single compiled BPF program to run with different configurations.

### Userspace Loader: cgroup_guard.c

```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* cgroup_guard.c - Userspace loader for cgroup eBPF policy guard */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>

#include "cgroup_guard.skel.h"
#include "cgroup_guard.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  -c, --cgroup PATH           cgroup v2 path (default: /sys/fs/cgroup/ebpf_demo)\n"
        "  -p, --block-port PORT       block TCP connect() to this dst port (IPv4)\n"
        "  -d, --deny-device MAJ:MIN   deny device access for (major:minor)\n"
        "  -s, --deny-sysctl NAME      deny sysctl READ of this name\n"
        "  -h, --help                  show this help\n",
        prog);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    (void)data_sz;

    const struct event *e = (const struct event *)data;

    if (e->type == EVENT_CONNECT4) {
        char ip[INET_ADDRSTRLEN] = {0};
        struct in_addr addr = { .s_addr = e->connect4.daddr };
        inet_ntop(AF_INET, &addr, ip, sizeof(ip));

        printf("[DENY connect4] pid=%u comm=%s daddr=%s dport=%u proto=%u\n",
               e->pid, e->comm, ip, e->connect4.dport, e->connect4.proto);
    } else if (e->type == EVENT_DEVICE) {
        printf("[DENY device]   pid=%u comm=%s major=%u minor=%u access_type=0x%x\n",
               e->pid, e->comm, e->device.major, e->device.minor, e->device.access_type);
    } else if (e->type == EVENT_SYSCTL) {
        printf("[DENY sysctl]   pid=%u comm=%s write=%u name=%s\n",
               e->pid, e->comm, e->sysctl.write, e->sysctl.name);
    }

    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    const char *cgroup_path = "/sys/fs/cgroup/ebpf_demo";
    int block_port = 0;
    int dev_major = 0, dev_minor = 0;
    const char *deny_sysctl = NULL;

    /* Parse command line arguments */
    static const struct option long_opts[] = {
        { "cgroup",      required_argument, NULL, 'c' },
        { "block-port",  required_argument, NULL, 'p' },
        { "deny-device", required_argument, NULL, 'd' },
        { "deny-sysctl", required_argument, NULL, 's' },
        { "help",        no_argument,       NULL, 'h' },
        {}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:p:d:s:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c': cgroup_path = optarg; break;
        case 'p': block_port = atoi(optarg); break;
        case 'd': /* parse major:minor */ break;
        case 's': deny_sysctl = optarg; break;
        default: usage(argv[0]); return 1;
        }
    }

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Create cgroup directory if needed */
    mkdir(cgroup_path, 0755);

    int cg_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY);
    if (cg_fd < 0) {
        fprintf(stderr, "open(%s) failed: %s\n", cgroup_path, strerror(errno));
        return 1;
    }

    /* Open and configure BPF skeleton */
    struct cgroup_guard_bpf *skel = cgroup_guard_bpf__open();
    if (!skel) {
        fprintf(stderr, "cgroup_guard_bpf__open() failed\n");
        close(cg_fd);
        return 1;
    }

    /* Write .rodata configuration (must be before load) */
    if (block_port > 0 && block_port <= 65535)
        skel->rodata->blocked_tcp_dport = (__u16)block_port;
    if (dev_major > 0 || dev_minor > 0) {
        skel->rodata->blocked_dev_major = (__u32)dev_major;
        skel->rodata->blocked_dev_minor = (__u32)dev_minor;
    }
    if (deny_sysctl) {
        snprintf((char *)skel->rodata->denied_sysctl_name,
                 SYSCTL_NAME_LEN, "%s", deny_sysctl);
    }

    /* Load BPF programs into kernel */
    int err = cgroup_guard_bpf__load(skel);
    if (err) {
        fprintf(stderr, "cgroup_guard_bpf__load() failed: %d\n", err);
        goto cleanup;
    }

    /* Attach programs to cgroup */
    struct bpf_link *link_connect = bpf_program__attach_cgroup(skel->progs.cg_connect4, cg_fd);
    struct bpf_link *link_dev = bpf_program__attach_cgroup(skel->progs.cg_dev, cg_fd);
    struct bpf_link *link_sysctl = bpf_program__attach_cgroup(skel->progs.cg_sysctl, cg_fd);

    /* Setup ring buffer for events */
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                                              handle_event, NULL, NULL);

    printf("Attached to cgroup: %s\n", cgroup_path);
    printf("Config: block_port=%d, deny_device=%d:%d, deny_sysctl_read=%s\n",
           block_port, dev_major, dev_minor, deny_sysctl ? deny_sysctl : "(none)");

    /* Main event loop */
    while (!exiting) {
        err = ring_buffer__poll(rb, 200 /* ms */);
        if (err == -EINTR)
            break;
    }

    ring_buffer__free(rb);

cleanup:
    bpf_link__destroy(link_sysctl);
    bpf_link__destroy(link_dev);
    bpf_link__destroy(link_connect);
    cgroup_guard_bpf__destroy(skel);
    close(cg_fd);
    return err ? 1 : 0;
}
```

#### Understanding the Userspace Code

The userspace loader's core job is to attach BPF programs to the specified cgroup, then continuously poll the ringbuf to print denied events.

The program first uses `getopt_long` to parse command-line arguments, getting the cgroup path and three policy configurations. Then it uses `open()` with `O_RDONLY | O_DIRECTORY` to open the cgroup directory and get a file descriptor. This fd is the attach target—cgroup eBPF programs are attached to cgroup directories.

Next comes the standard skeleton workflow: `open()` opens the BPF object, set `.rodata` configuration, then `load()` loads it into the kernel. Note that configuration must be set before load—after load, `.rodata` becomes read-only.

Attaching uses `bpf_program__attach_cgroup(prog, cg_fd)` to attach each BPF program to the cgroup. Here we attach three programs: connect4, dev, and sysctl. After successful attachment, all processes in this cgroup will have their relevant operations go through these BPF programs.

Finally, the event loop. `ring_buffer__poll()` polls the ringbuf, calling the `handle_event` callback whenever events arrive to print them. This lets you see which operations are being denied in real-time.

## Building

```bash
cd src/cgroup
make
```

## Running

### Terminal A: Start the loader

```bash
# Block: TCP port 9090, /dev/null (1:3), reading kernel/hostname
sudo ./cgroup_guard \
  --cgroup /sys/fs/cgroup/ebpf_demo \
  --block-port 9090 \
  --deny-device 1:3 \
  --deny-sysctl kernel/hostname
```

You should see:
```
Attached to cgroup: /sys/fs/cgroup/ebpf_demo
Config: block_port=9090, deny_device=1:3, deny_sysctl_read=kernel/hostname
Press Ctrl-C to stop.
```

### Terminal B: Start test servers (outside cgroup)

```bash
# Start two HTTP servers
python3 -m http.server 8080 --bind 127.0.0.1 &
python3 -m http.server 9090 --bind 127.0.0.1 &
```

### Terminal C: Test from within the cgroup

```bash
sudo bash -c '
echo $$ > /sys/fs/cgroup/ebpf_demo/cgroup.procs

echo "== TCP test =="
curl -s http://127.0.0.1:8080 >/dev/null && echo "8080 OK"
curl -s http://127.0.0.1:9090 >/dev/null && echo "9090 OK (unexpected)" || echo "9090 BLOCKED (expected)"

echo
echo "== Device test =="
cat /dev/null && echo "/dev/null OK (unexpected)" || echo "/dev/null BLOCKED (expected)"

echo
echo "== Sysctl test =="
cat /proc/sys/kernel/hostname && echo "sysctl read OK (unexpected)" || echo "sysctl read BLOCKED (expected)"
'
```

Expected output:
- `8080 OK` - Port 8080 is allowed
- `9090 BLOCKED (expected)` - Port 9090 is blocked
- `/dev/null BLOCKED (expected)` - Device 1:3 is blocked
- `sysctl read BLOCKED (expected)` - Reading kernel/hostname is blocked

### Terminal A output (events)

```
[DENY connect4] pid=12345 comm=curl daddr=127.0.0.1 dport=9090 proto=6
[DENY device]   pid=12346 comm=cat major=1 minor=3 access_type=0x...
[DENY sysctl]   pid=12347 comm=cat write=0 name=kernel/hostname
```

## One-click Test

We provide a test script that automatically compiles, starts servers, runs tests, and cleans up:

```bash
sudo ./test.sh
```

## Verifying with bpftool

```bash
sudo bpftool cgroup tree /sys/fs/cgroup/ebpf_demo
```

## When to Use cgroup eBPF

Choosing the right technology depends on your control granularity requirements.

cgroup eBPF's control granularity is **process groups**—put processes in a cgroup, attach a BPF program, and the policy applies to that group. This is perfect for container scenarios: each container is a cgroup, and you can set different network policies, device permissions, and sysctl access rules for different containers. When a process leaves the cgroup, the policy automatically stops applying—no manual cleanup needed.

XDP and tc's control granularity is **network interfaces**. They handle all traffic passing through a specific NIC, regardless of which process it comes from. If you need high-performance packet processing, DDoS protection, or load balancing, XDP/tc are better choices. But if you want "only allow container A to access port 80, while container B can access any port," XDP/tc become inconvenient.

seccomp-BPF's control granularity is **individual processes**. It filters system calls, such as preventing a process from calling `fork`, `exec`, or `socket`. seccomp is lower-level and suitable for process sandboxing. But it can't control network destination addresses or device major:minor—these higher-level semantics.

Traditional iptables/nftables are **global**. Rules you configure apply to all processes on the entire system—there's no way to say "this rule only affects container A."

In summary: if you need per-container/process-group policies, want to control network, devices, and sysctls together, and want policies to automatically follow process lifecycles, cgroup eBPF is the right choice.

## Summary

cgroup eBPF solves the problem of fine-grained control that traditional global policies can't achieve by binding policies to process groups. This tutorial demonstrated three commonly used cgroup hooks:

- **`cgroup/connect4`**: Filter destination ports at TCP connection time, blocking disallowed outbound connections
- **`cgroup/dev`**: Check major:minor at device access time, restricting reads/writes to specific devices
- **`cgroup/sysctl`**: Check names at sysctl read/write time, preventing sensitive configuration leaks or tampering

This "policy guard" pattern can be extended to production use cases: container network policies (similar to Kubernetes NetworkPolicy), device isolation (GPU/TPU exclusive access), security sandboxes (restricting system information access). With ringbuf event reporting, you can also implement policy auditing and alerting.

> If you want to learn more about eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- **Kernel docs:** [libbpf program types](https://docs.kernel.org/bpf/libbpf/program_types.html) - all cgroup-related section names
- **eBPF docs:** [CGROUP_SOCK_ADDR](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/) - socket address hooks explained
- **eBPF docs:** [CGROUP_DEVICE](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_DEVICE/) - device access control explained
- **eBPF docs:** [CGROUP_SYSCTL](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SYSCTL/) - sysctl access control explained
- **Tutorial repository:** <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/cgroup>

Full source code is available in the tutorial repository. Requires Linux kernel 4.10+ (cgroup v2) and libbpf.
