# eBPF 实例教程：基于 cgroup 的策略控制

你是否需要对容器或特定进程组实施网络访问控制，但又不想影响整个系统？或者你需要限制某些进程访问特定设备，同时允许其他进程正常使用？传统的 iptables 和设备权限是全局生效的，无法做到按进程组精细控制。

这就是 **cgroup eBPF** 解决的问题。通过将 eBPF 程序挂载到 cgroup（控制组），你可以实现按进程归属的策略控制，只有属于特定 cgroup 的进程才会受到影响。这使得容器隔离、多租户安全和沙箱环境成为可能。在本教程中，我们将构建一个完整的"策略守卫"程序，同时演示 TCP 连接过滤、设备访问控制和 sysctl 读取限制三种 cgroup eBPF 用法。

## cgroup eBPF 简介：按进程组做策略

cgroup eBPF 的核心思想很简单：把 eBPF 程序挂到 cgroup 上，这个 cgroup 里的所有进程都会受到这个程序的控制。与 XDP/tc 按网卡过滤流量不同，cgroup eBPF 按进程归属过滤，你把容器放进一个 cgroup，挂上策略程序，这个容器的网络访问、设备访问、sysctl 读写就都在你的控制之下了。其他 cgroup 里的进程完全不受影响。

这种模型非常适合容器和多租户场景。Kubernetes 的 NetworkPolicy 底层就用了 cgroup eBPF。你也可以用它来做设备隔离（比如限制哪些容器能访问 GPU）、安全沙箱（禁止读取敏感 sysctl）等。当 cgroup eBPF 程序拒绝一个操作时，用户态的系统调用会返回 `EPERM`（操作不允许）。

## cgroup eBPF 挂载点

### 1. `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` - Socket 地址钩子

在 socket 地址相关的系统调用（bind/connect/sendmsg/recvmsg）上触发：

| 钩子 | Section 名称 | 描述 |
|------|--------------|------|
| IPv4 bind | `cgroup/bind4` | 过滤 bind() 调用 |
| IPv6 bind | `cgroup/bind6` | 过滤 bind() 调用 |
| IPv4 connect | `cgroup/connect4` | 过滤 connect() 调用 |
| IPv6 connect | `cgroup/connect6` | 过滤 connect() 调用 |
| UDP sendmsg | `cgroup/sendmsg4`, `cgroup/sendmsg6` | 过滤 UDP 发送 |
| UDP recvmsg | `cgroup/recvmsg4`, `cgroup/recvmsg6` | 过滤 UDP 接收 |
| Unix connect | `cgroup/connect_unix` | 过滤 Unix socket 连接 |

**上下文**：`struct bpf_sock_addr` - 包含 `user_ip4`、`user_port`（网络字节序）

**返回语义**：`return 1` = 允许，`return 0` = 拒绝（EPERM）

### 2. `BPF_PROG_TYPE_CGROUP_DEVICE` - 设备访问控制

| 钩子 | Section 名称 | 描述 |
|------|--------------|------|
| 设备访问 | `cgroup/dev` | 过滤设备 open/read/write/mknod |

**上下文**：`struct bpf_cgroup_dev_ctx` - 包含 `major`、`minor`、`access_type`

**返回语义**：`return 0` = 拒绝（EPERM），非零 = 允许

### 3. `BPF_PROG_TYPE_CGROUP_SYSCTL` - Sysctl 访问控制

| 钩子 | Section 名称 | 描述 |
|------|--------------|------|
| Sysctl 访问 | `cgroup/sysctl` | 过滤 /proc/sys 的读写 |

**上下文**：`struct bpf_sysctl` - 使用 `bpf_sysctl_get_name()` 获取 sysctl 名称

**返回语义**：`return 0` = 拒绝（EPERM），`return 1` = 允许

### 4. 其他 cgroup 钩子

- `cgroup_skb/ingress`、`cgroup_skb/egress` - 包级过滤
- `cgroup/getsockopt`、`cgroup/setsockopt` - Socket 选项过滤
- `cgroup/sock_create`、`cgroup/sock_release` - Socket 生命周期
- `sockops` - TCP 层优化（通过 `BPF_CGROUP_SOCK_OPS` 挂载）

## 本教程：cgroup 策略守卫

我们实现一个包含三个程序的 eBPF 对象：

1. **网络（TCP）**：阻断到指定目的端口的 `connect()`
2. **设备**：阻断对指定 `major:minor` 设备的访问
3. **Sysctl**：阻断读取指定的 sysctl（只读，测试更安全）

事件通过 ringbuf 发送到用户态以便观测。

## 实现

### 共享头文件：cgroup_guard.h

这个头文件定义了内核态和用户态共享的数据结构：

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

`event` 结构使用 union 来存储不同类型事件的特定数据，这样可以节省空间并保持统一的事件格式。

### eBPF 程序：cgroup_guard.bpf.c

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

#### 理解 BPF 代码

这个程序的整体逻辑很清晰：三个 cgroup 钩子分别处理网络连接、设备访问和 sysctl 读写。每个钩子的工作流程都是一样的，检查当前操作是否匹配配置的阻断规则，如果匹配就通过 ringbuf 上报事件并返回 0（拒绝），否则返回 1（放行）。

`cg_connect4` 函数使用 `SEC("cgroup/connect4")` 挂载，在进程发起 IPv4 连接时触发。这里有一个重要的细节：`ctx->user_port` 是网络字节序（大端），而我们配置的端口号是主机字节序，所以必须用 `bpf_ntohs()` 转换后再比较。如果目标端口匹配我们配置的 `blocked_tcp_dport`，程序返回 0，用户态的 `connect()` 调用就会失败并返回 `EPERM`。

`cg_dev` 函数处理设备访问。它的上下文 `struct bpf_cgroup_dev_ctx` 包含三个关键字段：`major` 和 `minor` 标识设备（比如 `/dev/null` 是 1:3），`access_type` 表示访问类型（读/写/mknod）。我们只需要比较 major:minor 是否匹配配置值就行了。

`cg_sysctl` 函数拦截 `/proc/sys/` 下的 sysctl 读写。这里用 `bpf_sysctl_get_name()` 获取 sysctl 名称，格式是 `kernel/hostname` 这样的路径形式（用斜杠分隔，不是点）。我们只阻断读操作，写操作放行，这样测试更安全，不会意外改变系统配置。

程序顶部的配置项使用 `const volatile` 声明。这是 CO-RE（Compile Once, Run Everywhere）的标准模式：BPF 程序编译时这些值是默认值（0 或空字符串），用户态在 `load()` 之前通过 `skel->rodata->` 设置实际值。这样一份编译好的 BPF 程序可以用不同的配置运行。

### 用户态加载器：cgroup_guard.c

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

#### 理解用户态代码

用户态加载器的核心工作是把 BPF 程序挂载到指定的 cgroup 上，然后不断轮询 ringbuf 打印被拒绝的事件。

程序首先用 `getopt_long` 解析命令行参数，获取 cgroup 路径和三个策略配置。然后用 `open()` 以 `O_RDONLY | O_DIRECTORY` 打开 cgroup 目录，拿到一个文件描述符。这个 fd 就是后面 attach 的目标，cgroup eBPF 程序是挂到 cgroup 目录上的。

接下来是 skeleton 的标准流程：`open()` 打开 BPF 对象，设置 `.rodata` 配置项，然后 `load()` 加载到内核。注意配置必须在 load 之前设置，load 之后 `.rodata` 就是只读的了。

Attach 用的是 `bpf_program__attach_cgroup(prog, cg_fd)`，把每个 BPF 程序挂载到 cgroup。这里我们挂了三个程序：connect4、dev、sysctl。挂载成功后，这个 cgroup 里的所有进程的相关操作都会经过这些 BPF 程序。

最后是事件循环。`ring_buffer__poll()` 轮询 ringbuf，每当有事件到来就调用 `handle_event` 回调打印出来。这样你就能实时看到哪些操作被拒绝了。

## 编译

```bash
cd src/cgroup
make
```

## 运行

### 终端 A：启动加载器

```bash
# 阻断：TCP 端口 9090、/dev/null (1:3)、读取 kernel/hostname
sudo ./cgroup_guard \
  --cgroup /sys/fs/cgroup/ebpf_demo \
  --block-port 9090 \
  --deny-device 1:3 \
  --deny-sysctl kernel/hostname
```

你应该看到：
```
Attached to cgroup: /sys/fs/cgroup/ebpf_demo
Config: block_port=9090, deny_device=1:3, deny_sysctl_read=kernel/hostname
Press Ctrl-C to stop.
```

### 终端 B：启动测试服务器（在 cgroup 外）

```bash
# 启动两个 HTTP 服务器
python3 -m http.server 8080 --bind 127.0.0.1 &
python3 -m http.server 9090 --bind 127.0.0.1 &
```

### 终端 C：在 cgroup 内测试

```bash
sudo bash -c '
echo $$ > /sys/fs/cgroup/ebpf_demo/cgroup.procs

echo "== TCP 测试 =="
curl -s http://127.0.0.1:8080 >/dev/null && echo "8080 OK"
curl -s http://127.0.0.1:9090 >/dev/null && echo "9090 OK (意外)" || echo "9090 被阻断 (预期)"

echo
echo "== 设备测试 =="
cat /dev/null && echo "/dev/null OK (意外)" || echo "/dev/null 被阻断 (预期)"

echo
echo "== Sysctl 测试 =="
cat /proc/sys/kernel/hostname && echo "sysctl 读取 OK (意外)" || echo "sysctl 读取被阻断 (预期)"
'
```

预期输出：
- `8080 OK` - 端口 8080 允许访问
- `9090 被阻断 (预期)` - 端口 9090 被阻断
- `/dev/null 被阻断 (预期)` - 设备 1:3 被阻断
- `sysctl 读取被阻断 (预期)` - 读取 kernel/hostname 被阻断

### 终端 A 输出（事件）

```
[DENY connect4] pid=12345 comm=curl daddr=127.0.0.1 dport=9090 proto=6
[DENY device]   pid=12346 comm=cat major=1 minor=3 access_type=0x...
[DENY sysctl]   pid=12347 comm=cat write=0 name=kernel/hostname
```

## 一键测试

我们提供了一个测试脚本，可以自动完成编译、启动服务器、运行测试和清理：

```bash
sudo ./test.sh
```


## 使用 bpftool 验证

```bash
sudo bpftool cgroup tree /sys/fs/cgroup/ebpf_demo
```

## 何时使用 cgroup eBPF

选择合适的技术取决于你的控制粒度需求。

cgroup eBPF 的控制粒度是**进程组**，你把进程放进 cgroup，挂上 BPF 程序，策略就对这组进程生效。这非常适合容器场景：每个容器就是一个 cgroup，你可以给不同容器设置不同的网络策略、设备权限、sysctl 访问规则。进程离开 cgroup，策略自动失效，不需要手动清理。

XDP 和 tc 的控制粒度是**网卡**。它们处理经过某个网卡的所有流量，不区分来自哪个进程。如果你需要做高性能包处理、DDoS 防护、负载均衡，XDP/tc 是更好的选择。但如果你想"只允许容器 A 访问端口 80，容器 B 可以访问任意端口"，XDP/tc 就不太方便了。

seccomp-BPF 的控制粒度是**单个进程**。它过滤系统调用，比如禁止进程调用 `fork`、`exec`、`socket`。seccomp 更底层，适合做进程沙箱。但它不能控制网络目的地址、设备 major:minor 这些高层语义。

传统的 iptables/nftables 是**全局**生效的。你配置的规则对整个系统的所有进程都有效，无法区分"这条规则只对容器 A 生效"。

总结一下：如果你需要按容器/进程组做策略，同时控制网络、设备、sysctl，并且希望策略随进程生命周期自动管理，cgroup eBPF 就是正确的选择。

## 总结

cgroup eBPF 通过将策略与进程组绑定，解决了传统全局策略无法精细控制的问题。本教程演示了三种常用的 cgroup 钩子：

- **`cgroup/connect4`**：在 TCP 连接时过滤目标端口，阻断不允许的出站连接
- **`cgroup/dev`**：在设备访问时检查 major:minor，限制对特定设备的读写
- **`cgroup/sysctl`**：在 sysctl 读写时检查名称，防止敏感配置泄露或篡改

这种"策略守卫"模式可以扩展到生产用例：容器网络策略（类似 Kubernetes NetworkPolicy）、设备隔离（GPU/TPU 独占）、安全沙箱（限制系统信息访问）。通过 ringbuf 事件上报，你还可以实现策略审计和告警。

> 如果你想深入了解 eBPF，请查看我们的教程仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- **内核文档：** [libbpf 程序类型](https://docs.kernel.org/bpf/libbpf/program_types.html) - 所有 cgroup 相关 section 名称
- **eBPF 文档：** [CGROUP_SOCK_ADDR](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/) - socket 地址钩子详解
- **eBPF 文档：** [CGROUP_DEVICE](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_DEVICE/) - 设备访问控制详解
- **eBPF 文档：** [CGROUP_SYSCTL](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SYSCTL/) - sysctl 访问控制详解
- **教程仓库：** <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/cgroup>

完整源代码可在教程仓库中获得。需要 Linux 内核 4.10+（cgroup v2）和 libbpf。
