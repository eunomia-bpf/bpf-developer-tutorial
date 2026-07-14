# eBPF 示例教程：使用 XDP 捕获 TCP 信息

扩展伯克利包过滤器（eBPF）是 Linux 内核中的一项革命性技术，允许开发者在内核空间内运行沙箱程序。它提供了强大的网络、安全和跟踪能力，无需修改内核源代码或加载内核模块。本教程重点介绍如何使用 eBPF 结合 Express Data Path（XDP），在数据包进入时的最早阶段直接捕获 TCP 头信息。

## 使用 XDP 捕获 TCP 头信息

捕获网络数据包对于监控、调试和保护网络通信至关重要。传统工具如 `tcpdump` 在用户空间运行，可能会带来显著的开销。通过利用 eBPF 和 XDP，我们可以在内核中直接捕获 TCP 头信息，最小化开销并提高性能。

在本教程中，我们将开发一个 XDP 程序，该程序拦截传入的 TCP 数据包并提取其头信息。我们将这些数据存储在一个环形缓冲区中，用户空间的程序将读取并以可读的格式显示这些信息。

### 为什么使用 XDP 进行数据包捕获？

XDP 是 Linux 内核中一个高性能的数据路径，允许在网络栈的最低层进行可编程的数据包处理。通过将 eBPF 程序附加到 XDP，我们可以在数据包到达时立即处理它们，减少延迟并提高效率。

## 内核 eBPF 代码分析

让我们深入了解捕获 TCP 头信息的内核空间 eBPF 代码。

内核程序与用户空间程序通过 `xdp-tcpdump.h` 共享事件定义。TCP 头的长度可以是 20 到 60 字节，`header_len` 保存根据数据偏移字段计算出的准确长度。

```c
#define MAX_TCP_HEADER_BYTES 60

struct tcp_event {
    unsigned int header_len;
    unsigned char header[MAX_TCP_HEADER_BYTES];
};
```

### 完整的内核代码

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp-tcpdump.h"

#define ETH_P_IP 0x0800

// 定义环形缓冲区映射
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB 缓冲区
} rb SEC(".maps");

// 检查数据包是否为 TCP 的辅助函数
static bool is_tcp(struct ethhdr *eth, void *data_end)
{
    // 确保以太网头在边界内
    if ((void *)(eth + 1) > data_end)
        return false;

    // 仅处理 IPv4 数据包
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // 确保 IP 头在边界内
    if ((void *)(ip + 1) > data_end)
        return false;

    // 检查协议是否为 TCP
    if (ip->protocol != IPPROTO_TCP)
        return false;

    return true;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    // 数据包数据指针
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 解析以太网头
    struct ethhdr *eth = data;

    // 检查数据包是否为 TCP 数据包
    if (!is_tcp(eth, data_end)) {
        return XDP_PASS;
    }

    // 转换为 IP 头
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // 计算 IP 头长度
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }

    // 确保 IP 头在数据包边界内
    if ((void *)ip + ip_hdr_len > data_end) {
        return XDP_PASS;
    }

    // 解析 TCP 头
    struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)ip + ip_hdr_len);

    // 确保 TCP 头在数据包边界内
    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    // 根据以 32 位字为单位的数据偏移字段 doff 计算 TCP 头长度
    __u32 tcp_header_bytes = tcp->doff * 4;
    if (tcp_header_bytes < sizeof(*tcp) || tcp_header_bytes > MAX_TCP_HEADER_BYTES) {
        return XDP_PASS;
    }

    // bpf_ringbuf_reserve 要求大小为常量，因此预留固定大小的事件
    struct tcp_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) {
        return XDP_PASS;  // 如果预留失败，跳过处理
    }

    event->header_len = tcp_header_bytes;
    __builtin_memset(event->header, 0, sizeof(event->header));

    // 将 TCP 头字节复制到环形缓冲区
    // 使用循环以确保符合 eBPF 验证器要求
    for (int i = 0; i < MAX_TCP_HEADER_BYTES; i++) {
        if (i >= tcp_header_bytes)
            break;

        if ((void *)tcp + i + 1 > data_end) {
            bpf_ringbuf_discard(event, 0);
            return XDP_PASS;
        }

        unsigned char byte = *((unsigned char *)tcp + i);
        event->header[i] = byte;
    }

    // 将数据提交到环形缓冲区
    bpf_ringbuf_submit(event, 0);

    // 可选：打印调试信息
    bpf_printk("Captured TCP header (%u bytes)", tcp_header_bytes);

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
```

### 代码解释

#### 定义环形缓冲区映射

我们定义了一个名为 `rb` 的环形缓冲区映射，用于高效地将数据从内核传递到用户空间。

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB 缓冲区
} rb SEC(".maps");
```

#### 数据包解析与验证

`is_tcp` 辅助函数通过验证以太网和 IP 头，检查传入的数据包是否为 TCP 数据包。

```c
static bool is_tcp(struct ethhdr *eth, void *data_end)
{
    // ...（检查内容略）
}
```

#### 捕获 TCP 头信息

在 `xdp_pass` 函数中，我们：

1. 解析以太网、IP 和 TCP 头。
2. 读取并校验 TCP 数据偏移字段，得到实际的头长度。
3. 由于辅助函数要求使用编译期常量大小，在环形缓冲区中预留固定大小的事件。
4. 逐次检查数据包边界，只把经过校验的头字节复制到事件中。
5. 提交数据到环形缓冲区，供用户空间使用。

```c
__u32 tcp_header_bytes = tcp->doff * 4;
if (tcp_header_bytes < sizeof(*tcp) || tcp_header_bytes > MAX_TCP_HEADER_BYTES) {
    return XDP_PASS;
}

struct tcp_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
if (!event) {
    return XDP_PASS;
}

event->header_len = tcp_header_bytes;
__builtin_memset(event->header, 0, sizeof(event->header));

for (int i = 0; i < MAX_TCP_HEADER_BYTES; i++) {
    if (i >= tcp_header_bytes)
        break;
    if ((void *)tcp + i + 1 > data_end) {
        bpf_ringbuf_discard(event, 0);
        return XDP_PASS;
    }
    unsigned char byte = *((unsigned char *)tcp + i);
    event->header[i] = byte;
}

bpf_ringbuf_submit(event, 0);
```

#### 使用 bpf_printk 进行调试

`bpf_printk` 函数将消息记录到内核的跟踪管道，对于调试非常有用。

```c
bpf_printk("Captured TCP header (%u bytes)", tcp_header_bytes);
```

## 用户空间代码分析

让我们查看用户空间程序，该程序从环形缓冲区中读取捕获的 TCP 头信息并显示。

### 完整的用户空间代码

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp-tcpdump.skel.h"  // 生成的骨架头文件
#include "xdp-tcpdump.h"

// 处理环形缓冲区事件的回调函数
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    if (data_sz < sizeof(struct tcp_event)) {
        fprintf(stderr, "Received incomplete TCP event\n");
        return 0;
    }

    struct tcp_event *event = data;
    if (event->header_len < 20 || event->header_len > MAX_TCP_HEADER_BYTES) {
        fprintf(stderr, "Invalid TCP header length: %u\n", event->header_len);
        return 0;
    }

    // 解析原始 TCP 头字节
    struct tcphdr {
        uint16_t source;
        uint16_t dest;
        uint32_t seq;
        uint32_t ack_seq;
        uint16_t res1:4,
                 doff:4,
                 fin:1,
                 syn:1,
                 rst:1,
                 psh:1,
                 ack:1,
                 urg:1,
                 ece:1,
                 cwr:1;
        uint16_t window;
        uint16_t check;
        uint16_t urg_ptr;
        // 可能还有选项和填充
    } __attribute__((packed));

    struct tcphdr *tcp = (struct tcphdr *)event->header;

    // 将字段从网络字节序转换为主机字节序
    uint16_t source_port = ntohs(tcp->source);
    uint16_t dest_port = ntohs(tcp->dest);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack_seq = ntohl(tcp->ack_seq);
    uint16_t window = ntohs(tcp->window);

    // 提取标志位
    uint8_t flags = 0;
    flags |= (tcp->fin) ? 0x01 : 0x00;
    flags |= (tcp->syn) ? 0x02 : 0x00;
    flags |= (tcp->rst) ? 0x04 : 0x00;
    flags |= (tcp->psh) ? 0x08 : 0x00;
    flags |= (tcp->ack) ? 0x10 : 0x00;
    flags |= (tcp->urg) ? 0x20 : 0x00;
    flags |= (tcp->ece) ? 0x40 : 0x00;
    flags |= (tcp->cwr) ? 0x80 : 0x00;

    printf("Captured TCP Header:\n");
    printf("  源端口: %u\n", source_port);
    printf("  目的端口: %u\n", dest_port);
    printf("  序列号: %u\n", seq);
    printf("  确认号: %u\n", ack_seq);
    printf("  数据偏移: %u\n", tcp->doff);
    printf("  标志位: 0x%02x\n", flags);
    printf("  窗口大小: %u\n", window);
    printf("\n");

    return 0;
}

int main(int argc, char **argv)
{
    struct xdp_tcpdump_bpf *skel;
    struct ring_buffer *rb = NULL;
    int ifindex;
    int err;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        fprintf(stderr, "Invalid interface name %s\n", ifname);
        return 1;
    }

    /* 打开并加载 BPF 应用 */
    skel = xdp_tcpdump_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* 加载并验证 BPF 程序 */
    err = xdp_tcpdump_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* 附加 XDP 程序 */
    err = xdp_tcpdump_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* 将 XDP 程序附加到指定的接口 */
    skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, ifindex);
    if (!skel->links.xdp_pass)
    {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("成功将 XDP 程序附加到接口 %s\n", ifname);

    /* 设置环形缓冲区轮询 */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("开始轮询环形缓冲区\n");

    /* 轮询环形缓冲区 */
    while (1)
    {
        err = ring_buffer__poll(rb, -1);
        if (err == -EINTR)
            continue;
        if (err < 0)
        {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    xdp_tcpdump_bpf__destroy(skel);
    return -err;
}
```

### 代码解释

#### 处理环形缓冲区事件

`handle_event` 函数处理从环形缓冲区接收到的 TCP 头数据。

```c
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    if (data_sz < sizeof(struct tcp_event)) {
        fprintf(stderr, "Received incomplete TCP event\n");
        return 0;
    }

    struct tcp_event *event = data;
    if (event->header_len < 20 || event->header_len > MAX_TCP_HEADER_BYTES) {
        fprintf(stderr, "Invalid TCP header length: %u\n", event->header_len);
        return 0;
    }

    // ...（解析代码）
}
```

#### 解析 TCP 头

我们定义了一个本地的 `tcphdr` 结构来解释原始字节。

```c
struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    // ...（其他字段）
} __attribute__((packed));
```

#### 显示捕获的信息

解析后，我们以可读的格式打印 TCP 头字段。

```c
printf("Captured TCP Header:\n");
printf("  源端口: %u\n", source_port);
printf("  目的端口: %u\n", dest_port);
// ...（其他字段）
```

#### 设置 eBPF 骨架

我们使用生成的骨架 `xdp-tcpdump.skel.h` 来加载和附加 eBPF 程序。

```c
/* 打开并加载 BPF 应用 */
skel = xdp_tcpdump_bpf__open();
if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
}

/* 加载并验证 BPF 程序 */
err = xdp_tcpdump_bpf__load(skel);
if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
    goto cleanup;
}
```

#### 附加到网络接口

我们通过接口名称将 XDP 程序附加到指定的网络接口。

```c
/* 将 XDP 程序附加到指定的接口 */
skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, ifindex);
if (!skel->links.xdp_pass) {
    err = -errno;
    fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
    goto cleanup;
}
```

## 编译和执行说明

### 前提条件

- 支持 eBPF 和 XDP 的 Linux 系统内核。
- 安装了 libbpf 库。
- 具有 eBPF 支持的编译器（如 clang）。

### 构建程序

假设您已从 [GitHub](https://github.com/eunomia-bpf/bpf-developer-tutorial) 克隆了仓库，请导航到 `bpf-developer-tutorial/src/41-xdp-tcpdump` 目录。

```bash
cd bpf-developer-tutorial/src/41-xdp-tcpdump
make
```

此命令将编译内核 eBPF 代码和用户空间应用程序。

### 运行程序

首先，识别您的网络接口：

```bash
ifconfig
```

示例输出：

```
wlp0s20f3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255
        ether 00:1a:2b:3c:4d:5e  txqueuelen 1000  (Ethernet)
```

使用所需的网络接口运行用户空间程序：

```bash
sudo ./xdp-tcpdump wlp0s20f3
```

示例输出：

```
成功将 XDP 程序附加到接口 wlp0s20f3
开始轮询环形缓冲区
Captured TCP Header:
  源端口: 443
  目的端口: 53500
  序列号: 572012449
  确认号: 380198588
  数据偏移: 8
  标志位: 0x10
  窗口大小: 16380
```

### 完整的源代码和资源

- **源代码仓库:** [GitHub - bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)
- **教程网站:** [eunomia.dev Tutorials](https://eunomia.dev/tutorials/)

## 总结与结论

在本教程中，我们探讨了如何使用 eBPF 和 XDP 在 Linux 内核中直接捕获 TCP 头信息。通过分析内核 eBPF 代码和用户空间应用程序，我们学习了如何拦截数据包、提取关键的 TCP 字段，并使用环形缓冲区高效地将这些数据传递到用户空间。

这种方法为传统的数据包捕获方法提供了一种高性能的替代方案，对系统资源的影响最小。它是网络监控、安全分析和调试的强大技术。

如果您想了解更多关于 eBPF 的内容，请访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或我们的网站 <https://eunomia.dev/tutorials/>

编程愉快！
