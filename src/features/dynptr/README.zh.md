# eBPF 实例教程：BPF 动态指针处理可变长度数据

你是否曾经在编写 eBPF 包解析器时，被那些冗长的 `data_end` 边界检查搞得焦头烂额，而验证器仍然拒绝通过？是否尝试过用 ring buffer 发送可变长度事件，却发现自己只能用固定大小的结构体？传统的 eBPF 开发要求你在编译时静态证明内存安全性，当处理运行时才能确定的大小（比如包长度或用户配置的快照长度）时就会变得非常痛苦。

这正是 **BPF dynptrs**（动态指针）要解决的问题。从 Linux v5.19 开始逐步引入，dynptr 提供了一种验证器友好的方式来处理可变长度数据，它将部分边界检查从编译时静态分析转移到运行时验证。在本教程中，我们将构建一个 TC ingress 程序，使用 **skb dynptr** 安全解析 TCP 数据包，并使用 **ringbuf dynptr** 输出包含可配置 payload 快照的可变长度事件。

> 完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/dynptr>

## BPF 动态指针简介

### 问题：静态验证的局限性

eBPF 验证器的核心使命是在加载时证明内存安全性。每个指针解引用都必须有边界限制，每个数组访问都必须在范围内。这对简单场景效果很好，但当大小在运行时才能确定时就会遇到困难。

考虑这样的场景：解析一个数据包时 IP 头长度来自一个 4 位字段，或者要读取用户配置数量的 TCP payload。传统方法需要大量的 `data_end` 比较进行边界检查，即使代码写得完全正确，有时验证器仍然无法追踪所有可能的路径从而拒绝通过。当处理非线性 skb 数据（分页缓冲区）时情况更糟，因为这些数据根本无法通过 `ctx->data` 直接访问。

可变长度输出也面临类似的挑战。传统的 `bpf_ringbuf_reserve()` 返回原始指针，但向其中写入运行时确定数量的数据会让验证器感到不安，因为它无法静态证明你的写入会保持在边界内。

### 解决方案：运行时检查的动态指针

Dynptr 引入了一种不透明的句柄类型，它携带关于底层内存区域的元数据，包括边界和类型信息。你不能直接解引用 dynptr，验证器会拒绝这样的尝试。相反，你必须使用执行适当安全检查的 helper 函数或 kfunc。

关键在于**其中一些检查发生在运行时而非编译时**。像 `bpf_dynptr_read()` 和 `bpf_dynptr_write()` 这样的函数在执行时验证边界，失败时返回错误。像 `bpf_dynptr_slice()` 这样的函数在无法安全访问请求区域时返回 NULL。这让你能够表达静态无法证明的逻辑，同时保持安全保证。

对于验证器来说，dynptr 被特殊追踪。它们有生命周期规则（某些必须被释放），有类型约束（skb dynptr 与本地 dynptr 行为不同），验证器确保你遵循这些规则。运行时检查是验证器将它无法静态证明的部分委托出去的方式。

## Dynptr API 概览

### Helper 函数与 Kfunc

dynptr 生态系统跨越两类函数。**Helper 函数** 是稳定 UAPI 的一部分，通常保持向后兼容。**Kfunc**（内核函数）是内核向 BPF 暴露的内部导出，没有 ABI 稳定性保证，意味着它们可能在内核版本间发生变化。

对于 dynptr，基础的读写操作是 helper，而较新的特性如 skb dynptr 和切片操作是 kfunc。这意味着某些 dynptr 功能需要较新的内核，你应该在依赖特定特性前验证其可用性。

### 创建 Dynptr

根据数据来源有几种创建 dynptr 的方式。`bpf_dynptr_from_mem()` helper 从 map value 或全局变量创建 dynptr，用于处理配置数据或临时缓冲区。`bpf_dynptr_from_skb()` kfunc 从 socket buffer 创建 dynptr，允许安全访问包数据，包括非线性（分页）区域。对于 XDP 程序，`bpf_dynptr_from_xdp()` 提供类似功能。

Ring buffer 操作使用 `bpf_ringbuf_reserve_dynptr()` 来分配可变长度记录。与返回固定大小区域指针的普通 `bpf_ringbuf_reserve()` 不同，dynptr 变体允许你在运行时指定大小。这对可变长度事件结构至关重要。

### 读取和写入

`bpf_dynptr_read()` helper 将数据从 dynptr 复制到目标缓冲区。它接受偏移量和长度，执行运行时边界检查，如果读取超出 dynptr 边界则返回错误。当你需要将数据放入本地缓冲区时，这是安全的提取方式。

`bpf_dynptr_write()` helper 做相反的事情，将数据复制到 dynptr 中。对于 skb dynptr，写入可能有类似于 `bpf_skb_store_bytes()` 的额外语义，注意写入可能使之前获取的切片失效。

`bpf_dynptr_data()` helper 返回 dynptr 内数据的直接指针，验证器静态追踪边界。然而，这对 skb 或 xdp dynptr **不起作用**，因为它们的数据可能不在单个连续区域中。

### 用于包解析的切片操作

对于 skb 和 xdp dynptr，`bpf_dynptr_slice()` 是访问数据的主要方式。你提供偏移量、长度和可选的本地缓冲区。该函数返回指向请求数据的指针，它可能是直接指向包数据的指针，也可能是你提供的缓冲区（如果数据需要从非线性区域复制）。

关键规则是**必须对返回值进行 NULL 检查**。NULL 返回意味着无法访问请求的区域，要么因为超出包边界，要么因为其他内部原因。一旦你有了有效的切片指针，就可以在请求的边界内安全解引用它。

还有 `bpf_dynptr_slice_rdwr()` 用于获取可写切片，其可用性取决于程序类型和底层数据是否支持写入。

### Ring Buffer 生命周期

`bpf_ringbuf_reserve_dynptr()` 函数有验证器强制的特殊生命周期规则。一旦调用它，**必须**对 dynptr 调用 `bpf_ringbuf_submit_dynptr()` 或 `bpf_ringbuf_discard_dynptr()`，无论预留是否成功。这不是可选的，因为验证器追踪 dynptr 状态，会拒绝泄漏已预留 dynptr 的程序。

这与普通 ringbuf 用法不同，在那里 `bpf_ringbuf_reserve()` 返回 NULL 意味着没有分配任何东西。对于 dynptr，预留失败仍然需要通过 discard 进行显式清理。验证器需要这个保证来确保正确的资源管理。

## 实现：使用 Dynptr 解析和可变长度事件的 TC Ingress

我们的演示程序附加到 TC ingress 并完成三件事。首先，它使用 `bpf_dynptr_from_skb()` 从传入的数据包创建 skb dynptr。其次，它使用 `bpf_dynptr_slice()` 解析以太网、IPv4 和 TCP 头，实现安全的边界检查访问。第三，它通过 ringbuf dynptr 输出可变长度事件，包括可配置的 TCP payload 快照。

### 完整的 BPF 程序：dynptr_tc.bpf.c

```c
// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "dynptr_tc.h"

/* dynptr 操作的 kfunc 声明（v6.4+） */
extern int bpf_dynptr_from_skb(struct __sk_buff *s, __u64 flags,
                               struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, __u32 offset,
                              void *buffer__opt, __u32 buffer__sz) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16MB */
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} cfg_map SEC(".maps");

SEC("tc")
int dynptr_tc_ingress(struct __sk_buff *ctx)
{
    const struct config *cfg;
    struct bpf_dynptr skb_ptr;

    /* 用于切片的临时缓冲区（数据可能被复制到这里） */
    struct ethhdr eth_buf;
    struct iphdr  ip_buf;
    struct tcphdr tcp_buf;

    const struct ethhdr *eth;
    const struct iphdr  *iph;
    const struct tcphdr *tcp;

    cfg = bpf_map_lookup_elem(&cfg_map, &(__u32){0});
    if (!cfg)
        return TC_ACT_OK;

    /* 从 skb 创建 dynptr */
    if (bpf_dynptr_from_skb(ctx, 0, &skb_ptr))
        return TC_ACT_OK;

    /* 使用切片解析以太网头 */
    eth = bpf_dynptr_slice(&skb_ptr, 0, &eth_buf, sizeof(eth_buf));
    if (!eth)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* 解析 IPv4 头 */
    __u32 ip_off = sizeof(*eth);
    iph = bpf_dynptr_slice(&skb_ptr, ip_off, &ip_buf, sizeof(ip_buf));
    if (!iph || iph->version != 4 || iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    /* 解析 TCP 头 */
    __u32 tcp_off = ip_off + ((__u32)iph->ihl * 4);
    tcp = bpf_dynptr_slice(&skb_ptr, tcp_off, &tcp_buf, sizeof(tcp_buf));
    if (!tcp)
        return TC_ACT_OK;

    __u16 dport = bpf_ntohs(tcp->dest);
    __u8 drop = (cfg->blocked_port && dport == cfg->blocked_port);

    /* 使用 ringbuf dynptr 输出可变长度事件 */
    if (cfg->enable_ringbuf) {
        __u32 snap_len = cfg->snap_len;
        __u8 payload[MAX_SNAPLEN] = {};

        __u32 payload_off = tcp_off + ((__u32)tcp->doff * 4);
        if (payload_off < ctx->len) {
            __u32 avail = ctx->len - payload_off;
            if (snap_len > avail) snap_len = avail;
            if (snap_len > MAX_SNAPLEN) snap_len = MAX_SNAPLEN;

            if (bpf_dynptr_read(payload, snap_len, &skb_ptr, payload_off, 0))
                snap_len = 0;
        } else {
            snap_len = 0;
        }

        struct event_hdr hdr = {
            .ts_ns = bpf_ktime_get_ns(),
            .ifindex = ctx->ifindex,
            .pkt_len = ctx->len,
            .saddr = iph->saddr,
            .daddr = iph->daddr,
            .sport = bpf_ntohs(tcp->source),
            .dport = dport,
            .drop = drop,
            .snap_len = snap_len,
        };

        /* 预留可变长度的 ringbuf 记录 */
        struct bpf_dynptr rb;
        __u32 total_sz = sizeof(hdr) + snap_len;

        long err = bpf_ringbuf_reserve_dynptr(&events, total_sz, 0, &rb);
        if (err) {
            /* 即使失败也必须 discard */
            bpf_ringbuf_discard_dynptr(&rb, 0);
            return drop ? TC_ACT_SHOT : TC_ACT_OK;
        }

        bpf_dynptr_write(&rb, 0, &hdr, sizeof(hdr), 0);
        if (snap_len)
            bpf_dynptr_write(&rb, sizeof(hdr), payload, snap_len, 0);

        bpf_ringbuf_submit_dynptr(&rb, 0);
    }

    return drop ? TC_ACT_SHOT : TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
```

### BPF 代码解析

程序首先声明它需要的 kfunc。`bpf_dynptr_from_skb()` 函数从 socket buffer 创建 dynptr，`bpf_dynptr_slice()` 返回指向其中特定区域的指针。`__ksym` 属性告诉加载器这些是需要在加载时解析的内核符号。

在解析头部时，注意我们如何为每个切片调用提供本地缓冲区（`eth_buf`、`ip_buf`、`tcp_buf`）。如果数据可以线性访问，切片函数可能返回直接指向包数据的指针；或者它可能将数据复制到我们的缓冲区并返回指向缓冲区的指针。无论哪种方式，我们都能得到一个可以解引用的有效指针，或者在失败时得到 NULL。

NULL 检查模式至关重要。如果请求的偏移量加长度超过包边界，或者由于其他原因无法访问数据，每个切片调用都可能失败。在使用返回的指针之前检查 NULL 是必须的。

对于 ringbuf 输出，我们使用 `bpf_dynptr_read()` 先将 TCP payload 从 skb 复制到本地缓冲区。这展示了用运行时确定长度（受配置和可用数据限制）从 skb dynptr 读取的方式。如果超出边界，读取可能失败，在这种情况下我们将 `snap_len` 设为零。

ringbuf dynptr 预留展示了可变长度分配模式。我们计算总大小（头部加快照）并精确预留该数量。使用 `bpf_dynptr_write()` 写入头部和 payload 后，我们提交记录。注意预留失败时的 discard 调用，以满足验证器的生命周期要求。

### 完整的用户态程序：dynptr_tc.c

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "dynptr_tc.skel.h"
#include "dynptr_tc.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int signo) { exiting = 1; }

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event_hdr *e = data;
    char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &e->saddr, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &e->daddr, daddr, sizeof(daddr));

    printf("if=%u %s:%u -> %s:%u len=%u drop=%u snap=%u",
           e->ifindex, saddr, e->sport, daddr, e->dport,
           e->pkt_len, e->drop, e->snap_len);

    if (e->snap_len && data_sz >= sizeof(*e) + e->snap_len) {
        printf(" payload=\"");
        for (int i = 0; i < e->snap_len; i++) {
            unsigned char c = e->payload[i];
            putchar((c >= 32 && c <= 126) ? c : '.');
        }
        printf("\"");
    }
    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;
    struct config cfg = { .blocked_port = 0, .snap_len = 64, .enable_ringbuf = 1 };

    /* 解析参数 */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i+1 < argc) ifname = argv[++i];
        else if (!strcmp(argv[i], "-p") && i+1 < argc) cfg.blocked_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-s") && i+1 < argc) cfg.snap_len = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-n")) cfg.enable_ringbuf = 0;
    }

    if (!ifname) {
        fprintf(stderr, "Usage: %s -i <ifname> [-p port] [-s len] [-n]\n", argv[0]);
        return 1;
    }

    int ifindex = if_nametoindex(ifname);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct dynptr_tc_bpf *skel = dynptr_tc_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "Failed to load BPF\n"); return 1; }

    /* 配置 */
    bpf_map_update_elem(bpf_map__fd(skel->maps.cfg_map), &(__u32){0}, &cfg, BPF_ANY);

    /* 附加到 TC ingress */
    struct bpf_tc_hook hook = { .sz = sizeof(hook), .ifindex = ifindex, .attach_point = BPF_TC_INGRESS };
    struct bpf_tc_opts opts = { .sz = sizeof(opts), .handle = 1, .priority = 1,
                                .prog_fd = bpf_program__fd(skel->progs.dynptr_tc_ingress) };

    bpf_tc_hook_create(&hook);
    if (bpf_tc_attach(&hook, &opts)) { fprintf(stderr, "TC attach failed\n"); goto cleanup; }

    struct ring_buffer *rb = cfg.enable_ringbuf ?
        ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL) : NULL;

    printf("Attached to %s. blocked_port=%u snap_len=%u\n", ifname, cfg.blocked_port, cfg.snap_len);

    while (!exiting) {
        if (rb) ring_buffer__poll(rb, 100);
        else usleep(100000);
    }

    ring_buffer__free(rb);
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
cleanup:
    dynptr_tc_bpf__destroy(skel);
    return 0;
}
```

### 用户态代码解析

用户态程序加载 BPF skeleton，通过 array map 配置它，并附加到 TC ingress。ring buffer 回调 `handle_event()` 接收每个可变长度事件并打印它。

注意我们如何访问可变长度的 payload。`struct event_hdr` 末尾有一个柔性数组成员 `payload[]`。当事件到达时，`data_sz` 告诉我们总大小，`e->snap_len` 具体告诉我们包含了多少 payload。我们在访问 payload 字节前验证这两者。

配置 map 允许在不重新加载 BPF 程序的情况下运行时控制阻断行为和快照长度。这展示了使用 map 进行用户态到内核通信的常见模式。

## 编译和执行

进入 dynptr 目录并构建：

```bash
cd bpf-developer-tutorial/src/features/dynptr
make
```

这使用仓库的标准工具链编译 BPF 程序，生成 skeleton 头文件并链接 libbpf。

### 创建测试环境

为了正确测试，我们需要使用网络命名空间，这样流量才会真正经过 veth 对而不是走 loopback。附带的 `test.sh` 脚本会自动处理这些，但以下是手动设置方法：

```bash
# 创建网络命名空间
sudo ip netns add test_ns

# 创建 veth 对，一端放入命名空间
sudo ip link add veth_host type veth peer name veth_ns
sudo ip link set veth_ns netns test_ns

# 配置主机端
sudo ip addr add 10.200.0.1/24 dev veth_host
sudo ip link set veth_host up

# 配置命名空间端
sudo ip netns exec test_ns ip addr add 10.200.0.2/24 dev veth_ns
sudo ip netns exec test_ns ip link set veth_ns up

# 在命名空间内启动 HTTP 服务器
sudo ip netns exec test_ns python3 -m http.server 8080 --bind 10.200.0.2 &
```

### 运行演示

启动附加到 veth 主机端的 dynptr TC 程序：

```bash
sudo ./dynptr_tc -i veth_host -p 0 -s 32
```

在另一个终端发起请求：

```bash
curl http://10.200.0.2:8080/
```

你应该看到捕获的数据包输出：

```
Attached to TC ingress of veth_host (ifindex=X). Ctrl-C to exit.
blocked_port=0 snap_len=32 ringbuf=1
if=X 10.200.0.2:8080 -> 10.200.0.1:XXXXX len=221 drop=0 snap=32 payload="HTTP/1.0 200 OK..Server: SimpleH"
if=X 10.200.0.2:8080 -> 10.200.0.1:XXXXX len=742 drop=0 snap=32 payload="<!DOCTYPE HTML>.<html lang="en">"
```

输出显示来自服务器的 HTTP 响应包，payload 字段包含响应数据的开头部分。

### 测试丢包策略

通过指定端口 8080 测试阻断：

```bash
sudo ./dynptr_tc -i veth_host -p 8080 -s 32
```

在另一个终端：

```bash
curl --max-time 3 http://10.200.0.2:8080/
```

由于响应包被阻断，curl 应该会超时。dynptr_tc 输出显示 `drop=1`：

```
if=X 10.200.0.2:8080 -> 10.200.0.1:XXXXX len=74 drop=1 snap=0
```

### 使用测试脚本

为方便起见，运行附带的测试脚本，它会自动处理所有设置：

```bash
sudo ./test.sh
```

脚本会创建命名空间，运行捕获和阻断两个测试，最后自动清理。

## 何时使用 Dynptr

Dynptr 在几种场景中表现出色。**可变长度事件**是经典用例，因为 ringbuf dynptr 让你能够在运行时精确分配所需的大小，避免因过大的固定结构体而浪费空间，或需要使用复杂的多记录方案。

**包解析**在处理非线性 skb 或复杂协议栈时受益于 dynptr，在这些情况下传统的边界检查变得难以处理。切片 API 提供了更清晰的抽象，统一处理线性和分页数据。

**加密和验证**操作如 `bpf_crypto_encrypt()`、`bpf_verify_pkcs7_signature()` 和 `bpf_get_file_xattr()` 都使用 dynptr 作为缓冲区参数，使得熟悉 dynptr 对这些高级用例至关重要。

**用户 ringbuf 消费**通过 `bpf_user_ringbuf_drain()` 以 dynptr 形式传递样本，实现在 BPF 程序中安全处理用户空间提供的数据。

对于在编译时就知道边界的简单固定大小操作，传统方法可能更简单。但随着你的 BPF 程序变得更复杂，dynptr 会变得越来越有价值。

## 总结

BPF dynptr 提供了一种验证器友好的机制来处理可变长度和运行时边界的数据。它不是完全通过静态分析来证明内存安全性，而是将一些验证转移到运行时检查，实现了否则不可能或极其难以表达的模式。

我们的例子展示了两种主要的 dynptr 模式：使用带切片的 skb dynptr 进行清晰的包解析，以及使用 ringbuf dynptr 进行可变长度事件输出。关键要点是始终对切片返回值进行 NULL 检查，始终提交或丢弃 ringbuf dynptr，并记住 skb dynptr 需要从 Linux v6.4 开始可用的 kfunc。

随着 eBPF 能力的持续扩展，dynptr 成为工具集中越来越重要的部分。无论你是构建包处理器、安全监控器还是性能工具，理解 dynptr 都将帮助你编写更清晰、更强大的 BPF 程序。

> 如果你想深入学习 eBPF，请查看我们的教程仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- **Dynptr 概念文档：** <https://docs.ebpf.io/linux/concepts/dynptrs/>
- **bpf_ringbuf_reserve_dynptr Helper：** <https://docs.ebpf.io/linux/helper-function/bpf_ringbuf_reserve_dynptr/>
- **bpf_dynptr_from_skb Kfunc：** <https://docs.ebpf.io/linux/kfuncs/bpf_dynptr_from_skb/>
- **bpf_dynptr_slice Kfunc：** <https://docs.ebpf.io/linux/kfuncs/bpf_dynptr_slice/>
- **内核 Kfuncs 文档：** <https://docs.kernel.org/bpf/kfuncs.html>
- **教程仓库：** <https://github.com/eunomia-bpf/bpf-developer-tutorial>

本示例需要 Linux 内核 6.4 或更新版本以支持 skb dynptr kfunc。ringbuf dynptr helper 从 Linux 5.19 开始可用。完整源代码可在教程仓库中找到。
