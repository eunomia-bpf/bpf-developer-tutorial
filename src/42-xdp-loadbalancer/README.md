# eBPF 开发者教程： 简单的 XDP 负载均衡器

在本教程中，我们将指导您如何使用eBPF（扩展的Berkeley Packet Filter）实现一个简单的XDP（eXpress Data Path）负载均衡器。只需使用C语言和libbpf库，无需外部依赖，这是一个适合开发者的实践指南，帮助您充分利用Linux内核的强大功能来构建高效的网络应用程序。

## 为什么选择XDP？

`XDP`（eXpress Data Path）是Linux中的一个高速、内核级网络框架，它允许在网络堆栈的最早阶段，即在网络接口卡（NIC）上处理数据包。这使得XDP可以进行超低延迟和高吞吐量的数据包处理，非常适合用于负载均衡、DDoS保护和流量过滤等任务。

XDP的关键特性:

1. **快速数据包处理**：XDP直接在网络接口卡（NIC）级别处理数据包，减少了延迟，并通过避免通常的网络堆栈开销来提高性能。
2. **高效**：由于在数据包进入内核之前处理它们，XDP最大限度地减少了CPU使用率，能够在高流量负载下保持系统的快速响应。
3. **可定制的eBPF**：XDP程序使用eBPF编写，允许您为特定的用例创建自定义的数据包处理逻辑，例如丢弃、重定向或转发数据包。
4. **低CPU开销**：支持零拷贝数据包转发，XDP占用更少的系统资源，非常适合在最少CPU负载的情况下处理高流量。
5. **简单操作**：XDP程序返回预定义的操作，例如丢弃、通过或重定向数据包，提供对流量处理的控制。

### 使用XDP的项目

- `Cilium` 是一个为云原生环境（如Kubernetes）设计的开源网络工具。它使用XDP高效处理数据包过滤和负载均衡，提升了高流量网络中的性能。
- `Katran` 由Facebook开发，是一个负载均衡器，它使用XDP处理数百万的连接，且CPU使用率低。它高效地将流量分发到服务器，在Facebook内部被用于大规模的网络环境。
- `Cloudflare` 使用XDP来防御DDoS攻击。通过在NIC级别过滤恶意流量，Cloudflare可以在攻击数据包进入内核之前将其丢弃，最大限度地减少对网络的影响。

### 为什么选择XDP而不是其他方法？

与传统工具如`iptables`或`tc`相比，XDP具有以下优势：

- **速度**：它直接在NIC驱动程序中操作，数据包处理速度远快于传统方法。
- **灵活性**：通过eBPF，您可以编写自定义的数据包处理逻辑，以满足特定需求。
- **效率**：XDP使用更少的资源，非常适合需要处理高流量而不使系统过载的环境。

## 项目：构建一个简单的负载均衡器

在本项目中，我们将专注于使用XDP构建一个负载均衡器。负载均衡器通过将传入的网络流量高效地分发到多个后端服务器，防止单个服务器过载。结合XDP和eBPF，我们可以构建一个运行在Linux网络堆栈边缘的负载均衡器，确保即使在高流量情况下也能保持高性能。

我们将实现的负载均衡器将具备以下功能：

- 监听传入的网络数据包。
- 根据数据包的源IP和端口计算哈希值，从而将流量分发到多个后端服务器。
- 根据计算出的哈希值将数据包转发到相应的后端服务器。

我们将保持设计简单但强大，向您展示如何利用eBPF的能力来创建一个轻量级的负载均衡解决方案。

## kernel eBPF code

```c
// xdp_lb.bpf.c
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include "xx_hash.h"

struct backend_config {
    __u32 ip;
    unsigned char mac[ETH_ALEN];
};

// Backend IP and MAC address map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);  // Two backends
    __type(key, __u32);
    __type(value, struct backend_config);
} backends SEC(".maps");

int client_ip = bpf_htonl(0xa000001);  
unsigned char client_mac[ETH_ALEN] = {0xDE, 0xAD, 0xBE, 0xEF, 0x0, 0x1};
int load_balancer_ip = bpf_htonl(0xa00000a);
unsigned char load_balancer_mac[ETH_ALEN] = {0xDE, 0xAD, 0xBE, 0xEF, 0x0, 0x10};

static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    bpf_printk("xdp_load_balancer received packet");

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check if the packet is IP (IPv4)
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // IP header
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Check if the protocol is TCP or UDP
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    bpf_printk("Received Source IP: 0x%x", bpf_ntohl(iph->saddr));
    bpf_printk("Received Destination IP: 0x%x", bpf_ntohl(iph->daddr));
    bpf_printk("Received Source MAC: %x:%x:%x:%x:%x:%x", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    bpf_printk("Received Destination MAC: %x:%x:%x:%x:%x:%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    if (iph->saddr == client_ip)
    {
        bpf_printk("Packet from client");

        __u32 key = xxhash32((const char*)iph, sizeof(struct iphdr), 0) % 2;

        struct backend_config *backend = bpf_map_lookup_elem(&backends, &key);
        if (!backend)
            return XDP_PASS;
        
        iph->daddr = backend->ip;
        __builtin_memcpy(eth->h_dest, backend->mac, ETH_ALEN);
    }
    else
    {
        bpf_printk("Packet from backend");
        iph->daddr = client_ip;
        __builtin_memcpy(eth->h_dest, client_mac, ETH_ALEN);
    }

    // Update IP source address to the load balancer's IP
    iph->saddr = load_balancer_ip;
    // Update Ethernet source MAC address to the current lb's MAC
    __builtin_memcpy(eth->h_source, load_balancer_mac, ETH_ALEN);

    // Recalculate IP checksum
    iph->check = iph_csum(iph);

    bpf_printk("Redirecting packet to new IP 0x%x from IP 0x%x", 
                bpf_ntohl(iph->daddr), 
                bpf_ntohl(iph->saddr)
            );
    bpf_printk("New Dest MAC: %x:%x:%x:%x:%x:%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    bpf_printk("New Source MAC: %x:%x:%x:%x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    // Return XDP_TX to transmit the modified packet back to the network
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
```

## 内核代码关键部分解读

### 1. **头文件和数据结构**

代码首先包含了一些必要的头文件，例如 `<bpf/bpf_helpers.h>`、`<linux/if_ether.h>`、`<linux/ip.h>` 等。这些头文件提供了处理以太网帧、IP 数据包以及 BPF 辅助函数的定义。

`backend_config` 结构体被定义用于存储后端服务器的 IP 和 MAC 地址。这将在负载均衡逻辑中用于根据流量分配规则路由数据包。

```c
struct backend_config {
    __u32 ip;
    unsigned char mac[ETH_ALEN];
};
```

### 2. **后端和负载均衡器配置**

代码定义了一个名为 `backends` 的 eBPF map，用于存储两个后端的 IP 和 MAC 地址。`BPF_MAP_TYPE_ARRAY` 类型用于存储后端的配置信息，`max_entries` 设置为 2，表示该负载均衡器将把流量分配给两个后端服务器。

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct backend_config);
} backends SEC(".maps");
```

同时也预定义了客户端和负载均衡器的 IP 地址和 MAC 地址：

```c
int client_ip = bpf_htonl(0xa000001);  
unsigned char client_mac[ETH_ALEN] = {0xDE, 0xAD, 0xBE, 0xEF, 0x0, 0x1};
int load_balancer_ip = bpf_htonl(0xa00000a);
unsigned char load_balancer_mac[ETH_ALEN] = {0xDE, 0xAD, 0xBE, 0xEF, 0x0, 0x10};
```

### 3. **校验和函数**

`iph_csum()` 函数在修改数据包内容后重新计算 IP 头的校验和。在对头部进行任何修改时，确保 IP 数据包的完整性是至关重要的。

```c
static __always_inline __u16 iph_csum(struct iphdr *iph) {
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}
```

### 4. **XDP 程序逻辑**

XDP 负载均衡器的核心逻辑在 `xdp_load_balancer` 函数中实现，该函数附加到 XDP 钩子上。它处理传入的数据包，并根据不同情况将数据包转发到后端或回传给客户端。

- **初始检查**：
  函数首先验证数据包是否是以太网帧，接着检查它是否是 IP 数据包（IPv4）并且使用了 TCP 协议。

  ```c
  if (eth->h_proto != __constant_htons(ETH_P_IP))
      return XDP_PASS;
  if (iph->protocol != IPPROTO_TCP)
      return XDP_PASS;
  ```

- **客户端数据包处理**：
  如果源 IP 与客户端 IP 匹配，代码使用 `xxhash32` 对 IP 头进行哈希处理，以确定相应的后端（基于 key 对 2 取模）。

  ```c
  if (iph->saddr == client_ip) {
      __u32 key = xxhash32((const char*)iph, sizeof(struct iphdr), 0) % 2;
      struct backend_config *backend = bpf_map_lookup_elem(&backends, &key);
  ```

  之后将目标 IP 和 MAC 替换为选定的后端的值，并将数据包转发到后端。

- **后端数据包处理**：
  如果数据包来自后端服务器，代码将目标设置为客户端的 IP 和 MAC 地址，确保后端的响应数据包被正确地转发回客户端。

  ```c
  iph->daddr = client_ip;
  __builtin_memcpy(eth->h_dest, client_mac, ETH_ALEN);
  ```

- **重写 IP 和 MAC 地址**：
  对于所有的出站数据包，源 IP 和 MAC 地址会被更新为负载均衡器的值，以确保在客户端与后端之间通信时，负载均衡器作为源进行标识。

  ```c
  iph->saddr = load_balancer_ip;
  __builtin_memcpy(eth->h_source, load_balancer_mac, ETH_ALEN);
  ```

- **重新计算校验和**：
  修改 IP 头之后，使用之前定义的 `iph_csum()` 函数重新计算校验和。

  ```c
  iph->check = iph_csum(iph);
  ```

- **最终动作**：
  使用 `XDP_TX` 动作发送数据包，这指示网卡将修改后的数据包传输出去。

  ```c
  return XDP_TX;
  ```

### 5. **结论**

在这部分博客中，可以解释负载均衡器是如何通过检查源 IP、进行哈希计算来分配流量，并通过修改目标 IP 和 MAC 来确保数据包的转发。`XDP_TX` 动作是实现 eBPF 在 XDP 层中高速数据包处理的关键。

这一解释可以帮助读者理解数据包的流转过程，以及代码中每个部分在实现多个后端之间负载均衡的过程中所起的作用。


## Userspace code

```c
// xdp_lb.c
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include "xdp_lb.skel.h"  // The generated skeleton

struct backend_config {
    __u32 ip;
    unsigned char mac[6];
};

static int parse_mac(const char *str, unsigned char *mac) {
    if (sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        fprintf(stderr, "Invalid MAC address format\n");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <ifname> <backend1_ip> <backend1_mac> <backend2_ip> <backend2_mac>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    struct backend_config backend[2];

    // Parse backend 1
    if (inet_pton(AF_INET, argv[2], &backend[0].ip) != 1) {
        fprintf(stderr, "Invalid backend 1 IP address\n");
        return 1;
    }
    if (parse_mac(argv[3], backend[0].mac) < 0) {
        return 1;
    }

    // Parse backend 2
    if (inet_pton(AF_INET, argv[4], &backend[1].ip) != 1) {
        fprintf(stderr, "Invalid backend 2 IP address\n");
        return 1;
    }
    if (parse_mac(argv[5], backend[1].mac) < 0) {
        return 1;
    }

    // Load and attach the BPF program
    struct xdp_lb_bpf *skel = xdp_lb_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex < 0) {
        perror("if_nametoindex");
        xdp_lb_bpf__destroy(skel);
        return 1;
    }

    if (bpf_program__attach_xdp(skel->progs.xdp_load_balancer, ifindex) < 0) {
        fprintf(stderr, "Failed to attach XDP program\n");
        xdp_lb_bpf__destroy(skel);
        return 1;
    }

    // Update backend configurations
    for (int i = 0; i < 2; i++) {
        if (bpf_map_update_elem(bpf_map__fd(skel->maps.backends), &i, &backend[i], 0) < 0) {
            perror("bpf_map_update_elem");
            xdp_lb_bpf__destroy(skel);
            return 1;
        }
    }

    printf("XDP load balancer configured with backends:\n");
    printf("Backend 1 - IP: %s, MAC: %s\n", argv[2], argv[3]);
    printf("Backend 2 - IP: %s, MAC: %s\n", argv[4], argv[5]);

    printf("Press Ctrl+C to exit...\n");
    while (1) {
        sleep(1);  // Keep the program running
    }

    // Cleanup and detach
    bpf_xdp_detach(ifindex, 0, NULL);
    xdp_lb_bpf__detach(skel);
    xdp_lb_bpf__destroy(skel);
    return 0;
}
```

### 用户空间代码概述

提供的用户空间代码负责设置和配置在内核中运行的 XDP 负载均衡器程序。它接受命令行参数，加载 eBPF 程序，将其附加到网络接口，并更新后端服务器的配置信息。

### 1. **解析命令行参数和设置后端服务器**

程序期望五个命令行参数：网络接口的名称 (`ifname`)、两个后端服务器的 IP 地址和 MAC 地址。它通过 `inet_pton()` 函数解析 IP 地址，并使用 `parse_mac()` 函数解析 MAC 地址，确保提供的 MAC 地址格式正确。解析后的后端信息存储在 `backend_config` 结构体中。

### 2. **加载并附加 BPF 程序**

BPF skeleton（通过 `xdp_lb.skel.h` 生成）用于打开并将 XDP 程序加载到内核中。程序通过 `if_nametoindex()` 将网络接口名称转换为索引，然后使用 `bpf_program__attach_xdp()` 将加载的 BPF 程序附加到此接口上。

### 3. **配置后端服务器信息**

后端的 IP 和 MAC 地址被写入 `backends` BPF map 中，使用 `bpf_map_update_elem()` 函数。此步骤确保 BPF 程序能够访问后端配置，从而基于内核代码中的逻辑将数据包路由到正确的后端服务器。

### 4. **程序循环与清理**

程序进入无限循环（`while (1) { sleep(1); }`），使 XDP 程序保持运行。当用户通过按下 Ctrl+C 退出时，BPF 程序从网络接口上卸载，并通过调用 `xdp_lb_bpf__destroy()` 清理资源。

总的来说，这段用户空间代码负责配置和管理 XDP 负载均衡器的生命周期，使得可以动态更新后端配置，并确保负载均衡器正确附加到网络接口上。

### 测试环境拓扑

拓扑结构表示一个测试环境，其中本地机器通过负载均衡器与两个后端节点（h2 和 h3）通信。通过虚拟以太网对（veth0 到 veth6），本地机器与负载均衡器相连，在受控环境中模拟网络连接。每个虚拟接口都有自己的 IP 和 MAC 地址，代表不同的实体。

```txt
    +---------------------------+          
    |      本地机器              |
    |  IP: 10.0.0.1 (veth0)      |
    |  MAC: DE:AD:BE:EF:00:01    |
    +------------+---------------+
             |
             | (veth1)
             |
    +--------+---------------+       
    |    负载均衡器           |
    |  IP: 10.0.0.10 (veth6) |
    |  MAC: DE:AD:BE:EF:00:10|
    +--------+---------------+       
             | 
   +---------+----------------------------+            
   |                                      |
(veth2)                                (veth4)    
   |                                      | 
+--+---------------+             +--------+---------+
| h2               |             | h3               |
| IP:              |             | IP:              |
|10.0.0.2 (veth3)  |             |10.0.0.3 (veth5)  |
| MAC:             |             | MAC:             |
|DE:AD:BE:EF:00:02 |             |DE:AD:BE:EF:00:03 |
+------------------+             +------------------+
```

这个设置可以通过脚本（`setup.sh`）轻松初始化，并通过另一个脚本（`teardown.sh`）删除。

> 如果您对本教程感兴趣，请帮助我们创建一个容器化的版本，简化设置和拓扑结构！目前的设置和删除过程基于网络命名空间，容器化的版本会更加友好。

初始化：

```sh
sudo ./setup.sh
```

删除：

```sh
sudo ./teardown.sh
```

### 运行负载均衡器

要运行 XDP 负载均衡器，执行以下命令，指定接口和后端服务器的 IP 和 MAC 地址：

```console
sudo ip netns exec lb ./xdp_lb veth6 10.0.0.2 de:ad:be:ef:00:02 10.0.0.3 de:ad:be:ef:00:03
```

这将配置负载均衡器并输出后端服务器的详细信息：

```console
XDP load balancer configured with backends:
Backend 1 - IP: 10.0.0.2, MAC: de:ad:be:ef:00:02
Backend 2 - IP: 10.0.0.3, MAC: de:ad:be:ef:00:03
Press Ctrl+C to exit...
```

### 测试设置

您可以通过在两个后端命名空间（`h2` 和 `h3`）启动 HTTP 服务器，并从本地机器向负载均衡器发送请求来测试设置：

在 `h2` 和 `h3` 上启动服务器：

```sh
sudo ip netns exec h2 python3 -m http.server
sudo ip netns exec h3 python3 -m http.server
```

然后，向负载均衡器 IP 发送请求：

```sh
curl 10.0.0.10:8000
```

负载均衡器将根据哈希函数将流量分配到后端服务器（`h2` 和 `h3`）。

### 使用 `bpf_printk` 进行监控

您可以通过查看 `bpf_printk` 日志来监控负载均衡器的活动。BPF 程序在处理每个数据包时会打印诊断消息。您可以使用以下命令查看这些日志：

```console
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

日志示例：

```console
<idle>-0       [004] ..s2. 24174.812722: bpf_trace_printk: xdp_load_balancer received packet
<idle>-0       [004] .Ns2. 24174.812729: bpf_trace_printk: Received Source IP: 0xa000001
<idle>-0       [004] .Ns2. 24174.812729: Received Destination IP: 0xa00000a
<idle>-0       [004] .Ns2. 24174.812731: Received Source MAC: de:ad:be:ef:0:1
<idle>-0       [004] .Ns2. 24174.812732: Received Destination MAC: de:ad:be:ef:0:10
<idle>-0       [004] .Ns2. 24174.812732: Packet from client
<idle>-0       [004] .Ns2. 24174.812734: bpf_trace_printk: Redirecting packet to new IP 0xa000002 from IP 0xa00000a
<idle>-0       [004] .Ns2. 24174.812735: New Dest MAC: de:ad:be:ef:0:2
<idle>-0       [004] .Ns2. 24174.812735: New Source MAC: de:ad:be:ef:0:10
```

### 调试问题

某些系统可能会因为类似于此[博客文章](https://fedepaol.github.io/blog/2023/09/11/xdp-ate-my-packets-and-how-i-debugged-it/)中描述的问题而导致数据包丢失或转发失败。您可以使用 `bpftrace` 跟踪 XDP 错误进行调试：

```sh
sudo bpftrace -e 'tracepoint:xdp:xdp_bulk_tx{@redir_errno[-args->err] = count();}'
```

如果输出如下所示：

```sh
@redir_errno[6]: 3
```

这表明与 XDP 数据包转发相关的错误。错误代码 `6` 通常指向可以进一步调查的特定转发问题。

### 结论

本教程展示了如何使用 eBPF 设置一个简单的 XDP 负载均衡器，以实现高效的流量分发。对于那些想了解更多关于 eBPF 知识的用户，包括更高级的示例和教程，请访问我们的 [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) 或我们的网站 [https://eunomia.dev/tutorials/](https://eunomia.dev/tutorials/)。

### 参考文献

- [XDP 编程实践教程](https://github.com/xdp-project/xdp-tutorial)