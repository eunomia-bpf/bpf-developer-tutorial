# eBPF 实战教程 21：通过 XDP 实现可编程的包处理

在本教程中，我们将介绍 XDP（eXpress Data Path），并通过一个小例子来帮助您入门。稍后，我们将探索更多高级的 XDP 应用程序，如负载均衡、防火墙以及其他现实世界中的用例。如果您对 eBPF 或 XDP 感兴趣，请在 [Github](https://github.com/eunomia-bpf/bpf-developer-tutorial) 上给我们一个 Star！

## 什么是 XDP？

XDP 是 Linux 内核中的高性能可编程数据路径，专为网络接口级别的包处理而设计。通过将 eBPF 程序直接附加到网络设备驱动程序上，XDP 能够在数据包到达内核的网络栈之前拦截并处理它们。这使得 XDP 能以极低的延迟处理数据包，特别适合用于 DDoS 防护、负载均衡和流量过滤等任务。实际上，XDP 每核处理速度可以高达 **每秒 2400 万包（Mpps）**。

### 为什么选择 XDP？

XDP 运行在比传统 Linux 网络组件（如 cBPF）更低的层次，它在网络设备驱动程序的软中断上下文中运行，能够在数据包经过内核的标准网络栈之前处理它们，绕过创建代表网络数据包的 `skb_buff` 结构。对于诸如丢弃恶意包或负载均衡等简单但频繁的操作，这种早期阶段的处理可以显著提升性能。

与其他数据包处理机制相比，XDP 在性能和可用性之间取得了平衡，既利用了 Linux 内核的安全性和可靠性，又通过可编程的 eBPF 提供了灵活性。

## XDP 与其他方法的比较

在 XDP 之前，有多种其他方案试图通过绕过内核来加速数据包处理。其中一个显著的例子是 **DPDK**（数据平面开发套件）。DPDK 允许用户空间应用程序直接控制网络设备，从而实现非常高的性能。然而，这种方法也有其权衡之处：

1. **缺乏内核集成**：DPDK 等绕过内核的解决方案无法利用现有的内核网络功能，开发人员需要在用户空间重新实现许多协议和功能。

2. **安全边界**：这些绕过技术打破了内核的安全模型，难以利用内核提供的安全工具。

3. **用户空间与内核的切换成本**：当用户空间数据包处理需要与传统的内核网络交互（如基于套接字的应用程序）时，数据包必须重新注入内核，这会增加开销和复杂性。

4. **专用 CPU 使用**：为了处理高流量，DPDK 等解决方案通常需要专门分配一个或多个 CPU 核心来专门处理数据包，这限制了通用系统的可扩展性和效率。

另一种替代 XDP 的方法是使用 **内核模块** 或 Linux 网络栈中的 **钩子**。虽然这种方法与现有的内核功能很好地集成，但它需要对内核进行大量修改，并且由于它在数据包处理管道的后期操作，无法提供与 XDP 相同的性能提升。

### XDP + eBPF 的优势

XDP 和 eBPF 的组合在绕过内核的解决方案（如 DPDK）和内核集成解决方案之间提供了一个折中方案。以下是 XDP + eBPF 的优势：

- **高性能**：通过在网卡驱动程序层早期拦截数据包，XDP 能够以接近线速的性能执行数据包的丢弃、重定向或负载均衡操作，同时保持较低的资源使用率。
  
- **内核集成**：与 DPDK 不同，XDP 在 Linux 内核中工作，允许与现有的内核网络栈和工具（如 `iptables`、`nftables` 或套接字）无缝交互。无需在用户空间重新实现网络协议。

- **安全性**：eBPF 虚拟机（VM）确保用户定义的 XDP 程序在沙箱环境中运行，避免不稳定的代码影响内核。eBPF 的安全模型防止恶意或错误的代码破坏系统，为可编程数据包处理提供了一个安全的环境。

- **无需专用 CPU**：XDP 允许在无需专门分配 CPU 核心的情况下进行数据包处理，这提高了系统的整体效率，允许更灵活的资源分配。

总的来说，XDP + eBPF 提供了一个高性能、灵活且安全的可编程数据包处理解决方案，消除了完全绕过内核的方案的缺点，同时保留了内核的安全性和功能。

---

## XDP 的项目和应用案例

XDP 已经被用于多个高知名度的项目中，展示了它在现实网络场景中的强大功能和灵活性：

### 1. **Cilium**

- **描述**：Cilium 是一个开源的网络、安全和可观测性工具，专为云原生环境（特别是 Kubernetes）设计。它利用 XDP 实现高性能的数据包过滤和负载均衡。
- **用例**：Cilium 将数据包过滤和安全策略卸载到 XDP，以实现高吞吐量和低延迟的流量管理，而不牺牲可扩展性。
- **链接**：[Cilium](https://cilium.io/)

### 2. **Katran**

- **描述**：Katran 是 Facebook 开发的四层负载均衡器，经过优化以实现高可扩展性和高性能。它使用 XDP 来处理数据包转发，开销极小。
- **用例**：Katran 每秒处理数百万个数据包，将流量高效地分发到后端服务器，XDP 实现了低延迟和高性能的负载均衡，适用于大规模数据中心。
- **链接**：[Katran GitHub](https://github.com/facebookincubator/katran)

### 3. **Cloudflare 的 XDP DDoS 保护**

- **描述**：Cloudflare 已经实现了 XDP 用于实时 DDoS 缓解。通过在 NIC 层处理数据包，Cloudflare 可以在攻击流量到达网络栈之前将其过滤掉，最大限度地减少 DDoS 攻击对系统的影响。
- **用例**：Cloudflare 利用 XDP 在管道的早期丢弃恶意数据包，保护其基础设施免受大规模 DDoS 攻击，同时保持对合法流量的高可用性。
- **链接**：[Cloudflare 博客关于 XDP](https://blog.cloudflare.com/tag/xdp/)

这些项目展示了 XDP 在安全、负载均衡和云原生网络等不同领域的可扩展性和高效性。

---

### 为什么选择 XDP 而不是其他方法？

与 `iptables`、`nftables` 或 `tc` 等传统方法相比，XDP 具有几个明显的优势：

- **速度和低开销**：XDP 直接在网卡驱动程序中操作，绕过了内核的大部分开销，从而实现了更快的数据包处理。
  
- **定制性**：XDP 允许开发者通过 eBPF 创建自定义的包处理程序，提供了比传统工具（如 `iptables`）更灵活和细粒度的控制。

- **资源效率**：与 DPDK 等用户空间解决方案不同，XDP 不需要为数据包处理专门分配整个 CPU 核心，因此在高性能网络中是更高效的选择。

## 项目：构建一个简单的负载均衡器

在这个项目中，我们将专注于使用 XDP 构建一个负载均衡器。负载均衡器通过将传入的网络流量高效地分配到多个后端服务器，防止任何一台服务器过载。通过结合 XDP 和 eBPF，我们可以构建一个在 Linux 网络栈边缘运行的负载均衡器，确保即使在高流量条件下也能保持高性能。

我们将要实现的负载均衡器将具备以下功能：

- 监听传入的网络数据包。
- 根据数据包的源 IP 和端口计算哈希值，从而将流量分配到多个后端服务器。
- 根据计算的哈希值将数据包转发到相应的后端服务器。

我们将保持设计简单但功能强大，展示如何利用 eBPF 的能力来创建一个轻量级的负载均衡解决方案。

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