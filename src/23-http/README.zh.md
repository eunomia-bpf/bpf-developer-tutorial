# 通过 eBPF socket filter 或 syscall trace 追踪 HTTP 请求等七层协议 - eBPF 实践教程

在当今的技术环境中，随着微服务、云原生应用和复杂的分布式系统的崛起，系统的可观测性已成为确保其健康、性能和安全的关键要素。特别是在微服务架构中，应用程序的组件可能分布在多个容器和服务器上，这使得传统的监控方法往往难以提供足够的深度和广度来全面了解系统的行为。这就是为什么观测七层协议，如 HTTP、gRPC、MQTT 等，变得尤为重要。

七层协议为我们提供了关于应用程序如何与其他服务和组件交互的详细信息。在微服务环境中，了解这些交互是至关重要的，因为它们经常是性能瓶颈、故障和安全问题的根源。然而，监控这些协议并不简单。传统的网络监控工具，如 tcpdump，虽然在捕获网络流量方面非常有效，但在处理七层协议的复杂性和动态性时，它们往往显得力不从心。

这正是 eBPF 技术发挥作用的地方。eBPF 允许开发者和运维人员深入到系统的内核层，实时观测和分析系统的行为，而无需对应用程序代码进行任何修改或插入埋点。这为我们提供了一个独特的机会，可以更简单、更高效地处理应用层流量，特别是在微服务环境中。

在本教程中，我们将深入探讨以下内容：

- 追踪七层协议，如 HTTP，以及与其相关的挑战。
- eBPF 的 socket filter 和 syscall 追踪：这两种技术如何帮助我们在不同的内核层次追踪 HTTP 网络请求数据，以及这两种方法的优势和局限性。
- eBPF 实践教程：如何开发一个 eBPF 程序，使用 eBPF socket filter 或 syscall 追踪来捕获和分析 HTTP 流量

随着网络流量的增加和应用程序的复杂性增加，对七层协议的深入了解变得越来越重要。通过本教程，您将获得必要的知识和工具，以便更有效地监控和分析您的网络流量，从而为您的应用程序和服务器提供最佳的性能。

本文是 eBPF 开发者教程的一部分，更详细的内容可以在这里找到：<https://eunomia.dev/tutorials/> 源代码在 [GitHub 仓库](https://github.com/eunomia-bpf/bpf-developer-tutorial) 中开源。

## 追踪 HTTP, HTTP/2 等七层协议的挑战

在现代的网络环境中，七层协议不仅仅局限于 HTTP。实际上，有许多七层协议，如 HTTP/2, gRPC, MQTT, WebSocket, AMQP 和 SMTP，它们都在不同的应用场景中发挥着关键作用。这些协议为我们提供了关于应用程序如何与其他服务和组件交互的详细信息。但是，追踪这些协议并不是一个简单的任务，尤其是在复杂的分布式系统中。

1. **多样性和复杂性**：每种七层协议都有其特定的设计和工作原理。例如，gRPC 使用了 HTTP/2 作为其传输协议，并支持多种语言。而 MQTT 是为低带宽和不可靠的网络设计的轻量级发布/订阅消息传输协议。

2. **动态性**：许多七层协议都是动态的，这意味着它们的行为可能会根据网络条件、应用需求或其他因素而变化。

3. **加密和安全性**：随着安全意识的增强，许多七层协议都采用了加密技术，如 TLS/SSL。这为追踪和分析带来了额外的挑战，因为需要解密流量才能进行深入的分析。

4. **高性能需求**：在高流量的生产环境中，捕获和分析七层协议的流量可能会对系统性能产生影响。传统的网络监控工具可能无法处理大量的并发会话。

5. **数据的完整性和连续性**：与 tcpdump 这样的工具只捕获单独的数据包不同，追踪七层协议需要捕获完整的会话，这可能涉及多个数据包。这要求工具能够正确地重组和解析这些数据包，以提供连续的会话视图。

6. **代码侵入性**：为了深入了解七层协议的行为，开发人员可能需要修改应用程序代码以添加监控功能。这不仅增加了开发和维护的复杂性，而且可能会影响应用程序的性能。

正如上文所述，eBPF 提供了一个强大的解决方案，允许我们在内核层面捕获和分析七层协议的流量，而无需对应用程序进行任何修改。这种方法为我们提供了一个独特的机会，可以更简单、更高效地处理应用层流量，特别是在微服务和分布式环境中。

在处理网络流量和系统行为时，选择在内核态而非用户态进行处理有其独特的优势。首先，内核态处理可以直接访问系统资源和硬件，从而提供更高的性能和效率。其次，由于内核是操作系统的核心部分，它可以提供对系统行为的全面视图，而不受任何用户空间应用程序的限制。

**无插桩追踪（"zero-instrumentation observability"）**的优势如下：

1. **性能开销小**：由于不需要修改或添加额外的代码到应用程序中，所以对性能的影响最小化。
2. **透明性**：开发者和运维人员不需要知道应用程序的内部工作原理，也不需要访问源代码。
3. **灵活性**：可以轻松地在不同的环境和应用程序中部署和使用，无需进行任何特定的配置或修改。
4. **安全性**：由于不需要修改应用程序代码，所以降低了引入潜在安全漏洞的风险。

利用 eBPF 在内核态进行无插桩追踪，我们可以实时捕获和分析系统的行为，而不需要对应用程序进行任何修改。这种方法不仅提供了对系统深入的洞察力，而且确保了最佳的性能和效率。这是为什么 eBPF 成为现代可观测性工具的首选技术，特别是在需要高性能和低延迟的生产环境中。

## eBPF 中的 socket filter 与 syscall 追踪：深入解析与比较

### **eBPF Socket Filter**

**是什么？**
eBPF socket filter 是经典的 Berkeley Packet Filter (BPF) 的扩展，允许在内核中直接进行更高级的数据包过滤。它在套接字层操作，使得可以精细地控制哪些数据包被用户空间应用程序处理。

**主要特点：**

- **性能**：通过在内核中直接处理数据包，eBPF socket filters 减少了用户和内核空间之间的上下文切换的开销。
- **灵活性**：eBPF socket filters 可以附加到任何套接字，为各种协议和套接字类型提供了通用的数据包过滤机制。
- **可编程性**：开发者可以编写自定义的 eBPF 程序来定义复杂的过滤逻辑，超越简单的数据包匹配。

**用途：**

- **流量控制**：根据自定义条件限制或优先处理流量。
- **安全性**：在它们到达用户空间应用程序之前丢弃恶意数据包。
- **监控**：捕获特定数据包进行分析，而不影响其它流量。

### **eBPF Syscall Tracing**

**是什么？**
使用 eBPF 进行的系统调用跟踪允许监视和操作应用程序发出的系统调用。系统调用是用户空间应用程序与内核交互的主要机制，因此跟踪它们可以深入了解应用程序的行为。

**主要特点：**

- **粒度**：eBPF 允许跟踪特定的系统调用，甚至是这些系统调用中的特定参数。
- **低开销**：与其他跟踪方法相比，eBPF 系统调用跟踪旨在具有最小的性能影响。
- **安全性**：内核验证 eBPF 程序，以确保它们不会损害系统稳定性。

**工作原理：**
eBPF 系统调用跟踪通常涉及将 eBPF 程序附加到与系统调用相关的 tracepoints 或 kprobes。当跟踪的系统调用被调用时，执行 eBPF 程序，允许收集数据或甚至修改系统调用参数。

### eBPF 的 socket filter 和 syscall 追踪的对比

| 项目 | eBPF Socket Filter | eBPF Syscall Tracing |
|------|--------------------|----------------------|
| **操作层** | 套接字层，主要处理从套接字接收或发送的网络数据包 | 系统调用层，监视和可能更改应用程序发出的系统调用的行为 |
| **主要用途** | 主要用于网络数据包的过滤、监控和操作 | 用于性能分析、安全监控和系统调用交互的调试 |
| **粒度** | 专注于单个网络数据包 | 可以监视与网络无关的广泛的系统活动 |
| **追踪 HTTP 流量** | 可以用于过滤和捕获通过套接字传递的 HTTP 数据包 | 可以跟踪与网络操作相关的系统调用 |

总之，eBPF 的 socket filter 和 syscall 追踪都可以用于追踪 HTTP 流量，但 socket filters 更直接且更适合此目的。然而，如果您对应用程序如何与系统交互的更广泛的上下文感兴趣（例如，哪些系统调用导致了 HTTP 流量），那么系统调用跟踪将是非常有价值的。在许多高级的可观察性设置中，这两种工具可能会同时使用，以提供系统和网络行为的全面视图。

## 使用 eBPF socket filter 来捕获 HTTP 流量

eBPF 代码由用户态和内核态组成，这里主要关注于内核态代码。这是使用 eBPF socket filter 技术来在内核中捕获HTTP流量的主要逻辑，完整代码如下：

```c
SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
    struct so_event *e;
    __u8 verlen;
    __u16 proto;
    __u32 nhoff = ETH_HLEN;
    __u32 ip_proto = 0;
    __u32 tcp_hdr_len = 0;
    __u16 tlen;
    __u32 payload_offset = 0;
    __u32 payload_length = 0;
    __u8 hdr_len;

    bpf_skb_load_bytes(skb, 12, &proto, 2);
    proto = __bpf_ntohs(proto);
    if (proto != ETH_P_IP)
        return 0;

    if (ip_is_fragment(skb, nhoff))
        return 0;

    // ip4 header lengths are variable
    // access ihl as a u8 (linux/include/linux/skbuff.h)
    bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
    hdr_len &= 0x0f;
    hdr_len *= 4;

    /* verify hlen meets minimum size requirements */
    if (hdr_len < sizeof(struct iphdr))
    {
        return 0;
    }

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &ip_proto, 1);

    if (ip_proto != IPPROTO_TCP)
    {
        return 0;
    }

    tcp_hdr_len = nhoff + hdr_len;
    bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));

    __u8 doff;
    bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct __tcphdr, ack_seq) + 4, &doff, sizeof(doff)); // read the first byte past __tcphdr->ack_seq, we can't do offsetof bit fields
    doff &= 0xf0; // clean-up res1
    doff >>= 4; // move the upper 4 bits to low
    doff *= 4; // convert to bytes length

    payload_offset = ETH_HLEN + hdr_len + doff;
    payload_length = __bpf_ntohs(tlen) - hdr_len - doff;

    char line_buffer[7];
    if (payload_length < 7 || payload_offset < 0)
    {
        return 0;
    }
    bpf_skb_load_bytes(skb, payload_offset, line_buffer, 7);
    bpf_printk("%d len %d buffer: %s", payload_offset, payload_length, line_buffer);
    if (bpf_strncmp(line_buffer, 3, "GET") != 0 &&
        bpf_strncmp(line_buffer, 4, "POST") != 0 &&
        bpf_strncmp(line_buffer, 3, "PUT") != 0 &&
        bpf_strncmp(line_buffer, 6, "DELETE") != 0 &&
        bpf_strncmp(line_buffer, 4, "HTTP") != 0)
    {
        return 0;
    }

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ip_proto = ip_proto;
    bpf_skb_load_bytes(skb, nhoff + hdr_len, &(e->ports), 4);
    e->pkt_type = skb->pkt_type;
    e->ifindex = skb->ifindex;

    e->payload_length = payload_length;
    bpf_skb_load_bytes(skb, payload_offset, e->payload, MAX_BUF_SIZE);

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->src_addr), 4);
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->dst_addr), 4);
    bpf_ringbuf_submit(e, 0);

    return skb->len;
}
```

当分析这段eBPF程序时，我们将按照每个代码块的内容来详细解释，并提供相关的背景知识：

```c
SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
    // ...
}
```

这是eBPF程序的入口点，它定义了一个名为 `socket_handler` 的函数，它会被内核用于处理传入的网络数据包。这个函数位于一个名为 `socket` 的 eBPF 节（section）中，表明这个程序用于套接字处理。

```c
struct so_event *e;
__u8 verlen;
__u16 proto;
__u32 nhoff = ETH_HLEN;
__u32 ip_proto = 0;
__u32 tcp_hdr_len = 0;
__u16 tlen;
__u32 payload_offset = 0;
__u32 payload_length = 0;
__u8 hdr_len;
```

在这个代码块中，我们定义了一些变量来存储在处理数据包时需要的信息。这些变量包括了`struct so_event *e`用于存储事件信息，`verlen`、`proto`、`nhoff`、`ip_proto`、`tcp_hdr_len`、`tlen`、`payload_offset`、`payload_length`、`hdr_len`等用于存储数据包信息的变量。

- `struct so_event *e;`：这是一个指向`so_event`结构体的指针，用于存储捕获到的事件信息。该结构体的具体定义在程序的其他部分。
- `__u8 verlen;`、`__u16 proto;`、`__u32 nhoff = ETH_HLEN;`：这些变量用于存储各种信息，例如协议类型、数据包偏移量等。`nhoff`初始化为以太网帧头部的长度，通常为14字节，因为以太网帧头部包括目标MAC地址、源MAC地址和帧类型字段。
- `__u32 ip_proto = 0;`：这个变量用于存储IP协议的类型，初始化为0。
- `__u32 tcp_hdr_len = 0;`：这个变量用于存储TCP头部的长度，初始化为0。
- `__u16 tlen;`：这个变量用于存储IP数据包的总长度。
- `__u32 payload_offset = 0;`、`__u32 payload_length = 0;`：这两个变量用于存储HTTP请求的载荷（payload）的偏移量和长度。
- `__u8 hdr_len;`：这个变量用于存储IP头部的长度。

```c
bpf_skb_load_bytes(skb, 12, &proto, 2);
proto = __bpf_ntohs(proto);
if (proto != ETH_P_IP)
    return 0;
```

在这里，代码从数据包中加载了以太网帧的类型字段，这个字段告诉我们数据包使用的网络层协议。然后，使用`__bpf_ntohs`函数将网络字节序的类型字段转换为主机字节序。接下来，代码检查类型字段是否等于IPv4的以太网帧类型（0x0800）。如果不等于，说明这个数据包不是IPv4数据包，直接返回0，放弃处理。

这里需要了解以下几个概念：

- 以太网帧（Ethernet Frame）：是数据链路层（第二层）的协议，用于在局域网中传输数据帧。以太网帧通常包括目标MAC地址、源MAC地址和帧类型字段。
- 网络字节序（Network Byte Order）：网络协议通常使用大端字节序（Big-Endian）来表示数据。因此，需要将从网络中接收到的数据转换为主机字节序，以便在主机上正确解释数据。
- IPv4帧类型（ETH_P_IP）：表示以太网帧中包含的协议类型字段，0x0800表示IPv4。

```c
if (ip_is_fragment(skb, nhoff))
    return 0;
```

这一部分的代码检查是否处理IP分片。IP分片是将较大的IP数据包分割成多个小片段以进行传输的机制。在这里，如果数据包是IP分片，则直接返回0，表示不处理分片，只处理完整的数据包。

```c
static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
    __u16 frag_off;

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
    frag_off = __bpf_ntohs(frag_off);
    return frag_off & (IP_MF | IP_OFFSET);
}
```

上述代码是一个辅助函数，用于检查传入的IPv4数据包是否为IP分片。IP分片是一种机制，当IP数据包的大小超过了网络的最大传输单元（MTU），路由器会将其分割成多个较小的片段，以便在网络上进行传输。这个函数的目的是检查数据包的分片标志（Fragmentation Flag）以及片偏移（Fragment Offset）字段，以确定是否为分片。

下面是代码的逐行解释：

1. `__u16 frag_off;`：定义一个16位无符号整数变量`frag_off`，用于存储片偏移字段的值。
2. `bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);`：这行代码使用`bpf_skb_load_bytes`函数从数据包中加载IPv4头部的片偏移字段（`frag_off`），并加载2个字节。`nhoff`是IPv4头部在数据包中的偏移量，`offsetof(struct iphdr, frag_off)`用于计算片偏移字段在IPv4头部中的偏移量。
3. `frag_off = __bpf_ntohs(frag_off);`：将加载的片偏移字段从网络字节序（Big-Endian）转换为主机字节序。网络协议通常使用大端字节序表示数据，而主机可能使用大端或小端字节序。这里将片偏移字段转换为主机字节序，以便进一步处理。
4. `return frag_off & (IP_MF | IP_OFFSET);`：这行代码通过使用位运算检查片偏移字段的值，以确定是否为IP分片。具体来说，它使用位与运算符`&`将片偏移字段与两个标志位进行位与运算：
   - `IP_MF`：表示"更多分片"标志（More Fragments）。如果这个标志位被设置为1，表示数据包是分片的一部分，还有更多分片。
   - `IP_OFFSET`：表示片偏移字段。如果片偏移字段不为0，表示数据包是分片的一部分，且具有片偏移值。
   如果这两个标志位中的任何一个被设置为1，那么结果就不为零，说明数据包是IP分片。如果都为零，说明数据包不是分片。

需要注意的是，IP头部的片偏移字段以8字节为单位，所以实际的片偏移值需要左移3位来得到字节偏移。此外，IP头部的"更多分片"标志（IP_MF）表示数据包是否有更多的分片，通常与片偏移字段一起使用来指示整个数据包的分片情况。这个函数只关心这两个标志位，如果其中一个标志被设置，就认为是IP分片。

```c
bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
hdr_len &= 0x0f;
hdr_len *= 4;
```

这一部分的代码从数据包中加载IP头部的长度字段。IP头部长度字段包含了IP头部的长度信息，以4字节为单位，需要将其转换为字节数。这里通过按位与和乘以4来进行转换。

需要了解：

- IP头部（IP Header）：IP头部包含了关于数据包的基本信息，如源IP地址、目标IP地址、协议类型和头部校验和等。头部长度字段（IHL，Header Length）表示IP头部的长度，以4字节为单位，通常为20字节（5个4字节的字）。

```c
if (hdr_len < sizeof(struct iphdr))
{
    return 0;
}
```

这段代码检查IP头部的长度是否满足最小长度要求，通常IP头部的最小长度是20字节。如果IP头部的长度小于20字节，说明数据包不完整或损坏，直接返回0，放弃处理。

需要了解：

- `struct iphdr`：这是Linux内核中定义的结构体，表示IPv4头部的格式。它包括了版本、头部长度、服务类型、总长度、

标识符、标志位、片偏移、生存时间、协议、头部校验和、源IP地址和目标IP地址等字段。

```c
bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &ip_proto, 1);
if (ip_proto != IPPROTO_TCP)
{
    return 0;
}
```

在这里，代码从数据包中加载IP头部中的协议字段，以确定数据包使用的传输层协议。然后，它检查协议字段是否为TCP协议（IPPROTO_TCP）。如果不是TCP协议，说明不是HTTP请求或响应，直接返回0。

需要了解：

- 传输层协议：IP头部中的协议字段指示了数据包所使用的传输层协议，例如TCP、UDP或ICMP。

```c
tcp_hdr_len = nhoff + hdr_len;
```

这行代码计算了TCP头部的偏移量。它将以太网帧头部的长度（`nhoff`）与IP头部的长度（`hdr_len`）相加，得到TCP头部的起始位置。

```c
bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
```

这行代码从数据包中加载TCP头部的第一个字节，该字节包含了TCP头部长度信息。这个长度字段以4字节为单位，需要进行后续的转换。

```c
bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));
```

这行代码从数据包中加载IP头部的总长度字段。IP头部总长度字段表示整个IP数据包的长度，包括IP头部和数据部分。

```c
__u8 doff;
bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct __tcphdr, ack_seq) + 4, &doff, sizeof(doff));
doff &= 0xf0;
doff >>= 4;
doff *= 4;
```

这段代码用于计算TCP头部的长度。它加载TCP头部中的数据偏移字段（Data Offset，也称为头部长度字段），该字段表示TCP头部的长度以4字节为单位。代码将偏移字段的高四位清零，然后将其右移4位，最后乘以4，得到TCP头部的实际长度。

需要了解：

- TCP头部（TCP Header）：TCP头部包含了TCP协议相关的信息，如源端口、目标端口、序列号、确认号、标志位（如SYN、ACK、FIN等）、窗口大小和校验和等。

```c
payload_offset = ETH_HLEN + hdr_len + doff;
payload_length = __bpf_ntohs(tlen) - hdr_len - doff;
```

这两行代码计算HTTP请求的载荷（payload）的偏移量和长度。它们将以太网帧头部长度、IP头部长度和TCP头部长度相加，得到HTTP请求的数据部分的偏移量，然后通过减去总长度、IP头部长度和TCP头部长度，计算出HTTP请求数据的长度。

需要了解：

- HTTP请求载荷（Payload）：HTTP请求中包含的实际数据部分，通常是HTTP请求头和请求体。

```c
char line_buffer[7];
if (payload_length < 7 || payload_offset < 0)
{
    return 0;
}
bpf_skb_load_bytes(skb, payload_offset, line_buffer, 7);
bpf_printk("%d len %d buffer: %s", payload_offset, payload_length, line_buffer);
```

这部分代码用于加载HTTP请求行的前7个字节，存储在名为`line_buffer`的字符数组中。然后，它检查HTTP请求数据的长度是否小于7字节或偏移量是否为负数，如果满足这些条件，说明HTTP请求不完整，直接返回0。最后，它使用`bpf_printk`函数将HTTP请求行的内容打印到内核日志中，以供调试和分析。

```c
if (bpf_strncmp(line_buffer, 3, "GET") != 0 &&
    bpf_strncmp(line_buffer, 4, "POST") != 0 &&
    bpf_strncmp(line_buffer, 3, "PUT") != 0 &&
    bpf_strncmp(line_buffer, 6, "DELETE") != 0 &&
    bpf_strncmp(line_buffer, 4, "HTTP") != 0)
{
    return 0;
}
```

> 注意：bpf_strncmp 这个内核 helper 在 5.17 版本中才被引入，如果你的内核版本低于 5.17，可以手动匹配字符串来实现相同的功能。

这段代码使用`bpf_strncmp`函数比较`line_buffer`中的数据与HTTP请求方法（GET、POST、PUT、DELETE、HTTP）是否匹配。如果不匹配，说明不是HTTP请求，直接返回0，放弃处理。

```c
e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
if (!e)
    return 0;
```

这部分代码尝试从BPF环形缓冲区中保留一块内存以存储事件信息。如果无法保留内存块，返回0。BPF环形缓冲区用于在eBPF程序和用户空间之间传递事件数据。

需要了解：

- BPF环形缓冲区：BPF环形缓冲区是一种在eBPF程序和用户空间之间传递数据的机制。它可以用来存储事件信息，以便用户空间应用程序进行进一步处理或分析。

```c
e->ip_proto = ip_proto;
bpf_skb_load_bytes(skb, nhoff + hdr_len, &(e->ports), 4);
e->pkt_type = skb->pkt_type;
e->ifindex = skb->ifindex;

e->payload_length = payload_length;
bpf_skb_load_bytes(skb, payload_offset, e->payload, MAX_BUF_SIZE);

bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->src_addr), 4);
bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->dst_addr), 4);
bpf_ringbuf_submit(e, 0);

return skb->len;
```

最后，这段代码将捕获到的事件信息存储在`e`结构体中，并将

其提交到BPF环形缓冲区。它包括了捕获的IP协议、源端口和目标端口、数据包类型、接口索引、载荷长度、源IP地址和目标IP地址等信息。最后，它返回数据包的长度，表示成功处理了数据包。

这段代码主要用于将捕获的事件信息存储起来，以便后续的处理和分析。 BPF环形缓冲区用于将这些信息传递到用户空间，供用户空间应用程序进一步处理或记录。

总结：这段eBPF程序的主要任务是捕获HTTP请求，它通过解析数据包的以太网帧、IP头部和TCP头部来确定数据包是否包含HTTP请求，并将有关请求的信息存储在`so_event`结构体中，然后提交到BPF环形缓冲区。这是一种高效的方法，可以在内核层面捕获HTTP流量，适用于网络监控和安全分析等应用。

### 潜在缺陷

上述代码也存在一些潜在的缺陷，其中一个主要缺陷是它无法处理跨多个数据包的URL。

- 跨包URL：代码中通过解析单个数据包来检查HTTP请求中的URL，如果HTTP请求的URL跨足够多的数据包，那么只会检查第一个数据包中的URL部分。这会导致丢失或部分记录那些跨多个数据包的长URL。

解决这个问题的方法通常需要对多个数据包进行重新组装，以还原完整的HTTP请求。这可能需要在eBPF程序中实现数据包的缓存和组装逻辑，并在检测到HTTP请求结束之前等待并收集所有相关数据包。这需要更复杂的逻辑和额外的内存来处理跨多个数据包的情况。

### 用户态代码

用户态代码的主要目的是创建一个原始套接字（raw socket），然后将先前在内核中定义的eBPF程序附加到该套接字上，从而允许eBPF程序捕获和处理从该套接字接收到的网络数据包,例如：

```c
    /* Create raw socket for localhost interface */
    sock = open_raw_sock(interface);
    if (sock < 0) {
        err = -2;
        fprintf(stderr, "Failed to open raw socket\n");
        goto cleanup;
    }

    /* Attach BPF program to raw socket */
    prog_fd = bpf_program__fd(skel->progs.socket_handler);
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
        err = -3;
        fprintf(stderr, "Failed to attach to raw socket\n");
        goto cleanup;
    }
```

1. `sock = open_raw_sock(interface);`：这行代码调用了一个自定义的函数`open_raw_sock`，该函数用于创建一个原始套接字。原始套接字允许用户态应用程序直接处理网络数据包，而不经过协议栈的处理。函数`open_raw_sock`可能需要一个参数 `interface`，用于指定网络接口，以便确定从哪个接口接收数据包。如果创建套接字失败，它将返回一个负数，否则返回套接字的文件描述符`sock`。
2. 如果`sock`的值小于0，表示打开原始套接字失败，那么将`err`设置为-2，并在标准错误流上输出一条错误信息。
3. `prog_fd = bpf_program__fd(skel->progs.socket_handler);`：这行代码获取之前在eBPF程序定义中的套接字过滤器程序（`socket_handler`）的文件描述符，以便后续将它附加到套接字上。`skel`是一个eBPF程序对象的指针，可以通过它来访问程序集合。
4. `setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))`：这行代码使用`setsockopt`系统调用将eBPF程序附加到原始套接字。它设置了`SO_ATTACH_BPF`选项，将eBPF程序的文件描述符传递给该选项，以便内核知道要将哪个eBPF程序应用于这个套接字。如果附加成功，套接字将开始捕获和处理从中接收到的网络数据包。
5. 如果`setsockopt`失败，它将`err`设置为-3，并在标准错误流上输出一条错误信息。

### 编译运行

完整的源代码可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/23-http> 中找到。关于如何安装依赖，请参考：<https://eunomia.dev/tutorials/11-bootstrap/> 编译运行上述代码：

```console
$ git submodule update --init --recursive
$ make
  BPF      .output/sockfilter.bpf.o
  GEN-SKEL .output/sockfilter.skel.h
  CC       .output/sockfilter.o
  BINARY   sockfilter
$ sudo ./sockfilter 
...
```

在另外一个窗口中，使用 python 启动一个简单的 web server：

```console
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [18/Sep/2023 01:05:52] "GET / HTTP/1.1" 200 -
```

可以使用 curl 发起请求：

```c
$ curl http://0.0.0.0:8000/
<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Directory listing for /</title>
....
```

在 eBPF 程序中，可以看到打印出了 HTTP 请求的内容：

```console
127.0.0.1:34552(src) -> 127.0.0.1:8000(dst)
payload: GET / HTTP/1.1
Host: 0.0.0.0:8000
User-Agent: curl/7.88.1
...
127.0.0.1:8000(src) -> 127.0.0.1:34552(dst)
payload: HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.4
...
```

分别包含了请求和响应的内容。

## 使用 eBPF syscall tracepoint 来捕获 HTTP 流量

eBPF 提供了一种强大的机制，允许我们在内核级别追踪系统调用。在这个示例中，我们将使用 eBPF 追踪 accept 和 read 系统调用，以捕获 HTTP 流量。由于篇幅有限，这里我们仅仅对代码框架做简要的介绍。

```c
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct accept_args_t);
} active_accept_args_map SEC(".maps");

// 定义在 accept 系统调用入口的追踪点
SEC("tracepoint/syscalls/sys_enter_accept")
int sys_enter_accept(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    // ... 获取和存储 accept 调用的参数
    bpf_map_update_elem(&active_accept_args_map, &id, &accept_args, BPF_ANY);
    return 0;
}

// 定义在 accept 系统调用退出的追踪点
SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit *ctx)
{
    // ... 处理 accept 调用的结果
    struct accept_args_t *args =
        bpf_map_lookup_elem(&active_accept_args_map, &id);
    // ... 获取和存储 accept 调用获得的 socket 文件描述符
    __u64 pid_fd = ((__u64)pid << 32) | (u32)ret_fd;
    bpf_map_update_elem(&conn_info_map, &pid_fd, &conn_info, BPF_ANY);
    // ...
}

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct data_args_t);
} active_read_args_map SEC(".maps");

// 定义在 read 系统调用入口的追踪点
SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    // ... 获取和存储 read 调用的参数
    bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);
    return 0;
}

// 辅助函数，检查是否为 HTTP 连接
static inline bool is_http_connection(const char *line_buffer, u64 bytes_count)
{
    // ... 检查数据是否为 HTTP 请求或响应
}

// 辅助函数，处理读取的数据
static inline void process_data(struct trace_event_raw_sys_exit *ctx,
                                u64 id, const struct data_args_t *args, u64 bytes_count)
{
    // ... 处理读取的数据，检查是否为 HTTP 流量，并发送事件
    if (is_http_connection(line_buffer, bytes_count))
    {
        // ...
        bpf_probe_read_kernel(&event.msg, read_size, args->buf);
        // ...
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &event, sizeof(struct socket_data_event_t));
    }
}

// 定义在 read 系统调用退出的追踪点
SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    // ... 处理 read 调用的结果
    struct data_args_t *read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
    if (read_args != NULL)
    {
        process_data(ctx, id, read_args, bytes_count);
    }
    // ...
    return 0;
}

char _license[] SEC("license") = "GPL";
```

这段代码简要展示了如何使用eBPF追踪Linux内核中的系统调用来捕获HTTP流量。以下是对代码的hook位置和流程的详细解释，以及需要hook哪些系统调用来实现完整的请求追踪：

### **Hook 位置和流程**

- 该代码使用了eBPF的Tracepoint功能，具体来说，它定义了一系列的eBPF程序，并将它们绑定到了特定的系统调用的Tracepoint上，以捕获这些系统调用的入口和退出事件。

- 首先，它定义了两个eBPF哈希映射（`active_accept_args_map`和`active_read_args_map`）来存储系统调用参数。这些映射用于跟踪`accept`和`read`系统调用。

- 接着，它定义了多个Tracepoint追踪程序，其中包括：
  - `sys_enter_accept`：定义在`accept`系统调用的入口处，用于捕获`accept`系统调用的参数，并将它们存储在哈希映射中。
  - `sys_exit_accept`：定义在`accept`系统调用的退出处，用于处理`accept`系统调用的结果，包括获取和存储新的套接字文件描述符以及建立连接的相关信息。
  - `sys_enter_read`：定义在`read`系统调用的入口处，用于捕获`read`系统调用的参数，并将它们存储在哈希映射中。
  - `sys_exit_read`：定义在`read`系统调用的退出处，用于处理`read`系统调用的结果，包括检查读取的数据是否为HTTP流量，如果是，则发送事件。

- 在`sys_exit_accept`和`sys_exit_read`中，还涉及一些数据处理和事件发送的逻辑，例如检查数据是否为HTTP连接，组装事件数据，并使用`bpf_perf_event_output`将事件发送到用户空间供进一步处理。

### **需要 Hook 的完整系统调用**

要实现完整的HTTP请求追踪，通常需要hook的系统调用包括：

- `socket`：用于捕获套接字创建，以追踪新的连接。
- `bind`：用于获取绑定的端口信息。
- `listen`：用于开始监听连接请求。
- `accept`：用于接受连接请求，获取新的套接字文件描述符。
- `read`：用于捕获接收到的数据，以检查其中是否包含 HTTP 请求。
- `write`：用于捕获发送的数据，以检查其中是否包含 HTTP 响应。

上述代码已经涵盖了`accept`和`read`系统调用的追踪。要完整实现HTTP请求的追踪，还需要hook其他系统调用，并实现相应的逻辑来处理这些系统调用的参数和结果。

完整的源代码可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/23-http> 中找到。

## 总结

在当今复杂的技术环境中，系统的可观测性变得至关重要，特别是在微服务和云原生应用程序的背景下。本文探讨了如何利用eBPF技术来追踪七层协议，以及在这个过程中可能面临的挑战和解决方案。以下是对本文内容的总结：

1. **背景介绍**：
   - 现代应用程序通常由多个微服务和分布式组件组成，因此观测整个系统的行为至关重要。
   - 七层协议（如HTTP、gRPC、MQTT等）提供了深入了解应用程序交互的详细信息，但监控这些协议通常具有挑战性。

2. **eBPF技术的作用**：
   - eBPF允许开发者在不修改或插入应用程序代码的情况下，深入内核层来实时观测和分析系统行为。
   - eBPF技术为监控七层协议提供了一个强大的工具，特别适用于微服务环境。

3. **追踪七层协议**：
   - 本文介绍了如何追踪HTTP等七层协议的挑战，包括协议的复杂性和动态性。
   - 传统的网络监控工具难以应对七层协议的复杂性。

4. **eBPF的应用**：
   - eBPF提供两种主要方法来追踪七层协议：socket filter和syscall trace。
   - 这两种方法可以帮助捕获HTTP等协议的网络请求数据，并分析它们。

5. **eBPF实践教程**：
   - 本文提供了一个实际的eBPF教程，演示如何使用eBPF socket filter或syscall trace来捕获和分析HTTP流量。
   - 教程内容包括开发eBPF程序、使用eBPF工具链和实施HTTP请求的追踪。

通过这篇文章，读者可以获得深入了解如何使用eBPF技术来追踪七层协议，尤其是HTTP流量的知识。这将有助于更好地监控和分析网络流量，从而提高应用程序性能和安全性。如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。

> 原文地址：<https://eunomia.dev/zh/tutorials/23-http/> 转载请注明出处。
