# L7 Tracing with eBPF: HTTP and Beyond via Socket Filters and Syscall Tracepoints

In today's technology landscape, with the rise of microservices, cloud-native applications, and complex distributed systems, observability of systems has become a crucial factor in ensuring their health, performance, and security. Especially in a microservices architecture, application components may be distributed across multiple containers and servers, making traditional monitoring methods often insufficient to provide the depth and breadth needed to fully understand the behavior of the system. This is where observing seven-layer protocols such as HTTP, gRPC, MQTT, and more becomes particularly important.

Seven-layer protocols provide detailed insights into how applications interact with other services and components. In a microservices environment, understanding these interactions is vital, as they often serve as the root causes of performance bottlenecks, failures, and security issues. However, monitoring these protocols is not a straightforward task. Traditional network monitoring tools like tcpdump, while effective at capturing network traffic, often fall short when dealing with the complexity and dynamism of seven-layer protocols.

This is where eBPF (extended Berkeley Packet Filter) technology comes into play. eBPF allows developers and operators to delve deep into the kernel layer, observing and analyzing system behavior in real-time without the need to modify or insert instrumentation into application code. This presents a unique opportunity to handle application layer traffic more simply and efficiently, particularly in microservices environments.

In this tutorial, we will delve into the following:

- Tracking seven-layer protocols such as HTTP and the challenges associated with them.
- eBPF's socket filter and syscall tracing: How these two technologies assist in tracing HTTP network request data at different kernel layers, and the advantages and limitations of each.
- eBPF practical tutorial: How to develop an eBPF program and utilize eBPF socket filter or syscall tracing to capture and analyze HTTP traffic.

As network traffic increases and applications grow in complexity, gaining a deeper understanding of seven-layer protocols becomes increasingly important. Through this tutorial, you will acquire the necessary knowledge and tools to more effectively monitor and analyze your network traffic, ultimately enhancing the performance of your applications and servers.

This article is part of the eBPF Developer Tutorial, and for more detailed content, you can visit [here](https://eunomia.dev/tutorials/). The source code is available on the [GitHub repository](https://github.com/eunomia-bpf/bpf-developer-tutorial).

## Challenges in Tracking HTTP, HTTP/2, and Other Seven-Layer Protocols

In the modern networking environment, seven-layer protocols extend beyond just HTTP. In fact, there are many seven-layer protocols such as HTTP/2, gRPC, MQTT, WebSocket, AMQP, and SMTP, each serving critical roles in various application scenarios. These protocols provide detailed insights into how applications interact with other services and components. However, tracking these protocols is not a simple task, especially within complex distributed systems.

1. **Diversity and Complexity**: Each seven-layer protocol has its specific design and workings. For example, gRPC utilizes HTTP/2 as its transport protocol and supports multiple languages, while MQTT is a lightweight publish/subscribe messaging transport protocol designed for low-bandwidth and unreliable networks.

2. **Dynamism**: Many seven-layer protocols are dynamic, meaning their behavior can change based on network conditions, application requirements, or other factors.

3. **Encryption and Security**: With increased security awareness, many seven-layer protocols employ encryption technologies such as TLS/SSL. This introduces additional challenges for tracking and analysis, as decrypting traffic is required for in-depth examination.

4. **High-Performance Requirements**: In high-traffic production environments, capturing and analyzing traffic for seven-layer protocols can impact system performance. Traditional network monitoring tools may struggle to handle a large number of concurrent sessions.

5. **Data Completeness and Continuity**: Unlike tools like tcpdump, which capture individual packets, tracking seven-layer protocols requires capturing complete sessions, which may involve multiple packets. This necessitates tools capable of correctly reassembling and parsing these packets to provide a continuous session view.

6. **Code Intrusiveness**: To gain deeper insights into the behavior of seven-layer protocols, developers may need to modify application code to add monitoring functionalities. This not only increases development and maintenance complexity but can also impact application performance.

As mentioned earlier, eBPF provides a powerful solution, allowing us to capture and analyze seven-layer protocol traffic in the kernel layer without modifying application code. This approach not only offers insights into system behavior but also ensures optimal performance and efficiency. This is why eBPF has become the preferred technology for modern observability tools, especially in production environments that demand high performance and low latency.

## eBPF Socket Filter vs. Syscall Tracing: In-Depth Analysis and Comparison

### **eBPF Socket Filter**

**What Is It?**
eBPF socket filter is an extension of the classic Berkeley Packet Filter (BPF) that allows for more advanced packet filtering directly within the kernel. It operates at the socket layer, enabling fine-grained control over which packets are processed by user-space applications.

**Key Features:**

- **Performance**: By handling packets directly within the kernel, eBPF socket filters reduce the overhead of context switches between user and kernel spaces.
- **Flexibility**: eBPF socket filters can be attached to any socket, providing a universal packet filtering mechanism for various protocols and socket types.
- **Programmability**: Developers can write custom eBPF programs to define complex filtering logic beyond simple packet matching.

**Use Cases:**

- **Traffic Control**: Restrict or prioritize traffic based on custom conditions.
- **Security**: Discard malicious packets before they reach user-space applications.
- **Monitoring**: Capture specific packets for analysis without affecting other traffic.

### **eBPF Syscall Tracing**

**What Is It?**
System call tracing using eBPF allows monitoring and manipulation of system calls made by applications. System calls are the primary mechanism through which user-space applications interact with the kernel, making tracing them a valuable way to understand application behavior.

**Key Features:**

- **Granularity**: eBPF allows tracing specific system calls, even specific parameters within those system calls.
- **Low Overhead**: Compared to other tracing methods, eBPF syscall tracing is designed to have minimal performance impact.
- **Security**: Kernel validates eBPF programs to ensure they do not compromise system stability.

**How It Works:**
eBPF syscall tracing typically involves attaching eBPF programs to tracepoints or kprobes related to the system calls being traced. When the traced system call is invoked, the eBPF program is executed, allowing data collection or even modification of system call parameters.

### Comparison of eBPF Socket Filter and Syscall Tracing

| Aspect | eBPF Socket Filter | eBPF Syscall Tracing |
| ------ | ------------------- | --------------------- |
| **Operational Layer** | Socket layer, primarily dealing with network packets received from or sent to sockets. | System call layer, monitoring and potentially altering the behavior of system calls made by applications. |
| **Primary Use Cases** | Mainly used for filtering, monitoring, and manipulation of network packets. | Used for performance analysis, security monitoring, and debugging of interactions with the network. |
| **Granularity** | Focuses on individual network packets. | Can monitor a wide range of system activities, including those unrelated to networking. |
| **Tracking HTTP Traffic** | Can be used to filter and capture HTTP packets passed through sockets. | Can trace system calls associated with networking operations, which may include HTTP traffic. |

In summary, both eBPF socket filters and syscall tracing can be used to trace HTTP traffic, but socket filters are more direct and suitable for this purpose. However, if you are interested in the broader context of how an application interacts with the system (e.g., which system calls lead to HTTP traffic), syscall tracing can be highly valuable. In many advanced observability setups, both tools may be used simultaneously to provide a comprehensive view of system and network behavior.

## Capturing HTTP Traffic with eBPF Socket Filter

eBPF code consists of user-space and kernel-space components, and here we primarily focus on the kernel-space code. Below is the main logic for capturing HTTP traffic in the kernel using eBPF socket filter technology, and the complete code is provided:

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

When analyzing this eBPF program, we will explain it in detail according to the content of each code block and provide relevant background knowledge:

```c
SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
    // ...
}
```

This is the entry point of the eBPF program, defining a function named `socket_handler` that the kernel uses to handle incoming network packets. This function is located in an eBPF section named `socket`, indicating that it is intended for socket handling.

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

In this code block, several variables are defined to store information needed during packet processing. These variables include `struct so_event *e` for storing event information, `verlen`, `proto`, `nhoff`, `ip_proto`, `tcp_hdr_len`, `tlen`, `payload_offset`, `payload_length`, and `hdr_len` for storing packet information.

- `struct so_event *e;`: This is a pointer to the `so_event` structure for storing captured event information. The specific definition of this structure is located elsewhere in the program.
- `__u8 verlen;`, `__u16 proto;`, `__u32 nhoff = ETH_HLEN;`: These variables are used to store various pieces of information, such as protocol types, packet offsets, etc. `nhoff` is initialized to the length of the Ethernet frame header, typically 14 bytes, as Ethernet frame headers include destination MAC address, source MAC address, and frame type fields.
- `__u32 ip_proto = 0;`: This variable is used to store the type of the IP protocol and is initialized to 0.
- `__u32 tcp_hdr_len = 0;`: This variable is used to store the length of the TCP header and is initialized to 0.
- `__u16 tlen;`: This variable is used to store the total length of the IP packet.
- `__u32 payload_offset = 0;`, `__u32 payload_length = 0;`: These two variables are used to store the offset and length of the HTTP request payload.
- `__u8 hdr_len;`: This variable is used to store the length of the IP header.

```c
bpf_skb_load_bytes(skb, 12, &proto, 2);
proto = __bpf_ntohs(proto);
if (proto != ETH_P_IP)
    return 0;
```

Here, the code loads the Ethernet frame type field from the packet, which tells us the network layer protocol being used in the packet. It then uses the `__bpf_ntohs` function to convert the network byte order type field into host byte order. Next, the code checks if the type field is not equal to the Ethernet frame type for IPv4 (0x0800). If it's not equal, it means the packet is not an IPv4 packet, and the function returns 0, indicating that the packet should not be processed.

Key concepts to understand here:

- Ethernet Frame: The Ethernet frame is a data link layer (Layer 2) protocol used for transmitting data frames within a local area network (LAN). Ethernet frames typically include destination MAC address, source MAC address, and frame type fields.
- Network Byte Order: Network protocols often use big-endian byte order to represent data. Therefore, data received from the network needs to be converted into host byte order for proper interpretation on the host. Here, the type field from the network is converted to host byte order for further processing.
- IPv4 Frame Type (ETH_P_IP): This represents the frame type field in the Ethernet frame, where 0x0800 indicates IPv4.

```c
if (ip_is_fragment(skb, nhoff))
    return 0;
```

This part of the code checks if IP fragmentation is being handled. IP fragmentation is a mechanism for splitting larger IP packets into multiple smaller fragments for transmission. Here, if the packet is an IP fragment, the function returns 0, indicating that only complete packets will be processed.

```c
static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
    __u16 frag_off;

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
    frag_off = __bpf_ntohs(frag_off);
    return frag_off & (IP_MF | IP_OFFSET);
}
```

The above code is a helper function used to check if the incoming IPv4 packet is an IP fragment. IP fragmentation is a mechanism where, if the size of an IP packet exceeds the Maximum Transmission Unit (MTU) of the network, routers split it into smaller fragments for transmission across the network. The purpose of this function is to examine the fragment flags and fragment offset fields within the packet to determine if it is a fragment.

Here's an explanation of the code line by line:

1. `__u16 frag_off;`: Defines a 16-bit unsigned integer variable `frag_off` to store the fragment offset field.
2. `bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);`: This line of code uses the `bpf_skb_load_bytes` function to load the fragment offset field from the packet. `nhoff` is the offset of the IP header within the packet, and `offsetof(struct iphdr, frag_off)` calculates the offset of the fragment offset field within the IPv4 header.
3. `frag_off = __bpf_ntohs(frag_off);`: Converts the loaded fragment offset field from network byte order (big-endian) to host byte order. Network protocols typically use big-endian to represent data, and the conversion to host byte order is done for further processing.
4. `return frag_off & (IP_MF | IP_OFFSET);`: This line of code checks the value of the fragment offset field using a bitwise AND operation with two flag values:
   - `IP_MF`: Represents the "More Fragments" flag. If this flag is set to 1, it indicates that the packet is part of a fragmented sequence and more fragments are expected.
   - `IP_OFFSET`: Represents the fragment offset field. If the fragment offset field is non-zero, it indicates that the packet is part of a fragmented sequence and has a fragment offset value.
   If either of these flags is set to 1, the result is non-zero, indicating that the packet is an IP fragment. If both flags are 0, it means the packet is not fragmented.

It's important to note that the fragment offset field in the IP header is specified in units of 8 bytes, so the actual byte offset is obtained by left-shifting the value by 3 bits. Additionally, the "More Fragments" flag (IP_MF) in the IP header indicates whether there are more fragments in the sequence and is typically used in conjunction with the fragment offset field to indicate the status of fragmented packets.

```c
bpf_skb_load_bytes(skb, ETH_HLEN, &

hdr_len, sizeof(hdr_len));
hdr_len &= 0x0f;
hdr_len *= 4;
```

In this part of the code, the length of the IP header is loaded from the packet. The IP header length field contains information about the length of the IP header in units of 4 bytes, and it needs to be converted to bytes. Here, it is converted by performing a bitwise AND operation with 0x0f and then multiplying it by 4.

Key concept:

- IP Header: The IP header contains fundamental information about a packet, such as the source IP address, destination IP address, protocol type, total length, identification, flags, fragment offset, time to live (TTL), checksum, source port, and destination port.

```c
if (hdr_len < sizeof(struct iphdr))
{
    return 0;
}
```

This code segment checks if the length of the IP header meets the minimum length requirement, typically 20 bytes. If the length of the IP header is less than 20 bytes, it indicates an incomplete or corrupted packet, and the function returns 0, indicating that the packet should not be processed.

Key concept:

- `struct iphdr`: This is a structure defined in the Linux kernel, representing the format of an IPv4 header. It includes fields such as version, header length, service type, total length, identification, flags, fragment offset, time to live, protocol, header checksum, source IP address, and destination IP address, among others.

```c
bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &ip_proto, 1);
if (ip_proto != IPPROTO_TCP)
{
    return 0;
}
```

Here, the code loads the protocol field from the IP header to determine the transport layer protocol used in the packet. Then, it checks if the protocol field is not equal to the value for TCP (IPPROTO_TCP). If it's not TCP, it means the packet is not an HTTP request or response, and the function returns 0.

Key concept:

- Transport Layer Protocol: The protocol field in the IP header indicates the transport layer protocol used in the packet, such as TCP, UDP, or ICMP.

```c
tcp_hdr_len = nhoff + hdr_len;
```

This line of code calculates the offset of the TCP header. It adds the length of the Ethernet frame header (`nhoff`) to the length of the IP header (`hdr_len`) to obtain the starting position of the TCP header.

```c
bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
```

This line of code loads the first byte of the TCP header from the packet, which contains information about the TCP header length. This length field is specified in units of 4 bytes and requires further conversion.

```c
bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));
```

This line of code loads the total length field of the IP header from the packet. The IP header's total length field represents the overall length of the IP packet, including both the IP header and the data portion.

```c
__u8 doff;
bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct __tcphdr, ack_seq) + 4, &doff, sizeof(doff));
doff &= 0xf0;
doff >>= 4;
doff *= 4;
```

This piece of code is used to calculate the length of the TCP header. It loads the Data Offset field (also known as the Header Length field) from the TCP header, which represents the length of the TCP header in units of 4 bytes. The code clears the high four bits of the offset field, then shifts it right by 4 bits, and finally multiplies it by 4 to obtain the actual length of the TCP header.

Key points to understand:

- TCP Header: The TCP header contains information related to the TCP protocol, such as source port, destination port, sequence number, acknowledgment number, flags (e.g., SYN, ACK, FIN), window size, and checksum.

```c
payload_offset = ETH_HLEN + hdr_len + doff;
payload_length = __bpf_ntohs(tlen) - hdr_len - doff;
```

These two lines of code calculate the offset and length of the HTTP request payload. They add the lengths of the Ethernet frame header, IP header, and TCP header together to obtain the offset to the data portion of the HTTP request. Then, by subtracting the total length, IP header length, and TCP header length from the total length field, they calculate the length of the HTTP request data.

Key point:

- HTTP Request Payload: The actual data portion included in an HTTP request, typically consisting of the HTTP request headers and request body.

```c
char line_buffer[7];
if (payload_length < 7 || payload_offset < 0)
{
    return 0;
}
bpf_skb_load_bytes(skb, payload_offset, line_buffer, 7);
bpf_printk("%d len %d buffer: %s", payload_offset, payload_length, line_buffer);
```

This portion of the code loads the first 7 bytes of the HTTP request line and stores them in a character array named `line_buffer`. It then checks if the length of the HTTP request data is less than 7 bytes or if the offset is negative. If these conditions are met, it indicates an incomplete HTTP request, and the function returns 0. Finally, it uses the `bpf_printk` function to print the content of the HTTP request line to the kernel log for debugging and analysis.

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

> Note: The `bpf_strncmp` function is a helper function available from kernel version 5.17. For earlier versions, you can manually write a function to compare strings.

This piece of code uses the `bpf_strncmp` function to compare the data in `line_buffer` with HTTP request methods (GET, POST, PUT, DELETE, HTTP). If there is no match, indicating that it is not an HTTP request, it returns 0, indicating that it should not be processed.

```c
e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
if (!e)
    return 0;
```

This section of the code attempts to reserve a block of memory from the BPF ring buffer to store event information. If it cannot reserve the memory block, it returns 0. The BPF ring buffer is used to pass event data between the eBPF program and user space.

Key point:

- BPF Ring Buffer: The BPF ring buffer is a mechanism for passing data between eBPF programs and user space. It can be used to store event information for further processing or analysis by user space applications.

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

Finally, this code segment stores the captured event information in the `e` structure and submits it to the BPF ring buffer. It includes information such as the captured IP protocol, source and destination ports, packet type, interface index, payload length, source IP address, and destination IP address. Finally, it returns the length of the packet, indicating that the packet was successfully processed.

This code is primarily used to store captured event information for further processing. The BPF ring buffer is used to pass this information to user space for additional handling or logging.

In summary, this eBPF program's main task is to capture HTTP requests. It accomplishes this by parsing the Ethernet frame, IP header, and TCP header of incoming packets to determine if they contain HTTP requests. Information about the requests is then stored in the `so_event` structure and submitted to the BPF ring buffer. This is an efficient method for capturing HTTP traffic at the kernel level and is suitable for applications such as network monitoring and security analysis.

### Potential Limitations

The above code has some potential limitations, and one of the main limitations is that it cannot handle URLs that span multiple packets.

- Cross-Packet URLs: The code checks the URL in an HTTP request by parsing a single data packet. If the URL of an HTTP request spans multiple packets, it will only examine the URL in the first packet. This can lead to missing or partially capturing long URLs that span multiple data packets.

To address this issue, a solution often involves reassembling multiple packets to reconstruct the complete HTTP request. This may require implementing packet caching and assembly logic within the eBPF program and waiting to collect all relevant packets until the HTTP request is detected. This adds complexity and may require additional memory to handle cases where URLs span multiple packets.

### User-Space Code

The user-space code's main purpose is to create a raw socket and then attach the previously defined eBPF program in the kernel to that socket, allowing the eBPF program to capture and process network packets received on that socket. Here's an example of the user-space code:

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

1. `sock = open_raw_sock(interface);`: This line of code calls a custom function `open_raw_sock`, which is used to create a raw socket. Raw sockets allow a user-space application to handle network packets directly without going through the protocol stack. The `interface` parameter might specify the network interface from which to receive packets, determining where to capture packets from. If creating the socket fails, it returns a negative value, otherwise, it returns the file descriptor of the socket `sock`.
2. If the value of `sock` is less than 0, indicating a failure to open the raw socket, it sets `err` to -2 and prints an error message on the standard error stream.
3. `prog_fd = bpf_program__fd(skel->progs.socket_handler);`: This line of code retrieves the file descriptor of the socket filter program (`socket_handler`) previously defined in the eBPF program. It is necessary to attach this program to the socket. `skel` is a pointer to an eBPF program object, and it provides access to the program collection.
4. `setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))`: This line of code uses the `setsockopt` system call to attach the eBPF program to the raw socket. It sets the `SO_ATTACH_BPF` option and passes the file descriptor of the eBPF program to the option, letting the kernel know which eBPF program to apply to this socket. If the attachment is successful, the socket starts capturing and processing network packets received on it.
5. If `setsockopt` fails, it sets `err` to -3 and prints an error message on the standard error stream.

### Compilation and Execution

The complete source code can be found at <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/23-http>. To compile and run the code:

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

In another terminal, start a simple web server using Python:

```console
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [18/Sep/2023 01:05:52] "GET / HTTP/1.1" 200 -
```

You can use `curl` to make requests:

```c
$ curl http://0.0.0.0:8000/
<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Directory listing for /</title>
....
```

In the eBPF program, you can see that it prints the content of HTTP requests:

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

It captures both request and response content.

## Capturing HTTP Traffic Using eBPF Syscall Tracepoints

eBPF provides a powerful mechanism for tracing system calls at the kernel level. In this example, we'll use eBPF to trace the `accept` and `read` system calls to capture HTTP traffic. Due to space limitations, we'll provide a brief overview of the code framework.

```c
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct accept_args_t);
} active_accept_args_map SEC(".maps");

// Define a tracepoint at the entry of the accept system call
SEC("tracepoint/syscalls/sys_enter_accept")
int sys_enter_accept(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    // ... Get and store the arguments of the accept call
    bpf_map_update_elem(&active_accept_args_map, &id, &accept_args, BPF_ANY);
    return 0;
}

// Define a tracepoint at the exit of the accept system call
SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit *ctx)
{
    // ... Process the result of the accept call
    struct accept_args_t *args =
        bpf_map_lookup_elem(&active_accept_args_map, &id);
    // ... Get and store the socket file descriptor obtained from the accept call
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

// Define a tracepoint at the entry of the read system call
SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    // ... Get and store the arguments of the read call
    bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);
    return 0;
}

// Helper function to check if it's an HTTP connection
static inline bool is_http_connection(const char *line_buffer, u64 bytes_count)
{
    // ... Check if the data is an HTTP request or response
}

// Helper function to process the read data
static inline void process_data(struct trace_event_raw_sys_exit *ctx,
                                u64 id, const struct data_args_t *args, u64 bytes_count)
{
    // ... Process the read data, check if it's HTTP traffic, and send events
    if (is_http_connection(line_buffer, bytes_count))
    {
        // ...
        bpf_probe_read_kernel(&event.msg, read_size, args->buf);
        // ...
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &event, sizeof(struct socket_data_event_t));
    }
}

// Define a tracepoint at the exit of the read system call
SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    // ... Process the result of the read call
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

This code briefly demonstrates how to use eBPF to trace system calls in the Linux kernel to capture HTTP traffic. Here's a detailed explanation of the hook locations and the flow, as well as the complete set of system calls that need to be hooked for comprehensive request tracing:

### Hook Locations and Flow

- The code uses eBPF Tracepoint functionality. Specifically, it defines a series of eBPF programs and binds them to specific system call Tracepoints to capture entry and exit events of these system calls.

- First, it defines two eBPF hash maps (`active_accept_args_map` and `active_read_args_map`) to store system call parameters. These maps are used to track `accept` and `read` system calls.

- Next, it defines multiple Tracepoint tracing programs, including:
  - `sys_enter_accept`: Defined at the entry of the `accept` system call, used to capture the arguments of the `accept` system call and store them in the hash map.
  - `sys_exit_accept`: Defined at the exit of the `accept` system call, used to process the result of the `accept` system call, including obtaining and storing the new socket file descriptor and related connection information.
  - `sys_enter_read`: Defined at the entry of the `read` system call, used to capture the arguments of the `read` system call and store them in the hash map.
  - `sys_exit_read`: Defined at the exit of the `read` system call, used to process the result of the `read` system call, including checking if the read data is HTTP traffic and sending events.

- In `sys_exit_accept` and `sys_exit_read`, there is also some data processing and event sending logic, such as checking if the data is an HTTP connection, assembling event data, and using `bpf_perf_event_output` to send events to user space for further processing.

### Complete Set of System Calls to Hook

To fully implement HTTP request tracing, the system calls that typically need to be hooked include:

- `socket`: Used to capture socket creation for tracking new connections.
- `bind`: Used to obtain port information where the socket is bound.
- `listen`: Used to start listening for connection requests.
- `accept`: Used to accept connection requests and obtain new socket file descriptors.
- `read`: Used to capture received data and check if it contains HTTP requests.
- `write`: Used to capture sent data and check if it contains HTTP responses.

The provided code already covers the tracing of `accept` and `read` system calls. To complete HTTP request tracing, additional system calls need to be hooked, and corresponding logic needs to be implemented to handle the parameters and results of these system calls.

The complete source code can be found at <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/23-http>.

## Summary

In today's complex technological landscape, system observability has become crucial, especially in the context of microservices and cloud-native applications. This article explores how to leverage eBPF technology for tracing the seven-layer protocols, along with the challenges and solutions that may arise in this process. Here's a summary of the content covered in this article:

1. **Introduction**:
   - Modern applications often consist of multiple microservices and distributed components, making it essential to observe the behavior of the entire system.
   - Seven-layer protocols (such as HTTP, gRPC, MQTT, etc.) provide detailed insights into application interactions, but monitoring these protocols can be challenging.

2. **Role of eBPF Technology**:
   - eBPF allows developers to dive deep into the kernel layer for real-time observation and analysis of system behavior without modifying or inserting application code.
   - eBPF technology offers a powerful tool for monitoring seven-layer protocols, especially in a microservices environment.

3. **Tracing Seven-Layer Protocols**:
   - The article discusses the challenges of tracing seven-layer protocols, including their complexity and dynamism.
   - Traditional network monitoring tools struggle with the complexity of seven-layer protocols.

4. **Applications of eBPF**:
   - eBPF provides two primary methods for tracing seven-layer protocols: socket filters and syscall tracing.
   - Both of these methods help capture network request data for protocols like HTTP and analyze them.

5. **eBPF Practical Tutorial**:
   - The article provides a practical eBPF tutorial demonstrating how to capture and analyze HTTP traffic using eBPF socket filters or syscall tracing.
   - The tutorial covers the development of eBPF programs, the use of the eBPF toolchain, and the implementation of HTTP request tracing.

Through this article, readers can gain a deep understanding of how to use eBPF technology for tracing seven-layer protocols, particularly HTTP traffic. This knowledge will help enhance the monitoring and analysis of network traffic, thereby improving application performance and security. If you're interested in learning more about eBPF and its practical applications, you can visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or our website at <https://eunomia.dev/tutorials/> for more examples and complete tutorials.

> The original link of this article: <https://eunomia.dev/tutorials/23-http>
