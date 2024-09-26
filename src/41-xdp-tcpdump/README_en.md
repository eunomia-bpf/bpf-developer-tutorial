# eBPF Tutorial by Example: Capturing TCP Information with XDP

Extended Berkeley Packet Filter (eBPF) is a revolutionary technology in the Linux kernel that allows developers to run sandboxed programs within the kernel space. It enables powerful networking, security, and tracing capabilities without the need to modify the kernel source code or load kernel modules. This tutorial focuses on using eBPF with the Express Data Path (XDP) to capture TCP header information directly from network packets at the earliest point of ingress.

## Capturing TCP Headers with XDP

Capturing network packets is essential for monitoring, debugging, and securing network communications. Traditional tools like `tcpdump` operate in user space and can incur significant overhead. By leveraging eBPF and XDP, we can capture TCP header information directly within the kernel, minimizing overhead and improving performance.

In this tutorial, we'll develop an XDP program that intercepts incoming TCP packets and extracts their header information. We'll store this data in a ring buffer, which a user-space program will read and display in a human-readable format.

### Why Use XDP for Packet Capturing?

XDP is a high-performance data path within the Linux kernel that allows for programmable packet processing at the lowest level of the network stack. By attaching an eBPF program to XDP, we can process packets immediately as they arrive, reducing latency and improving efficiency.

## Kernel eBPF Code Analysis

Let's dive into the kernel-space eBPF code that captures TCP header information.

### Full Kernel Code

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

// Define the ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB buffer
} rb SEC(".maps");

// Helper function to check if the packet is TCP
static bool is_tcp(struct ethhdr *eth, void *data_end)
{
    // Ensure Ethernet header is within bounds
    if ((void *)(eth + 1) > data_end)
        return false;

    // Only handle IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Ensure IP header is within bounds
    if ((void *)(ip + 1) > data_end)
        return false;

    // Check if the protocol is TCP
    if (ip->protocol != IPPROTO_TCP)
        return false;

    return true;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    // Pointers to packet data
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;

    // Check if the packet is a TCP packet
    if (!is_tcp(eth, data_end)) {
        return XDP_PASS;
    }

    // Cast to IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Calculate IP header length
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }

    // Ensure IP header is within packet bounds
    if ((void *)ip + ip_hdr_len > data_end) {
        return XDP_PASS;
    }

    // Parse TCP header
    struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)ip + ip_hdr_len);

    // Ensure TCP header is within packet bounds
    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    // Define the number of bytes you want to capture from the TCP header
    const int tcp_header_bytes = 32;

    // Ensure that the desired number of bytes does not exceed packet bounds
    if ((void *)tcp + tcp_header_bytes > data_end) {
        return XDP_PASS;
    }

    // Reserve space in the ring buffer
    void *ringbuf_space = bpf_ringbuf_reserve(&rb, tcp_header_bytes, 0);
    if (!ringbuf_space) {
        return XDP_PASS;  // If reservation fails, skip processing
    }

    // Copy the TCP header bytes into the ring buffer
    // Using a loop to ensure compliance with eBPF verifier
    for (int i = 0; i < tcp_header_bytes; i++) {
        unsigned char byte = *((unsigned char *)tcp + i);
        ((unsigned char *)ringbuf_space)[i] = byte;
    }

    // Submit the data to the ring buffer
    bpf_ringbuf_submit(ringbuf_space, 0);

    // Optional: Print a debug message
    bpf_printk("Captured TCP header (%d bytes)", tcp_header_bytes);

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
```

### Code Explanation

#### Defining the Ring Buffer Map

We define a ring buffer map named `rb` to pass data from the kernel to user space efficiently.

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB buffer
} rb SEC(".maps");
```

#### Packet Parsing and Validation

The `is_tcp` helper function checks whether the incoming packet is a TCP packet by verifying the Ethernet and IP headers.

```c
static bool is_tcp(struct ethhdr *eth, void *data_end)
{
    // ... (checks omitted for brevity)
}
```

#### Capturing TCP Header Information

In the `xdp_pass` function, we:

1. Parse the Ethernet, IP, and TCP headers.
2. Ensure all headers are within the packet bounds to prevent invalid memory access.
3. Reserve space in the ring buffer to store the TCP header.
4. Copy the TCP header bytes into the ring buffer.
5. Submit the data to the ring buffer for user-space consumption.

```c
// Reserve space in the ring buffer
void *ringbuf_space = bpf_ringbuf_reserve(&rb, tcp_header_bytes, 0);
if (!ringbuf_space) {
    return XDP_PASS;
}

// Copy the TCP header bytes
for (int i = 0; i < tcp_header_bytes; i++) {
    unsigned char byte = *((unsigned char *)tcp + i);
    ((unsigned char *)ringbuf_space)[i] = byte;
}

// Submit to ring buffer
bpf_ringbuf_submit(ringbuf_space, 0);
```

#### Using bpf_printk for Debugging

The `bpf_printk` function logs messages to the kernel's trace pipe, which can be invaluable for debugging.

```c
bpf_printk("Captured TCP header (%d bytes)", tcp_header_bytes);
```

## User-Space Code Analysis

Let's examine the user-space program that reads the captured TCP headers from the ring buffer and displays them.

### Full User-Space Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp-tcpdump.skel.h"  // Generated skeleton header

// Callback function to handle events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    if (data_sz < 20) {  // Minimum TCP header size
        fprintf(stderr, "Received incomplete TCP header\n");
        return 0;
    }

    // Parse the raw TCP header bytes
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
        // Options and padding may follow
    } __attribute__((packed));

    if (data_sz < sizeof(struct tcphdr)) {
        fprintf(stderr, "Data size (%zu) less than TCP header size\n", data_sz);
        return 0;
    }

    struct tcphdr *tcp = (struct tcphdr *)data;

    // Convert fields from network byte order to host byte order
    uint16_t source_port = ntohs(tcp->source);
    uint16_t dest_port = ntohs(tcp->dest);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack_seq = ntohl(tcp->ack_seq);
    uint16_t window = ntohs(tcp->window);

    // Extract flags
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
    printf("  Source Port: %u\n", source_port);
    printf("  Destination Port: %u\n", dest_port);
    printf("  Sequence Number: %u\n", seq);
    printf("  Acknowledgment Number: %u\n", ack_seq);
    printf("  Data Offset: %u\n", tcp->doff);
    printf("  Flags: 0x%02x\n", flags);
    printf("  Window Size: %u\n", window);
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

    /* Open and load BPF application */
    skel = xdp_tcpdump_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = xdp_tcpdump_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach XDP program */
    err = xdp_tcpdump_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach the XDP program to the specified interface */
    skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, ifindex);
    if (!skel->links.xdp_pass)
    {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully attached XDP program to interface %s\n", ifname);

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Start polling ring buffer\n");

    /* Poll the ring buffer */
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

### Code Explanation

#### Handling Ring Buffer Events

The `handle_event` function processes TCP header data received from the ring buffer.

```c
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    // Validate data size
    if (data_sz < 20) {
        fprintf(stderr, "Received incomplete TCP header\n");
        return 0;
    }

    // Parse the TCP header
    // ... (parsing code)
}
```

#### Parsing the TCP Header

We define a local `tcphdr` structure to interpret the raw bytes.

```c
struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    // ... (other fields)
} __attribute__((packed));
```

#### Displaying Captured Information

After parsing, we print the TCP header fields in a readable format.

```c
printf("Captured TCP Header:\n");
printf("  Source Port: %u\n", source_port);
printf("  Destination Port: %u\n", dest_port);
// ... (other fields)
```

#### Setting Up the eBPF Skeleton

We use the generated skeleton `xdp-tcpdump.skel.h` to load and attach the eBPF program.

```c
/* Open and load BPF application */
skel = xdp_tcpdump_bpf__open();
if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
}

/* Load & verify BPF programs */
err = xdp_tcpdump_bpf__load(skel);
if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
    goto cleanup;
}
```

#### Attaching to the Network Interface

We attach the XDP program to the specified network interface by name.

```c
skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, ifindex);
if (!skel->links.xdp_pass) {
    err = -errno;
    fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
    goto cleanup;
}
```

## Compilation and Execution Instructions

### Prerequisites

- A Linux system with a kernel version that supports eBPF and XDP.
- libbpf library installed.
- Compiler with eBPF support (clang).

### Building the Program

Assuming you have cloned the repository from [GitHub](https://github.com/eunomia-bpf/bpf-developer-tutorial), navigate to the `bpf-developer-tutorial/src/41-xdp-tcpdump` directory.

```bash
cd bpf-developer-tutorial/src/41-xdp-tcpdump
make
```

This command compiles both the kernel eBPF code and the user-space application.

### Running the Program

First, identify your network interfaces:

```bash
ifconfig
```

Sample output:

```
wlp0s20f3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255
        ether 00:1a:2b:3c:4d:5e  txqueuelen 1000  (Ethernet)
```

Run the user-space program with the desired network interface:

```bash
sudo ./xdp-tcpdump wlp0s20f3
```

Sample output:

```
Successfully attached XDP program to interface wlp0s20f3
Start polling ring buffer
Captured TCP Header:
  Source Port: 443
  Destination Port: 53500
  Sequence Number: 572012449
  Acknowledgment Number: 380198588
  Data Offset: 8
  Flags: 0x10
  Window Size: 16380
```

### Complete Source Code and Resources

- **Source Code Repository:** [GitHub - bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)
- **Tutorial Website:** [eunomia.dev Tutorials](https://eunomia.dev/tutorials/)

## Summary and Conclusion

In this tutorial, we explored how to use eBPF and XDP to capture TCP header information directly within the Linux kernel. By analyzing both the kernel eBPF code and the user-space application, we learned how to intercept packets, extract essential TCP fields, and communicate this data to user space efficiently using a ring buffer.

This approach offers a high-performance alternative to traditional packet capturing methods, with minimal impact on system resources. It's a powerful technique for network monitoring, security analysis, and debugging.

If you would like to learn more about eBPF, visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or our website at <https://eunomia.dev/tutorials/>.

Happy coding!
