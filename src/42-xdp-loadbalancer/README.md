
# eBPF Developer Tutorial: XDP Load Balancer

In this tutorial, we will guide you through the process of implementing a simple XDP (eXpress Data Path) load balancer using eBPF (Extended Berkeley Packet Filter). With just C, libbpf, and no external dependencies, this hands-on guide is perfect for developers interested in harnessing the full power of the Linux kernel to build highly efficient network applications.

## Why XDP?

`XDP` (eXpress Data Path) is a fast, in-kernel networking framework in Linux that allows packet processing at the earliest point in the network stack, right in the network interface card (NIC). This enables ultra-low-latency and high-throughput packet handling, making XDP ideal for tasks like load balancing, DDoS protection, and traffic filtering.

Key Features of XDP

1. **Fast Packet Processing**: XDP handles packets directly at the NIC level, reducing latency and improving performance by avoiding the usual networking stack overhead.
2. **Efficient**: Because it processes packets before they reach the kernel, XDP minimizes CPU usage and handles high traffic loads without slowing down the system.
3. **Customizable with eBPF**: XDP programs are written using eBPF, allowing you to create custom packet-handling logic for specific use cases like dropping, redirecting, or forwarding packets.
4. **Low CPU Overhead**: With support for zero-copy packet forwarding, XDP uses fewer system resources, making it perfect for handling high traffic with minimal CPU load.
5. **Simple Actions**: XDP programs return predefined actions like dropping, passing, or redirecting packets, providing control over how traffic is handled.

Projects That Use XDP

- `Cilium` is an open-source networking tool for cloud-native environments like Kubernetes. It uses XDP to efficiently handle packet filtering and load balancing, improving performance in high-traffic networks.
- `Katran`, developed by Facebook, is a load balancer that uses XDP to handle millions of connections with low CPU usage. It distributes traffic efficiently across servers and is used internally at Facebook for large-scale networking.
- `Cloudflare` uses XDP to protect against DDoS attacks. By filtering out malicious traffic at the NIC level, Cloudflare can drop attack packets before they even reach the kernel, minimizing the impact on their network.

### Why Choose XDP Over Other Methods?

Compared to traditional tools like `iptables` or `tc`, XDP offers:

- **Speed**: It operates directly in the NIC driver, processing packets much faster than traditional methods.
- **Flexibility**: With eBPF, you can write custom packet-handling logic to meet specific needs.
- **Efficiency**: XDP uses fewer resources, making it suitable for environments that need to handle high traffic without overloading the system.

## The Project: Building a Simple Load Balancer

In this project, we will be focusing on building a load balancer using XDP. A load balancer efficiently distributes incoming network traffic across multiple backend servers to prevent any single server from becoming overwhelmed. With the combination of XDP and eBPF, we can build a load balancer that operates at the edge of the Linux networking stack, ensuring high performance even under heavy traffic conditions.

The load balancer we’ll be implementing will:

- Listen for incoming network packets.
- Calculate a hash based on the packet's source IP and port, allowing us to distribute the traffic across multiple backend servers.
- Forward the packet to the appropriate backend server based on the calculated hash.

We'll keep the design simple but powerful, showing you how to leverage eBPF’s capabilities to create a lightweight load balancing solution.

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

Here’s a breakdown of the key sections of the kernel code for your blog:

### 1. **Header Files and Data Structures**

The code begins with necessary header files like `<bpf/bpf_helpers.h>`, `<linux/if_ether.h>`, `<linux/ip.h>`, and more. These headers provide definitions for handling Ethernet frames, IP packets, and BPF helper functions.

The `backend_config` struct is defined to hold the IP and MAC address of backend servers. This will later be used for routing packets based on load balancing logic.

```c
struct backend_config {
    __u32 ip;
    unsigned char mac[ETH_ALEN];
};
```

### 2. **Backend and Load Balancer Configuration**

The code defines an eBPF map named `backends` that stores IP and MAC addresses for two backends. The `BPF_MAP_TYPE_ARRAY` type is used to store backend configuration, with `max_entries` set to 2, indicating the load balancer will route to two backend servers.

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct backend_config);
} backends SEC(".maps");
```

There are also predefined IP addresses and MAC addresses for the client and load balancer:

```c
int client_ip = bpf_htonl(0xa000001);  
unsigned char client_mac[ETH_ALEN] = {0xDE, 0xAD, 0xBE, 0xEF, 0x0, 0x1};
int load_balancer_ip = bpf_htonl(0xa00000a);
unsigned char load_balancer_mac[ETH_ALEN] = {0xDE, 0xAD, 0xBE, 0xEF, 0x0, 0x10};
```

### 3. **Checksum Functions**

The function `iph_csum()` recalculates the IP header checksum after modifying the packet's contents. It's essential to keep the integrity of IP packets when any modification is done to the headers.

```c
static __always_inline __u16 iph_csum(struct iphdr *iph) {
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}
```

### 4. **XDP Program Logic**

The core of the XDP load balancer logic is implemented in the `xdp_load_balancer` function, which is attached to the XDP hook. It processes incoming packets and directs them either to a backend or back to the client.

- **Initial Checks**:
  The function begins by verifying that the packet is an Ethernet frame, then checks if it's an IP packet (IPv4) and if it's using the TCP protocol.

  ```c
  if (eth->h_proto != __constant_htons(ETH_P_IP))
      return XDP_PASS;
  if (iph->protocol != IPPROTO_TCP)
      return XDP_PASS;
  ```

- **Client Packet Handling**:
  If the source IP matches the client IP, the code hashes the IP header using `xxhash32` to determine the appropriate backend (based on the key modulo 2).

  ```c
  if (iph->saddr == client_ip) {
      __u32 key = xxhash32((const char*)iph, sizeof(struct iphdr), 0) % 2;
      struct backend_config *backend = bpf_map_lookup_elem(&backends, &key);
  ```

  The destination IP and MAC are replaced with those of the selected backend, and the packet is forwarded to the backend.

- **Backend Packet Handling**:
  If the packet is from a backend server, the destination is set to the client’s IP and MAC address, ensuring that the backend’s response is directed back to the client.

  ```c
  iph->daddr = client_ip;
  __builtin_memcpy(eth->h_dest, client_mac, ETH_ALEN);
  ```

- **Rewriting IP and MAC Addresses**:
  The source IP and MAC are updated to the load balancer’s values for all outgoing packets, ensuring that the load balancer appears as the source for both client-to-backend and backend-to-client communication.

  ```c
  iph->saddr = load_balancer_ip;
  __builtin_memcpy(eth->h_source, load_balancer_mac, ETH_ALEN);
  ```

- **Recalculate Checksum**:
  After modifying the IP header, the checksum is recalculated using the previously defined `iph_csum()` function.

  ```c
  iph->check = iph_csum(iph);
  ```

- **Final Action**:
  The packet is transmitted using the `XDP_TX` action, which instructs the NIC to send the modified packet.

  ```c
  return XDP_TX;
  ```

### 5. **Conclusion**

This part of the blog could explain how the load balancer ensures traffic is efficiently routed between the client and two backend servers by inspecting the source IP, hashing it for load distribution, and modifying the destination IP and MAC before forwarding the packet. The `XDP_TX` action is key to the high-speed packet handling provided by eBPF in the XDP layer.

This explanation can help readers understand the flow of the packet and the role of each section of the code in managing load balancing across multiple backends.

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

The userspace code provided is responsible for setting up and configuring the XDP load balancer program that runs in the kernel. It accepts command-line arguments, loads the eBPF program, attaches it to a network interface, and updates the backend configurations.

### 1. **Argument Parsing and Backend Setup**

The program expects five command-line arguments: the name of the network interface (`ifname`), the IP addresses and MAC addresses of two backend servers. It then parses the IP addresses using `inet_pton()` and the MAC addresses using the `parse_mac()` function, which ensures that the format of the provided MAC addresses is correct. The parsed backend information is stored in a `backend_config` structure.

### 2. **Loading and Attaching the BPF Program**

The BPF skeleton (generated via `xdp_lb.skel.h`) is used to open and load the XDP program into the kernel. The program then identifies the network interface by converting the interface name into an index using `if_nametoindex()`. Afterward, it attaches the loaded BPF program to this interface using `bpf_program__attach_xdp()`.

### 3. **Configuring Backend Information**

The backend IP and MAC addresses are written to the `backends` BPF map using `bpf_map_update_elem()`. This step ensures that the BPF program has access to the backend configurations, allowing it to route packets to the correct backend servers based on the logic in the kernel code.

### 4. **Program Loop and Cleanup**

The program enters an infinite loop (`while (1) { sleep(1); }`) to keep running, allowing the XDP program to continue functioning. When the user decides to exit by pressing Ctrl+C, the BPF program is detached from the network interface, and resources are cleaned up by calling `xdp_lb_bpf__destroy()`.

In summary, this userspace code is responsible for configuring and managing the lifecycle of the XDP load balancer, making it easy to update backend configurations dynamically and ensuring the load balancer is correctly attached to a network interface.

## The topology of test environment

The topology represents a test environment where a local machine communicates with two backend nodes (h2 and h3) through a load balancer. The local machine is connected to the load balancer via virtual Ethernet pairs (veth0 to veth6), simulating network connections in a controlled environment. Each virtual interface has its own IP and MAC address to represent different entities.

```txt
    +---------------------------+          
    |      Local Machine         |
    |  IP: 10.0.0.1 (veth0)      |
    |  MAC: DE:AD:BE:EF:00:01    |
    +------------+---------------+
             |
             | (veth1)
             |
    +--------+---------------+       
    |    Load Balancer       |
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

The setup can be easily initialized with a script (setup.sh), and removed with a teardown script (teardown.sh).

> If you are interested in this tutorial, please help us create a containerized version of the setup and topology! Currently the setup and teardown are based on the network namespace, it will be more friendly to have a containerized version of the setup and topology.

Setup:

```sh
sudo ./setup.sh
```

Teardown:

```sh
sudo ./teardown.sh
```

### Running the Load Balancer

To run the XDP load balancer, execute the following command, specifying the interface and backends' IP and MAC addresses:

```console
sudo ip netns exec lb ./xdp_lb veth6 10.0.0.2 de:ad:be:ef:00:02 10.0.0.3 de:ad:be:ef:00:03
```

This will configure the load balancer and print the details of the backends:

```console
XDP load balancer configured with backends:
Backend 1 - IP: 10.0.0.2, MAC: de:ad:be:ef:00:02
Backend 2 - IP: 10.0.0.3, MAC: de:ad:be:ef:00:03
Press Ctrl+C to exit...
```

### Testing the Setup

You can test the setup by starting HTTP servers on the two backend namespaces (`h2` and `h3`) and sending requests from the local machine to the load balancer:

Start servers on `h2` and `h3`:

```sh
sudo ip netns exec h2 python3 -m http.server
sudo ip netns exec h3 python3 -m http.server
```

Then, send a request to the load balancer IP:

```sh
curl 10.0.0.10:8000
```

The load balancer will distribute traffic to the backends (`h2` and `h3`) based on the hashing function.

### Monitoring with `bpf_printk`

You can monitor the load balancer's activity by checking the `bpf_printk` logs. The BPF program prints diagnostic messages whenever a packet is processed. You can view these logs using:

```console
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Example output:

```console
<idle>-0       [004] ..s2. 24174.812722: bpf_trace_printk: xdp_load_balancer received packet
<idle>-0       [004] .Ns2. 24174.812729: bpf_trace_printk: Received Source IP: 0xa000001
<idle>-0       [004] .Ns2. 24174.812729: bpf_trace_printk: Received Destination IP: 0xa00000a
<idle>-0       [004] .Ns2. 24174.812731: bpf_trace_printk: Received Source MAC: de:ad:be:ef:0:1
<idle>-0       [004] .Ns2. 24174.812732: bpf_trace_printk: Received Destination MAC: de:ad:be:ef:0:10
<idle>-0       [004] .Ns2. 24174.812732: bpf_trace_printk: Packet from client
<idle>-0       [004] .Ns2. 24174.812734: bpf_trace_printk: Redirecting packet to new IP 0xa000002 from IP 0xa00000a
<idle>-0       [004] .Ns2. 24174.812735: bpf_trace_printk: New Dest MAC: de:ad:be:ef:0:2
<idle>-0       [004] .Ns2. 24174.812735: bpf_trace_printk: New Source MAC: de:ad:be:ef:0:10
```

### Debugging Issues

Some systems may experience packet loss or failure to forward packets due to issues similar to those described in this [blog post](https://fedepaol.github.io/blog/2023/09/11/xdp-ate-my-packets-and-how-i-debugged-it/). You can debug these issues using `bpftrace` to trace XDP errors:

```sh
sudo bpftrace -e 'tracepoint:xdp:xdp_bulk_tx{@redir_errno[-args->err] = count();}'
```

If you see an output like this:

```sh
@redir_errno[6]: 3
```

It indicates errors related to XDP packet forwarding. The error code `6` typically points to a particular forwarding issue that can be further investigated.

### Conclusion

This tutorial demonstrates how to set up a simple XDP load balancer using eBPF, providing efficient traffic distribution across backend servers. For those interested in learning more about eBPF, including more advanced examples and tutorials, please visit our [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) or our website [https://eunomia.dev/tutorials/](https://eunomia.dev/tutorials/).

### References

Here’s a simple list of XDP references:

1. [XDP Programming Hands-On Tutorial](https://github.com/xdp-project/xdp-tutorial)
2. [XDP Tutorial in bpf-developer-tutorial](https://eunomia.dev/tutorials/21-xdp/)
