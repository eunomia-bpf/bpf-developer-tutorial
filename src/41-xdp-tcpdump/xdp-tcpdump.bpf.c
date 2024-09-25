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
    // Typically, the TCP header is 20 bytes, but with options, it can be longer
    // Here, we'll capture the first 32 bytes to include possible options
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
        // Accessing each byte safely within bounds
        unsigned char byte = *((unsigned char *)tcp + i);
        ((unsigned char *)ringbuf_space)[i] = byte;
    }

    // Submit the data to the ring buffer
    bpf_ringbuf_submit(ringbuf_space, 0);

    // Optional: Print a debug message (will appear in kernel logs)
    bpf_printk("Captured TCP header (%d bytes)", tcp_header_bytes);

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
