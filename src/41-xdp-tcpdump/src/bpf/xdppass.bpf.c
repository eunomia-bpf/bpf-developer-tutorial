#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

// Define the ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB buffer
} rb SEC(".maps");

// Helper function to check if it is TCP
static int is_tcp(struct ethhdr *eth, void *data_end)
{
    // Check if the packet is large enough to contain Ethernet and IP headers
    if ((void *)(eth + 1) > data_end)
        return 0;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    // Check if it is an IPv4 TCP packet
    if (ip->protocol == IPPROTO_TCP)
        return 1;

    return 0;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int pkt_sz = data_end - data;

    struct ethhdr *eth = data;

    // Filter for TCP packets
    if (is_tcp(eth, data_end)) {
        bpf_printk("TCP packet detected");
		if (pkt_sz > 16000 || pkt_sz <= 0) {
			bpf_printk("Packet size not support, pass: %d", pkt_sz);
			return XDP_PASS;
		}

        // Reserve space in the ring buffer
        void *pkt = bpf_ringbuf_reserve(&rb, 16000, 0);
        if (!pkt) {
            return XDP_PASS;
        }

        // Load the packet bytes using btf_bpf_xdp_load_bytes
        int bytes_loaded = bpf_xdp_load_bytes(ctx, 0, pkt, pkt_sz);
        if (bytes_loaded != pkt_sz) {
            bpf_printk("Failed to load all packet bytes");
            bpf_ringbuf_discard(pkt, 0);
            return XDP_PASS;
        }

        // Submit the packet to the ring buffer
        bpf_ringbuf_submit(pkt, 0);

        bpf_printk("Captured TCP packet size: %d", pkt_sz);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
