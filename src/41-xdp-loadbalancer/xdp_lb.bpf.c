// xdp_lb.bpf.c
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

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

static __always_inline __u16 csum_reduce_helper(__u32 csum)
{
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);

	return csum;
}

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    bpf_printk("xdp_load_balancer received packet\n");

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
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Round-robin between two backends
    static __u32 key = 0;
    struct backend_config *backend = bpf_map_lookup_elem(&backends, &key);

    if (!backend)
        return XDP_PASS;

    // Update Ethernet source MAC address to the backend's MAC
    // So the backend can reply directly to the load balancer
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    // Update Ethernet destination MAC address to the backend's MAC
    __builtin_memcpy(eth->h_dest, backend->mac, ETH_ALEN);

    // // Update IP destination address to the backend's IP
    iph->daddr = backend->ip;

    // // Update IP source address (if needed, for example, to load balancer IP)
    // // iph->saddr = bpf_htonl(YOUR_LB_IP_HERE);

    // // Recalculate IP checksum
	iph->check = ~csum_reduce_helper(bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(struct iphdr), 0));

    bpf_printk("Redirecting packet to backend %u, IP: 0x%x\n", key, bpf_ntohl(backend->ip));

    // Return XDP_TX to transmit the modified packet back to the network
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
