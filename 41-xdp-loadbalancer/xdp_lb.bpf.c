// xdp_lb.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);  // Two backends
    __type(key, __u32);
    __type(value, __u32);    // Backend IPs
} backends SEC(".maps");

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 key = 0;
    static __u32 cnt = 0;
    __u32 *backend_ip = bpf_map_lookup_elem(&backends, &key);

    if (!backend_ip)
        return XDP_PASS;

    cnt = (cnt + 1) % 2;  // Round-robin
    key = cnt;
    backend_ip = bpf_map_lookup_elem(&backends, &key);

    if (backend_ip) {
        iph->daddr = *backend_ip;  // Redirect to the backend IP
        iph->check = 0;  // Needs recomputation in real cases
    }

    return XDP_TX;  // Transmit modified packet back
}

char _license[] SEC("license") = "GPL";
