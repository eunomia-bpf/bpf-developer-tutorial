// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "afxdp_dump.h"

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define IP_MF 0x2000
#define IP_OFFSET 0x1fff

const volatile __u16 capture_port = 8080;

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, AFXDP_MAX_QUEUES);
	__type(key, __u32);
	__type(value, __u32);
} xsk_map SEC(".maps");

__u64 redirected_packets;

SEC("xdp")
int redirect_udp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *ethernet = data;
	struct iphdr *ip;
	struct udphdr *udp;
	__u32 queue = ctx->rx_queue_index;
	__u32 ip_header_length;
	__u32 ip_length;
	__u32 udp_length;

	if ((void *)(ethernet + 1) > data_end ||
	    ethernet->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	ip = (void *)(ethernet + 1);
	if ((void *)(ip + 1) > data_end || ip->version != 4 ||
	    ip->protocol != IPPROTO_UDP ||
	    ip->ihl < 5 || (bpf_ntohs(ip->frag_off) & (IP_MF | IP_OFFSET)))
		return XDP_PASS;
	ip_header_length = ip->ihl * 4;
	ip_length = bpf_ntohs(ip->tot_len);
	udp = (void *)ip + ip_header_length;
	if (ip_length < ip_header_length + sizeof(*udp) ||
	    (void *)ip + ip_length > data_end ||
	    (void *)(udp + 1) > data_end)
		return XDP_PASS;
	udp_length = bpf_ntohs(udp->len);
	if (udp_length < sizeof(*udp) ||
	    udp_length > ip_length - ip_header_length ||
	    udp->dest != bpf_htons(capture_port))
		return XDP_PASS;
	if (!bpf_map_lookup_elem(&xsk_map, &queue))
		return XDP_PASS;
	__sync_fetch_and_add(&redirected_packets, 1);
	return bpf_redirect_map(&xsk_map, queue, XDP_PASS);
}
