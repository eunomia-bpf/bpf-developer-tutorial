// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "sockfilter.h"

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define IP_TCP 6
#define ETH_HLEN 14

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Taken from uapi/linux/tcp.h
struct __tcphdr
{
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

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
	doff &= 0xf0;																						// clean-up res1
	doff >>= 4;																							// move the upper 4 bits to low
	doff *= 4;																							// convert to bytes length

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
