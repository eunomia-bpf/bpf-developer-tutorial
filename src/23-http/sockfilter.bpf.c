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

// Here we keep information on the packets passing through the socket filter
typedef struct protocol_info
{
	__u32 hdr_len;
	__u32 seq;
	__u8 flags;
} protocol_info_t;

#define IP_V6_ADDR_LEN 16

// Struct to keep information on the connections in flight
// s = source, d = destination
// h = high word, l = low word
// used as hashmap key, must be 4 byte aligned?
typedef struct http_connection_info
{
	__u8 s_addr[IP_V6_ADDR_LEN];
	__u8 d_addr[IP_V6_ADDR_LEN];
	__u16 s_port;
	__u16 d_port;
} connection_info_t;

const __u8 ip4ip6_prefix[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

static __always_inline int read_sk_buff(struct __sk_buff *skb, protocol_info_t *tcp, connection_info_t *conn)
{
	// we read the protocol just like here linux/samples/bpf/parse_ldabs.c
	__u16 h_proto;
	bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto, sizeof(h_proto));
	h_proto = __bpf_htons(h_proto);

	__u8 proto = 0;
	// do something similar as linux/samples/bpf/parse_varlen.c
	switch (h_proto)
	{
	case ETH_P_IP:
	{
		__u8 hdr_len;
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

		// we read the ip header linux/samples/bpf/parse_ldabs.c and linux/samples/bpf/tcbpf1_kern.c
		// the level 4 protocol let's us only filter TCP packets, the ip protocol gets us the source
		// and destination IP pairs
		bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), &proto, sizeof(proto));

		__u32 saddr;
		bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), &saddr, sizeof(saddr));
		__u32 daddr;
		bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &daddr, sizeof(daddr));

		__builtin_memcpy(conn->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
		__builtin_memcpy(conn->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
		__builtin_memcpy(conn->s_addr + sizeof(ip4ip6_prefix), &saddr, sizeof(saddr));
		__builtin_memcpy(conn->d_addr + sizeof(ip4ip6_prefix), &daddr, sizeof(daddr));

		tcp->hdr_len = ETH_HLEN + hdr_len;
		break;
	}
	default:
		return 0;
	}

	if (proto != IPPROTO_TCP)
	{
		return 0;
	}

	__u16 port;
	bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, source), &port, sizeof(port));
	conn->s_port = __bpf_htons(port);

	bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, dest), &port, sizeof(port));
	conn->d_port = __bpf_htons(port);

	__u16 seq;
	bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, seq), &seq, sizeof(seq));
	tcp->seq = __bpf_htons(seq);

	__u8 doff;
	bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, ack_seq) + 4, &doff, sizeof(doff)); // read the first byte past __tcphdr->ack_seq, we can't do offsetof bit fields
	doff &= 0xf0;																						 // clean-up res1
	doff >>= 4;																							 // move the upper 4 bits to low
	doff *= 4;																							 // convert to bytes length

	tcp->hdr_len += doff;

	__u8 flags;
	bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, ack_seq) + 4 + 1, &flags, sizeof(flags)); // read the second byte past __tcphdr->doff, again bit fields offsets
	tcp->flags = flags;

	if ((skb->len - tcp->hdr_len) < 0)
	{ // less than 0 is a packet we can't parse
		return 0;
	}

	return 1;
}

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

struct tcp_t
{
	unsigned short src_port; // byte 0
	unsigned short dst_port;
	unsigned int seq_num;	  // byte 4
	unsigned int ack_num;	  // byte 8
	unsigned char offset : 4; // byte 12
	unsigned char reserved : 4;
	unsigned char flag_cwr : 1;
	unsigned char flag_ece : 1;
	unsigned char flag_urg : 1;
	unsigned char flag_ack : 1;
	unsigned char flag_psh : 1;
	unsigned char flag_rst : 1;
	unsigned char flag_syn : 1;
	unsigned char flag_fin : 1;
	unsigned short rcv_wnd;
	unsigned short cksum; // byte 16
	unsigned short urg_ptr;
};

SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
	struct so_event *e;
	__u8 verlen;
	__u16 proto;
	__u32 nhoff = ETH_HLEN;

	bpf_skb_load_bytes(skb, 12, &proto, 2);
	proto = __bpf_ntohs(proto);
	if (proto != ETH_P_IP)
		return 0;

	if (ip_is_fragment(skb, nhoff))
		return 0;
	
	__u8 hdr_len;
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

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &e->ip_proto, 1);

	if (e->ip_proto != IPPROTO_GRE)
	{
		bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->src_addr), 4);
		bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->dst_addr), 4);
	}

	bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
	bpf_skb_load_bytes(skb, nhoff + hdr_len, &(e->ports), 4);
	e->pkt_type = skb->pkt_type;
	e->ifindex = skb->ifindex;

	if (e->ip_proto == IPPROTO_TCP && hdr_len >= sizeof(struct iphdr))
	{
		__u32 tcp_hdr_len = nhoff + hdr_len;
		__u16 tlen;
		__u32 payload_offset = 0;
		__u32 payload_length = 0;

		bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));
		payload_offset = ETH_HLEN + hdr_len + tcp_hdr_len;
		payload_length = tlen - hdr_len - tcp_hdr_len;
		bpf_printk("payload_offset: %d, payload_length: %d\n", payload_offset, payload_length);
		bpf_printk("hdr_len %d\n", hdr_len);
		e->payload_length = payload_length;
		if (payload_length >= 0 && payload_length < MAX_BUF_SIZE) {
			bpf_skb_load_bytes(skb, payload_offset, e->payload, 7);
		}
	}

	bpf_ringbuf_submit(e, 0);

	return skb->len;
}
