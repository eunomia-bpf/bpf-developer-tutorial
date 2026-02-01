// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 eunomia-bpf
//
// Demonstrates BPF dynptrs with TC ingress:
// - bpf_dynptr_from_skb() to create skb dynptr (kfunc, v6.4+)
// - bpf_dynptr_slice() to parse packet headers safely
// - bpf_ringbuf_reserve_dynptr() for variable-length ringbuf records
// - bpf_dynptr_read/write() for data copying

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* __BPF__ is auto-defined by clang when targeting BPF */
#include "dynptr_tc.h"

/* Constants not in vmlinux.h */
#define TC_ACT_OK       0
#define TC_ACT_SHOT     2
#define ETH_P_IP        0x0800

/* kfunc: bpf_dynptr_from_skb (v6.4+) */
extern int bpf_dynptr_from_skb(struct __sk_buff *s, __u64 flags,
                               struct bpf_dynptr *ptr__uninit) __ksym;

/* kfunc: bpf_dynptr_slice */
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, __u32 offset,
                              void *buffer__opt, __u32 buffer__sz) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16MB ringbuf */
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dynptr_cfg);
} cfg_map SEC(".maps");

static __always_inline const struct dynptr_cfg *get_cfg(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&cfg_map, &key);
}

SEC("tc")
int dynptr_tc_ingress(struct __sk_buff *ctx)
{
    const struct dynptr_cfg *cfg = get_cfg();
    struct bpf_dynptr skb_ptr;
    __u32 pkt_len = ctx->len;

    /* Temporary buffers for slice (data may be copied here) */
    struct ethhdr eth_buf;
    struct iphdr  ip_buf;
    struct tcphdr tcp_buf;

    const struct ethhdr *eth;
    const struct iphdr  *iph;
    const struct tcphdr *tcp;

    __u32 ip_off, tcp_off, payload_off;
    __u32 ip_hdr_len, tcp_hdr_len;

    __u16 sport, dport;
    __u8  drop = 0;
    int   act = TC_ACT_OK;

    if (!cfg)
        return TC_ACT_OK;

    /* Create dynptr from skb using kfunc */
    if (bpf_dynptr_from_skb(ctx, 0, &skb_ptr))
        return TC_ACT_OK;

    /* Parse Ethernet header using dynptr_slice */
    eth = bpf_dynptr_slice(&skb_ptr, 0, &eth_buf, sizeof(eth_buf));
    if (!eth)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* Parse IPv4 header */
    ip_off = sizeof(*eth);
    iph = bpf_dynptr_slice(&skb_ptr, ip_off, &ip_buf, sizeof(ip_buf));
    if (!iph)
        return TC_ACT_OK;

    if (iph->version != 4)
        return TC_ACT_OK;

    ip_hdr_len = (__u32)iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > 60)
        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    /* Parse TCP header */
    tcp_off = ip_off + ip_hdr_len;
    tcp = bpf_dynptr_slice(&skb_ptr, tcp_off, &tcp_buf, sizeof(tcp_buf));
    if (!tcp)
        return TC_ACT_OK;

    tcp_hdr_len = (__u32)tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || tcp_hdr_len > 60)
        return TC_ACT_OK;

    sport = bpf_ntohs(tcp->source);
    dport = bpf_ntohs(tcp->dest);

    /* Simple policy: drop packets to/from specified port
     * Check both sport and dport to work on both ingress and egress */
    if (cfg->blocked_port && (sport == cfg->blocked_port || dport == cfg->blocked_port)) {
        drop = 1;
        act = TC_ACT_SHOT;
    }

    /* Output event to ringbuf using dynptr record (variable length) */
    if (cfg->enable_ringbuf) {
        __u32 snap_len = cfg->snap_len;
        __u8  payload[MAX_SNAPLEN] = {};
        long  err;

        if (snap_len > MAX_SNAPLEN)
            snap_len = MAX_SNAPLEN;

        payload_off = tcp_off + tcp_hdr_len;

        /* Calculate available payload length */
        if (payload_off >= pkt_len) {
            snap_len = 0;
        } else {
            __u32 avail = pkt_len - payload_off;
            if (avail < snap_len)
                snap_len = avail;
        }

        /* Read payload from skb dynptr */
        if (snap_len) {
            err = bpf_dynptr_read(payload, snap_len, &skb_ptr, payload_off, 0);
            if (err)
                snap_len = 0;
        }

        /* Build event header */
        struct event_hdr hdr = {};
        hdr.ts_ns   = bpf_ktime_get_ns();
        hdr.ifindex = ctx->ifindex;
        hdr.pkt_len = pkt_len;
        hdr.saddr   = iph->saddr;
        hdr.daddr   = iph->daddr;
        hdr.sport   = sport;
        hdr.dport   = dport;
        hdr.drop    = drop;
        hdr.snap_len = (__u16)snap_len;

        /* Reserve ringbuf dynptr record (runtime-determined size) */
        struct bpf_dynptr rb;
        __u32 total_sz = sizeof(hdr) + snap_len;

        err = bpf_ringbuf_reserve_dynptr(&events, total_sz, 0, &rb);
        if (err) {
            /* Critical: must discard/submit even on reserve failure */
            bpf_ringbuf_discard_dynptr(&rb, 0);
            return act;
        }

        /* Write header to ringbuf dynptr */
        err = bpf_dynptr_write(&rb, 0, &hdr, sizeof(hdr), 0);
        if (err) {
            bpf_ringbuf_discard_dynptr(&rb, 0);
            return act;
        }

        /* Write payload (if any) */
        if (snap_len) {
            err = bpf_dynptr_write(&rb, sizeof(hdr), payload, snap_len, 0);
            if (err) {
                bpf_ringbuf_discard_dynptr(&rb, 0);
                return act;
            }
        }

        bpf_ringbuf_submit_dynptr(&rb, 0);
    }

    return act;
}

char _license[] SEC("license") = "GPL";
