// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef TCX_NEXT
#define TCX_NEXT -1
#endif

#ifndef TCX_PASS
#define TCX_PASS 0
#endif

char LICENSE[] SEC("license") = "GPL";

__u64 stats_hits;
__u64 classifier_hits;
__u32 last_len;
__u16 last_protocol;
__u32 last_ifindex;

SEC("tcx/ingress")
int tcx_stats(struct __sk_buff *skb)
{
	stats_hits++;
	last_len = skb->len;
	last_protocol = bpf_ntohs(skb->protocol);
	last_ifindex = skb->ifindex;
	return TCX_NEXT;
}

SEC("tcx/ingress")
int tcx_classifier(struct __sk_buff *skb)
{
	classifier_hits++;
	return TCX_PASS;
}
