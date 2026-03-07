// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct token_stats {
	__u64 packets;
	__u32 last_ifindex;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct token_stats);
} stats_map SEC(".maps");

SEC("xdp")
int handle_packet(struct xdp_md *ctx)
{
	struct token_stats *stats;
	__u32 key = 0;

	stats = bpf_map_lookup_elem(&stats_map, &key);
	if (!stats)
		return 0;

	stats->packets++;
	stats->last_ifindex = ctx->ingress_ifindex;
	return XDP_PASS;
}
