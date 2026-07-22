// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "dns_egress.h"

char LICENSE[] SEC("license") = "GPL";

#define IPPROTO_UDP 17
#define IPPROTO_TCP 6
#define IP_MF 0x2000
#define IP_OFFSET 0x1fff
#define DNS_QUERY_LIFETIME_NS (5ULL * 1000000000ULL)

const volatile __u32 target_tgid;
const volatile __u32 dns_server_ip;
const volatile __u16 dns_server_port = 53;
const volatile __u16 protected_tcp_port = 443;
const volatile __u32 configured_qname_length;
const volatile unsigned char configured_qname[DNS_QNAME_MAX];

struct dns_state {
	__u64 expires_ns;
	__u32 ttl_seconds;
	__u32 pad;
	__u64 expired_reported;
};

struct dns_query_key {
	__u32 server_ip;
	__u32 client_ip;
	__u16 client_port;
	__u16 transaction_id;
};

struct dns_query_state {
	__u64 expires_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct dns_query_key);
	__type(value, struct dns_query_state);
} pending_queries SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct dns_state);
} allowed_ips SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline void emit_event(__u32 type, __u32 ip4,
				       __u32 ttl_seconds, __u64 expires_ns)
{
	struct dns_egress_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return;
	event->timestamp_ns = bpf_ktime_get_ns();
	event->expires_ns = expires_ns;
	event->type = type;
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->ip4 = ip4;
	event->ttl_seconds = ttl_seconds;
	bpf_ringbuf_submit(event, 0);
}

static __noinline bool matches_qname(struct __sk_buff *skb, __u32 offset)
{
	unsigned char byte;

	if (!configured_qname_length || configured_qname_length > DNS_QNAME_MAX)
		return false;
#pragma clang loop unroll(disable)
	for (int i = 0; i < DNS_QNAME_MAX; i++) {
		if (i >= configured_qname_length)
			break;
		if (bpf_skb_load_bytes(skb, offset + i, &byte, sizeof(byte)) ||
		    byte != configured_qname[i])
			return false;
	}
	return true;
}

static __always_inline bool parse_query_transport(
	struct __sk_buff *skb, __u32 *dns_offset, struct dns_query_key *key)
{
	struct udphdr udp;
	struct iphdr ip;
	__u32 ip_header_len;

	if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)))
		return false;
	if (ip.version != 4 || ip.protocol != IPPROTO_UDP || ip.ihl < 5 ||
	    (bpf_ntohs(ip.frag_off) & (IP_MF | IP_OFFSET)) ||
	    ip.daddr != dns_server_ip)
		return false;
	ip_header_len = ip.ihl * 4;
	if (bpf_skb_load_bytes(skb, ip_header_len, &udp, sizeof(udp)) ||
	    bpf_ntohs(udp.dest) != dns_server_port)
		return false;
	*dns_offset = ip_header_len + sizeof(udp);
	key->server_ip = ip.daddr;
	key->client_ip = ip.saddr;
	key->client_port = udp.source;
	return true;
}

static __always_inline bool parse_dns_query(struct __sk_buff *skb,
					     __u32 dns_offset,
					     struct dns_query_key *key)
{
	struct dns_question question;
	struct dns_header header;
	__u16 flags;

	if (bpf_skb_load_bytes(skb, dns_offset, &header, sizeof(header)))
		return false;
	flags = bpf_ntohs(header.flags);
	if ((flags & 0xf800) || bpf_ntohs(header.questions) != 1)
		return false;
	if (!matches_qname(skb, dns_offset + sizeof(header)))
		return false;
	dns_offset += sizeof(header) + configured_qname_length;
	if (bpf_skb_load_bytes(skb, dns_offset, &question, sizeof(question)) ||
	    bpf_ntohs(question.type) != 1 || bpf_ntohs(question.class) != 1)
		return false;
	key->transaction_id = header.id;
	return true;
}

SEC("cgroup_skb/egress")
int record_dns_query(struct __sk_buff *skb)
{
	struct dns_query_state state = {
		.expires_ns = bpf_ktime_get_ns() + DNS_QUERY_LIFETIME_NS,
	};
	struct dns_query_key key = {};
	__u32 dns_offset;

	if (!parse_query_transport(skb, &dns_offset, &key) ||
	    !parse_dns_query(skb, dns_offset, &key))
		return 1;
	bpf_map_update_elem(&pending_queries, &key, &state, BPF_ANY);
	return 1;
}

static __always_inline bool parse_response_transport(
	struct __sk_buff *skb, __u32 *dns_offset, struct dns_query_key *query_key)
{
	struct udphdr udp;
	struct iphdr ip;
	__u32 ip_header_len;

	if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)))
		return false;
	if (ip.version != 4 || ip.protocol != IPPROTO_UDP || ip.ihl < 5 ||
	    (bpf_ntohs(ip.frag_off) & (IP_MF | IP_OFFSET)) ||
	    ip.saddr != dns_server_ip)
		return false;
	ip_header_len = ip.ihl * 4;
	if (bpf_skb_load_bytes(skb, ip_header_len, &udp, sizeof(udp)) ||
	    bpf_ntohs(udp.source) != dns_server_port)
		return false;
	*dns_offset = ip_header_len + sizeof(udp);
	query_key->server_ip = ip.saddr;
	query_key->client_ip = ip.daddr;
	query_key->client_port = udp.dest;
	return true;
}

static __always_inline bool pending_query_is_live(
	struct dns_query_key *query_key)
{
	struct dns_query_state *query;

	query = bpf_map_lookup_elem(&pending_queries, query_key);
	if (!query)
		return false;
	if (bpf_ktime_get_ns() >= query->expires_ns) {
		bpf_map_delete_elem(&pending_queries, query_key);
		return false;
	}
	return true;
}

static __always_inline bool parse_response_question(
	struct __sk_buff *skb, __u32 dns_offset,
	struct dns_query_key *query_key, __u32 *answer_offset)
{
	struct dns_question question;
	struct dns_header header;

	if (bpf_skb_load_bytes(skb, dns_offset, &header, sizeof(header)))
		return false;
	query_key->transaction_id = header.id;
	if (!pending_query_is_live(query_key))
		return false;
	if ((bpf_ntohs(header.flags) & 0xf80f) != 0x8000 ||
	    bpf_ntohs(header.questions) != 1 || !bpf_ntohs(header.answers))
		return false;
	if (!matches_qname(skb, dns_offset + sizeof(header)))
		return false;
	dns_offset += sizeof(header) + configured_qname_length;
	if (bpf_skb_load_bytes(skb, dns_offset, &question, sizeof(question)) ||
	    bpf_ntohs(question.type) != 1 || bpf_ntohs(question.class) != 1)
		return false;
	*answer_offset = dns_offset + sizeof(question);
	return true;
}

static __always_inline bool parse_direct_a_answer(struct __sk_buff *skb,
						   __u32 answer_offset,
						   __u32 *key, __u32 *ttl)
{
	struct dns_a_answer answer;

	if (bpf_skb_load_bytes(skb, answer_offset, &answer, sizeof(answer)) ||
	    bpf_ntohs(answer.name) != 0xc00c || bpf_ntohs(answer.type) != 1 ||
	    bpf_ntohs(answer.class) != 1 ||
	    bpf_ntohs(answer.address_length) != 4)
		return false;
	*key = answer.address;
	*ttl = bpf_ntohl(answer.ttl);
	return *ttl && *ttl <= 86400;
}

SEC("cgroup_skb/ingress")
int learn_dns_answer(struct __sk_buff *skb)
{
	struct dns_query_key query_key = {};
	struct dns_state state = {};
	__u64 ttl_ns, expires;
	__u32 dns_offset, answer_offset;
	__u32 key, ttl;

	if (!parse_response_transport(skb, &dns_offset, &query_key) ||
	    !parse_response_question(skb, dns_offset, &query_key,
				     &answer_offset) ||
	    !parse_direct_a_answer(skb, answer_offset, &key, &ttl))
		return 1;
	bpf_map_delete_elem(&pending_queries, &query_key);
	ttl_ns = (__u64)ttl * 1000000000ULL;
	expires = bpf_ktime_get_ns() + ttl_ns;
	state.expires_ns = expires;
	state.ttl_seconds = ttl;
	if (bpf_map_update_elem(&allowed_ips, &key, &state, BPF_ANY))
		return 1;
	emit_event(DNS_LEARNED, key, ttl, expires);
	return 1;
}

SEC("cgroup/connect4")
int enforce_dns_policy(struct bpf_sock_addr *ctx)
{
	struct dns_state *state;
	__u64 expires = 0;
	__u32 ip4;
	__u32 ttl = 0;

	if ((target_tgid &&
	     (__u32)(bpf_get_current_pid_tgid() >> 32) != target_tgid) ||
	    ctx->protocol != IPPROTO_TCP ||
	    bpf_ntohs((__u16)ctx->user_port) != protected_tcp_port)
		return 1;

	ip4 = ctx->user_ip4;
	state = bpf_map_lookup_elem(&allowed_ips, &ip4);
	if (state) {
		expires = state->expires_ns;
		ttl = state->ttl_seconds;
		if (bpf_ktime_get_ns() < expires) {
			emit_event(DNS_ALLOWED, ip4, ttl, expires);
			return 1;
		}
		if (__sync_val_compare_and_swap(&state->expired_reported, 0, 1) == 0)
			emit_event(DNS_EXPIRED, ip4, ttl, expires);
	}
	emit_event(DNS_DENIED, ip4, ttl, expires);
	return 0;
}
