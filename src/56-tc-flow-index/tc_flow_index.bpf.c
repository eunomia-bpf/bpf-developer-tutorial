// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "tc_flow_index.h"

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IP_MF 0x2000
#define IP_OFFSET 0x1fff
#define INDEX_SEARCH_DEPTH 32
#define TC_ACT_OK 0

const volatile __u32 maximum_entries = 4096;

struct flow_entry {
	struct bpf_refcount ref;
	struct bpf_rb_node by_identity;
	struct bpf_rb_node by_traffic;
	struct flow_key key;
	__u64 packets;
	__u64 bytes;
	__u64 last_seen_ns;
	char comm[FLOW_COMM_LEN];
};

#define private(name) \
	SEC(".data." #name) __hidden __attribute__((aligned(8)))

private(index) struct bpf_spin_lock index_lock;
private(index) struct bpf_rb_root identity_root
	__contains(flow_entry, by_identity);
private(index) struct bpf_rb_root traffic_root
	__contains(flow_entry, by_traffic);

struct flow_cursor snapshot_cursor;
struct flow_snapshot snapshot_result;
__u64 observed_packets;
__u64 indexed_flows;
__u64 dropped_new_flows;
__u64 allocation_failures;
__u64 refcount_failures;
__u64 rank_update_failures;

static __always_inline int compare_key(const struct flow_key *left,
				       const struct flow_key *right)
{
	if (left->source_ip != right->source_ip)
		return left->source_ip < right->source_ip ? -1 : 1;
	if (left->destination_ip != right->destination_ip)
		return left->destination_ip < right->destination_ip ? -1 : 1;
	if (left->source_port != right->source_port)
		return left->source_port < right->source_port ? -1 : 1;
	if (left->destination_port != right->destination_port)
		return left->destination_port < right->destination_port ? -1 : 1;
	if (left->protocol != right->protocol)
		return left->protocol < right->protocol ? -1 : 1;
	return 0;
}

static bool identity_less(struct bpf_rb_node *a,
			  const struct bpf_rb_node *b)
{
	struct flow_entry *left = container_of(a, struct flow_entry,
					       by_identity);
	struct flow_entry *right = container_of(b, struct flow_entry,
						by_identity);

	return compare_key(&left->key, &right->key) < 0;
}

static __always_inline bool traffic_before(__u64 left_bytes,
					   __u64 left_packets,
					   const struct flow_key *left_key,
					   __u64 right_bytes,
					   __u64 right_packets,
					   const struct flow_key *right_key)
{
	if (left_bytes != right_bytes)
		return left_bytes > right_bytes;
	if (left_packets != right_packets)
		return left_packets > right_packets;
	return compare_key(left_key, right_key) < 0;
}

static bool traffic_less(struct bpf_rb_node *a,
			 const struct bpf_rb_node *b)
{
	struct flow_entry *left = container_of(a, struct flow_entry, by_traffic);
	struct flow_entry *right = container_of(b, struct flow_entry, by_traffic);

	return traffic_before(left->bytes, left->packets, &left->key,
			      right->bytes, right->packets, &right->key);
}

static __always_inline struct flow_entry *
find_flow_locked(const struct flow_key *key)
{
	struct bpf_rb_node *rb = bpf_rbtree_root(&identity_root);

	for (int i = 0; i < INDEX_SEARCH_DEPTH && rb; i++) {
		struct flow_entry *entry =
			container_of(rb, struct flow_entry, by_identity);
		int comparison = compare_key(key, &entry->key);

		if (!comparison)
			return entry;
		if (comparison < 0)
			rb = bpf_rbtree_left(&identity_root, rb);
		else
			rb = bpf_rbtree_right(&identity_root, rb);
	}
	return NULL;
}

static __always_inline bool update_existing_locked(struct flow_entry *entry,
						    __u32 packet_bytes,
						    __u64 now_ns)
{
	struct flow_entry *owner;
	struct bpf_rb_node *removed;

	removed = bpf_rbtree_remove(&traffic_root, &entry->by_traffic);
	if (!removed)
		return false;
	owner = container_of(removed, struct flow_entry, by_traffic);
	owner->packets++;
	owner->bytes += packet_bytes;
	owner->last_seen_ns = now_ns;
	bpf_rbtree_add(&traffic_root, &owner->by_traffic, traffic_less);
	return true;
}

static __always_inline void update_flow(const struct flow_key *key,
					__u32 packet_bytes, __u64 now_ns,
					const char comm[FLOW_COMM_LEN])
{
	struct flow_entry *entry, *new_entry, *traffic_owner;

	bpf_spin_lock(&index_lock);
	entry = find_flow_locked(key);
	if (entry) {
		if (!update_existing_locked(entry, packet_bytes, now_ns))
			rank_update_failures++;
		bpf_spin_unlock(&index_lock);
		return;
	}
	bpf_spin_unlock(&index_lock);

	new_entry = bpf_obj_new(typeof(*new_entry));
	if (!new_entry) {
		__sync_fetch_and_add(&allocation_failures, 1);
		return;
	}
	traffic_owner = bpf_refcount_acquire(new_entry);
	if (!traffic_owner) {
		__sync_fetch_and_add(&refcount_failures, 1);
		bpf_obj_drop(new_entry);
		return;
	}
	new_entry->key.source_ip = key->source_ip;
	new_entry->key.destination_ip = key->destination_ip;
	new_entry->key.source_port = key->source_port;
	new_entry->key.destination_port = key->destination_port;
	new_entry->key.protocol = key->protocol;
	new_entry->packets = 1;
	new_entry->bytes = packet_bytes;
	new_entry->last_seen_ns = now_ns;
	__builtin_memcpy(new_entry->comm, comm, sizeof(new_entry->comm));

	bpf_spin_lock(&index_lock);
	entry = find_flow_locked(key);
	if (entry) {
		if (!update_existing_locked(entry, packet_bytes, now_ns))
			rank_update_failures++;
		bpf_spin_unlock(&index_lock);
		bpf_obj_drop(new_entry);
		bpf_obj_drop(traffic_owner);
		return;
	}
	if (indexed_flows >= maximum_entries) {
		dropped_new_flows++;
		bpf_spin_unlock(&index_lock);
		bpf_obj_drop(new_entry);
		bpf_obj_drop(traffic_owner);
		return;
	}
	bpf_rbtree_add(&identity_root, &new_entry->by_identity, identity_less);
	bpf_rbtree_add(&traffic_root, &traffic_owner->by_traffic, traffic_less);
	indexed_flows++;
	bpf_spin_unlock(&index_lock);
}

static __always_inline bool parse_flow(struct __sk_buff *skb,
				       struct flow_key *key)
{
	struct ethhdr ethernet;
	struct iphdr ip;
	__u32 transport_offset;
	__be16 ports[2];

	if (bpf_skb_load_bytes(skb, 0, &ethernet, sizeof(ethernet)) ||
	    ethernet.h_proto != bpf_htons(ETH_P_IP))
		return false;
	if (bpf_skb_load_bytes(skb, sizeof(ethernet), &ip, sizeof(ip)) ||
	    ip.version != 4 || ip.ihl < 5 ||
	    (bpf_ntohs(ip.frag_off) & (IP_MF | IP_OFFSET)) ||
	    (ip.protocol != IPPROTO_TCP && ip.protocol != IPPROTO_UDP))
		return false;
	transport_offset = sizeof(ethernet) + ip.ihl * 4;
	if (bpf_skb_load_bytes(skb, transport_offset, ports, sizeof(ports)))
		return false;
	key->source_ip = ip.saddr;
	key->destination_ip = ip.daddr;
	key->source_port = ports[0];
	key->destination_port = ports[1];
	key->protocol = ip.protocol;
	return true;
}

SEC("tc")
int index_egress_flow(struct __sk_buff *skb)
{
	struct flow_key key = {};
	char comm[FLOW_COMM_LEN];

	if (!parse_flow(skb, &key))
		return TC_ACT_OK;
	__sync_fetch_and_add(&observed_packets, 1);
	bpf_get_current_comm(comm, sizeof(comm));
	update_flow(&key, skb->len, bpf_ktime_get_ns(), comm);
	return TC_ACT_OK;
}

static __always_inline bool cursor_before_entry(const struct flow_cursor *cursor,
						 const struct flow_entry *entry)
{
	return traffic_before(cursor->bytes, cursor->packets, &cursor->key,
			      entry->bytes, entry->packets, &entry->key);
}

SEC("syscall")
int snapshot_next(void *ctx)
{
	struct flow_entry *entry = NULL;
	struct bpf_rb_node *candidate = NULL;
	struct bpf_rb_node *rb;

	(void)ctx;
	__builtin_memset(&snapshot_result, 0, sizeof(snapshot_result));
	bpf_spin_lock(&index_lock);
	if (!snapshot_cursor.valid) {
		candidate = bpf_rbtree_first(&traffic_root);
	} else {
		rb = bpf_rbtree_root(&traffic_root);
		for (int i = 0; i < INDEX_SEARCH_DEPTH && rb; i++) {
			entry = container_of(rb, struct flow_entry, by_traffic);
			if (cursor_before_entry(&snapshot_cursor, entry)) {
				candidate = rb;
				rb = bpf_rbtree_left(&traffic_root, rb);
			} else {
				rb = bpf_rbtree_right(&traffic_root, rb);
			}
		}
	}
	if (candidate) {
		entry = container_of(candidate, struct flow_entry, by_traffic);
		snapshot_result.packets = entry->packets;
		snapshot_result.bytes = entry->bytes;
		snapshot_result.last_seen_ns = entry->last_seen_ns;
		snapshot_result.key.source_ip = entry->key.source_ip;
		snapshot_result.key.destination_ip = entry->key.destination_ip;
		snapshot_result.key.source_port = entry->key.source_port;
		snapshot_result.key.destination_port = entry->key.destination_port;
		snapshot_result.key.protocol = entry->key.protocol;
		snapshot_result.found = 1;
		__builtin_memcpy(snapshot_result.comm, entry->comm,
				 sizeof(snapshot_result.comm));
	}
	bpf_spin_unlock(&index_lock);
	return 0;
}
