# eBPF Tutorial: Building a Top-Flow Monitor with Dual Rbtree Indexing

Ever tried building a network flow monitor and hit this wall? Every packet needs lightning-fast lookup to update counters, but at report time you want flows sorted by traffic volume. One index can't do both efficiently, and keeping two separate copies means counters drift apart. What if you could have both views of the same data, always in sync?

This tutorial builds a TC egress flow monitor that solves exactly this problem. We'll index each IPv4 TCP or UDP flow in two red-black trees simultaneously: one keyed by five-tuple for fast packet lookup, another sorted by bytes for instant top-flow output. The magic ingredient is BPF refcounting, which lets both trees own the same flow record without duplication.

> Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/56-tc-flow-index>

## The Dual-Index Challenge

Network monitoring tools face a fundamental tension. When a packet arrives, you need to find the matching flow record by its five-tuple (source IP, destination IP, source port, destination port, protocol) in microseconds. But when the user asks "show me the top 10 flows," you need those same records sorted by traffic volume.

Traditional solutions either maintain two independent data structures (which can drift out of sync) or rebuild the ranking on demand (which burns CPU and delays output). Neither feels right.

The approach we take here is different. Each flow record lives in memory exactly once, but it participates in two different orderings through two embedded tree nodes. When you update the byte counter, both views see the change immediately because they point to the same object. This is possible thanks to three recent eBPF features:

- **BPF object allocation** (`bpf_obj_new`): Create dynamically allocated structures in BPF programs
- **BPF refcounting** (`bpf_refcount_acquire`): Give multiple owners shared access to one object
- **Rbtree traversal** (`bpf_rbtree_root/left/right`): Search and walk trees without removing nodes

Linux 6.4 introduced refcounting, and 6.16 completed the picture with tree traversal. Together, they enable data structures that were previously impossible in BPF.

## How One Object Joins Two Trees

Let's trace what happens when a new flow appears. The TC program sees a packet with five-tuple (10.0.0.1, 10.0.0.2, 50000, 80, TCP). It searches the identity tree by key and finds nothing. Time to create a new entry.

First, `bpf_obj_new()` allocates a `flow_entry`. This structure embeds a `bpf_refcount` and two `bpf_rb_node` fields, one for each tree. Right after allocation, the object has exactly one owning reference.

Next, `bpf_refcount_acquire()` creates a second owning reference to the same object. Now we have two references pointing to one piece of memory. The first `bpf_rbtree_add()` transfers one reference to the identity tree. The second call transfers the other to the traffic tree. At this point, both trees jointly own the flow entry, and the verifier knows no raw pointers escaped.

When a subsequent packet for this flow arrives, we find the existing entry in the identity tree. But adding bytes changes the traffic ranking. The program removes only the traffic-tree node (which returns its owning reference), updates the counters, and reinserts at the new position. The identity node never moves, so lookup remains valid throughout.

## Architecture Overview

The implementation splits into three files:

| File | Purpose |
|------|---------|
| `tc_flow_index.h` | Shared structures: five-tuple, snapshot, and cursor |
| `bpf_experimental.h` | Kfunc declarations for BPF graph APIs |
| `tc_flow_index.bpf.c` | BPF program: TC hook and snapshot syscall |
| `tc_flow_index.c` | User-space loader, demo traffic, and output |

The BPF side handles packet parsing, tree maintenance, and cursor-based snapshot iteration. The user side attaches the TC program, optionally generates test traffic, and queries the index through `BPF_PROG_TEST_RUN`.

## Shared Data Structures

The header file defines the flow key, snapshot result, and traversal cursor:

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TC_FLOW_INDEX_H
#define __TC_FLOW_INDEX_H

#define FLOW_COMM_LEN 16

struct flow_key {
	unsigned int source_ip;
	unsigned int destination_ip;
	unsigned short source_port;
	unsigned short destination_port;
	unsigned char protocol;
	unsigned char padding[3];
};

struct flow_snapshot {
	unsigned long long packets;
	unsigned long long bytes;
	unsigned long long last_seen_ns;
	struct flow_key key;
	unsigned int found;
	char comm[FLOW_COMM_LEN];
};

struct flow_cursor {
	unsigned long long bytes;
	unsigned long long packets;
	struct flow_key key;
	unsigned int valid;
};

#endif /* __TC_FLOW_INDEX_H */
```

The `flow_key` keeps addresses and ports in network byte order, so the BPF program can copy packet fields directly without conversion. User space converts to host order only when formatting output.

## Experimental Kfunc Declarations

BPF graph APIs use kfuncs rather than stable UAPI helpers. This compatibility header declares the functions our program uses:

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TC_FLOW_INDEX_EXPERIMENTAL_H
#define __TC_FLOW_INDEX_EXPERIMENTAL_H

#include <bpf/bpf_core_read.h>

#define __contains(name, node) \
	__attribute__((btf_decl_tag("contains:" #name ":" #node)))

extern void *bpf_obj_new_impl(__u64 local_type_id, void *meta) __ksym;
#define bpf_obj_new(type) \
	((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))

extern void bpf_obj_drop_impl(void *kptr, void *meta) __ksym;
#define bpf_obj_drop(kptr) bpf_obj_drop_impl(kptr, NULL)

extern void *bpf_refcount_acquire_impl(void *kptr, void *meta) __ksym;
#define bpf_refcount_acquire(kptr) \
	bpf_refcount_acquire_impl(kptr, NULL)

extern int bpf_rbtree_add_impl(struct bpf_rb_root *root,
			       struct bpf_rb_node *node,
			       bool (*less)(struct bpf_rb_node *,
					    const struct bpf_rb_node *),
			       void *meta, __u64 off) __ksym;
#define bpf_rbtree_add(root, node, less) \
	bpf_rbtree_add_impl(root, node, less, NULL, 0)

extern struct bpf_rb_node *
bpf_rbtree_remove(struct bpf_rb_root *root, struct bpf_rb_node *node) __ksym;
extern struct bpf_rb_node *
bpf_rbtree_first(struct bpf_rb_root *root) __ksym;
extern struct bpf_rb_node *
bpf_rbtree_root(struct bpf_rb_root *root) __ksym;
extern struct bpf_rb_node *
bpf_rbtree_left(struct bpf_rb_root *root, struct bpf_rb_node *node) __ksym;
extern struct bpf_rb_node *
bpf_rbtree_right(struct bpf_rb_root *root, struct bpf_rb_node *node) __ksym;

#endif /* __TC_FLOW_INDEX_EXPERIMENTAL_H */
```

The `__contains(flow_entry, by_identity)` annotation tells the verifier which containing type and member belong to each root. Combined with the neighboring spin lock, this lets the verifier enforce ownership and critical-section rules. These interfaces may evolve between kernels, which is why we note a concrete minimum version below.

## The BPF Program

Here's the complete BPF implementation. We'll walk through the key parts afterward.

```c
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
```

### Understanding the Flow Entry

The `flow_entry` structure is the heart of this design. It embeds one `bpf_refcount` for ownership tracking and two `bpf_rb_node` fields for participation in both trees. The lock, `identity_root`, and `traffic_root` share a private map value, ensuring all access is serialized.

### The Packet Path

When `index_egress_flow` runs, `parse_flow()` extracts the five-tuple from non-fragmented IPv4 TCP and UDP packets. The main function always returns `TC_ACT_OK` because we're observing, not filtering.

The `update_flow()` function first searches under lock. If the flow exists, it removes the traffic node, updates counters, and reinserts. If not, it allocates outside the lock, then locks again for a second lookup. This double-check handles two CPUs discovering the same new flow simultaneously: one wins the insertion race, the other updates the existing entry and drops its unused references.

### The Snapshot Mechanism

The `snapshot_next` syscall program reads the traffic tree under the same lock. With an empty cursor, it returns `bpf_rbtree_first()`. Subsequent calls search for the first entry after the previous position. Since the cursor and result live in BSS, user space can fetch one ranked entry at a time without receiving a per-packet event stream.

## The User-Space Program

The loader attaches the TC program, optionally generates demo traffic, detaches before reading, then queries through `BPF_PROG_TEST_RUN`:

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "tc_flow_index.h"
#include "tc_flow_index.skel.h"

#define MAX_TOP 64

struct options {
	const char *interface;
	unsigned int duration_seconds;
	unsigned int top;
	bool demo;
};

static volatile sig_atomic_t stop;

static void handle_signal(int signal_number)
{
	(void)signal_number;
	stop = 1;
}

static unsigned long long monotonic_ns(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static int parse_uint(const char *text, unsigned int maximum,
		      unsigned int *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !*text || *end || !parsed || parsed > maximum)
		return -1;
	*value = parsed;
	return 0;
}

static void usage(const char *program)
{
	printf("Usage: %s --interface IFACE [--duration SEC] [--top N]\n"
	       "       %s --demo [--top N]\n", program, program);
}

static int parse_options(int argc, char **argv, struct options *options)
{
	static const struct option long_options[] = {
		{ "interface", required_argument, NULL, 'i' },
		{ "duration", required_argument, NULL, 'd' },
		{ "top", required_argument, NULL, 't' },
		{ "demo", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "i:d:t:Dh", long_options,
				     NULL)) != -1) {
		switch (option) {
		case 'i': options->interface = optarg; break;
		case 'd':
			if (parse_uint(optarg, 86400, &options->duration_seconds))
				return -1;
			break;
		case 't':
			if (parse_uint(optarg, MAX_TOP, &options->top))
				return -1;
			break;
		case 'D': options->demo = true; break;
		case 'h': usage(argv[0]); exit(0);
		default: return -1;
		}
	}
	if (options->demo) {
		if (options->interface)
			return -1;
		options->interface = "lo";
	}
	return optind == argc && options->interface ? 0 : -1;
}

static int send_demo_flow(unsigned int datagrams, size_t payload_size)
{
	struct sockaddr_in receiver_address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in sender_address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t address_length = sizeof(receiver_address);
	char payload[1000] = {};
	int receiver = -1, sender = -1;
	int err = -1;

	if (payload_size > sizeof(payload))
		return -1;
	receiver = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	sender = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (receiver < 0 || sender < 0 ||
	    bind(receiver, (struct sockaddr *)&receiver_address,
		 sizeof(receiver_address)) ||
	    getsockname(receiver, (struct sockaddr *)&receiver_address,
			&address_length) ||
	    bind(sender, (struct sockaddr *)&sender_address,
		 sizeof(sender_address)))
		goto cleanup;
	for (unsigned int i = 0; i < datagrams; i++)
		if (sendto(sender, payload, payload_size, 0,
			   (struct sockaddr *)&receiver_address,
			   sizeof(receiver_address)) != (ssize_t)payload_size)
			goto cleanup;
	err = 0;

cleanup:
	if (receiver >= 0) close(receiver);
	if (sender >= 0) close(sender);
	return err;
}

static int run_demo_traffic(void)
{
	return send_demo_flow(2, 100) ||
	       send_demo_flow(4, 300) ||
	       send_demo_flow(6, 700);
}

static int snapshot_next(struct tc_flow_index_bpf *skel,
			 struct flow_snapshot *result)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	if (bpf_prog_test_run_opts(bpf_program__fd(skel->progs.snapshot_next),
				   &opts)) {
		fprintf(stderr, "failed to query BPF flow index: %s\n",
			strerror(errno));
		return -1;
	}
	*result = skel->bss->snapshot_result;
	if (result->found) {
		skel->bss->snapshot_cursor.bytes = result->bytes;
		skel->bss->snapshot_cursor.packets = result->packets;
		skel->bss->snapshot_cursor.key = result->key;
		skel->bss->snapshot_cursor.valid = 1;
	}
	return 0;
}

static int print_flows(struct tc_flow_index_bpf *skel, unsigned int top)
{
	struct flow_snapshot entry;

	memset(&skel->bss->snapshot_cursor, 0,
	       sizeof(skel->bss->snapshot_cursor));
	printf("\nTop egress flows, ranked in the BPF rbtree by bytes:\n");
	printf("%-21s %-21s %-5s %10s %12s %-16s\n",
	       "SOURCE", "DESTINATION", "PROTO", "PACKETS", "BYTES", "COMM");
	for (unsigned int i = 0; i < top; i++) {
		char source_ip[INET_ADDRSTRLEN], destination_ip[INET_ADDRSTRLEN];
		char source[64], destination[64];

		if (snapshot_next(skel, &entry))
			return -1;
		if (!entry.found)
			break;
		inet_ntop(AF_INET, &entry.key.source_ip, source_ip,
			  sizeof(source_ip));
		inet_ntop(AF_INET, &entry.key.destination_ip, destination_ip,
			  sizeof(destination_ip));
		snprintf(source, sizeof(source), "%s:%u", source_ip,
			 ntohs(entry.key.source_port));
		snprintf(destination, sizeof(destination), "%s:%u",
			 destination_ip, ntohs(entry.key.destination_port));
		printf("%-21s %-21s %-5s %10llu %12llu %-16s\n",
		       source, destination,
		       entry.key.protocol == IPPROTO_TCP ? "TCP" : "UDP",
		       entry.packets, entry.bytes, entry.comm);
	}
	return 0;
}

static int attach_tc_program(struct bpf_tc_hook *hook,
			     struct bpf_tc_opts *attach,
			     bool *hook_created, bool *attached)
{
	int err = bpf_tc_hook_create(hook);

	if (!err)
		*hook_created = true;
	else if (err != -EEXIST) {
		fprintf(stderr, "failed to create clsact hook: %s\n", strerror(-err));
		return -1;
	}
	err = bpf_tc_attach(hook, attach);
	if (err) {
		fprintf(stderr, "failed to attach TC program: %s\n", strerror(-err));
		return -1;
	}
	*attached = true;
	return 0;
}

static int capture_traffic(const struct options *options)
{
	unsigned long long deadline;

	if (options->demo)
		return run_demo_traffic();
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	deadline = monotonic_ns() +
		   (unsigned long long)options->duration_seconds * 1000000000ULL;
	while (!stop && monotonic_ns() < deadline) {
		struct timespec pause = { .tv_nsec = 100000000 };

		nanosleep(&pause, NULL);
	}
	return 0;
}

static int detach_tc_program(struct bpf_tc_hook *hook,
			     struct bpf_tc_opts *detach, bool *attached)
{
	int err = bpf_tc_detach(hook, detach);

	if (err) {
		fprintf(stderr, "failed to detach TC program: %s\n", strerror(-err));
		return -1;
	}
	*attached = false;
	return 0;
}

int main(int argc, char **argv)
{
	struct options options = { .duration_seconds = 10, .top = 10 };
	struct tc_flow_index_bpf *skel = NULL;
	LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, attach, .handle = 1, .priority = 1);
	LIBBPF_OPTS(bpf_tc_opts, detach, .handle = 1, .priority = 1);
	bool hook_created = false;
	bool attached = false;
	int err = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (parse_options(argc, argv, &options)) {
		usage(argv[0]);
		return 2;
	}
	hook.ifindex = if_nametoindex(options.interface);
	if (!hook.ifindex) {
		fprintf(stderr, "interface does not exist: %s\n", options.interface);
		return 2;
	}

	skel = tc_flow_index_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to load TC flow index\n");
		goto cleanup;
	}
	attach.prog_fd = bpf_program__fd(skel->progs.index_egress_flow);
	if (attach_tc_program(&hook, &attach, &hook_created, &attached))
		goto cleanup;
	printf("Indexing IPv4 TCP/UDP egress flows on %s for %u seconds.\n",
	       options.interface, options.demo ? 0 : options.duration_seconds);

	if (capture_traffic(&options)) {
		fprintf(stderr, "failed to generate traffic\n");
		goto cleanup;
	}

	if (detach_tc_program(&hook, &detach, &attached))
		goto cleanup;
	if (print_flows(skel, options.top))
		goto cleanup;
	printf("observed_packets=%llu indexed_flows=%llu dropped_new=%llu "
	       "allocation_failures=%llu refcount_failures=%llu rank_update_failures=%llu\n",
	       (unsigned long long)skel->bss->observed_packets,
	       (unsigned long long)skel->bss->indexed_flows,
	       (unsigned long long)skel->bss->dropped_new_flows,
	       (unsigned long long)skel->bss->allocation_failures,
	       (unsigned long long)skel->bss->refcount_failures,
	       (unsigned long long)skel->bss->rank_update_failures);
	if (options.demo &&
	    (skel->bss->indexed_flows != 3 || skel->bss->rank_update_failures))
		goto cleanup;
	err = 0;

cleanup:
	if (attached)
		bpf_tc_detach(&hook, &detach);
	if (hook_created)
		bpf_tc_hook_destroy(&hook);
	tc_flow_index_bpf__destroy(skel);
	return err;
}
```

Detaching before output freezes packet updates, so the cursor walks a stable traffic ordering. The demo mode creates three UDP flows over loopback: 2 packets at 100 bytes, 4 at 300 bytes, and 6 at 700 bytes. With headers, these become 284, 1368, and 4452 bytes total, producing a deterministic ranking.

## Building and Running

Build the tool:

```bash
cd src/56-tc-flow-index
make
```

Monitor real egress traffic for 30 seconds:

```bash
sudo ./tc_flow_index --interface eth0 --duration 30 --top 10
```

Run the deterministic demo:

```bash
sudo ./tc_flow_index --demo --top 3
```

Expected demo output:

```text
Indexing IPv4 TCP/UDP egress flows on lo for 0 seconds.

Top egress flows, ranked in the BPF rbtree by bytes:
SOURCE                DESTINATION           PROTO    PACKETS        BYTES COMM
127.0.0.1:38918       127.0.0.1:47669       UDP            6         4452 tc_flow_index
127.0.0.1:57860       127.0.0.1:52539       UDP            4         1368 tc_flow_index
127.0.0.1:54177       127.0.0.1:45452       UDP            2          284 tc_flow_index
observed_packets=12 indexed_flows=3 dropped_new=0 allocation_failures=0 refcount_failures=0 rank_update_failures=0
```

The table arrives pre-sorted by bytes. Twelve packets created three identity entries, and all ownership counters remain zero, confirming correct dual-tree management.

## Requirements

| Requirement | Details |
|-------------|---------|
| Kernel | Linux 6.16+ (refcounted BPF objects + rbtree search kfuncs) |
| Config | `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_NET_SCHED`, `CONFIG_NET_CLS_BPF` |
| Privileges | Root or CAP_BPF + CAP_NET_ADMIN |
| Interface | Any interface supporting clsact egress |
| Architecture | Tested on x86-64 |

## Extending the Design

This example covers non-fragmented IPv4 TCP/UDP egress with a fixed 4096-entry capacity. For production use, consider:

- **Idle expiry**: Remove flows that haven't seen traffic for N seconds, freeing both tree nodes before dropping references
- **Ingress indexing**: Add a second TC program for incoming packets
- **IPv6 support**: Extend the flow key structure
- **Real-time streaming**: Use a ring buffer alongside the trees for per-packet events

## Summary

This tutorial showed how BPF object ownership enables sophisticated data structures that weren't possible before. The identity tree handles fast five-tuple lookups, the traffic tree provides instant top-flow rankings, and refcounting lets both share one object without state duplication. The technique generalizes to any scenario where you need multiple orderings over the same dataset.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [BPF graph data structures](https://docs.kernel.org/bpf/graph_ds_impl.html)
- [Linux rbtree search selftest](https://github.com/torvalds/linux/blob/v6.16/tools/testing/selftests/bpf/progs/rbtree_search.c)
- [Linux refcounted graph selftests](https://github.com/torvalds/linux/tree/v6.16/tools/testing/selftests/bpf/progs)
- [libbpf TC attach implementation](https://github.com/libbpf/libbpf/blob/master/src/netlink.c)
