# eBPF 实战教程：用两棵 refcounted rbtree 索引 TC 流量

流量监控会遇到两种完全不同的查询。每个报文到来时，需要按五元组快速找到原有 flow 并更新计数；输出报告时，又希望同一批记录按流量大小排列，让最繁忙的 flow 出现在前面。一种排序很难同时高效回答两个问题，两份独立副本又会让计数和生命周期逐渐分叉。

本课围绕一个对象的两种视图构建 TC egress flow index。每条 IPv4 TCP 或 UDP 流会同时进入 identity rbtree 和按字节数排序的 traffic rbtree，BPF object allocator 创建记录，BPF refcount 让两棵树共同持有对象，rbtree traversal 则直接产出 top-flow 结果，用户态无需重建索引。

> 完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/56-tc-flow-index>

## 为什么同一个对象可以进入两棵树

eBPF 可以让经过验证器检查的程序运行在 TC 等内核数据路径上，并在多次调用之间保留结构化状态。Linux 6.4 引入 `bpf_refcount_acquire()`，动态分配的 BPF object 可以获得新的 owning reference。Linux 6.16 又加入 `bpf_rbtree_root()`、`bpf_rbtree_left()` 和 `bpf_rbtree_right()`，BPF 程序开始能够搜索并遍历有序树，也补齐了本例使用的整组能力。

每个 `flow_entry` 内嵌一个 `bpf_refcount` 和两个不同的 `bpf_rb_node`。`identity_root` 通过 `by_identity` 按源地址、目的地址、源端口、目的端口和协议排序；`traffic_root` 通过 `by_traffic` 按 bytes、packets 和五元组排序，其中 bytes 与 packets 都是降序，五元组负责稳定处理并列项。两个 node 最终都能通过 `container_of()` 回到同一份计数和时间戳。

先看一条新 flow 的第一个报文。TC 程序搜索 identity tree，没有发现匹配项，于是分配一个 `flow_entry`，再调用 `bpf_refcount_acquire()` 取得第二个 owning reference。第一次 `bpf_rbtree_add()` 把一个 reference 交给 identity tree，第二次调用把另一个交给 traffic tree。临界区结束以后没有裸指针逃逸，验证器可以证明两棵 collection 都拥有这个对象。

后续报文会在 identity tree 找到条目，但 bytes 增加后，原来的 traffic 顺序已经失效。程序只从 traffic tree 移除 `by_traffic`，remove 返回这棵树持有的 owning reference；计数更新以后，同一个 traffic node 会重新插入正确位置。identity node 始终留在原位，因此查找顺序在整个更新期间保持有效。

## 共享的 flow 与 cursor 类型

共享头文件定义五元组、BPF 返回的 snapshot，以及继续有序遍历所需的 cursor。

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

`flow_key` 中的地址和端口保留 network byte order，BPF 侧可以直接复制报文字段，只有用户态格式化表格时才作转换。

## 实验性 kfunc 声明

BPF graph API 使用 kfunc，而不是稳定 UAPI helper。这个兼容头文件声明程序实际调用的函数，并用本地 BTF type ID 包装 object allocator。

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

`__contains(flow_entry, by_identity)` 和 traffic tree 对应的声明会告诉验证器，每个 root 关联的 containing type 与 node member。验证器再把这层类型关系和相邻 spin lock 结合起来，检查 graph ownership 与临界区规则。kfunc 接口可能随内核演进，因此本课明确记录最低版本，并把声明放在例子旁边。

## 在 TC egress 维护两份索引

下面是完整 BPF 程序。

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

`index_lock`、`identity_root` 和 `traffic_root` 位于同一个 private map value，所有搜索与修改都持有这把锁。二叉树搜索最多执行 32 步，让验证器看到确定的控制流；索引最多保存 4096 个 entry，平衡 rbtree 的实际深度远小于这个上限。

第一次加锁查找失败以后，程序会在锁外分配对象，再次加锁并重新查找。这次 double check 用于处理两个 CPU 同时发现新 flow 的情况：胜者把对象交给两棵树，另一方更新已有条目，并释放自己刚分配的两个 reference。allocation、refcount、capacity 和 re-ranking failure 都有独立计数，ownership 问题可以直接从输出中看到。

`parse_flow()` 接收未分片的 IPv4 TCP 与 UDP 报文，从 Ethernet、IP 和 transport header 组装 key。`index_egress_flow()` 始终返回 `TC_ACT_OK`，工具只观察并建立索引，不会改变报文传输。

`snapshot_next` 程序在同一把锁下读取 traffic tree。空 cursor 从 `bpf_rbtree_first()` 开始，之后则搜索前一个 `(bytes, packets, key)` 之后的第一项。result 与 cursor 都放在 BSS，用户态每次取一个有序 entry，不需要接收每报文事件流。

## 挂载 TC 并读取稳定 snapshot

用户态程序挂载 classifier，按需生成 demo 流量，在 snapshot 之前解除挂载，再通过 `BPF_PROG_TEST_RUN` 调用 snapshot program。

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

输出前解除挂载会冻结所有 packet update，cursor 因此可以遍历一份稳定的 traffic ordering。`snapshot_next()` 从 BSS 复制结果并推进 cursor，直到 `found` 变成 0，或者已经打印 `--top` 指定的数量。包括两棵树和 object ownership 在内的索引仍保存在 BPF 内存中，直到 skeleton 被销毁。

demo 模式创建三组 UDP socket pair，在 loopback 上分别发送 2 × 100 字节、4 × 300 字节和 6 × 700 字节 payload。算上 Ethernet、IPv4 与 UDP header，最终观测到 284、1368 和 4452 字节。这组流量会稳定产生三档排名，同时反复执行 traffic node 的 remove、update 和 reinsert。

## 编译和运行

构建工具：

```bash
cd src/56-tc-flow-index
make
```

在指定接口上索引 30 秒 egress 流量，并打印最繁忙的 10 条 flow：

```bash
sudo ./tc_flow_index --interface eth0 --duration 30 --top 10
```

运行可重复的 loopback demo：

```bash
sudo ./tc_flow_index --demo --top 3
```

一次真实 demo 会直接展示双树排序结果：

```text
Indexing IPv4 TCP/UDP egress flows on lo for 0 seconds.

Top egress flows, ranked in the BPF rbtree by bytes:
SOURCE                DESTINATION           PROTO    PACKETS        BYTES COMM
127.0.0.1:38918       127.0.0.1:47669       UDP            6         4452 tc_flow_index
127.0.0.1:57860       127.0.0.1:52539       UDP            4         1368 tc_flow_index
127.0.0.1:54177       127.0.0.1:45452       UDP            2          284 tc_flow_index
observed_packets=12 indexed_flows=3 dropped_new=0 allocation_failures=0 refcount_failures=0 rank_update_failures=0
```

表格到达用户态时已经按照 `BYTES` 降序排列，12 个报文创建 3 个 identity entry，所有 ownership 相关失败计数都是 0。

## 环境要求

| 要求 | 说明 |
|---|---|
| 内核 | Linux 6.16 或更高版本，需要 refcounted BPF object 与可搜索的 rbtree kfunc |
| 内核配置 | `CONFIG_BPF`、`CONFIG_BPF_SYSCALL`、`CONFIG_BPF_JIT`、`CONFIG_DEBUG_INFO_BTF`、`CONFIG_NET_SCHED`、`CONFIG_NET_CLS_BPF` |
| 权限 | root，或者等价的 BPF 与网络管理 capability |
| 网络接口 | 可以挂载 `clsact` egress program 的接口 |
| 架构与硬件 | 当前声明并完成测试的目标是 x86-64，普通网络接口即可 |

## 实现范围

这个索引覆盖未分片的 IPv4 TCP 与 UDP egress 流量，并保留 flow 首次创建时观察到的 command name。容量固定为 4096 条 flow，entry 会一直保留到程序退出，适合有边界的实验和短时间观察。长期运行的服务可以继续加入 idle expiry，在释放 reference 之前从两棵树移除对应 node。

## 总结

这个例子用 BPF object ownership 在同一条 flow 记录上维护两种有用顺序。identity tree 负责每报文更新，traffic tree 提供 top-flow traversal，refcount 则让两棵 collection 共享对象，同时保持状态只有一份。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [BPF graph data structures](https://docs.kernel.org/bpf/graph_ds_impl.html)
- [Linux rbtree search selftest](https://github.com/torvalds/linux/blob/v6.16/tools/testing/selftests/bpf/progs/rbtree_search.c)
- [Linux refcounted graph selftests](https://github.com/torvalds/linux/tree/v6.16/tools/testing/selftests/bpf/progs)
- [libbpf TC attach implementation](https://github.com/libbpf/libbpf/blob/master/src/netlink.c)
