# eBPF 实战教程：用双红黑树索引构建 Top-Flow 监控器

做过流量监控的人可能都遇到过这个问题：每个报文到达时，需要按五元组快速找到对应的 flow 记录更新计数器；但输出报告时，又希望同一批数据按流量大小排序，让最繁忙的 flow 排在前面。一份索引很难同时满足两种需求，而维护两份独立副本又会让计数器逐渐失去同步。有没有办法让两种视图共享同一份数据，始终保持一致？

本教程构建的 TC egress 流量监控器正是为了解决这个问题。我们把每条 IPv4 TCP 或 UDP 流同时索引到两棵红黑树中：一棵按五元组键值排序，用于快速报文查找；另一棵按字节数排序，用于即时输出 top-flow 结果。核心技术是 BPF 引用计数，它让两棵树能够共同拥有同一条 flow 记录，无需复制数据。

> 完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/56-tc-flow-index>

## 双索引的挑战

网络监控工具面临一个根本性的矛盾。报文到达时，需要在微秒级别内按五元组（源 IP、目的 IP、源端口、目的端口、协议）找到对应的 flow 记录。但当用户查询"显示前 10 条流量最大的 flow"时，又需要这些记录按流量大小排序。

传统方案要么维护两份独立的数据结构（可能出现不一致），要么在查询时重新排序（消耗 CPU 并延迟输出）。两种方案都不够理想。

我们采用的方法完全不同。每条 flow 记录在内存中只存在一份，但通过两个内嵌的树节点参与两种不同的排序。更新字节计数器时，两种视图立即看到变化，因为它们指向同一个对象。这得益于三个最新的 eBPF 特性：

- **BPF 对象分配**（`bpf_obj_new`）：在 BPF 程序中创建动态分配的结构体
- **BPF 引用计数**（`bpf_refcount_acquire`）：让多个所有者共享同一个对象
- **红黑树遍历**（`bpf_rbtree_root/left/right`）：不移除节点也能搜索和遍历树

Linux 6.4 引入了引用计数，6.16 又添加了树遍历功能。两者结合，使得以前在 BPF 中不可能实现的数据结构成为现实。

## 一个对象如何加入两棵树

我们来追踪一条新 flow 出现时会发生什么。TC 程序看到一个五元组为 (10.0.0.1, 10.0.0.2, 50000, 80, TCP) 的报文。它在 identity 树中按键值搜索，没有找到匹配项。是时候创建新条目了。

首先，`bpf_obj_new()` 分配一个 `flow_entry`。这个结构体内嵌一个 `bpf_refcount` 和两个 `bpf_rb_node` 字段，分别对应两棵树。刚分配时，对象恰好有一个 owning reference。

接下来，`bpf_refcount_acquire()` 为同一个对象创建第二个 owning reference。现在我们有两个引用指向同一块内存。第一次 `bpf_rbtree_add()` 把一个引用交给 identity 树。第二次调用把另一个交给 traffic 树。此时，两棵树共同拥有这个 flow entry，验证器知道没有裸指针逃逸。

当这条 flow 的后续报文到达时，我们在 identity 树中找到已有条目。但增加字节数会改变 traffic 排名。程序只移除 traffic 树节点（返回其 owning reference），更新计数器，然后在新位置重新插入。identity 节点始终不动，所以查找在整个过程中保持有效。

## 架构概览

实现分为三个文件：

| 文件 | 作用 |
|------|------|
| `tc_flow_index.h` | 共享结构体：五元组、快照、游标 |
| `bpf_experimental.h` | BPF graph API 的 kfunc 声明 |
| `tc_flow_index.bpf.c` | BPF 程序：TC hook 和快照系统调用 |
| `tc_flow_index.c` | 用户态加载器、演示流量和输出 |

BPF 端负责报文解析、树维护和基于游标的快照迭代。用户端挂载 TC 程序，可选生成测试流量，并通过 `BPF_PROG_TEST_RUN` 查询索引。

## 共享数据结构

头文件定义 flow key、快照结果和遍历游标：

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

`flow_key` 中的地址和端口保留网络字节序，BPF 程序可以直接从报文复制字段。只有用户态格式化输出时才转换为主机字节序。

## 实验性 kfunc 声明

BPF graph API 使用 kfunc 而非稳定的 UAPI helper。这个兼容头文件声明了程序使用的函数：

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

`__contains(flow_entry, by_identity)` 注解告诉验证器每个 root 对应的 containing type 和 member。结合相邻的 spin lock，验证器可以强制检查 ownership 和临界区规则。这些接口可能随内核版本演进，因此我们在下文注明了最低版本要求。

## BPF 程序

下面是完整的 BPF 实现，之后我们会逐一讲解关键部分。

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

### 理解 Flow Entry

`flow_entry` 结构体是整个设计的核心。它内嵌一个 `bpf_refcount` 用于 ownership 跟踪，以及两个 `bpf_rb_node` 字段用于参与两棵树。lock、`identity_root` 和 `traffic_root` 共享一个 private map value，确保所有访问都是串行化的。

### 报文处理路径

当 `index_egress_flow` 运行时，`parse_flow()` 从非分片的 IPv4 TCP 和 UDP 报文中提取五元组。主函数始终返回 `TC_ACT_OK`，因为我们只是观察，不是过滤。

`update_flow()` 函数首先在锁内搜索。如果 flow 存在，它移除 traffic 节点、更新计数器并重新插入。如果不存在，则在锁外分配，然后重新加锁做第二次查找。这个 double-check 处理了两个 CPU 同时发现新 flow 的情况：一个赢得插入竞争，另一个更新已有条目并释放自己未使用的引用。

### 快照机制

`snapshot_next` syscall 程序在同一把锁下读取 traffic 树。空游标时返回 `bpf_rbtree_first()`，后续调用则搜索上一个位置之后的第一个条目。由于游标和结果都在 BSS 中，用户态可以逐个获取排序好的条目，无需接收每报文事件流。

## 用户态程序

加载器挂载 TC 程序，可选生成演示流量，读取前先解挂，然后通过 `BPF_PROG_TEST_RUN` 查询：

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

输出前解挂会冻结报文更新，让游标可以遍历一份稳定的 traffic 排序。演示模式创建三条 loopback 上的 UDP 流：2 个报文 100 字节、4 个报文 300 字节、6 个报文 700 字节。加上协议头后，分别是 284、1368 和 4452 字节，产生确定性的排名。

## 编译和运行

构建工具：

```bash
cd src/56-tc-flow-index
make
```

监控真实 egress 流量 30 秒：

```bash
sudo ./tc_flow_index --interface eth0 --duration 30 --top 10
```

运行确定性演示：

```bash
sudo ./tc_flow_index --demo --top 3
```

预期演示输出：

```text
Indexing IPv4 TCP/UDP egress flows on lo for 0 seconds.

Top egress flows, ranked in the BPF rbtree by bytes:
SOURCE                DESTINATION           PROTO    PACKETS        BYTES COMM
127.0.0.1:38918       127.0.0.1:47669       UDP            6         4452 tc_flow_index
127.0.0.1:57860       127.0.0.1:52539       UDP            4         1368 tc_flow_index
127.0.0.1:54177       127.0.0.1:45452       UDP            2          284 tc_flow_index
observed_packets=12 indexed_flows=3 dropped_new=0 allocation_failures=0 refcount_failures=0 rank_update_failures=0
```

表格到达用户态时已按字节数降序排列。12 个报文创建了 3 个 identity 条目，所有 ownership 计数器都是 0，确认双树管理正确无误。

## 环境要求

| 要求 | 说明 |
|------|------|
| 内核 | Linux 6.16+（需要 refcounted BPF object + rbtree search kfunc） |
| 配置 | `CONFIG_BPF`、`CONFIG_BPF_SYSCALL`、`CONFIG_BPF_JIT`、`CONFIG_DEBUG_INFO_BTF`、`CONFIG_NET_SCHED`、`CONFIG_NET_CLS_BPF` |
| 权限 | root 或 CAP_BPF + CAP_NET_ADMIN |
| 网络接口 | 支持 clsact egress 的任意接口 |
| 架构 | 已在 x86-64 上测试 |

## 扩展方向

本示例覆盖非分片的 IPv4 TCP/UDP egress 流量，容量固定为 4096 条。对于生产环境，可以考虑：

- **空闲过期**：移除 N 秒内没有流量的 flow，先释放两棵树的节点再 drop reference
- **入口索引**：为入站报文添加第二个 TC 程序
- **IPv6 支持**：扩展 flow key 结构
- **实时流式输出**：在树之外添加 ring buffer 用于每报文事件

## 总结

本教程展示了 BPF object ownership 如何实现以前不可能的复杂数据结构。identity 树负责快速的五元组查找，traffic 树提供即时的 top-flow 排名，而引用计数让两者共享同一个对象，无需状态复制。这个技术可以推广到任何需要对同一数据集维护多种排序的场景。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [BPF graph data structures](https://docs.kernel.org/bpf/graph_ds_impl.html)
- [Linux rbtree search selftest](https://github.com/torvalds/linux/blob/v6.16/tools/testing/selftests/bpf/progs/rbtree_search.c)
- [Linux refcounted graph selftests](https://github.com/torvalds/linux/tree/v6.16/tools/testing/selftests/bpf/progs)
- [libbpf TC attach implementation](https://github.com/libbpf/libbpf/blob/master/src/netlink.c)
