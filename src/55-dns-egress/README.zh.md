# eBPF 实战教程：用 cgroup BPF 构建基于 DNS 的 IP 允许列表

假设你希望一个容器化服务只能访问 `api.example.com`，拒绝所有其他连接。最直接的方案是 IP 白名单，但 DNS 应答会变、TTL 会过期。到了 `connect()` 阶段，内核只看到一个裸 IP，完全不知道它源自哪个域名。缺少的是一条短期关联：把 DNS 查询和随后的 TCP 连接串起来。

本教程就来构建这条关联。我们监控特定域名的 DNS 流量，只从有效的查询与响应对中提取 IP 地址，并在 TTL 有效期内允许连接。最终是一个简洁但完整的策略工具，展示 cgroup BPF 程序如何跨多个内核 hook 共享状态。

> 完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/55-dns-egress>

## 问题的本质：DNS 和 connect 相互隔离

当应用解析 `api.example.com` 时，DNS 响应包含 IP 地址和 TTL。但这些信息只存在于用户空间：解析器库把它缓存起来，应用拿着这个 IP 调用 `connect()`，而内核完全不知道这个 IP 从何而来。这种割裂造成了根本性的安全缺口。

考虑一个只应该访问后端 API 的容器。传统防火墙可以按目标 IP 过滤，却无法执行“只允许连接最近 60 秒内从 api.example.com 解析出来的 IP”这类策略。内核网络栈和应用层 DNS 解析彼此孤立，互不感知。

cgroup BPF 弥合了这个缺口。在同一个 cgroup 上同时挂载 packet hook 和 socket-address hook，就能先观察 DNS 流量，再据此执行连接策略。关键洞察是：cgroup BPF 程序通过 map 共享状态，从而把 DNS 查询、响应和最终连接串成一条信任链。

## 整体架构

eBPF 允许在多个内核 hook 上运行经过验证的程序，并通过 map 在它们之间共享状态。cgroup BPF 让这些 hook 跟随工作负载：packet 程序检查进出 cgroup 的流量，socket-address 程序则能在连接建立之前决定放行或拦截。

本工具在同一个 cgroup 上挂载三个程序：

1. **`cgroup_skb/egress`**：监控出站 DNS 查询，记录哪些响应是我们期待的
2. **`cgroup_skb/ingress`**：验证入站 DNS 响应，只从匹配待处理查询的回复中提取 IP 地址
3. **`cgroup/connect4`**：做最终裁决，只允许连接到从有效 DNS 响应中学到的 IP，且仅在 TTL 有效期内

下面跟着一次成功的解析走完整个流程。应用发送 `lab.test` 的 A 查询，egress hook 保存一个关联 key，包含四个字段：解析器地址、客户端地址、客户端 UDP 端口和 DNS 事务 ID。这条记录 5 秒后过期。响应到达后，ingress hook 用相同字段重建 key，验证响应内容，并提取 IP 地址和 TTL。之后发往这个地址的 `connect()` 可以成功，但只在 TTL 有效期内。

待处理查询记录就是信任边界。主动推送的伪造响应在 map 中找不到匹配的键；事务 ID 错误的响应会查找另一个键而落空。两者都无法污染允许列表。即使条目还留在 LRU map 中，connect hook 也会重新检查过期时间戳，所以地址会随 DNS TTL 自然失效。

## 数据结构

先看让这一切运转的数据结构。共享头文件定义了 DNS 协议布局和上报给用户空间的事件：

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __DNS_EGRESS_H
#define __DNS_EGRESS_H

#define DNS_QNAME_MAX 64

enum dns_egress_event_type {
	DNS_LEARNED = 1,
	DNS_ALLOWED = 2,
	DNS_DENIED = 3,
	DNS_EXPIRED = 4,
};

struct dns_header {
	unsigned short id;
	unsigned short flags;
	unsigned short questions;
	unsigned short answers;
	unsigned short authorities;
	unsigned short additionals;
} __attribute__((packed));

struct dns_question {
	unsigned short type;
	unsigned short class;
} __attribute__((packed));

struct dns_a_answer {
	unsigned short name;
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short address_length;
	unsigned int address;
} __attribute__((packed));

struct dns_egress_event {
	unsigned long long timestamp_ns;
	unsigned long long expires_ns;
	unsigned int type;
	unsigned int pid;
	unsigned int ip4;
	unsigned int ttl_seconds;
};

#endif /* __DNS_EGRESS_H */
```

协议结构使用 `packed` 属性，因为它们直接映射网络报文字节，不允许填充。`dns_header` 对应每个查询和响应开头的 12 字节 DNS 头。`dns_question` 跟在问题名（使用长度前缀标签）后面。`dns_a_answer` 期望常见的压缩格式，其中 name 指针是 `0xc00c`，指回问题部分。

发给用户空间的每个事件同时携带以秒为单位的 DNS TTL 和以纳秒为单位的绝对过期时间戳。用户空间打印人类可读的 TTL 用于日志，而 BPF 程序用单调时间戳做决策。这种分离让内核逻辑保持简洁，BPF 代码中无需时间格式转换。

## BPF 程序：完整实现

下面是完整的内核态实现。虽然比某些例子长，但每个部分都有明确的职责：

```c
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
```

### Map 设计

程序使用三个 BPF map，各自在信任链中承担不同角色。

**`pending_queries`** 是一个 LRU hash，保存 DNS 查询的关联状态。键由四个字段组成：服务器 IP、客户端 IP、客户端端口和事务 ID。这些字段共同唯一标识一个查询与响应对。值只存储过期时间戳，这就是时序验证所需的全部信息。LRU 淘汰机制确保即使 DNS 流量很大，内存占用也保持有界。

**`allowed_ips`** 也是 LRU hash，但只用 IPv4 地址作为键。值包含过期时间戳、以秒为单位的原始 TTL（用于日志）、对齐填充，以及一个标记是否已上报过期的标志位。这个标志位可以防止多线程竞争访问过期条目时产生重复的 `expired` 事件。

**`events`** 是一个 256 KB 的 ring buffer，用于向用户空间发送通知。这个容量可以容纳数千个事件而不会阻塞内核路径。ring buffer 是 perf buffer 的现代替代方案：效率更高，顺序保证也更清晰。

### 出站路径：记录待处理查询

当报文离开 cgroup 时，`record_dns_query` 开始执行。函数首先通过 `parse_query_transport` 验证传输层：加载 IP 头，确认这是 IPv4 UDP 报文，拒绝分片报文（需要我们没有实现的重组逻辑），并验证目标是否匹配配置的解析器。所有检查通过后，计算 DNS 数据的起始位置并填充关联键。

接着 `parse_dns_query` 验证 DNS 层。它检查 flags 是否表示标准查询（而非响应）、是否恰好有一个问题、以及问题名是否匹配配置的域名。问题类型和类必须是 A（地址）和 IN（互联网）。只有所有验证都通过后，才提取事务 ID 并将记录插入 `pending_queries`。

注意 `record_dns_query` 始终返回 1，告诉内核继续正常处理报文。我们是在观察，不是阻断。DNS 查询原样流过。

### 入站路径：从响应中学习

入站程序 `learn_dns_answer` 反转了视角。现在我们检查的是从解析器到达的报文，所以 `parse_response_transport` 检查*源*（而非目标）是否匹配解析器 IP 和端口。关联键使用相同的字段填充，但改从响应的视角取值。

关键的安全检查发生在 `pending_query_is_live`。这个函数在 `pending_queries` 中查找关联键。如果没有条目，说明我们从未看到匹配的查询，响应会被拒绝。如果条目存在但已过期，删除它并拒绝响应。只有匹配活跃待处理查询的响应才能继续。

确认响应合法后，`parse_response_question` 验证 DNS 头。它检查 flags 是否表示成功响应且无错误、是否恰好包含一个匹配我们域名的问题、以及是否至少有一个应答。然后 `parse_direct_a_answer` 提取第一个 A 记录，要求常见的 `0xc00c` 压缩 name 格式、正确的 type 和 class，以及 1 到 86400 秒之间的 TTL。

验证通过后，待处理查询被删除（已被消费），IP 地址以基于 DNS TTL 的过期时间添加到 `allowed_ips`。`emit_event` 调用向用户空间发送 `DNS_LEARNED` 通知。

### 连接路径：执行策略

`enforce_dns_policy` 挂载到 `cgroup/connect4`，在每个 IPv4 TCP 连接之前执行。函数首先应用过滤：如果我们针对特定进程且这不是它，放行；如果不是 TCP 或不是受保护端口，放行。这些提前返回将无关流量的开销降到最低。

对于需要策略执行的连接，我们在 `allowed_ips` 中查找目标 IP。如果找到且未过期，发出 `DNS_ALLOWED` 并返回 1（允许）。如果找到但已过期，使用原子 compare-and-swap 操作 `expired_reported`，确保即使并发访问也只发出一个 `DNS_EXPIRED` 事件。这个原子操作在 Linux 5.12 引入，也确定了本工具的最低内核版本。

如果 IP 不在 map 中或已过期，发出 `DNS_DENIED` 并返回 0。内核将返回值 0 转换为 `EPERM`，应用的 `connect()` 立即失败。

## 用户态程序

用户态程序配置 BPF 只读数据区，把三个程序挂载到 cgroup，并处理 ring buffer 事件。它还包含一个自测的 demo 模式，用于验证完整的信任链。

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "dns_egress.h"
#include "dns_egress.skel.h"

#define DEMO_DNS_PORT 15353
#define DEMO_TCP_PORT 19090
#define DNS_ID 0x4b1d

struct options {
	const char *cgroup_path;
	const char *domain;
	const char *dns_server;
	unsigned int port;
	unsigned int dns_port;
	unsigned int duration_seconds;
	bool demo;
};

struct dns_runtime {
	struct dns_egress_bpf *skel;
	struct bpf_link *query_link;
	struct bpf_link *ingress_link;
	struct bpf_link *connect_link;
	struct ring_buffer *ring;
	int cgroup_fd;
};

static int event_counts[5];
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

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct dns_egress_event *event = data;
	char address[INET_ADDRSTRLEN];
	const char *name;

	(void)ctx;
	if (size != sizeof(*event) || event->type > DNS_EXPIRED)
		return 0;
	event_counts[event->type]++;
	inet_ntop(AF_INET, &event->ip4, address, sizeof(address));
	name = event->type == DNS_LEARNED ? "learned" :
	       event->type == DNS_ALLOWED ? "allowed" :
	       event->type == DNS_DENIED ? "denied" : "expired";
	printf("event=%s pid=%u ip=%s ttl=%u\n", name, event->pid, address,
	       event->ttl_seconds);
	return 0;
}

static int parse_uint(const char *text, unsigned int maximum,
		      unsigned int *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !*text || *end || parsed > maximum)
		return -1;
	*value = parsed;
	return 0;
}

static void usage(const char *program)
{
	printf("Usage: %s --cgroup PATH --domain NAME --dns-server IPV4 [--port PORT] [--dns-port PORT] [--duration SEC]\n"
	       "       %s --demo\n", program, program);
}

static int apply_option(int option, const char *program,
			struct options *options)
{
	switch (option) {
	case 'c': options->cgroup_path = optarg; return 0;
	case 'n': options->domain = optarg; return 0;
	case 'r': options->dns_server = optarg; return 0;
	case 'p':
		return parse_uint(optarg, 65535, &options->port) || !options->port ?
		       -1 : 0;
	case 's':
		return parse_uint(optarg, 65535, &options->dns_port) ||
		       !options->dns_port ? -1 : 0;
	case 'd':
		return parse_uint(optarg, 86400, &options->duration_seconds);
	case 'D': options->demo = true; return 0;
	case 'h': usage(program); exit(0);
	default: return -1;
	}
}

static int finish_options(struct options *options)
{
	if (!options->demo)
		return options->cgroup_path && options->domain &&
		       options->dns_server ? 0 : -1;
	if (options->cgroup_path || options->domain || options->dns_server)
		return -1;
	options->cgroup_path = "/sys/fs/cgroup";
	options->domain = "lab.test";
	options->dns_server = "127.0.0.1";
	options->port = DEMO_TCP_PORT;
	options->dns_port = DEMO_DNS_PORT;
	return 0;
}

static int parse_options(int argc, char **argv, struct options *options)
{
	static const struct option long_options[] = {
		{ "cgroup", required_argument, NULL, 'c' },
		{ "domain", required_argument, NULL, 'n' },
		{ "dns-server", required_argument, NULL, 'r' },
		{ "port", required_argument, NULL, 'p' },
		{ "dns-port", required_argument, NULL, 's' },
		{ "duration", required_argument, NULL, 'd' },
		{ "demo", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "c:n:r:p:s:d:Dh", long_options,
				     NULL)) != -1)
		if (apply_option(option, argv[0], options))
			return -1;
	return optind == argc ? finish_options(options) : -1;
}

static int encode_qname(const char *domain, unsigned char output[DNS_QNAME_MAX],
			unsigned int *output_length)
{
	const char *label = domain;
	unsigned int used = 0;

	if (!*domain)
		return -1;
	while (*label) {
		const char *dot = strchr(label, '.');
		size_t length = dot ? (size_t)(dot - label) : strlen(label);

		if (!length || length > 63 || used + length + 2 > DNS_QNAME_MAX)
			return -1;
		output[used++] = length;
		memcpy(output + used, label, length);
		used += length;
		if (!dot)
			break;
		label = dot + 1;
		if (!*label)
			break;
	}
	output[used++] = 0;
	*output_length = used;
	return 0;
}

static int bind_udp(struct sockaddr_in *address)
{
	socklen_t length = sizeof(*address);
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (bind(fd, (struct sockaddr *)address, sizeof(*address)) ||
	    getsockname(fd, (struct sockaddr *)address, &length)) {
		close(fd);
		return -1;
	}
	return fd;
}

static int begin_dns_exchange(int server, int client,
			      struct sockaddr_in *server_address,
			      const unsigned char *qname,
			      unsigned int qname_length,
			      unsigned char message[512],
			      size_t *query_length,
			      struct sockaddr_in *client_address)
{
	struct dns_question question = {
		.type = htons(1),
		.class = htons(1),
	};
	struct dns_header *header = (void *)message;
	socklen_t address_length = sizeof(*client_address);
	ssize_t received;

	memset(message, 0, 512);
	header->id = htons(DNS_ID);
	header->flags = htons(0x0100);
	header->questions = htons(1);
	memcpy(message + sizeof(*header), qname, qname_length);
	memcpy(message + sizeof(*header) + qname_length, &question,
	       sizeof(question));
	*query_length = sizeof(*header) + qname_length + sizeof(question);
	if (sendto(client, message, *query_length, 0,
		   (struct sockaddr *)server_address, sizeof(*server_address)) !=
	    (ssize_t)*query_length)
		return -1;
	received = recvfrom(server, message, 512, 0,
			    (struct sockaddr *)client_address, &address_length);
	return received == (ssize_t)*query_length ? 0 : -1;
}

static int send_dns_answer(int server, int client,
			   struct sockaddr_in *client_address,
			   unsigned char message[512], size_t query_length,
			   unsigned short transaction_id,
			   unsigned int ttl_seconds)
{
	struct dns_a_answer answer = {
		.name = htons(0xc00c),
		.type = htons(1),
		.class = htons(1),
		.ttl = htonl(ttl_seconds),
		.address_length = htons(4),
	};
	struct dns_header *header = (void *)message;

	if (query_length + sizeof(answer) > 512)
		return -1;
	header->id = htons(transaction_id);
	header->flags = htons(0x8180);
	header->answers = htons(1);
	inet_pton(AF_INET, "127.0.0.1", &answer.address);
	memcpy(message + query_length, &answer, sizeof(answer));
	if (sendto(server, message, query_length + sizeof(answer), 0,
		   (struct sockaddr *)client_address, sizeof(*client_address)) !=
	    (ssize_t)(query_length + sizeof(answer)))
		return -1;
	return recv(client, message, 512, 0) ==
	       (ssize_t)(query_length + sizeof(answer)) ? 0 : -1;
}

static int send_unsolicited_dns(int server, int client,
				const unsigned char *qname,
				unsigned int qname_length)
{
	unsigned char message[512] = {};
	struct sockaddr_in client_address;
	struct dns_a_answer answer = {
		.name = htons(0xc00c),
		.type = htons(1),
		.class = htons(1),
		.ttl = htonl(30),
		.address_length = htons(4),
	};
	struct dns_question question = {
		.type = htons(1),
		.class = htons(1),
	};
	struct dns_header *header = (void *)message;
	socklen_t address_length = sizeof(client_address);
	size_t message_length;

	if (getsockname(client, (struct sockaddr *)&client_address,
			&address_length))
		return -1;
	header->id = htons(DNS_ID + 1);
	header->flags = htons(0x8180);
	header->questions = htons(1);
	header->answers = htons(1);
	memcpy(message + sizeof(*header), qname, qname_length);
	memcpy(message + sizeof(*header) + qname_length, &question,
	       sizeof(question));
	message_length = sizeof(*header) + qname_length + sizeof(question);
	inet_pton(AF_INET, "127.0.0.1", &answer.address);
	memcpy(message + message_length, &answer, sizeof(answer));
	message_length += sizeof(answer);
	if (sendto(server, message, message_length, 0,
		   (struct sockaddr *)&client_address, address_length) !=
	    (ssize_t)message_length)
		return -1;
	return recv(client, message, sizeof(message), 0) ==
	       (ssize_t)message_length ? 0 : -1;
}

static int create_tcp_listener(unsigned int port)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(port),
	};
	int one = 1;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) ||
	    listen(fd, 4)) {
		close(fd);
		return -1;
	}
	return fd;
}

static int connect_tcp(unsigned int port)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(port),
	};
	int saved_errno;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (!connect(fd, (struct sockaddr *)&address, sizeof(address)))
		return fd;
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return -1;
}

static int complete_tcp(int listener, int client)
{
	int accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
	char byte = 'x';
	int result = 0;

	if (accepted < 0) {
		close(client);
		return -1;
	}
	if (write(accepted, &byte, 1) != 1 || read(client, &byte, 1) != 1)
		result = -1;
	close(accepted);
	close(client);
	return result;
}

static int poll_demo_events(struct ring_buffer *ring)
{
	int result = ring_buffer__poll(ring, 100);

	return result < 0 && result != -EINTR ? -1 : 0;
}

static int expect_blocked_connect(struct ring_buffer *ring,
				  unsigned int port, const char *step)
{
	int client;

	errno = 0;
	client = connect_tcp(port);
	if (client >= 0) {
		close(client);
		return -1;
	}
	if (errno != EPERM || poll_demo_events(ring))
		return -1;
	printf("demo step=%s result=blocked\n", step);
	return 0;
}

static int expect_allowed_connect(struct ring_buffer *ring, int listener,
				  unsigned int port)
{
	int client = connect_tcp(port);

	if (client < 0 || complete_tcp(listener, client))
		return -1;
	if (poll_demo_events(ring))
		return -1;
	printf("demo step=live-answer result=allowed\n");
	return 0;
}

static int expected_demo_events(void)
{
	return event_counts[DNS_LEARNED] == 1 &&
	       event_counts[DNS_ALLOWED] == 1 &&
	       event_counts[DNS_DENIED] == 4 &&
	       event_counts[DNS_EXPIRED] == 1 ? 0 : -1;
}

struct demo_context {
	struct sockaddr_in server_address;
	struct sockaddr_in response_client_address;
	unsigned char dns_message[512];
	size_t query_length;
	int dns_server;
	int dns_client;
	int listener;
};

static int open_demo_sockets(struct demo_context *demo,
			     const struct options *options)
{
	struct sockaddr_in client_address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};

	demo->server_address = (struct sockaddr_in) {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(options->dns_port),
	};
	demo->dns_server = bind_udp(&demo->server_address);
	demo->dns_client = bind_udp(&client_address);
	demo->listener = create_tcp_listener(options->port);
	return demo->dns_server < 0 || demo->dns_client < 0 || demo->listener < 0 ?
		-1 : 0;
}

static int test_rejected_dns_answers(struct ring_buffer *ring,
				     const struct options *options,
				     const unsigned char *qname,
				     unsigned int qname_length,
				     struct demo_context *demo)
{
	if (expect_blocked_connect(ring, options->port, "before-dns"))
		return -1;
	if (send_unsolicited_dns(demo->dns_server, demo->dns_client, qname,
				   qname_length) ||
	    poll_demo_events(ring) ||
	    expect_blocked_connect(ring, options->port,
				   "unsolicited-response"))
		return -1;
	if (begin_dns_exchange(demo->dns_server, demo->dns_client,
			       &demo->server_address, qname, qname_length,
			       demo->dns_message, &demo->query_length,
			       &demo->response_client_address) ||
	    send_dns_answer(demo->dns_server, demo->dns_client,
			    &demo->response_client_address, demo->dns_message,
			    demo->query_length, DNS_ID + 1, 30) ||
	    poll_demo_events(ring) ||
	    expect_blocked_connect(ring, options->port, "wrong-transaction-id"))
		return -1;
	return 0;
}

static int test_live_and_expired_answer(struct ring_buffer *ring,
					const struct options *options,
					struct demo_context *demo)
{
	struct timespec wait_time = { .tv_sec = 1, .tv_nsec = 300000000 };

	if (send_dns_answer(demo->dns_server, demo->dns_client,
			    &demo->response_client_address, demo->dns_message,
			    demo->query_length, DNS_ID, 1) ||
	    poll_demo_events(ring) ||
	    expect_allowed_connect(ring, demo->listener, options->port))
		return -1;
	nanosleep(&wait_time, NULL);
	if (poll_demo_events(ring) ||
	    expect_blocked_connect(ring, options->port, "expired-answer"))
		return -1;
	return expected_demo_events();
}

static void close_demo_sockets(struct demo_context *demo)
{
	if (demo->listener >= 0)
		close(demo->listener);
	if (demo->dns_client >= 0)
		close(demo->dns_client);
	if (demo->dns_server >= 0)
		close(demo->dns_server);
}

static int run_demo(struct ring_buffer *ring, const struct options *options,
		    const unsigned char *qname, unsigned int qname_length)
{
	struct demo_context demo = {
		.dns_server = -1,
		.dns_client = -1,
		.listener = -1,
	};
	int err;

	err = open_demo_sockets(&demo, options);
	if (!err)
		err = test_rejected_dns_answers(ring, options, qname,
						qname_length, &demo);
	if (!err)
		err = test_live_and_expired_answer(ring, options, &demo);
	close_demo_sockets(&demo);
	return err;
}

static bool link_failed(struct bpf_link **link)
{
	if (!libbpf_get_error(*link))
		return false;
	*link = NULL;
	return true;
}

static int prepare_runtime(struct dns_runtime *runtime,
			   const struct options *options,
			   const struct in_addr *dns_server,
			   const unsigned char *qname,
			   unsigned int qname_length)
{
	bool failed;

	runtime->cgroup_fd = open(options->cgroup_path,
				  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (runtime->cgroup_fd < 0) {
		fprintf(stderr, "failed to open cgroup %s: %s\n",
			options->cgroup_path, strerror(errno));
		return -1;
	}
	runtime->skel = dns_egress_bpf__open();
	if (!runtime->skel)
		return -1;
	runtime->skel->rodata->target_tgid = options->demo ? getpid() : 0;
	runtime->skel->rodata->dns_server_ip = dns_server->s_addr;
	runtime->skel->rodata->dns_server_port = options->dns_port;
	runtime->skel->rodata->protected_tcp_port = options->port;
	runtime->skel->rodata->configured_qname_length = qname_length;
	memcpy((void *)runtime->skel->rodata->configured_qname, qname,
	       qname_length);
	if (dns_egress_bpf__load(runtime->skel)) {
		fprintf(stderr, "failed to load DNS egress BPF programs\n");
		return -1;
	}
	runtime->query_link = bpf_program__attach_cgroup(
		runtime->skel->progs.record_dns_query, runtime->cgroup_fd);
	runtime->ingress_link = bpf_program__attach_cgroup(
		runtime->skel->progs.learn_dns_answer, runtime->cgroup_fd);
	runtime->connect_link = bpf_program__attach_cgroup(
		runtime->skel->progs.enforce_dns_policy, runtime->cgroup_fd);
	failed = link_failed(&runtime->query_link);
	failed |= link_failed(&runtime->ingress_link);
	failed |= link_failed(&runtime->connect_link);
	if (failed) {
		fprintf(stderr, "failed to attach programs to cgroup %s\n",
			options->cgroup_path);
		return -1;
	}
	runtime->ring = ring_buffer__new(
		bpf_map__fd(runtime->skel->maps.events), handle_event, NULL, NULL);
	return runtime->ring ? 0 : -1;
}

static int poll_policy_events(struct ring_buffer *ring,
			      unsigned int duration_seconds)
{
	unsigned long long deadline = 0;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	if (duration_seconds)
		deadline = monotonic_ns() +
			   (unsigned long long)duration_seconds * 1000000000ULL;
	while (!stop && (!deadline || monotonic_ns() < deadline)) {
		int result = ring_buffer__poll(ring, 100);

		if (result < 0 && result != -EINTR) {
			fprintf(stderr, "ring buffer poll failed: %d\n", result);
			return -1;
		}
	}
	return 0;
}

static void destroy_runtime(struct dns_runtime *runtime)
{
	ring_buffer__free(runtime->ring);
	bpf_link__destroy(runtime->connect_link);
	bpf_link__destroy(runtime->ingress_link);
	bpf_link__destroy(runtime->query_link);
	if (runtime->cgroup_fd >= 0)
		close(runtime->cgroup_fd);
	dns_egress_bpf__destroy(runtime->skel);
}

int main(int argc, char **argv)
{
	struct options options = { .port = 443, .dns_port = 53 };
	struct dns_runtime runtime = { .cgroup_fd = -1 };
	struct in_addr dns_server = {};
	unsigned char qname[DNS_QNAME_MAX] = {};
	unsigned int qname_length = 0;
	int err = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (parse_options(argc, argv, &options) ||
	    encode_qname(options.domain, qname, &qname_length) ||
	    inet_pton(AF_INET, options.dns_server, &dns_server) != 1) {
		usage(argv[0]);
		return 2;
	}
	if (prepare_runtime(&runtime, &options, &dns_server, qname,
			    qname_length))
		goto cleanup;

	printf("dns-egress attached cgroup=%s domain=%s resolver=%s tcp_port=%u dns_port=%u\n",
	       options.cgroup_path, options.domain, options.dns_server,
	       options.port, options.dns_port);
	if (options.demo) {
		if (run_demo(runtime.ring, &options, qname, qname_length))
			goto cleanup;
	} else if (poll_policy_events(runtime.ring, options.duration_seconds))
		goto cleanup;
	err = 0;

cleanup:
	destroy_runtime(&runtime);
	return err;
}
```

### 用户态控制流程

用户态程序遵循清晰的初始化序列。首先 `parse_options` 处理命令行参数，验证输入并设置默认值。Demo 模式自动配置 loopback 地址和非标准端口，以避免与真实 DNS 和 Web 流量冲突。

`encode_qname` 函数将人类可读的域名如 `lab.test` 转换为 DNS 报文格式：`\x03lab\x04test\x00`。每个标签以长度字节开头，后跟标签内容，以零字节结尾。这个编码在启动时只执行一次，写入 BPF skeleton 的 `rodata` 部分，验证器将其视为常量。

`prepare_runtime` 把一切串联起来。它打开目标 cgroup 目录、打开 BPF skeleton、配置所有 `rodata` 值（解析器 IP、端口、域名）、加载 BPF 程序，并将每个程序挂载到 cgroup。三个独立的 link 允许独立地挂载和卸载。最后，它创建一个 ring buffer 消费者，为每个内核通知调用 `handle_event`。

在普通模式下，`poll_policy_events` 在 ring buffer 上循环，直到持续时间结束或收到信号。每个事件都会打印其 IP 地址、PID、TTL 和类型。Demo 模式则运行 `run_demo`，用合成的 DNS 流量和 TCP 连接验证完整的信任链。

### Demo 模式：验证安全属性

Demo 模式既是集成测试，也是安全模型的演示。它完全在 loopback 上运行，使用非标准端口（DNS 15353，TCP 19090）以避免干扰真实服务。

测试序列首先验证在任何 DNS 流量之前连接被阻止。然后发送一个未经请求的 DNS 响应，也就是一个没有前置查询就到达的响应。BPF 程序拒绝它，因为 `pending_queries` 中没有匹配的条目。测试确认连接仍然被阻止。

接下来，发送一个合法的 DNS 查询，但响应使用错误的事务 ID。BPF 程序同样拒绝它，因为事务 ID 是关联键的一部分。测试再次确认连接仍处于阻断状态。

最后，发送一个事务 ID 正确、TTL 为 1 秒的响应。现在连接成功了。等待 1.3 秒（超过 TTL）后，测试确认连接再次被阻止。

这个序列证明了工具正确实现了查询-响应关联、拒绝欺骗尝试、遵守 TTL，并正确使允许列表条目过期。

## 编译和运行

构建示例：

```bash
cd src/55-dns-egress
make
```

挂载到服务 cgroup 并监控特定域名：

```bash
sudo ./dns_egress \
  --cgroup /sys/fs/cgroup/my-service \
  --domain api.example.com \
  --dns-server 127.0.0.53 \
  --port 443
```

指定的 cgroup 必须包含目标工作负载，让它的 DNS 报文和连接共享策略状态。TCP 443 和 DNS 53 是默认端口；`--dns-port` 选择其他解析器端口，`--duration` 设置时间上限。内置 demo 不需要外部 DNS 服务器：

```bash
sudo ./dns_egress --demo
```

示例输出：

```text
dns-egress attached cgroup=/sys/fs/cgroup domain=lab.test resolver=127.0.0.1 tcp_port=19090 dns_port=15353
event=denied pid=1246 ip=127.0.0.1 ttl=0
demo step=before-dns result=blocked
event=denied pid=1246 ip=127.0.0.1 ttl=0
demo step=unsolicited-response result=blocked
event=denied pid=1246 ip=127.0.0.1 ttl=0
demo step=wrong-transaction-id result=blocked
event=learned pid=1246 ip=127.0.0.1 ttl=1
event=allowed pid=1246 ip=127.0.0.1 ttl=1
demo step=live-answer result=allowed
event=expired pid=1246 ip=127.0.0.1 ttl=1
event=denied pid=1246 ip=127.0.0.1 ttl=1
demo step=expired-answer result=blocked
```

前三个 `denied` 事件说明，仅仅收到 DNS 格式的流量或看到正确的域名是不够的。只有正确关联的响应才产生 `learned`，`allowed` 覆盖其有效 TTL 窗口，TTL 一过期，下一次连接立即被拒绝。

## 环境要求

| 要求 | 说明 |
|---|---|
| 内核 | Linux 5.12+（BPF atomic compare-and-exchange） |
| 内核配置 | `CONFIG_BPF`、`CONFIG_BPF_SYSCALL`、`CONFIG_BPF_JIT`、`CONFIG_CGROUP_BPF`、`CONFIG_DEBUG_INFO_BTF`、`CONFIG_INET` |
| cgroup | cgroup v2，工作负载位于挂载目录之下 |
| 权限 | root 权限，或等价的 BPF 与网络能力 |
| 架构 | x86-64 已测试；不需要特殊网卡 |

## 范围与限制

本工具刻意实现了一个紧凑的范围：一个精确域名、一个解析器、一个受保护的 TCP 端口、IPv4 UDP DNS 和第一个直接 A 应答。它识别常见的 `0xc00c` 压缩 owner name 格式。支持 CNAME 链、其他应答布局、TCP DNS、IPv6、DoH 或 DoT 需要额外的解析器或新的观察点。

这个紧凑范围保留了核心属性的可见性：IP 通过最近一次匹配的 DNS 查询进入允许列表，在 DNS TTL 过期时退出。

## 总结

本示例把观察到的 DNS 结果转化为有时间边界的连接策略。egress 和 ingress hook 建立可信的查询与响应关联，TTL 控制地址生命周期，connect hook 对受保护端口执行策略。

> 更多 eBPF 教程，请访问我们的代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [BPF ring buffer](https://docs.kernel.org/bpf/ringbuf.html)
- [BPF LRU hash map](https://docs.kernel.org/bpf/map_hash.html)
- [BPF atomic compare-and-exchange commit](https://github.com/torvalds/linux/commit/5ffa25502b5ab3d639829a2d1e316cff7f59a41e)
- [Control Group v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [RFC 1035：Domain Names: Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035.html)
