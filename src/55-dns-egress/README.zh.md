# eBPF 实战教程：用 cgroup BPF 构建 DNS 派生的 IP 允许列表

假设一个服务只能通过 HTTPS 访问 `api.example.com`，其余目的地址都需要拒绝。静态 IP 允许列表很难完成这件事，因为 DNS 应答会变化，也会过期；到了 `connect()` 阶段，内核看到的又只是一个 IP 地址，并不知道它来自哪个域名。这里缺少的是一条短期关联，把应用刚刚完成的 DNS 解析和随后的连接连起来。

本课会把这条关联做成一个最小可运行的策略工具。它通过指定的 DNS 解析器观察一个域名，只从匹配的查询与响应中学习 IPv4 A 记录，并在 DNS TTL 有效期间允许访问一个 TCP 端口。

> 完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/55-dns-egress>

## eBPF 在哪里执行策略

eBPF 可以让经过验证器检查的程序运行在 Linux 内核 hook 上，通过 map 保留状态，也可以把选出的事件交给用户态。cgroup BPF 让这些 hook 跟随一组工作负载：packet program 可以观察 cgroup 的出入流量，socket-address program 则能在内核发起 IPv4 连接之前允许或拒绝这次请求。

这个例子在同一个 cgroup 上挂载三个程序。`cgroup_skb/egress` 识别指定的 DNS 问题并记录待匹配查询，`cgroup_skb/ingress` 只从与查询对应的响应中接纳地址，`cgroup/connect4` 对受保护的 TCP 端口作最终判断。ring buffer 负责报告 learned、allowed、denied 和 expired 事件，并不参与策略结果。

先跟着一次成功的解析走一遍。应用发送 `lab.test` 的 A 查询，egress hook 保存解析器地址、客户端地址、客户端 UDP 端口和 DNS transaction ID，这份记录有效 5 秒。响应回来后，ingress hook 用反向报文重建同一个 key，检查响应标志与 question，再读取第一个直接 A 应答。通过检查的地址会和 TTL 推导出的过期时间一起进入允许列表，随后发往这个地址和受保护端口的 `connect()` 可以在 TTL 内成功。

待匹配查询就是这里的信任边界。未经请求的响应没有 pending key，transaction ID 不同的响应也会查到另一个 key，因此两者都无法写入允许列表。connect hook 还会再次比较过期时间，即使 LRU map 中仍保留着旧条目，地址也会按 DNS 时间自然失效。

## DNS 协议与事件结构

共享头文件包含 BPF 程序需要解析的少量 DNS 布局，以及用户态接收的固定事件格式。

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

这些协议结构直接描述线上字节，因此使用 packed 布局。事件同时携带 DNS TTL 和内核单调时钟下的绝对过期时间，命令行展示 TTL，BPF 程序则用时间戳作策略判断。

## 三个 BPF hook

下面是完整的内核态程序。

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

`pending_queries` 和 `allowed_ips` 都是固定容量的 LRU hash map。前者保存最多 5 秒的查询关联状态，后者保存处于 DNS 生命周期内的 IPv4 地址。LRU 淘汰把内存开销限制在确定范围内；当条目超过 1024 个时，最近活跃的查询和地址也会得到优先保留。

egress 路径先验证 IPv4、UDP、分片状态、解析器地址和端口，再检查报文是不是指定名称的单 question A 查询。只有这些字段全部成立，`record_dns_query()` 才会插入四字段关联 key。程序返回 `1`，DNS 报文仍然按正常路径继续传输。

ingress 路径从反向 transport tuple 开始解析。`parse_response_question()` 补上 transaction ID，要求 pending entry 仍然有效，并验证这是包含指定 question 的成功响应。`parse_direct_a_answer()` 接受常见的 `0xc00c` 压缩 name pointer、IN class、A type、4 字节地址，以及 1 到 86400 秒的 TTL。应答通过以后，pending query 会被消费，解析出的 IP 才获得连接资格。

`enforce_dns_policy()` 的范围很窄。发往其他目的端口的 TCP 连接直接通过；发往受保护端口的连接使用 `ctx->user_ip4` 查表，有效条目返回 `1`，缺失或过期条目返回 `0`，应用会收到 `EPERM`。`expired_reported` 上的 64 位 compare-and-swap 让多个线程同时访问旧地址时只产生一次 expired 通知。BPF atomic compare-and-exchange 在 Linux 5.12 引入，这也确定了工具的最低内核版本。

## 加载策略并验证完整信任链

用户态程序会配置只读 BPF 数据，把三个程序附加到一个 cgroup，再消费 ring buffer 事件。

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

域名会在 BPF object 加载前编码为 DNS label 格式，例如 `lab.test` 会变成 `\x03lab\x04test\x00`，这正是 packet hook 逐字节比较的内容。解析器与端口写入 skeleton 的 `rodata`，验证器可以把它们视为常量。

普通模式会保持三个 link 存活，直到运行时间结束或收到退出信号。demo 模式用 loopback socket 走完信任链：先证明初始连接会被拒绝，再分别发送未经请求的应答和错误 ID 应答，随后接纳一个 TTL 为 1 秒的正确应答，最后等待它过期。这些检查很重要，因为“解析所有 DNS 响应”的简单实现也能通过成功路径，却很容易被伪造响应污染。

## 编译和运行

使用仓库内置的 libbpf 与 bpftool 构建示例：

```bash
cd src/55-dns-egress
make
```

将它挂到服务 cgroup，通过服务实际使用的解析器观察一个域名，并保护 TCP 443 端口：

```bash
sudo ./dns_egress \
  --cgroup /sys/fs/cgroup/my-service \
  --domain api.example.com \
  --dns-server 127.0.0.53 \
  --port 443
```

这个 cgroup 需要包含目标工作负载，让它的 DNS 报文和连接共享同一份策略状态。TCP 443 和 DNS 53 是默认端口，`--dns-port` 可以选择其他解析器端口，`--duration` 则为运行时间设置上限。内置 demo 不依赖外部 DNS 服务器：

```bash
sudo ./dns_egress --demo
```

一次真实运行的输出如下：

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

前三个 denied 说明，仅仅收到 DNS 格式的流量或者看到正确域名还不足以学习地址。只有关联正确的响应会产生 learned，allowed 覆盖它的有效 TTL，expired 之后的连接则立刻回到 denied。

## 环境要求

| 要求 | 说明 |
|---|---|
| 内核 | Linux 5.12 或更高版本，最新依赖来自 BPF atomic compare-and-exchange |
| 内核配置 | `CONFIG_BPF`、`CONFIG_BPF_SYSCALL`、`CONFIG_BPF_JIT`、`CONFIG_CGROUP_BPF`、`CONFIG_DEBUG_INFO_BTF`、`CONFIG_INET` |
| cgroup | cgroup v2，目标工作负载位于挂载目录之下 |
| 权限 | root，或者等价的 BPF 与网络管理 capability |
| 架构与硬件 | 当前声明并完成测试的目标是 x86-64，不需要特殊网卡 |

## 实现范围

这个工具处理一个精确域名、一个解析器、一个受保护的 TCP 端口、IPv4 UDP DNS 和第一个直接 A 应答，并识别常见的 `0xc00c` owner name。CNAME 链、多种 answer 布局、TCP DNS、IPv6、DoH 和 DoT 需要更多解析逻辑或新的观察位置。这个紧凑范围保留了策略最关键的性质：IP 通过最近一次匹配查询进入允许列表，再按照 DNS 时间退出。

## 总结

这个例子把观察到的 DNS 结果变成有时间边界的 connect 策略。egress 与 ingress hook 建立可信的查询响应关联，TTL 管理地址生命周期，connect hook 则对工作负载的受保护端口执行结果。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [BPF ring buffer](https://docs.kernel.org/bpf/ringbuf.html)
- [BPF LRU hash map](https://docs.kernel.org/bpf/map_hash.html)
- [BPF atomic compare-and-exchange 引入 commit](https://github.com/torvalds/linux/commit/5ffa25502b5ab3d639829a2d1e316cff7f59a41e)
- [Control Group v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [RFC 1035：Domain Names — Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035.html)
