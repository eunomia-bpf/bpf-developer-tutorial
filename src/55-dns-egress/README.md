# eBPF Tutorial by Example: DNS-Aware Egress Policy Enforcement

How do you allow TCP connections on one protected port only to IP addresses that your application just resolved through DNS? This tutorial builds a cgroup-based egress filter that learns IPs from DNS responses, allows matching connections while the DNS TTL is valid, and rejects other destinations on that port. The kernel enforces the policy at connect time.

> Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/55-dns-egress>

## eBPF and cgroup Hooks

eBPF lets verified programs run at Linux kernel hooks and send selected state to user space. This tutorial uses cgroup BPF hooks to intercept network packets and connection attempts for one cgroup. The `cgroup_skb/egress` and `cgroup_skb/ingress` hooks observe DNS traffic, while `cgroup/connect4` intercepts IPv4 connect calls. LRU hash maps keep the most recently used query and address entries within fixed capacities, and the BPF ring buffer, introduced in Linux 5.8, carries policy events to user space. This implementation therefore requires Linux 5.8 or later.

## How the Implementation Works

The tool attaches three BPF programs to a cgroup. The egress program records outgoing DNS queries by saving the transaction ID, client port, and server IP as a pending query. Queries expire after 5 seconds if no matching response arrives. The ingress program learns IPs from DNS responses by verifying the response matches a pending query and extracting the A record IP with its TTL. For TCP connections to the configured protected port, the connect hook checks whether the destination IP exists in the allowed list and has not expired. Other destination ports proceed unchanged.

## Header File

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

The header defines DNS protocol structures used to parse packets. The `dns_header` structure matches the DNS message header format. The `dns_question` and `dns_a_answer` structures parse the query and answer sections. The `dns_egress_event` structure carries policy events (learned, allowed, denied, expired) to user space through the ring buffer.

## BPF Program

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

SEC("cgroup_skb/egress")
int record_dns_query(struct __sk_buff *skb)
{
	struct dns_query_state state = {
		.expires_ns = bpf_ktime_get_ns() + DNS_QUERY_LIFETIME_NS,
	};
	struct dns_query_key key = {};
	struct dns_question question;
	struct dns_header header;
	struct udphdr udp;
	struct iphdr ip;
	__u32 ip_header_len;
	__u32 dns_offset;
	__u16 flags;

	if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)))
		return 1;
	if (ip.version != 4 || ip.protocol != IPPROTO_UDP || ip.ihl < 5 ||
	    (bpf_ntohs(ip.frag_off) & (IP_MF | IP_OFFSET)) ||
	    ip.daddr != dns_server_ip)
		return 1;
	ip_header_len = ip.ihl * 4;
	if (bpf_skb_load_bytes(skb, ip_header_len, &udp, sizeof(udp)) ||
	    bpf_ntohs(udp.dest) != dns_server_port)
		return 1;
	dns_offset = ip_header_len + sizeof(udp);
	if (bpf_skb_load_bytes(skb, dns_offset, &header, sizeof(header)))
		return 1;
	flags = bpf_ntohs(header.flags);
	if ((flags & 0xf800) || bpf_ntohs(header.questions) != 1)
		return 1;
	if (!matches_qname(skb, dns_offset + sizeof(header)))
		return 1;
	dns_offset += sizeof(header) + configured_qname_length;
	if (bpf_skb_load_bytes(skb, dns_offset, &question, sizeof(question)) ||
	    bpf_ntohs(question.type) != 1 || bpf_ntohs(question.class) != 1)
		return 1;

	key.server_ip = ip.daddr;
	key.client_ip = ip.saddr;
	key.client_port = udp.source;
	key.transaction_id = header.id;
	bpf_map_update_elem(&pending_queries, &key, &state, BPF_ANY);
	return 1;
}

SEC("cgroup_skb/ingress")
int learn_dns_answer(struct __sk_buff *skb)
{
	struct dns_a_answer answer;
	struct dns_question question;
	struct dns_header header;
	struct dns_query_key query_key = {};
	struct dns_query_state *query;
	struct dns_state state = {};
	struct udphdr udp;
	struct iphdr ip;
	__u64 ttl_ns, expires;
	__u32 ip_header_len;
	__u32 dns_offset;
	__u32 key;
	__u32 ttl;

	if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)))
		return 1;
	if (ip.version != 4 || ip.protocol != IPPROTO_UDP || ip.ihl < 5 ||
	    (bpf_ntohs(ip.frag_off) & (IP_MF | IP_OFFSET)) ||
	    ip.saddr != dns_server_ip)
		return 1;
	ip_header_len = ip.ihl * 4;
	if (bpf_skb_load_bytes(skb, ip_header_len, &udp, sizeof(udp)) ||
	    bpf_ntohs(udp.source) != dns_server_port)
		return 1;
	dns_offset = ip_header_len + sizeof(udp);
	if (bpf_skb_load_bytes(skb, dns_offset, &header, sizeof(header)))
		return 1;
	query_key.server_ip = ip.saddr;
	query_key.client_ip = ip.daddr;
	query_key.client_port = udp.dest;
	query_key.transaction_id = header.id;
	query = bpf_map_lookup_elem(&pending_queries, &query_key);
	if (!query)
		return 1;
	if (bpf_ktime_get_ns() >= query->expires_ns) {
		bpf_map_delete_elem(&pending_queries, &query_key);
		return 1;
	}
	if ((bpf_ntohs(header.flags) & 0xf80f) != 0x8000 ||
	    bpf_ntohs(header.questions) != 1 || !bpf_ntohs(header.answers))
		return 1;
	if (!matches_qname(skb, dns_offset + sizeof(header)))
		return 1;
	dns_offset += sizeof(header) + configured_qname_length;
	if (bpf_skb_load_bytes(skb, dns_offset, &question, sizeof(question)) ||
	    bpf_ntohs(question.type) != 1 || bpf_ntohs(question.class) != 1)
		return 1;
	dns_offset += sizeof(question);
	if (bpf_skb_load_bytes(skb, dns_offset, &answer, sizeof(answer)) ||
	    bpf_ntohs(answer.name) != 0xc00c || bpf_ntohs(answer.type) != 1 ||
	    bpf_ntohs(answer.class) != 1 ||
	    bpf_ntohs(answer.address_length) != 4)
		return 1;
	bpf_map_delete_elem(&pending_queries, &query_key);

	key = answer.address;
	ttl = bpf_ntohl(answer.ttl);
	if (!ttl || ttl > 86400)
		return 1;
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

The BPF program uses three maps. The `pending_queries` LRU hash tracks outgoing DNS queries using a composite key of server IP, client IP, client port, and transaction ID. The `allowed_ips` LRU hash stores learned IPs with their expiration timestamps. The `events` ring buffer sends policy decisions to user space.

The `record_dns_query` function runs on cgroup egress and captures DNS queries to the configured resolver. It validates the packet is IPv4 UDP to the correct server and port, checks the query name matches, and stores the query with a 5-second expiration.

The `learn_dns_answer` function runs on cgroup ingress and parses DNS responses. It looks up the matching pending query, validates the response format, extracts the IP address and TTL from the first A record, and stores the IP in the allowed list with the TTL-based expiration.

The `enforce_dns_policy` function runs when a process calls `connect()`. IPv4 TCP connections to the configured protected port are checked against the allowed list and its expiration timestamps. A successful lookup returns 1 to permit the connection; a missing or stale entry returns 0, which makes `connect()` fail with `EPERM`. Connections to other ports return 1 immediately.

## User Space Program

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
				     NULL)) != -1) {
		switch (option) {
		case 'c': options->cgroup_path = optarg; break;
		case 'n': options->domain = optarg; break;
		case 'r': options->dns_server = optarg; break;
		case 'p':
			if (parse_uint(optarg, 65535, &options->port) ||
			    !options->port)
				return -1;
			break;
		case 's':
			if (parse_uint(optarg, 65535, &options->dns_port) ||
			    !options->dns_port)
				return -1;
			break;
		case 'd':
			if (parse_uint(optarg, 86400,
				       &options->duration_seconds))
				return -1;
			break;
		case 'D': options->demo = true; break;
		case 'h': usage(argv[0]); exit(0);
		default: return -1;
		}
	}
	if (optind != argc)
		return -1;
	if (options->demo) {
		if (options->cgroup_path || options->domain || options->dns_server)
			return -1;
		options->cgroup_path = "/sys/fs/cgroup";
		options->domain = "lab.test";
		options->dns_server = "127.0.0.1";
		options->port = DEMO_TCP_PORT;
		options->dns_port = DEMO_DNS_PORT;
		return 0;
	}
	return options->cgroup_path && options->domain && options->dns_server ?
	       0 : -1;
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

	if (accepted < 0)
		return -1;
	if (write(accepted, &byte, 1) != 1 || read(client, &byte, 1) != 1) {
		close(accepted);
		return -1;
	}
	close(accepted);
	close(client);
	return 0;
}

static int run_demo(struct ring_buffer *ring, const struct options *options,
		    const unsigned char *qname, unsigned int qname_length)
{
	struct sockaddr_in server_address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(options->dns_port),
	};
	struct sockaddr_in client_address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct timespec wait_time = { .tv_sec = 1, .tv_nsec = 300000000 };
	struct sockaddr_in response_client_address;
	unsigned char dns_message[512];
	size_t query_length;
	int dns_server = -1, dns_client = -1, listener = -1, client = -1;
	int err = -1;

	dns_server = bind_udp(&server_address);
	dns_client = bind_udp(&client_address);
	listener = create_tcp_listener(options->port);
	if (dns_server < 0 || dns_client < 0 || listener < 0)
		goto cleanup;

	errno = 0;
	client = connect_tcp(options->port);
	if (client >= 0 || errno != EPERM)
		goto cleanup;
	ring_buffer__poll(ring, 100);
	printf("demo step=before-dns result=blocked\n");

	if (send_unsolicited_dns(dns_server, dns_client, qname, qname_length))
		goto cleanup;
	ring_buffer__poll(ring, 100);
	errno = 0;
	client = connect_tcp(options->port);
	if (client >= 0 || errno != EPERM)
		goto cleanup;
	ring_buffer__poll(ring, 100);
	printf("demo step=unsolicited-response result=blocked\n");

	if (begin_dns_exchange(dns_server, dns_client, &server_address, qname,
			       qname_length, dns_message, &query_length,
			       &response_client_address) ||
	    send_dns_answer(dns_server, dns_client, &response_client_address,
			    dns_message, query_length, DNS_ID + 1, 30))
		goto cleanup;
	ring_buffer__poll(ring, 100);
	errno = 0;
	client = connect_tcp(options->port);
	if (client >= 0 || errno != EPERM)
		goto cleanup;
	ring_buffer__poll(ring, 100);
	printf("demo step=wrong-transaction-id result=blocked\n");

	if (send_dns_answer(dns_server, dns_client, &response_client_address,
			    dns_message, query_length, DNS_ID, 1))
		goto cleanup;
	ring_buffer__poll(ring, 100);
	client = connect_tcp(options->port);
	if (client < 0 || complete_tcp(listener, client))
		goto cleanup;
	client = -1;
	ring_buffer__poll(ring, 100);
	printf("demo step=live-answer result=allowed\n");

	nanosleep(&wait_time, NULL);
	ring_buffer__poll(ring, 100);
	errno = 0;
	client = connect_tcp(options->port);
	if (client >= 0 || errno != EPERM)
		goto cleanup;
	ring_buffer__poll(ring, 100);
	printf("demo step=expired-answer result=blocked\n");

	if (event_counts[DNS_LEARNED] != 1 || event_counts[DNS_ALLOWED] != 1 ||
	    event_counts[DNS_DENIED] != 4 || event_counts[DNS_EXPIRED] != 1)
		goto cleanup;
	err = 0;

cleanup:
	if (client >= 0) close(client);
	if (listener >= 0) close(listener);
	if (dns_client >= 0) close(dns_client);
	if (dns_server >= 0) close(dns_server);
	return err;
}

int main(int argc, char **argv)
{
	struct options options = { .port = 443, .dns_port = 53 };
	struct dns_egress_bpf *skel = NULL;
	struct bpf_link *query_link = NULL, *ingress_link = NULL;
	struct bpf_link *connect_link = NULL;
	struct ring_buffer *ring = NULL;
	struct in_addr dns_server = {};
	unsigned char qname[DNS_QNAME_MAX] = {};
	unsigned long long deadline = 0;
	unsigned int qname_length = 0;
	int cgroup_fd = -1;
	int err = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (parse_options(argc, argv, &options) ||
	    encode_qname(options.domain, qname, &qname_length) ||
	    inet_pton(AF_INET, options.dns_server, &dns_server) != 1) {
		usage(argv[0]);
		return 2;
	}
	cgroup_fd = open(options.cgroup_path,
			 O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cgroup_fd < 0) {
		fprintf(stderr, "failed to open cgroup %s: %s\n",
			options.cgroup_path, strerror(errno));
		goto cleanup;
	}

	skel = dns_egress_bpf__open();
	if (!skel)
		goto cleanup;
	skel->rodata->target_tgid = options.demo ? getpid() : 0;
	skel->rodata->dns_server_ip = dns_server.s_addr;
	skel->rodata->dns_server_port = options.dns_port;
	skel->rodata->protected_tcp_port = options.port;
	skel->rodata->configured_qname_length = qname_length;
	memcpy((void *)skel->rodata->configured_qname, qname, qname_length);
	if (dns_egress_bpf__load(skel)) {
		fprintf(stderr, "failed to load DNS egress BPF programs\n");
		goto cleanup;
	}
	query_link = bpf_program__attach_cgroup(skel->progs.record_dns_query,
					       cgroup_fd);
	ingress_link = bpf_program__attach_cgroup(skel->progs.learn_dns_answer,
						 cgroup_fd);
	connect_link = bpf_program__attach_cgroup(skel->progs.enforce_dns_policy,
						 cgroup_fd);
	if (libbpf_get_error(query_link) || libbpf_get_error(ingress_link) ||
	    libbpf_get_error(connect_link)) {
		fprintf(stderr, "failed to attach programs to cgroup %s\n",
			options.cgroup_path);
		query_link = libbpf_get_error(query_link) ? NULL : query_link;
		ingress_link = libbpf_get_error(ingress_link) ? NULL : ingress_link;
		connect_link = libbpf_get_error(connect_link) ? NULL : connect_link;
		goto cleanup;
	}
	ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
				NULL, NULL);
	if (!ring)
		goto cleanup;

	printf("dns-egress attached cgroup=%s domain=%s resolver=%s tcp_port=%u dns_port=%u\n",
	       options.cgroup_path, options.domain, options.dns_server,
	       options.port, options.dns_port);
	if (options.demo) {
		if (run_demo(ring, &options, qname, qname_length))
			goto cleanup;
	} else {
		signal(SIGINT, handle_signal);
		signal(SIGTERM, handle_signal);
		if (options.duration_seconds)
			deadline = monotonic_ns() +
				   (unsigned long long)options.duration_seconds *
				   1000000000ULL;
		while (!stop && (!deadline || monotonic_ns() < deadline)) {
			int poll_result = ring_buffer__poll(ring, 100);

			if (poll_result < 0 && poll_result != -EINTR) {
				fprintf(stderr, "ring buffer poll failed: %d\n",
					poll_result);
				goto cleanup;
			}
		}
	}
	err = 0;

cleanup:
	ring_buffer__free(ring);
	bpf_link__destroy(connect_link);
	bpf_link__destroy(ingress_link);
	bpf_link__destroy(query_link);
	if (cgroup_fd >= 0) close(cgroup_fd);
	dns_egress_bpf__destroy(skel);
	return err;
}
```

The user space program loads and attaches the BPF programs to a cgroup. It encodes the domain name in DNS label format, configures the BPF programs with the target resolver and protected port, and polls the ring buffer for policy events.

The demo mode runs a self-contained test: it creates local UDP and TCP sockets, simulates DNS resolution, and verifies the policy works correctly. It tests connection blocking before DNS, rejection of unsolicited responses, rejection of wrong transaction IDs, connection allowing after valid DNS, and connection blocking after TTL expiry.

## Compilation and Execution

Build the example:

```bash
cd src/55-dns-egress
make
```

Run with the required parameters:

```bash
sudo ./dns_egress --cgroup /sys/fs/cgroup/my-service --domain api.example.com --dns-server 127.0.0.53 --port 443
```

Or run the built-in demo:

```bash
sudo ./dns_egress --demo
```

Example demo output:

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

## Requirements

| Requirement | Details |
|-------------|---------|
| Kernel | Linux 5.8+ (BPF ring buffer) |
| Config | `CONFIG_BPF_SYSCALL`, `CONFIG_CGROUP_BPF`, `CONFIG_DEBUG_INFO_BTF` |
| Privileges | Root |
| cgroup | cgroup v2 mounted |

## Scope and Limitations

This implementation protects one configured TCP destination port and leaves other ports unchanged. It supports one exact query name configured at startup, IPv4 UDP DNS only, and parses direct first A record answers. Pending queries expire after 5 seconds. Allowed IPs use a 1024-entry LRU hash with DNS TTL. It does not handle CNAME chains, multiple answer layouts, TCP DNS, IPv6, DNS-over-HTTPS, or DNS-over-TLS.

## Summary

By correlating each DNS response with a recent query and carrying its TTL into connect-time policy, this example turns one domain name into a short-lived kernel allowlist. The three cgroup hooks separate DNS observation from connection enforcement, while ring buffer events make every decision visible in user space.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [BPF ring buffer documentation](https://docs.kernel.org/6.6/bpf/ringbuf.html)
- [BPF hash map documentation](https://docs.kernel.org/bpf/map_hash.html)
- [cgroup BPF commit](https://github.com/torvalds/linux/commit/d74bad4e74ee)
