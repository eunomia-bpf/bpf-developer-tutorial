# eBPF Tutorial by Example: Build a DNS-Derived IP Allowlist with cgroup BPF

Suppose a service may open HTTPS connections to `api.example.com`, while direct connections to every other address should be rejected. A static IP allowlist is a poor fit because DNS answers change and expire. A connect hook sees an IP address rather than the name that produced it. The missing piece is a short-lived link between the application's DNS exchange and its later `connect()` call.

This tutorial builds that link as a minimal working policy tool. It watches one domain through one configured DNS resolver, learns a direct IPv4 A record only from a matching query and response, and allows connections to one TCP port until the DNS TTL expires.

> Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/55-dns-egress>

## Where eBPF Enforces the Decision

eBPF runs verifier-checked programs at Linux kernel hooks and can retain state in maps or send selected events to user space. cgroup BPF makes those hooks follow a workload: packet programs can inspect traffic entering and leaving a cgroup, while a socket-address program can accept or reject an IPv4 connection before the kernel sends it.

This example attaches three programs to the same cgroup. `cgroup_skb/egress` recognizes the configured DNS question and records a pending query. `cgroup_skb/ingress` accepts an address into the allowlist only after the response matches that query. `cgroup/connect4` makes the final decision for the protected TCP port. The ring buffer reports learned, allowed, denied, and expired decisions without participating in enforcement.

Follow one successful exchange. The application sends an A query for `lab.test`. The egress hook saves the resolver address, client address, client UDP port, and DNS transaction ID for five seconds. When the reply returns, the ingress hook reconstructs the same key, checks the response flags and question, and reads the first direct A answer. It stores the returned address with an expiration time derived from the TTL. A later `connect()` to that address and the protected port succeeds while the entry is live.

The query record is the trust boundary. An unsolicited response has no pending key, and a response with a different transaction ID searches for a different key. Neither can populate the allowlist. Expiration is checked again at connect time, so an address naturally stops working even if its LRU entry is still present.

## Shared Protocol and Event Types

The shared header contains the small DNS layouts parsed by the BPF programs and the fixed event format consumed in user space.

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

The protocol structs are packed because they describe bytes on the wire. The event carries both the learned TTL and the absolute kernel expiration timestamp. The command prints the TTL, while the BPF side uses the monotonic timestamp for its decision.

## The Three BPF Hooks

Here is the complete kernel-side program.

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

`pending_queries` and `allowed_ips` are LRU hash maps with fixed capacities. The first map holds correlation state for at most five seconds. The second holds admitted IPv4 addresses for their DNS lifetime. LRU eviction keeps memory bounded; it also means this example favors recently active queries and addresses when either map reaches 1024 entries.

The egress path first validates IPv4, UDP, fragmentation state, resolver address, and resolver port. It then checks a standard one-question A query for the exact encoded name. Only after those checks does `record_dns_query()` insert the four-field correlation key. Packet observation itself returns `1`, so DNS traffic continues normally.

On ingress, parsing starts with the reverse transport tuple. `parse_response_question()` adds the transaction ID, requires a live pending entry, and verifies a successful response containing the configured question. `parse_direct_a_answer()` accepts the compact `0xc00c` name pointer, class IN, type A, four-byte address, and a TTL from 1 to 86400 seconds. Once the answer passes, the pending query is consumed and the IP becomes eligible for connections.

`enforce_dns_policy()` stays narrow. TCP connects to other destination ports pass immediately. A connect to the protected port looks up `ctx->user_ip4`; a live entry returns `1`, while a missing or expired entry returns `0`, which surfaces to the application as `EPERM`. The compare-and-swap on `expired_reported` keeps the expiry notification to one event even when several threads race on the stale address.

## Loading the Policy and Exercising Its Trust Chain

The complete user-space program configures the read-only BPF data, attaches all three programs to one cgroup, and consumes ring-buffer events.

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
	int dns_server = -1, dns_client = -1, listener = -1;
	int err = -1;

	dns_server = bind_udp(&server_address);
	dns_client = bind_udp(&client_address);
	listener = create_tcp_listener(options->port);
	if (dns_server < 0 || dns_client < 0 || listener < 0)
		goto cleanup;

	if (expect_blocked_connect(ring, options->port, "before-dns"))
		goto cleanup;

	if (send_unsolicited_dns(dns_server, dns_client, qname, qname_length))
		goto cleanup;
	if (poll_demo_events(ring) ||
	    expect_blocked_connect(ring, options->port, "unsolicited-response"))
		goto cleanup;

	if (begin_dns_exchange(dns_server, dns_client, &server_address, qname,
			       qname_length, dns_message, &query_length,
			       &response_client_address) ||
	    send_dns_answer(dns_server, dns_client, &response_client_address,
			    dns_message, query_length, DNS_ID + 1, 30))
		goto cleanup;
	if (poll_demo_events(ring) ||
	    expect_blocked_connect(ring, options->port, "wrong-transaction-id"))
		goto cleanup;

	if (send_dns_answer(dns_server, dns_client, &response_client_address,
			    dns_message, query_length, DNS_ID, 1))
		goto cleanup;
	if (poll_demo_events(ring) ||
	    expect_allowed_connect(ring, listener, options->port))
		goto cleanup;

	nanosleep(&wait_time, NULL);
	if (poll_demo_events(ring) ||
	    expect_blocked_connect(ring, options->port, "expired-answer"))
		goto cleanup;

	if (expected_demo_events())
		goto cleanup;
	err = 0;

cleanup:
	if (listener >= 0) close(listener);
	if (dns_client >= 0) close(dns_client);
	if (dns_server >= 0) close(dns_server);
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

The domain is converted to DNS label form before the BPF object is loaded. For example, `lab.test` becomes `\x03lab\x04test\x00`, the exact byte sequence compared in the packet hooks. The configured resolver and ports are written into skeleton `rodata`, which makes them constants from the verifier's point of view.

Normal mode keeps the links alive and prints policy decisions until the duration ends or a signal arrives. Demo mode runs the whole trust chain with loopback sockets. It first proves that a connection is blocked, sends an unsolicited answer and a wrong-ID answer, admits a correctly correlated one-second answer, then waits for that TTL to expire. These are useful checks because a simple “parse every DNS response” implementation would pass the happy path while remaining easy to poison.

## Build and Run

Build the example with the repository's vendored libbpf and bpftool:

```bash
cd src/55-dns-egress
make
```

Attach it to a service cgroup, watch one domain through its actual resolver, and protect TCP port 443:

```bash
sudo ./dns_egress \
  --cgroup /sys/fs/cgroup/my-service \
  --domain api.example.com \
  --dns-server 127.0.0.53 \
  --port 443
```

The cgroup must contain the workload whose DNS packets and connections should share the policy state. TCP port 443 and DNS port 53 are the defaults; `--dns-port` selects another resolver port, and `--duration` adds a time limit. The built-in demo needs no external DNS server:

```bash
sudo ./dns_egress --demo
```

A real demo run looks like this:

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

The three early `denied` events show that neither receiving DNS-shaped traffic nor seeing the right name is sufficient. `learned` appears only for the correlated response, `allowed` covers its live TTL, and `expired` is immediately followed by the denied connect.

## Requirements

| Requirement | Details |
|---|---|
| Kernel | Linux 5.8 or newer; the newest dependency is BPF ring buffer support |
| Kernel config | `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_CGROUP_BPF`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_INET` |
| cgroup | cgroup v2, with the target workload placed below the attached directory |
| Privileges | Root, or an equivalent set of BPF and network-administration capabilities |
| Architecture and hardware | x86-64 is the declared and tested target; no special network hardware |

## Scope

The tool deliberately implements one exact domain, one resolver, one protected TCP port, IPv4 UDP DNS, and the first direct A answer. It understands the common compressed owner name `0xc00c`. CNAME chains, several answer layouts, TCP DNS, IPv6, DoH, and DoT need additional parsers or observation points. This compact scope keeps the important policy property visible: an IP enters the allowlist through a recent matching query and leaves it through DNS time.

## Summary

This example turns an observed DNS result into a time-bounded connect policy. The egress and ingress hooks establish a trustworthy query-response relation, the TTL controls the address lifetime, and the connect hook enforces the result for the workload's protected port.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [BPF ring buffer](https://docs.kernel.org/bpf/ringbuf.html)
- [BPF LRU hash maps](https://docs.kernel.org/bpf/map_hash.html)
- [Control Group v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [RFC 1035: Domain Names — Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035.html)
