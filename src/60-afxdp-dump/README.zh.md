# eBPF 实战教程：用 AF_XDP 实现高性能 UDP 抓包

你有没有好奇过 Suricata 这样的抓包工具或者高频交易系统是如何每秒接收数百万个报文而不被内核开销拖垮的？秘密在于绕过大部分网络协议栈。AF_XDP 让你在网卡驱动入口拦截报文，直接复制到应用程序的内存空间，处理时几乎不需要为每个报文做系统调用。

本教程从零开始，使用原始的 AF_XDP 接口构建一个完整的抓包工具。没有辅助库，没有魔法抽象。你会清楚看到 UMEM 注册、ring buffer 和 XDP 重定向是如何协同工作的。最终成果是 `afxdp-dump`，一个捕获指定端口 IPv4 UDP 报文、打印 payload 预览、并正确回收每个 frame 以持续接收的工具。

> 完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/60-afxdp-dump>

## 为什么选择 AF_XDP？

传统的 `libpcap` 或 raw socket 抓包有一个根本问题：每个报文都要通过昂贵的系统调用跨越内核与用户态的边界。当你抓取 10 Gbps 流量时，这些开销会成为瓶颈，而不是你的处理代码。

AF_XDP 通过在内核和用户态之间建立共享内存来解决这个问题。内核把报文直接写入你的应用程序可以读取的内存，双方通过无锁的 ring buffer 通信，而不是系统调用。一次 `poll()` 就能唤醒你处理数百个报文。这种架构在普通硬件上就能达到每秒数百万报文的接收速率。

这项技术已经在生产环境中使用。Meta 的负载均衡器运行 AF_XDP，Cilium 用它做 Kubernetes 网络，高频交易公司用它来缩短微秒级延迟。即使你永远不会构建交易系统，理解 AF_XDP 也能教会你高性能系统中反复出现的模式：共享内存、无锁数据结构、显式的所有权转移。

## AF_XDP 架构

AF_XDP 通过四个必须精确协调的组件工作：

**UMEM（User Memory）** 是你分配的、内核和用户态都能访问的内存区域。你把它划分为固定大小的 frame，通常每个 4096 字节。内核送达的每个报文都会放进这些 frame 之一。

**Fill Ring** 是你告诉内核哪些 frame 可用于接收报文的方式。你把 frame 地址发布到这里，内核需要存放报文时就会消费这些地址。

**RX Ring** 是内核通知你已接收报文的地方。每个 entry 包含 frame 地址和报文长度。当你在这里看到 entry 时，你就拥有那个 frame 的所有权，直到你归还它。

**XSKMAP** 是一个 BPF map，用于连接 XDP 程序和 AF_XDP socket。XDP 程序决定重定向哪些报文，在这个 map 中查找当前 RX queue 对应的 socket，然后调用 `bpf_redirect_map()` 来投递报文。

流程是这样的：你向 Fill Ring 发布 64 个 frame 地址。一个 UDP 报文到达。你的 XDP 程序检查目的端口，在 XSKMAP 中查找 socket，然后重定向。内核把报文复制到你的某个 frame 中，并在 RX Ring 上发布一个 descriptor。你读取 descriptor、处理报文，再把这个 frame 地址放回 Fill Ring。循环继续。

这个所有权模型至关重要。一个 frame 开始时属于你。你通过 Fill Ring 借给内核。内核借用它来接收报文。你从 RX Ring 回收它。你必须把它归还到 Fill Ring，否则 64 个报文之后就会耗尽 frame。我们的工具通过成功捕获 65 个报文来证明这个机制有效——这需要至少一个 frame 完成完整的所有权周期。

## XDP 程序：过滤和重定向

内核侧的 BPF 程序很精简，因为它只负责过滤和重定向。buffer 管理的所有复杂性都在用户态。

首先，我们定义一个共享头文件来设置 XSKMAP 容量。queue ID 是 map 的 key，所以这个例子可以寻址 0 到 63 号队列：

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __AFXDP_DUMP_H
#define __AFXDP_DUMP_H

#define AFXDP_MAX_QUEUES 64

#endif /* __AFXDP_DUMP_H */
```

现在是 XDP 程序本身：

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "afxdp_dump.h"

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define IP_MF 0x2000
#define IP_OFFSET 0x1fff

const volatile __u16 capture_port = 8080;

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, AFXDP_MAX_QUEUES);
	__type(key, __u32);
	__type(value, __u32);
} xsk_map SEC(".maps");

__u64 redirected_packets;

SEC("xdp")
int redirect_udp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *ethernet = data;
	struct iphdr *ip;
	struct udphdr *udp;
	__u32 queue = ctx->rx_queue_index;
	__u32 ip_header_length;
	__u32 ip_length;
	__u32 udp_length;

	if ((void *)(ethernet + 1) > data_end ||
	    ethernet->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	ip = (void *)(ethernet + 1);
	if ((void *)(ip + 1) > data_end || ip->version != 4 ||
	    ip->protocol != IPPROTO_UDP ||
	    ip->ihl < 5 || (bpf_ntohs(ip->frag_off) & (IP_MF | IP_OFFSET)))
		return XDP_PASS;
	ip_header_length = ip->ihl * 4;
	ip_length = bpf_ntohs(ip->tot_len);
	udp = (void *)ip + ip_header_length;
	if (ip_length < ip_header_length + sizeof(*udp) ||
	    (void *)ip + ip_length > data_end ||
	    (void *)(udp + 1) > data_end)
		return XDP_PASS;
	udp_length = bpf_ntohs(udp->len);
	if (udp_length < sizeof(*udp) ||
	    udp_length > ip_length - ip_header_length ||
	    udp->dest != bpf_htons(capture_port))
		return XDP_PASS;
	if (!bpf_map_lookup_elem(&xsk_map, &queue))
		return XDP_PASS;
	__sync_fetch_and_add(&redirected_packets, 1);
	return bpf_redirect_map(&xsk_map, queue, XDP_PASS);
}
```

程序逐层解析报文，在每一步都验证边界。这种仔细的边界检查是 BPF 验证器的要求，同时也确保我们不会误解截断或畸形的报文。

解析从 Ethernet 开始，检查是否有足够空间容纳头部，以及 EtherType 是否表示 IPv4。然后验证 IPv4 头部：正确的版本、UDP 协议、最小头部长度、没有分片（分片报文需要重组，超出了我们的范围）。程序从 IHL 字段计算实际的 IP 头部长度，并用它来定位 UDP 头部。

UDP 验证确保长度字段合理，目的端口与目标匹配。只有这时程序才检查这个 queue 是否真的注册了 socket。这个顺序是刻意的：大多数报文会在更早的检查中失败，所以对不会捕获的报文我们避免了 map lookup 的开销。

XSKMAP lookup 也是一个安全检查。如果用户态没有为这个 queue 注册 socket，lookup 返回 NULL，我们就把报文传递给普通协议栈。当所有检查都通过时，`bpf_redirect_map()` 把报文发送到 AF_XDP。第二个参数是 queue index，会成为 map 的 key。第三个参数是出错时的回退 action。

一个重要细节：一旦报文被重定向，它就被 AF_XDP 消费了。普通的 socket 协议栈永远不会看到它。这正是抓包工具需要的，但这意味着你需要小心选择重定向什么。

## 用户态应用程序

用户态代码处理 AF_XDP 需要的一切：内存分配、ring 设置、socket 绑定、XDP 加载和接收循环。以下是完整实现：

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#define _FILE_OFFSET_BITS 64
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "afxdp_dump.h"
#include "afxdp_dump.skel.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif
#ifndef AF_XDP
#define AF_XDP 44
#endif
#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define FRAME_SIZE 4096
#define FRAME_COUNT 64
#define RING_SIZE 64
#define UMEM_SIZE ((size_t)FRAME_SIZE * FRAME_COUNT)
#define PAYLOAD_PREVIEW 32
#define IPV4_MORE_FRAGMENTS 0x2000
#define IPV4_FRAGMENT_OFFSET 0x1fff

struct options {
	const char *interface;
	unsigned int queue;
	unsigned int port;
	unsigned int count;
	bool skb_mode;
};

struct mapped_ring {
	void *mapping;
	size_t mapping_size;
	unsigned int *producer;
	unsigned int *consumer;
	unsigned int *flags;
	void *descriptors;
	unsigned int mask;
};

struct xsk_state {
	int fd;
	void *umem;
	struct mapped_ring fill;
	struct mapped_ring completion;
	struct mapped_ring rx;
};

static volatile sig_atomic_t stop;

static void handle_signal(int signal_number)
{
	(void)signal_number;
	stop = 1;
}

static void map_ring_fields(struct mapped_ring *ring, void *mapping,
			    size_t mapping_size,
			    const struct xdp_ring_offset *offset)
{
	ring->mapping = mapping;
	ring->mapping_size = mapping_size;
	ring->producer = mapping + offset->producer;
	ring->consumer = mapping + offset->consumer;
	ring->flags = mapping + offset->flags;
	ring->descriptors = mapping + offset->desc;
	ring->mask = RING_SIZE - 1;
}

static int map_xsk_ring(struct mapped_ring *ring, int fd,
			const struct xdp_ring_offset *offset,
			off_t page_offset, size_t descriptor_size)
{
	size_t size = offset->desc + RING_SIZE * descriptor_size;
	void *mapping;

	mapping = mmap(NULL, size, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_POPULATE, fd, page_offset);
	if (mapping == MAP_FAILED)
		return -1;
	map_ring_fields(ring, mapping, size, offset);
	return 0;
}

static void close_xsk(struct xsk_state *xsk)
{
	struct mapped_ring *rings[] = {
		&xsk->rx, &xsk->completion, &xsk->fill,
	};

	for (size_t i = 0; i < sizeof(rings) / sizeof(rings[0]); i++)
		if (rings[i]->mapping && rings[i]->mapping != MAP_FAILED)
			munmap(rings[i]->mapping, rings[i]->mapping_size);
	if (xsk->fd >= 0)
		close(xsk->fd);
	if (xsk->umem && xsk->umem != MAP_FAILED)
		munmap(xsk->umem, UMEM_SIZE);
	memset(xsk, 0, sizeof(*xsk));
	xsk->fd = -1;
}

static int open_xsk(struct xsk_state *xsk, int ifindex, unsigned int queue)
{
	struct xdp_umem_reg registration = {
		.len = UMEM_SIZE,
		.chunk_size = FRAME_SIZE,
	};
	struct sockaddr_xdp address = {
		.sxdp_family = PF_XDP,
		.sxdp_ifindex = ifindex,
		.sxdp_queue_id = queue,
		.sxdp_flags = XDP_COPY,
	};
	struct xdp_mmap_offsets offsets;
	socklen_t offsets_size = sizeof(offsets);
	unsigned int ring_size = RING_SIZE;
	unsigned long long *fill_addresses;

	memset(xsk, 0, sizeof(*xsk));
	xsk->fd = -1;
	xsk->umem = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (xsk->umem == MAP_FAILED)
		return -1;
	xsk->fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (xsk->fd < 0)
		return -1;
	registration.addr = (uintptr_t)xsk->umem;
	if (setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_REG, &registration,
		       sizeof(registration)) ||
	    setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_FILL_RING, &ring_size,
		       sizeof(ring_size)) ||
	    setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &ring_size,
		       sizeof(ring_size)) ||
	    setsockopt(xsk->fd, SOL_XDP, XDP_RX_RING, &ring_size,
		       sizeof(ring_size)) ||
	    getsockopt(xsk->fd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets,
		       &offsets_size))
		return -1;

	if (map_xsk_ring(&xsk->fill, xsk->fd, &offsets.fr,
			 XDP_UMEM_PGOFF_FILL_RING, sizeof(unsigned long long)) ||
	    map_xsk_ring(&xsk->completion, xsk->fd, &offsets.cr,
			 XDP_UMEM_PGOFF_COMPLETION_RING,
			 sizeof(unsigned long long)) ||
	    map_xsk_ring(&xsk->rx, xsk->fd, &offsets.rx,
			 XDP_PGOFF_RX_RING, sizeof(struct xdp_desc)) ||
	    bind(xsk->fd, (struct sockaddr *)&address, sizeof(address)))
		return -1;

	fill_addresses = xsk->fill.descriptors;
	for (unsigned int i = 0; i < FRAME_COUNT; i++)
		fill_addresses[i & xsk->fill.mask] =
			(unsigned long long)i * FRAME_SIZE;
	__atomic_store_n(xsk->fill.producer, FRAME_COUNT, __ATOMIC_RELEASE);
	return 0;
}

static unsigned long long data_address(unsigned long long address)
{
	return (address & XSK_UNALIGNED_BUF_ADDR_MASK) +
	       (address >> XSK_UNALIGNED_BUF_OFFSET_SHIFT);
}

static int recycle_frame(struct xsk_state *xsk, unsigned long long address)
{
	unsigned long long *fill_addresses = xsk->fill.descriptors;
	unsigned int producer, consumer;

	producer = __atomic_load_n(xsk->fill.producer, __ATOMIC_RELAXED);
	consumer = __atomic_load_n(xsk->fill.consumer, __ATOMIC_ACQUIRE);
	if (producer - consumer == RING_SIZE)
		return -1;
	fill_addresses[producer & xsk->fill.mask] = address;
	__atomic_store_n(xsk->fill.producer, producer + 1, __ATOMIC_RELEASE);
	return 0;
}

static const struct iphdr *parse_ipv4(const void *packet, unsigned int length,
				      unsigned int *ip_header_length,
				      unsigned int *ip_length)
{
	const struct ethhdr *ethernet = packet;
	const struct iphdr *ip;
	unsigned int available_ip;

	if (length < sizeof(*ethernet) + sizeof(*ip) ||
	    ethernet->h_proto != htons(ETH_P_IP))
		return NULL;
	ip = packet + sizeof(*ethernet);
	*ip_header_length = ip->ihl * 4;
	if (ip->version != 4 || ip->protocol != IPPROTO_UDP ||
	    (ntohs(ip->frag_off) &
	     (IPV4_MORE_FRAGMENTS | IPV4_FRAGMENT_OFFSET)) ||
	    *ip_header_length < sizeof(*ip) ||
	    length < sizeof(*ethernet) + *ip_header_length)
		return NULL;
	*ip_length = ntohs(ip->tot_len);
	available_ip = length - sizeof(*ethernet);
	if (*ip_length < *ip_header_length + sizeof(struct udphdr) ||
	    *ip_length > available_ip)
		return NULL;
	return ip;
}

static const struct udphdr *parse_udp(const void *packet,
				      unsigned int length,
				      unsigned int ip_header_length,
				      unsigned int ip_length,
				      const unsigned char **payload,
				      unsigned int *payload_length)
{
	const struct udphdr *udp = packet + sizeof(struct ethhdr) +
				    ip_header_length;
	unsigned int available_payload;
	unsigned int udp_length;

	*payload = (const unsigned char *)(udp + 1);
	udp_length = ntohs(udp->len);
	available_payload = length - (*payload - (const unsigned char *)packet);
	if (udp_length < sizeof(*udp) ||
	    udp_length > ip_length - ip_header_length ||
	    udp_length - sizeof(*udp) > available_payload)
		return NULL;
	*payload_length = udp_length - sizeof(*udp);
	return udp;
}

static void dump_packet(const void *packet, unsigned int length,
			unsigned int packet_number)
{
	const struct iphdr *ip;
	const struct udphdr *udp;
	const unsigned char *payload;
	char source[INET_ADDRSTRLEN], destination[INET_ADDRSTRLEN];
	char preview[PAYLOAD_PREVIEW + 1];
	unsigned int ip_header_length, ip_length, payload_length, preview_length;

	ip = parse_ipv4(packet, length, &ip_header_length, &ip_length);
	if (!ip)
		return;
	udp = parse_udp(packet, length, ip_header_length, ip_length, &payload,
			&payload_length);
	if (!udp)
		return;
	preview_length = payload_length < PAYLOAD_PREVIEW ?
			 payload_length : PAYLOAD_PREVIEW;
	for (unsigned int i = 0; i < preview_length; i++)
		preview[i] = isprint(payload[i]) ? payload[i] : '.';
	preview[preview_length] = '\0';
	inet_ntop(AF_INET, &ip->saddr, source, sizeof(source));
	inet_ntop(AF_INET, &ip->daddr, destination, sizeof(destination));
	printf("packet=%u %s:%u -> %s:%u bytes=%u payload=\"%s\"\n",
	       packet_number, source, ntohs(udp->source), destination,
	       ntohs(udp->dest), length, preview);
}

static int receive_packets(struct xsk_state *xsk, unsigned int count)
{
	struct pollfd poll_fd = { .fd = xsk->fd, .events = POLLIN };
	unsigned int received = 0;

	while (!stop && (!count || received < count)) {
		unsigned int consumer, producer;
		int poll_result = poll(&poll_fd, 1, 250);

		if (poll_result < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!poll_result)
			continue;
		consumer = __atomic_load_n(xsk->rx.consumer, __ATOMIC_RELAXED);
		producer = __atomic_load_n(xsk->rx.producer, __ATOMIC_ACQUIRE);
		while (consumer != producer && (!count || received < count)) {
			struct xdp_desc *descriptors = xsk->rx.descriptors;
			struct xdp_desc descriptor =
				descriptors[consumer & xsk->rx.mask];
			unsigned long long address = data_address(descriptor.addr);

			if (descriptor.options & XDP_PKT_CONTD) {
				errno = EMSGSIZE;
				return -1;
			}
			if (address + descriptor.len > UMEM_SIZE) {
				errno = EFAULT;
				return -1;
			}
			received++;
			dump_packet(xsk->umem + address, descriptor.len, received);
			consumer++;
			__atomic_store_n(xsk->rx.consumer, consumer,
					 __ATOMIC_RELEASE);
			if (recycle_frame(xsk, descriptor.addr)) {
				errno = ENOBUFS;
				return -1;
			}
		}
	}
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
	printf("Usage: %s --interface IFACE [--queue N] [--port PORT] [--count N] [--skb-mode]\n",
	       program);
}

static int parse_options(int argc, char **argv, struct options *options)
{
	static const struct option long_options[] = {
		{ "interface", required_argument, NULL, 'i' },
		{ "queue", required_argument, NULL, 'q' },
		{ "port", required_argument, NULL, 'p' },
		{ "count", required_argument, NULL, 'n' },
		{ "skb-mode", no_argument, NULL, 'S' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "i:q:p:n:Sh", long_options,
				     NULL)) != -1) {
		switch (option) {
		case 'i': options->interface = optarg; break;
		case 'q':
			if (parse_uint(optarg, AFXDP_MAX_QUEUES - 1,
				       &options->queue))
				return -1;
			break;
		case 'p':
			if (parse_uint(optarg, 65535, &options->port) ||
			    !options->port)
				return -1;
			break;
		case 'n':
			if (parse_uint(optarg, 1000000, &options->count))
				return -1;
			break;
		case 'S': options->skb_mode = true; break;
		case 'h': usage(argv[0]); exit(0);
		default: return -1;
		}
	}
	return optind == argc && options->interface ? 0 : -1;
}

static int attach_xdp(int ifindex, int program_fd, bool skb_mode,
		      unsigned int *attached_flags)
{
	unsigned int flags = XDP_FLAGS_UPDATE_IF_NOEXIST |
			     (skb_mode ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE);
	int err;

	err = bpf_xdp_attach(ifindex, program_fd, flags, NULL);
	if (err && !skb_mode && (err == -EOPNOTSUPP || err == -EINVAL)) {
		flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
		err = bpf_xdp_attach(ifindex, program_fd, flags, NULL);
	}
	if (!err)
		*attached_flags = flags;
	return err;
}

int main(int argc, char **argv)
{
	struct options options = { .port = 8080 };
	struct afxdp_dump_bpf *skel = NULL;
	struct xsk_state xsk;
	unsigned int attached_flags = 0;
	int ifindex;
	int err = 1;
	bool attached = false;

	setvbuf(stdout, NULL, _IONBF, 0);
	memset(&xsk, 0, sizeof(xsk));
	xsk.fd = -1;
	if (parse_options(argc, argv, &options)) {
		usage(argv[0]);
		return 2;
	}
	ifindex = if_nametoindex(options.interface);
	if (!ifindex) {
		fprintf(stderr, "unknown interface: %s\n", options.interface);
		return 2;
	}
	if (open_xsk(&xsk, ifindex, options.queue)) {
		fprintf(stderr, "failed to create AF_XDP socket: %s\n",
			strerror(errno));
		goto cleanup;
	}
	skel = afxdp_dump_bpf__open();
	if (!skel)
		goto cleanup;
	skel->rodata->capture_port = options.port;
	if (afxdp_dump_bpf__load(skel)) {
		fprintf(stderr, "failed to load XDP program\n");
		goto cleanup;
	}
	if (bpf_map__update_elem(skel->maps.xsk_map, &options.queue,
				 sizeof(options.queue), &xsk.fd, sizeof(xsk.fd),
				 BPF_ANY)) {
		fprintf(stderr, "failed to populate XSK map: %s\n", strerror(errno));
		goto cleanup;
	}
	{
		int attach_error = attach_xdp(ifindex,
				bpf_program__fd(skel->progs.redirect_udp),
				options.skb_mode, &attached_flags);

		if (attach_error) {
			fprintf(stderr, "failed to attach XDP program: %s\n",
				strerror(-attach_error));
			goto cleanup;
		}
	}
	attached = true;
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	printf("afxdp-dump ready interface=%s queue=%u port=%u mode=%s count=%u\n",
	       options.interface, options.queue, options.port,
	       attached_flags & XDP_FLAGS_SKB_MODE ? "skb" : "driver",
	       options.count);

	if (receive_packets(&xsk, options.count)) {
		fprintf(stderr, "AF_XDP receive failed: %s\n", strerror(errno));
		goto cleanup;
	}
	printf("redirected=%llu\n",
	       (unsigned long long)skel->bss->redirected_packets);
	err = 0;

cleanup:
	if (attached) {
		LIBBPF_OPTS(bpf_xdp_attach_opts, detach_options,
			    .old_prog_fd = bpf_program__fd(
				    skel->progs.redirect_udp));
		int detach_error = bpf_xdp_detach(
			ifindex, attached_flags & XDP_FLAGS_MODES,
			&detach_options);

		if (detach_error) {
			fprintf(stderr, "failed to detach XDP program: %s\n",
				strerror(-detach_error));
			err = 1;
		}
	}
	afxdp_dump_bpf__destroy(skel);
	close_xsk(&xsk);
	return err;
}
```

### 理解 UMEM 和 Ring 设置

`open_xsk()` 函数创建 AF_XDP socket 及其所有支撑基础设施。它首先映射 256 KiB 的匿名内存作为 UMEM，划分为 64 个 4096 字节的 frame。这块内存在注册后会与内核共享。

用 `AF_XDP` 创建 socket 后，它通过 `XDP_UMEM_REG` 注册 UMEM，告诉内核我们的报文 buffer 在哪里。然后用 `setsockopt` 请求各 64 个 entry 的 fill、completion 和 RX ring。`XDP_MMAP_OFFSETS` getsockopt 揭示了每个 ring 的 producer index、consumer index、flags 和 descriptor 数组在可 mmap 的页面中的位置。

Ring 映射有些技巧，因为内核把每个 ring 放在固定的页面偏移。Fill Ring 在 `XDP_UMEM_PGOFF_FILL_RING`，Completion Ring 在 `XDP_UMEM_PGOFF_COMPLETION_RING`，RX Ring 在 `XDP_PGOFF_RX_RING`。每个 ring 包含指向 producer 和 consumer index 的指针，它们是内核和用户态之间的同步点。

bind 之前的最后一步是把所有 64 个 frame 地址发布到 Fill Ring。我们把每个地址写入 descriptor 数组，然后用 release 语义发布 producer index。这告诉内核有 64 个 frame 可用于接收报文。

### Ring 操作中的内存顺序

Ring index 由内核和用户态共享，这使得内存顺序至关重要。模式是一致的：producer 在用 release 语义发布 index 之前先写 descriptor，consumer 在读取 descriptor 之前先 acquire producer index。

在 `recycle_frame()` 中，我们用 relaxed 顺序读取自己的 producer index（只有我们修改它），但要 acquire consumer index，因为内核会写它。如果 ring 有空间，我们写入地址并用 release 发布。内核最终会 acquire 我们的 producer 更新并看到我们写的地址。

同样的模式出现在接收循环中。我们 acquire 内核写的 producer index，读取 descriptor，用 release 发布我们的 consumer 更新。这确保内核知道我们已经完成这些 frame，然后才能复用它们。

### Copy Mode 与 Zero-Copy

Socket 地址中的 `XDP_COPY` 标志告诉 AF_XDP 把报文复制到 UMEM，而不是真正的 zero-copy。Copy mode 在任何接口上都能工作，不需要驱动支持，是学习示例的正确选择。内核为传入报文分配自己的内存，然后复制到我们的 UMEM frame。

XDP 程序的 attach mode 是另一回事。我们首先尝试 native driver mode（`XDP_FLAGS_DRV_MODE`），它在 SKB 分配之前在驱动中运行 XDP 程序。如果因为驱动不支持 XDP 而失败，我们回退到 generic SKB mode（`XDP_FLAGS_SKB_MODE`），它在 SKB 创建之后运行，但仍然让我们重定向到 AF_XDP。`--skb-mode` 标志直接强制使用 generic mode。

### 接收循环

接收循环轮询报文，批量处理它们，并立即回收 frame。250ms 超时确保即使没有报文到达，我们也能响应信号。

当 poll 指示有数据时，我们检查 RX ring 是否有新 descriptor。对于每一个，我们计算实际的数据地址（descriptor 地址可能编码了 offset 信息），验证它在 UMEM 边界内，并检查这不是一个 multi-buffer 报文（那会设置 `XDP_PKT_CONTD`）。Multi-buffer 支持需要累积分片，超出了这个例子的范围。

打印报文后，我们立即通过 `recycle_frame()` 把 frame 归还到 Fill Ring。这至关重要：不回收的话，64 个报文之后就会耗尽 frame。工具通过成功捕获 65 个报文来证明回收有效。

### 清理和安全卸载

退出时，我们使用 compare-and-detach 只移除我们自己的 XDP 程序。`old_prog_fd` 选项告诉 `bpf_xdp_detach` 只在当前挂载的程序与我们的匹配时才卸载。这防止了在我们运行期间如果有人挂载了其他 XDP 程序时，意外卸载别人的程序。

## 编译和运行

构建可执行文件：

```bash
cd src/60-afxdp-dump
make
```

捕获 queue 0 上发往 UDP 8080 端口的 5 个报文：

```bash
sudo ./afxdp_dump --interface eth0 --queue 0 --port 8080 --count 5
```

使用 `--count 0` 持续运行直到 Ctrl+C 中断。添加 `--skb-mode` 强制使用 generic XDP mode。选中的 queue 必须实际接收到流量；在多队列网卡上，这取决于 RSS（receive-side scaling）配置。

从另一台机器或另一个终端发送测试流量：

```bash
echo "hello-afxdp" | nc -u target-ip 8080
```

使用 `--count 65` 运行更长时间可以证明 frame 回收有效：

```text
afxdp-dump ready interface=eth0 queue=0 port=8080 mode=driver count=65
packet=1 10.77.0.1:60414 -> 10.77.0.2:8080 bytes=53 payload="hello-afxdp"
packet=65 10.77.0.1:60414 -> 10.77.0.2:8080 bytes=53 payload="hello-afxdp"
redirected=65
```

Packet 65 证明至少有一个 frame 完成了完整的所有权周期：发布到 Fill，用于接收，从 RX 消费，再发布回 Fill。`redirected=65` 计数器来自 BPF 程序，与我们的接收计数一致。

## 环境要求

| 要求 | 说明 |
|---|---|
| 内核 | Linux 5.7 或更高版本。AF_XDP 在 4.18 引入，XDP 对 XSKMAP 的 lookup 在 5.3 引入，安全的 expected-FD detach 在 5.7 引入 |
| 内核配置 | `CONFIG_BPF`、`CONFIG_BPF_SYSCALL`、`CONFIG_BPF_JIT`、`CONFIG_XDP_SOCKETS`、`CONFIG_DEBUG_INFO_BTF` |
| 权限 | root 或等价的 BPF 与网络管理 capability |
| 网络接口 | 任何包含所选 RX queue 的接口。native XDP 可选，generic mode 处处可用 |
| 架构 | x86-64 已测试。copy mode 不需要驱动 zero-copy 支持 |

## 后续扩展

这个例子有意做得最小化：只接收、单队列、single-buffer 报文、copy mode。真正的生产 AF_XDP 应用会在这个基础上向多个方向扩展：

**TX ring** 让你用同样的零开销模型发送报文。你需要添加 TX ring，发布带有报文数据的 frame 地址，然后轮询 completion 通知。

**Zero-copy mode** 消除了复制到 UMEM 的过程。驱动直接使用你的 UMEM，但这需要驱动支持和仔细的 buffer 对齐。

**Multi-buffer 报文** 处理巨型帧或 UMEM frame 小于 MTU 的情况。你需要累积标记了 `XDP_PKT_CONTD` 的分片，直到最后一个分片。

**Shared UMEM** 让多个 socket 共享同一块内存，对于跨 queue 负载均衡或 RX 和 TX 路径之间共享很有用。

## 总结

AF_XDP 给你提供了具有 eBPF 安全保证的内核旁路报文接收。XDP 程序在驱动边界选择流量，XSKMAP 把报文路由到你的 socket，无锁的 ring buffer 不用系统调用就能传输数据。这个例子展示了完整的接收契约：向 Fill 发布 frame，在 RX 上接收 descriptor，处理报文，把 frame 回收到 Fill。

理解这个流程的价值超越了抓包本身。这里的模式——内核与用户态之间的共享内存、显式的所有权转移、无锁同步——在从数据库到 GPU 驱动的各种高性能系统中反复出现。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [Linux AF_XDP 文档](https://docs.kernel.org/networking/af_xdp.html)
- [AF_XDP 引入 commit](https://github.com/torvalds/linux/commit/c0c77d8fb787cfe0c3fca689c2a30d1dad4eaba7)
- [XDP 支持 XSKMAP lookup 的 commit](https://github.com/torvalds/linux/commit/fada7fdc83c0)
- [XDP detach 的 expected-program FD](https://github.com/torvalds/linux/commit/92234c8f15c8d96ad7e52afdc5994cba6be68eb9)
- [libxdp 库](https://github.com/xdp-project/xdp-tools) - 如果想跳过原始 ABI，这里有更高层的 AF_XDP 辅助函数
