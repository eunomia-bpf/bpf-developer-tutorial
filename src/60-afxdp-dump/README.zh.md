# eBPF 实战教程：用 AF_XDP 在用户态接收 UDP 报文

有些报文需要在进入普通 socket stack 之前交给用户态程序。抓包工具、协议原型或专用转发器通常需要一条清晰的接收路径：在驱动入口筛选流量，把报文放入共享内存，完成检查，再把 buffer 交还给下一次接收。

本课直接使用 AF_XDP ABI 构建这条路径，不用库隐藏 ring 和 UMEM 的细节。最终得到的 `afxdp-dump` 会捕获一个队列上发往指定端口的 IPv4 UDP 报文，打印 payload 预览并循环使用每个 frame。它采用单队列、single-buffer packet 和 copy mode，适合作为 zero-copy 与 multi-buffer 之前的第一个 AF_XDP 例子。

> 完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/60-afxdp-dump>

## XDP 选择报文，AF_XDP 完成交付

eBPF 可以让经过验证器检查的程序运行在内核 hook 上，XDP 则把其中一个 hook 放在 Linux 网络接收路径的最前端。Linux 4.18 引入的 AF_XDP 把 XDP redirect 连接到由用户态注册内存支撑的 socket，XSKMAP 再建立 RX queue number 与对应 AF_XDP socket 之间的关系。

两边的职责很明确。XDP 程序只解析足够的信息，判断报文是否属于这个工具；AF_XDP socket 管理共享内存 ring，并把选中的字节交给用户态。本例还会在 redirect 之前用 `bpf_map_lookup_elem()` 检查 XSKMAP，这项能力从 Linux 5.3 开始可用。清理阶段的 compare-and-detach 使用 Linux 5.7 加入的 expected-program FD，因此完整工具的最低内核版本是 5.7。

跟着一个报文和一个 frame 走一遍。用户态在 UMEM 中分配 64 个 4096 字节 frame，把它们的地址发布到 fill ring。发往指定端口的 UDP 报文到达 XDP hook 后，程序检查 Ethernet、IPv4 与 UDP 长度，通过 `ctx->rx_queue_index` 找到注册 socket，再返回 `XDP_REDIRECT`。copy mode 下，内核把报文复制到一个已发布的 frame，并把 `xdp_desc` 放入 RX ring。用户态读取 descriptor、打印报文、推进 consumer index，最后把同一个地址放回 fill ring。

最后一步决定了接收循环能否持续。如果 frame 没有回收，最初的 64 个地址会在 64 个报文之后耗尽。集成测试故意接收 65 个报文，用第 65 个报文证明至少有一个 frame 已经走完完整的所有权循环。

## 共享的队列上限

共享头文件定义 XSKMAP 容量。queue ID 是 map key，因此例子可以表示 0 到 63 号队列，每个进程绑定其中一个。

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __AFXDP_DUMP_H
#define __AFXDP_DUMP_H

#define AFXDP_MAX_QUEUES 64

#endif /* __AFXDP_DUMP_H */
```

## 在 XDP 中筛选并重定向

完整 BPF 程序很短，因为 buffer 管理属于 AF_XDP 一侧。

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

程序在每次 header 访问之前都检查边界或协议长度。它接收 Ethernet IPv4 报文，排除分片，根据 IPv4 header length 找到 UDP，再确认 UDP length 位于 IP payload 内。只有指定目的端口会进入 redirect 路径。

XSKMAP lookup 也是正确性的一部分。队列没有 socket entry 时返回 `XDP_PASS`，无关报文和格式异常的报文同样沿普通网络路径继续；`bpf_redirect_map()` 的 fallback action 也是 pass。一旦 redirect 成功，报文会由 AF_XDP 消费，而不是复制一份镜像，因此普通 UDP socket 不会再收到这条被选中的报文。

## 直接使用 ABI 构建 AF_XDP socket

下面的用户态程序完成 UMEM 注册、ring 映射、socket bind、XDP 加载和接收循环。

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

`open_xsk()` 创建 256 KiB UMEM，通过 `XDP_UMEM_REG` 注册内存，再向内核申请各 64 个 fill、completion 和 RX entry。`XDP_MMAP_OFFSETS` 描述每个 producer、consumer、flags 和 descriptor array 的位置，程序据此映射页面，并在 redirect 开始前发布全部 frame 地址。

ring index 由内核和用户态共享，因此内存顺序很关键。producer 需要先写 descriptor，再用 release 语义发布新 index；consumer 则先 acquire producer index，再读取 descriptor。代码在消费 RX entry 和向 fill ring 归还地址时都遵循这组规则。

socket bind 使用的 `XDP_COPY` 与 XDP attach mode 解决的是两个问题。copy mode 决定报文如何进入 UMEM，不依赖驱动的 zero-copy 支持；XDP 程序本身会先尝试 native driver mode，如果网卡不支持，再回退到 generic SKB mode。`--skb-mode` 可以直接选择 generic 路径。

接收循环要求一个 descriptor 对应一个完整报文。遇到 `XDP_PKT_CONTD` 时会返回 `EMSGSIZE`，避免把 multi-buffer packet 的第一个 fragment 当成完整报文打印。地址和长度检查还会保证 descriptor 始终落在已注册 UMEM 内。退出时 compare-and-detach 把当前 program FD 作为 `old_prog_fd`，工具只会移除自己挂载的 XDP 程序。

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

`--count 0` 会持续运行到收到信号，`--skb-mode` 用于 generic XDP。选中的 queue 必须实际接收这条流量，在多队列网卡上，这取决于 NIC 的 receive-side steering 配置。

集成测试会创建隔离的 veth 路径，验证 8081 端口仍能到达普通 UDP socket，再通过 AF_XDP 发送 65 个匹配报文：

```bash
sudo make test
```

一次真实测试的输出如下：

```text
afxdp-dump ready interface=axdp1267r queue=0 port=8080 mode=driver count=65
packet=1 10.77.0.1:60414 -> 10.77.0.2:8080 bytes=53 payload="hello-afxdp"
packet=65 10.77.0.1:60414 -> 10.77.0.2:8080 bytes=53 payload="hello-afxdp"
redirected=65
nonmatching-pass=verified
AF_XDP dump integration test: PASS
```

`packet=65` 证明 frame 已经在最初的 64 个地址之外完成复用，`redirected=65` 来自 BPF 侧计数器，`nonmatching-pass=verified` 则说明 filter 让其他 UDP 流量继续走普通网络路径。

## 环境要求

| 要求 | 说明 |
|---|---|
| 内核 | Linux 5.7 或更高版本，AF_XDP 在 4.18 引入，XDP 对 XSKMAP 的 lookup 在 5.3 引入，安全的 expected-FD detach 在 5.7 引入 |
| 内核配置 | `CONFIG_BPF`、`CONFIG_BPF_SYSCALL`、`CONFIG_BPF_JIT`、`CONFIG_XDP_SOCKETS`、`CONFIG_DEBUG_INFO_BTF` |
| 权限 | root，或者等价的 BPF 与网络管理 capability |
| 网络接口 | 接口包含所选 RX queue，native XDP 可选，工具也支持 generic XDP |
| 架构与硬件 | 当前声明并完成测试的目标是 x86-64，copy mode 不要求驱动支持 AF_XDP zero-copy |

## 实现范围

`afxdp-dump` 是一个 receive-only、单队列、single-buffer 的 IPv4 UDP 工具，使用固定的 64-frame UMEM，最多打印 32 个 payload 字符。它保留了一个实用接收器需要的 buffer 生命周期，TX ring、shared UMEM、zero-copy、multi-buffer 重组和 RX metadata 可以在后续例子中继续展开。

## 总结

这个例子展示了完整的 AF_XDP 接收契约：XDP 选择一条 UDP 流，XSKMAP 把 RX queue 解析到 socket，内核发布 UMEM descriptor，用户态检查完成后归还 frame。65 个报文的测试进一步证明所有权确实回到了 fill ring。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [Linux AF_XDP 文档](https://docs.kernel.org/networking/af_xdp.html)
- [AF_XDP 引入 commit](https://github.com/torvalds/linux/commit/c0c77d8fb787cfe0c3fca689c2a30d1dad4eaba7)
- [XDP 支持 XSKMAP lookup 的 commit](https://github.com/torvalds/linux/commit/fada7fdc83c0)
- [XDP replace 与 detach 的 expected-program FD](https://github.com/torvalds/linux/commit/92234c8f15c8d96ad7e52afdc5994cba6be68eb9)
