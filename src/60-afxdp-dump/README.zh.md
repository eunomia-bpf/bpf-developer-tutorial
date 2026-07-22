# eBPF 实战教程：AF_XDP 数据包转储

如何将网络数据包直接接收到用户空间？AF_XDP 通过在内核和应用程序之间共享内存提供数据包处理路径。本教程构建一个数据包转储器，使用 XDP 将选定的 UDP 数据包重定向到 AF_XDP 套接字。此实现使用拷贝模式以获得兼容性。

> 完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/60-afxdp-dump>

## eBPF、XDP 与 AF_XDP

eBPF 让经过验证器检查的程序运行在 Linux 内核 hook 上，并把选出的状态发送到用户态。XDP（eXpress Data Path）在报文进入普通内核网络栈前运行程序，Linux 4.18 引入的 AF_XDP 则把 XDP 重定向与用户态报文 ring 连接起来。本例使用 `bpf_map_lookup_elem()` 查找 XSKMAP，在重定向前确认 AF_XDP 套接字已经绑定，这项能力在 Linux 5.3 中启用，因此本工具的最低内核版本是 Linux 5.3。

## 实现原理

我们的工具附加一个 XDP 程序，按目标端口过滤 UDP 数据包。匹配的数据包被重定向到 AF_XDP 套接字；其他所有数据包都传递到正常的网络栈。XDP 程序在重定向之前检查是否有 AF_XDP 套接字绑定到该队列。

## 头文件

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __AFXDP_DUMP_H
#define __AFXDP_DUMP_H

#define AFXDP_MAX_QUEUES 64

#endif /* __AFXDP_DUMP_H */
```

头文件定义了 XSKMAP 支持的最大 RX 队列数。

## BPF 程序

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

XDP 程序在每个层级解析以太网、IP 和 UDP 头，并进行边界检查。它过滤发往配置端口的 IPv4 UDP 数据包，跳过分片数据包。`bpf_map_lookup_elem()` 检查确保我们只在此队列实际绑定了 AF_XDP 套接字时才重定向。`bpf_redirect_map()` 中的回退操作是 `XDP_PASS`，所以如果重定向失败，数据包正常传递。

XSKMAP 将队列 ID 与 AF_XDP 套接字文件描述符关联。当 `bpf_redirect_map()` 成功时，数据包直接传递到 AF_XDP 套接字而不是内核网络栈。

## 用户空间程序

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

static void dump_packet(const void *packet, unsigned int length,
			unsigned int packet_number)
{
	const struct ethhdr *ethernet = packet;
	const struct iphdr *ip;
	const struct udphdr *udp;
	const unsigned char *payload;
	char source[INET_ADDRSTRLEN], destination[INET_ADDRSTRLEN];
	char preview[PAYLOAD_PREVIEW + 1];
	unsigned int available_ip, available_payload, ip_header_length;
	unsigned int ip_length, payload_length, preview_length, udp_length;

	if (length < sizeof(*ethernet) + sizeof(*ip) ||
	    ethernet->h_proto != htons(ETH_P_IP))
		return;
	ip = packet + sizeof(*ethernet);
	ip_header_length = ip->ihl * 4;
	if (ip->version != 4 || ip->protocol != IPPROTO_UDP ||
	    (ntohs(ip->frag_off) &
	     (IPV4_MORE_FRAGMENTS | IPV4_FRAGMENT_OFFSET)) ||
	    ip_header_length < sizeof(*ip) ||
	    length < sizeof(*ethernet) + ip_header_length + sizeof(*udp))
		return;
	ip_length = ntohs(ip->tot_len);
	available_ip = length - sizeof(*ethernet);
	if (ip_length < ip_header_length + sizeof(*udp) ||
	    ip_length > available_ip)
		return;
	udp = packet + sizeof(*ethernet) + ip_header_length;
	payload = (const unsigned char *)(udp + 1);
	udp_length = ntohs(udp->len);
	available_payload = length - (payload - (const unsigned char *)packet);
	if (udp_length < sizeof(*udp) ||
	    udp_length > ip_length - ip_header_length ||
	    udp_length - sizeof(*udp) > available_payload)
		return;
	payload_length = udp_length - sizeof(*udp);
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

用户空间程序设置 AF_XDP 涉及几个组件：

**UMEM**：一个 256KB 区域（64 个 4KB 帧），使用 `mmap()` 分配并通过 `XDP_UMEM_REG` 注册到内核。数据包直接接收到这些帧中。

**Fill ring（填充环）**：预填充所有 64 个帧地址，告诉内核将传入数据包放在哪里。

**RX ring（接收环）**：轮询数据包描述符。当数据包到达时，内核在此处发布包含帧地址和长度的描述符。

**XSKMAP**：使用 AF_XDP 套接字文件描述符更新，以启用从 XDP 的数据包重定向。

绑定套接字时使用 `XDP_COPY` 标志，它把报文从驱动缓冲区复制到 UMEM，而不是使用基于 DMA 的零拷贝。拷贝模式可以覆盖更多驱动，也让这篇入门 AF_XDP 教程不依赖驱动的零拷贝支持。

## 编译和执行

构建工具：

```bash
cd src/60-afxdp-dump
make
```

使用选项运行：

```bash
sudo ./afxdp_dump --interface eth0 --queue 0 --port 8080 --count 5
```

选项：

- `--interface IFACE`：要捕获的网络接口
- `--queue N`：RX 队列索引（默认 0）
- `--port PORT`：要过滤的 UDP 目标端口（默认 8080）
- `--count N`：要捕获的数据包数量（0 表示无限）
- `--skb-mode`：强制使用 SKB 模式而不是驱动模式

运行确定性的集成测试，它会在最初投递的 64 个 frame 之外继续验证 frame 回收，并确认不匹配的 UDP 报文仍然进入普通网络栈：

```bash
sudo make test
```

测试输出如下：

```text
afxdp-dump ready interface=axdp1267r queue=0 port=8080 mode=driver count=65
packet=1 10.77.0.1:60414 -> 10.77.0.2:8080 bytes=53 payload="hello-afxdp"
packet=65 10.77.0.1:60414 -> 10.77.0.2:8080 bytes=53 payload="hello-afxdp"
redirected=65
nonmatching-pass=verified
AF_XDP dump integration test: PASS
```

## 环境要求

| 要求 | 详情 |
|------|------|
| 内核 | Linux 5.3+（XDP 中的 XSKMAP 查找） |
| 配置 | `CONFIG_BPF_SYSCALL`、`CONFIG_XDP_SOCKETS` |
| 权限 | Root |
| 接口 | 具有所选 RX 队列的网络接口，工具会回退到 generic XDP，因此 native XDP 是可选项 |

## 重定向数据包的去向

重定向到 AF_XDP 的数据包是被消费的，而不是被镜像。它们不会继续进入正常的内核网络栈。在常规套接字上监听的应用程序将看不到这些数据包。不匹配的数据包（错误的端口、错误的协议）正常传递并由内核处理。

## 实现细节

这是一个基本的单缓冲区仅接收 AF_XDP 转储器：

- **拷贝模式**：使用 `XDP_COPY`，不依赖驱动的零拷贝支持
- **单队列**：绑定到一个 RX 队列
- **64 帧 UMEM**：使用固定大小控制内存占用
- **帧回收**：处理后将帧返回 fill ring
- **安全附加**：使用 `UPDATE_IF_NOEXIST` 和比较-分离清理

## XDP 附加模式

该工具支持两种 XDP 模式：

- **驱动模式**（原生）：需要驱动支持 XDP
- **SKB 模式**（通用）：无需驱动提供 native XDP 支持

我们首先尝试驱动模式，然后回退到 SKB 模式：

```c
err = bpf_xdp_attach(ifindex, program_fd, XDP_FLAGS_DRV_MODE, NULL);
if (err && (err == -EOPNOTSUPP || err == -EINVAL)) {
    err = bpf_xdp_attach(ifindex, program_fd, XDP_FLAGS_SKB_MODE, NULL);
}
```

## 总结

这个例子走完了 AF_XDP 接收路径，XDP 程序选择一个 UDP 流，XSKMAP 把它重定向到已经绑定的队列，用户态从 RX ring 读取描述符，再把处理过的 frame 放回 fill ring。拷贝模式和 generic XDP 自动回退让工具可以运行在没有 native zero-copy 支持的系统上。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [AF_XDP 内核文档](https://docs.kernel.org/networking/af_xdp.html)
- [AF_XDP 引入 commit](https://github.com/torvalds/linux/commit/c0c77d8fb787cfe0c3fca689c2a30d1dad4eaba7)
- [XDP 中的 XSKMAP 查找 commit](https://github.com/torvalds/linux/commit/fada7fdc83c0)
- [libxdp 文档](https://github.com/xdp-project/xdp-tools/blob/master/lib/libxdp/README.org)
