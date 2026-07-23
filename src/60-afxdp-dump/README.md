# eBPF Tutorial: High-Performance UDP Packet Capture with AF_XDP

Have you ever wondered how packet capture tools like Suricata or high-frequency trading systems receive millions of packets per second without drowning in kernel overhead? The secret is bypassing most of the network stack entirely. AF_XDP lets you intercept packets at the driver boundary, copy them directly into your application's memory, and process them without system calls for every packet.

This tutorial builds a complete packet capture tool from scratch using the raw AF_XDP interface. No helper libraries, no magic abstractions. You'll see exactly how UMEM registration, ring buffers, and XDP redirection work together. The result is `afxdp-dump`, a tool that captures IPv4 UDP packets for a specific port, prints a payload preview, and properly recycles every frame to keep receiving indefinitely.

> Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/60-afxdp-dump>

## Why AF_XDP?

Traditional packet capture with `libpcap` or raw sockets has a fundamental problem: every packet crosses the kernel-userspace boundary through expensive system calls. When you're capturing 10 Gbps of traffic, this overhead becomes the bottleneck, not your processing code.

AF_XDP solves this by establishing shared memory between kernel and userspace. The kernel writes packets directly into memory your application can read. You communicate through lock-free ring buffers instead of system calls. A single `poll()` can wake you for hundreds of packets. This architecture enables packet rates of millions per second on commodity hardware.

The technology has real production use. Meta runs AF_XDP in their load balancers. Cilium uses it for Kubernetes networking. High-frequency trading firms use it to shave microseconds off their latency. Even if you never build a trading system, understanding AF_XDP teaches you patterns that appear throughout high-performance systems: shared memory, lock-free data structures, and explicit ownership transfer.

## The AF_XDP Architecture

AF_XDP works through four components that must coordinate precisely:

**UMEM (User Memory)** is a region of memory you allocate that both kernel and userspace can access. You divide it into fixed-size frames, typically 4096 bytes each. Every packet the kernel delivers arrives in one of these frames.

**The Fill Ring** is how you tell the kernel which frames are available for incoming packets. You post frame addresses here. The kernel consumes these addresses when it needs somewhere to put a packet.

**The RX Ring** is where the kernel tells you about received packets. Each entry contains a frame address and packet length. When you see an entry here, you own that frame until you return it.

**XSKMAP** is a BPF map that connects XDP programs to AF_XDP sockets. The XDP program decides which packets to redirect, looks up the socket for the current RX queue in this map, and calls `bpf_redirect_map()` to deliver the packet.

The flow works like this: you post 64 frame addresses to the Fill Ring. A UDP packet arrives. Your XDP program checks the destination port, looks up the socket in XSKMAP, and redirects. The kernel copies the packet into one of your frames and publishes a descriptor on the RX Ring. You read the descriptor, process the packet, and post the frame address back to the Fill Ring. The cycle continues indefinitely.

This ownership model is critical. A frame starts with you. You lend it to the kernel via the Fill Ring. The kernel borrows it to receive a packet. You reclaim it from the RX Ring. You must return it to the Fill Ring or you'll run out of frames after 64 packets. Our tool proves this works by successfully capturing 65 packets, which requires at least one frame to complete the full ownership cycle.

## The XDP Program: Filtering and Redirecting

The kernel-side BPF program is compact because it only handles filtering and redirection. All the complexity of buffer management lives in userspace.

First, we define a shared header that sets the XSKMAP capacity. Queue IDs are map keys, so this example can address queues 0 through 63:

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __AFXDP_DUMP_H
#define __AFXDP_DUMP_H

#define AFXDP_MAX_QUEUES 64

#endif /* __AFXDP_DUMP_H */
```

Now the XDP program itself:

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

The program parses packets layer by layer, validating boundaries at each step. This careful bounds checking is required by the BPF verifier and also ensures we don't misinterpret truncated or malformed packets.

The parsing starts with Ethernet, checking that there's room for the header and that the EtherType indicates IPv4. Then it validates the IPv4 header: correct version, UDP protocol, minimum header length, and no fragmentation (fragmented packets would need reassembly, which is beyond our scope). The program computes the actual IP header length from the IHL field and uses it to locate the UDP header.

The UDP validation ensures the length field is sane and that the destination port matches our target. Only then does the program check if there's actually a socket registered for this queue. This ordering is deliberate: most packets will fail earlier checks, so we avoid the map lookup cost for packets we won't capture anyway.

The XSKMAP lookup is also a safety check. If userspace hasn't registered a socket for this queue, the lookup returns NULL and we pass the packet to the normal stack. When everything checks out, `bpf_redirect_map()` sends the packet to AF_XDP. The second argument is the queue index, which becomes the map key. The third argument is the fallback action if something goes wrong.

One important detail: once a packet is redirected, it's consumed by AF_XDP. The regular socket stack will never see it. This is exactly what we want for a capture tool, but it means you need to be careful about what you redirect.

## The Userspace Application

The userspace code handles everything AF_XDP needs: memory allocation, ring setup, socket binding, XDP loading, and the receive loop. Here's the complete implementation:

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

### Understanding UMEM and Ring Setup

The `open_xsk()` function creates the AF_XDP socket and all its supporting infrastructure. It starts by mapping 256 KiB of anonymous memory for UMEM, divided into 64 frames of 4096 bytes each. This memory will be shared with the kernel after registration.

After creating the socket with `AF_XDP`, it registers the UMEM with `XDP_UMEM_REG`, telling the kernel where our packet buffers live. Then it requests fill, completion, and RX rings of 64 entries each with `setsockopt`. The `XDP_MMAP_OFFSETS` getsockopt reveals where each ring's producer index, consumer index, flags, and descriptor array are located within pages that can be mmap'd.

The ring mapping is tricky because the kernel lays out each ring at a fixed page offset. The Fill Ring lives at `XDP_UMEM_PGOFF_FILL_RING`, the Completion Ring at `XDP_UMEM_PGOFF_COMPLETION_RING`, and the RX Ring at `XDP_PGOFF_RX_RING`. Each ring contains pointers to the producer and consumer indices, which are the synchronization points between kernel and userspace.

The final step before binding is posting all 64 frame addresses to the Fill Ring. We write each address into the descriptor array and then publish the producer index with release semantics. This tells the kernel it has 64 frames available for receiving packets.

### Memory Ordering in Ring Operations

Ring indices are shared between kernel and userspace, which makes memory ordering critical. The pattern is consistent throughout: a producer writes descriptors before publishing its index with release semantics, and a consumer acquires the producer index before reading descriptors.

In `recycle_frame()`, we read our own producer index (which only we modify) with relaxed ordering, but we acquire the consumer index because the kernel writes it. If there's room in the ring, we write the address and publish with release. The kernel will eventually acquire our producer update and see the address we wrote.

The same pattern appears in the receive loop. We acquire the producer index written by the kernel, read descriptors, and publish our consumer update with release. This ensures the kernel knows we're done with those frames before it reuses them.

### Copy Mode vs Zero-Copy

The `XDP_COPY` flag in the socket address tells AF_XDP to copy packets into UMEM rather than doing true zero-copy. Copy mode works on any interface without driver support, making it the right choice for a learning example. The kernel allocates its own memory for incoming packets and copies them into our UMEM frames.

The XDP program attach mode is different. We first try native driver mode (`XDP_FLAGS_DRV_MODE`), which runs the XDP program in the driver before SKB allocation. If that fails because the driver doesn't support XDP, we fall back to generic SKB mode (`XDP_FLAGS_SKB_MODE`), which runs after the SKB is created but still lets us redirect to AF_XDP. The `--skb-mode` flag forces generic mode directly.

### The Receive Loop

The receive loop polls for packets, processes them in batches, and recycles frames immediately. The 250ms timeout ensures we can respond to signals even when no packets arrive.

When poll indicates data, we check the RX ring for new descriptors. For each one, we compute the actual data address (the descriptor address might be encoded with offset information), verify it's within UMEM bounds, and check that this isn't a multi-buffer packet (which would have `XDP_PKT_CONTD` set). Multi-buffer support would require accumulating fragments, which is beyond this example's scope.

After printing the packet, we immediately return the frame to the Fill Ring via `recycle_frame()`. This is critical: without recycling, we'd run out of frames after 64 packets. The tool proves recycling works by successfully capturing 65 packets.

### Cleanup and Safe Detach

On exit, we use compare-and-detach to remove only our XDP program. The `old_prog_fd` option tells `bpf_xdp_detach` to only detach if the currently attached program matches ours. This prevents accidentally detaching someone else's XDP program if they attached one while we were running.

## Compilation and Execution

Build the executable:

```bash
cd src/60-afxdp-dump
make
```

Capture five UDP packets arriving on queue 0 with destination port 8080:

```bash
sudo ./afxdp_dump --interface eth0 --queue 0 --port 8080 --count 5
```

Use `--count 0` to run until interrupted with Ctrl+C. Add `--skb-mode` to force generic XDP mode. The selected queue must actually receive the traffic; on multi-queue NICs, this depends on RSS (receive-side scaling) configuration.

Send test traffic from another machine or terminal:

```bash
echo "hello-afxdp" | nc -u target-ip 8080
```

A longer run with `--count 65` demonstrates that frame recycling works:

```text
afxdp-dump ready interface=eth0 queue=0 port=8080 mode=driver count=65
packet=1 10.77.0.1:60414 -> 10.77.0.2:8080 bytes=53 payload="hello-afxdp"
packet=65 10.77.0.1:60414 -> 10.77.0.2:8080 bytes=53 payload="hello-afxdp"
redirected=65
```

Packet 65 proves that at least one frame completed the full ownership cycle: posted to Fill, used for receive, consumed from RX, and posted back to Fill. The `redirected=65` counter comes from the BPF program and matches our receive count.

## Requirements

| Requirement | Details |
|---|---|
| Kernel | Linux 5.7 or newer. AF_XDP arrived in 4.18, XSKMAP lookup from XDP in 5.3, and safe expected-FD detach in 5.7 |
| Kernel config | `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_XDP_SOCKETS`, `CONFIG_DEBUG_INFO_BTF` |
| Privileges | Root or equivalent BPF and network-admin capabilities |
| Interface | Any interface with the selected RX queue. Native XDP is optional since generic mode works everywhere |
| Architecture | x86-64 is tested. Copy mode works without driver zero-copy support |

## What's Next

This example is deliberately minimal: receive-only, single-queue, single-buffer packets, copy mode. Real production AF_XDP applications extend this foundation in several directions:

**TX rings** let you send packets with the same zero-overhead model. You'd add a TX ring, post frame addresses with packet data, and poll for completion notifications.

**Zero-copy mode** eliminates the copy into UMEM. The driver uses your UMEM directly, but this requires driver support and careful buffer alignment.

**Multi-buffer packets** handle jumbo frames or when UMEM frames are smaller than the MTU. You'd accumulate fragments marked with `XDP_PKT_CONTD` until the final fragment.

**Shared UMEM** lets multiple sockets share the same memory, useful for load-balancing across queues or between RX and TX paths.

## Summary

AF_XDP gives you kernel-bypass packet reception with eBPF's safety guarantees. The XDP program selects traffic at the driver boundary, the XSKMAP routes packets to your socket, and lock-free ring buffers transfer data without system calls. This example showed the complete receive contract: post frames to Fill, receive descriptors on RX, process packets, recycle frames back to Fill.

Understanding this flow is valuable beyond packet capture. The patterns here, shared memory between kernel and userspace, explicit ownership transfer, lock-free synchronization, appear throughout high-performance systems from databases to GPU drivers.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [Linux AF_XDP Documentation](https://docs.kernel.org/networking/af_xdp.html)
- [AF_XDP Introduction Commit](https://github.com/torvalds/linux/commit/c0c77d8fb787cfe0c3fca689c2a30d1dad4eaba7)
- [XSKMAP Lookup from XDP](https://github.com/torvalds/linux/commit/fada7fdc83c0)
- [Expected-Program FD for XDP Detach](https://github.com/torvalds/linux/commit/92234c8f15c8d96ad7e52afdc5994cba6be68eb9)
- [libxdp Library](https://github.com/xdp-project/xdp-tools) - Higher-level AF_XDP helpers if you want to skip the raw ABI
