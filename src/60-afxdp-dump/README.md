# eBPF Tutorial by Example: Receive UDP Packets with AF_XDP

Sometimes a packet needs to reach a user-space program before the normal socket stack processes it. A packet recorder, protocol prototype, or specialized forwarder may want a small, explicit receive path: select traffic at the driver boundary, place it in shared memory, inspect it, then return the buffer for another packet.

This tutorial builds that path from the AF_XDP ABI rather than hiding it behind a library. The resulting `afxdp-dump` tool captures IPv4 UDP packets for one port and queue, prints a payload preview, and recycles every frame. It uses one queue, single-buffer packets, and copy mode, which makes it a practical first AF_XDP program before zero-copy and multi-buffer extensions.

> Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/60-afxdp-dump>

## XDP Selects; AF_XDP Delivers

eBPF runs verifier-checked programs at kernel hooks, and XDP places one of those hooks at the earliest receive point in the Linux network path. AF_XDP, added in Linux 4.18, connects an XDP redirect to a socket backed by user-registered memory. An XSKMAP supplies the missing association between an RX queue number and the AF_XDP socket that serves it.

The roles are deliberately separate. The XDP program parses just enough of the packet to decide whether it belongs to the tool. The AF_XDP socket owns the shared-memory rings and carries selected bytes to user space. This example also checks XSKMAP with `bpf_map_lookup_elem()` before redirecting, support added in Linux 5.3, so Linux 5.3 is its minimum kernel version.

Follow one packet and one frame. User space allocates 64 frames of 4096 bytes in UMEM and posts their addresses to the fill ring. A UDP packet for the configured port reaches the XDP hook. The program validates Ethernet, IPv4, and UDP lengths, finds the socket registered for `ctx->rx_queue_index`, and returns `XDP_REDIRECT`. In copy mode the kernel copies the packet into one posted frame and publishes an `xdp_desc` on the RX ring. User space reads the descriptor, prints the packet, advances the consumer index, and puts the same address back on the fill ring.

That last step is what keeps the receiver alive. Without recycling, the initial 64 addresses would be exhausted after 64 packets. The integration test deliberately receives 65 packets to prove that at least one frame has completed the entire ownership cycle.

## Shared Queue Limit

The shared header sets the XSKMAP capacity. Queue IDs are the map keys, so this example can address queues 0 through 63 while binding one queue per process.

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __AFXDP_DUMP_H
#define __AFXDP_DUMP_H

#define AFXDP_MAX_QUEUES 64

#endif /* __AFXDP_DUMP_H */
```

## Filtering and Redirecting in XDP

The complete BPF program is small because buffer management belongs to the AF_XDP side.

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

Every header access is preceded by a bounds or length check. The program accepts Ethernet IPv4 packets, excludes fragments, follows the IPv4 header length to UDP, and verifies that the UDP length fits inside the IP payload. Only the configured destination port reaches the redirect path.

The XSKMAP lookup is also part of correctness. A queue with no socket entry returns `XDP_PASS`, as do unrelated or malformed packets. `bpf_redirect_map()` uses the same pass action as its fallback. Once a redirect succeeds, the packet is consumed by AF_XDP rather than mirrored; a regular UDP socket will not receive that selected packet.

## Building an AF_XDP Socket from the ABI

The user-space side below performs the UMEM registration, maps the rings, binds the socket, loads XDP, and runs the receive loop.

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

`open_xsk()` creates a 256 KiB UMEM area, registers it through `XDP_UMEM_REG`, and asks the kernel for 64 fill, completion, and RX entries. `XDP_MMAP_OFFSETS` describes where each producer, consumer, flags, and descriptor array lives. The program maps those pages and posts all frame addresses before traffic can be redirected.

The ring indices are shared between kernel and user space, so their memory ordering matters. A producer writes a descriptor before publishing its new index with release semantics. A consumer acquires the producer index before reading descriptors. The code applies that pattern both while consuming RX entries and while returning addresses to the fill ring.

`XDP_COPY` on the socket bind and XDP attach mode solve different problems. Copy mode tells AF_XDP how packet data enters UMEM and works without driver zero-copy support. The XDP program itself first tries native driver mode, then falls back to generic SKB mode when the interface rejects native XDP. `--skb-mode` selects the generic path directly.

The receive loop expects one descriptor per packet. `XDP_PKT_CONTD` therefore produces `EMSGSIZE` instead of silently printing only the first fragment of a multi-buffer packet. Address and packet-length checks also keep every descriptor within the registered UMEM. On shutdown, compare-and-detach supplies the program FD as `old_prog_fd`, so the tool removes only the XDP program it attached.

## Build and Run

Build the executable:

```bash
cd src/60-afxdp-dump
make
```

Capture five UDP packets arriving on queue 0 and destination port 8080:

```bash
sudo ./afxdp_dump --interface eth0 --queue 0 --port 8080 --count 5
```

`--count 0` runs until a signal. Add `--skb-mode` for generic XDP. The selected queue must receive the traffic; on a multi-queue interface this depends on the NIC's receive-side steering configuration.

The integration test creates an isolated veth path, verifies that port 8081 still reaches a normal UDP socket, and sends 65 matching packets through AF_XDP:

```bash
sudo make test
```

A real test run produces:

```text
afxdp-dump ready interface=axdp1267r queue=0 port=8080 mode=driver count=65
packet=1 10.77.0.1:60414 -> 10.77.0.2:8080 bytes=53 payload="hello-afxdp"
packet=65 10.77.0.1:60414 -> 10.77.0.2:8080 bytes=53 payload="hello-afxdp"
redirected=65
nonmatching-pass=verified
AF_XDP dump integration test: PASS
```

`packet=65` demonstrates frame reuse beyond the 64 initially posted frames. `redirected=65` comes from the BPF-side counter, while `nonmatching-pass=verified` confirms that the filter leaves other UDP traffic on the normal network path.

## Requirements

| Requirement | Details |
|---|---|
| Kernel | Linux 5.3 or newer; AF_XDP arrived in 4.18 and this example also uses XSKMAP lookup from XDP |
| Kernel config | `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_XDP_SOCKETS`, `CONFIG_DEBUG_INFO_BTF` |
| Privileges | Root, or equivalent BPF and network-administration capabilities |
| Interface | An interface with the selected RX queue; native XDP is optional because generic XDP is available |
| Architecture and hardware | x86-64 is the declared and tested target; copy mode needs no AF_XDP zero-copy driver support |

## Scope

`afxdp-dump` is a receive-only, single-queue, single-buffer IPv4 UDP tool. It uses a fixed 64-frame UMEM and prints at most 32 payload characters. It provides the buffer lifecycle needed for a useful packet receiver while keeping TX rings, shared UMEM, zero-copy setup, multi-buffer reconstruction, and RX metadata for later examples.

## Summary

This example exposes the complete AF_XDP receive contract. XDP selects one UDP flow, XSKMAP resolves the RX queue to a socket, the kernel publishes a UMEM descriptor, and user space returns the frame after inspection. The 65-packet test closes the loop by proving that ownership really comes back to the fill ring.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [Linux AF_XDP documentation](https://docs.kernel.org/networking/af_xdp.html)
- [AF_XDP introduction commit](https://github.com/torvalds/linux/commit/c0c77d8fb787cfe0c3fca689c2a30d1dad4eaba7)
- [XSKMAP lookup from XDP commit](https://github.com/torvalds/linux/commit/fada7fdc83c0)
