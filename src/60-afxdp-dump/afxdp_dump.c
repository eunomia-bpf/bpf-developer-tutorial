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
