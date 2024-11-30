#ifndef TEST_UDP_PKT_H
#define TEST_UDP_PKT_H

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_link.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <arpa/inet.h>  // For inet_addr()
#include <string.h>     // For memcpy, memset
#include <bpf/bpf_endian.h>
#include <linux/netdev.h>
#include <assert.h>

#define PORT 9876
#define SERVER_IP "127.0.0.1"

// Define packet structures first
struct test_udp_packet {
    struct ethhdr eth;
    struct ipv6hdr iph;
    struct udphdr udp;
    __u8 payload[64 - sizeof(struct udphdr) - sizeof(struct ethhdr) - sizeof(struct ipv6hdr)];
} __attribute__((packed));

struct test_udp_packet_v4 {
    struct ethhdr eth;
    struct iphdr iph;
    struct udphdr udp;
    uint8_t payload[64 - sizeof(struct udphdr) - sizeof(struct ethhdr) - sizeof(struct iphdr)];
} __attribute__((packed));

// Helper function declarations
static uint16_t ip_checksum(void *vdata, size_t length);
static __be16 __calc_udp_cksum(const struct test_udp_packet *pkt);

// Helper function implementations
static uint16_t ip_checksum(void *vdata, size_t length) {
    char *data = vdata;
    uint64_t acc = 0xffff;
    
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }
    
    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }
    
    return htons(~acc);
}

static __be16 __calc_udp_cksum(const struct test_udp_packet *pkt) {
    __u32 chksum = pkt->iph.nexthdr + bpf_ntohs(pkt->iph.payload_len);
    int i;

    for (i = 0; i < 8; i++) {
        chksum += bpf_ntohs(pkt->iph.saddr.s6_addr16[i]);
        chksum += bpf_ntohs(pkt->iph.daddr.s6_addr16[i]);
    }
    chksum += bpf_ntohs(pkt->udp.source);
    chksum += bpf_ntohs(pkt->udp.dest);
    chksum += bpf_ntohs(pkt->udp.len);

    while (chksum >> 16)
        chksum = (chksum & 0xFFFF) + (chksum >> 16);
    return bpf_htons(~chksum);
}

static struct test_udp_packet_v4 create_test_udp_packet_v4(void) {
    struct test_udp_packet_v4 pkt = {0};

    // Ethernet header
    pkt.eth.h_proto = htons(ETH_P_IP);
    memcpy(pkt.eth.h_dest, (const unsigned char[]){0xb8, 0x3f, 0xd2, 0x2a, 0xe5, 0x11}, sizeof(pkt.eth.h_dest));
    memcpy(pkt.eth.h_source, (const unsigned char[]){0xb8, 0x3f, 0xd2, 0x2a, 0xe7, 0x69}, sizeof(pkt.eth.h_source));
    
    // IPv4 header
    pkt.iph.version = 4;
    pkt.iph.ihl = 5;
    pkt.iph.tot_len = htons(sizeof(struct test_udp_packet_v4) - sizeof(struct ethhdr));
    pkt.iph.ttl = 64;  // default TTL
    pkt.iph.protocol = IPPROTO_UDP;
    pkt.iph.saddr = inet_addr(SERVER_IP);
    pkt.iph.daddr = inet_addr(SERVER_IP);
    pkt.iph.check = ip_checksum(&pkt.iph, sizeof(struct iphdr));

    // UDP header
    pkt.udp.source = htons(12345);
    pkt.udp.dest = htons(PORT);
    pkt.udp.len = htons(sizeof(struct udphdr) + sizeof(pkt.payload));
    pkt.udp.check = 0;  // Optional for IPv4

    // Payload
    memset(pkt.payload, 0x42, sizeof(pkt.payload));

    return pkt;
}

#endif // TEST_UDP_PKT_H
