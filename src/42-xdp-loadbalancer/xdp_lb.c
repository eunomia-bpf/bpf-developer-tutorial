// xdp_lb.c
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include "xdp_lb.skel.h"  // The generated skeleton

struct backend_config {
    __u32 ip;
    unsigned char mac[6];
};

static int parse_mac(const char *str, unsigned char *mac) {
    if (sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        fprintf(stderr, "Invalid MAC address format\n");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <ifname> <backend1_ip> <backend1_mac> <backend2_ip> <backend2_mac>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    struct backend_config backend[2];

    // Parse backend 1
    if (inet_pton(AF_INET, argv[2], &backend[0].ip) != 1) {
        fprintf(stderr, "Invalid backend 1 IP address\n");
        return 1;
    }
    if (parse_mac(argv[3], backend[0].mac) < 0) {
        return 1;
    }

    // Parse backend 2
    if (inet_pton(AF_INET, argv[4], &backend[1].ip) != 1) {
        fprintf(stderr, "Invalid backend 2 IP address\n");
        return 1;
    }
    if (parse_mac(argv[5], backend[1].mac) < 0) {
        return 1;
    }

    // Load and attach the BPF program
    struct xdp_lb_bpf *skel = xdp_lb_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex < 0) {
        perror("if_nametoindex");
        xdp_lb_bpf__destroy(skel);
        return 1;
    }

    if (bpf_program__attach_xdp(skel->progs.xdp_load_balancer, ifindex) < 0) {
        fprintf(stderr, "Failed to attach XDP program\n");
        xdp_lb_bpf__destroy(skel);
        return 1;
    }

    // Update backend configurations
    for (int i = 0; i < 2; i++) {
        if (bpf_map_update_elem(bpf_map__fd(skel->maps.backends), &i, &backend[i], 0) < 0) {
            perror("bpf_map_update_elem");
            xdp_lb_bpf__destroy(skel);
            return 1;
        }
    }

    printf("XDP load balancer configured with backends:\n");
    printf("Backend 1 - IP: %s, MAC: %s\n", argv[2], argv[3]);
    printf("Backend 2 - IP: %s, MAC: %s\n", argv[4], argv[5]);

    printf("Press Ctrl+C to exit...\n");
    while (1) {
        sleep(1);  // Keep the program running
    }

    // Cleanup and detach
    bpf_xdp_detach(ifindex, 0, NULL);
    xdp_lb_bpf__detach(skel);
    xdp_lb_bpf__destroy(skel);
    return 0;
}
