// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 eunomia-bpf
//
// User-space loader for dynptr TC demo

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "dynptr_tc.skel.h"
#include "dynptr_tc.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int signo)
{
    (void)signo;
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

static void print_ascii_sanitized(const unsigned char *p, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = p[i];
        if (c >= 32 && c <= 126)
            putchar(c);
        else
            putchar('.');
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    const struct event_hdr *e = data;

    char saddr[INET_ADDRSTRLEN];
    char daddr[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &e->saddr, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &e->daddr, daddr, sizeof(daddr));

    printf("if=%u %s:%u -> %s:%u len=%u drop=%u snap=%u ",
           e->ifindex,
           saddr, e->sport,
           daddr, e->dport,
           e->pkt_len,
           e->drop,
           e->snap_len);

    if (e->snap_len && data_sz >= sizeof(*e) + e->snap_len) {
        printf("payload=\"");
        print_ascii_sanitized(e->payload, e->snap_len);
        printf("\"");
    }
    printf("\n");
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s -i <ifname> [-p blocked_port] [-s snap_len] [-n]\n"
            "\n"
            "  -i <ifname>        attach to TC ingress of this netdev\n"
            "  -p <port>          drop TCP packets whose dport == port (0 = disable)\n"
            "  -s <len>           snapshot first <len> bytes of TCP payload (max %d)\n"
            "  -n                 disable ringbuf output\n"
            "\n"
            "Example:\n"
            "  sudo %s -i veth1 -p 8080 -s 64\n",
            prog, MAX_SNAPLEN, prog);
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;
    int opt, err;
    int ifindex;

    struct dynptr_cfg cfg = {
        .blocked_port = 0,
        .snap_len = 64,
        .enable_ringbuf = 1,
    };

    while ((opt = getopt(argc, argv, "i:p:s:nh")) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            break;
        case 'p':
            cfg.blocked_port = (__u16)atoi(optarg);
            break;
        case 's':
            cfg.snap_len = (__u32)atoi(optarg);
            break;
        case 'n':
            cfg.enable_ringbuf = 0;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (!ifname) {
        usage(argv[0]);
        return 1;
    }

    if (cfg.snap_len > MAX_SNAPLEN)
        cfg.snap_len = MAX_SNAPLEN;

    if (bump_memlock_rlimit()) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "if_nametoindex(%s) failed: %s\n", ifname, strerror(errno));
        return 1;
    }

    struct dynptr_tc_bpf *skel = dynptr_tc_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = dynptr_tc_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Write configuration to map */
    {
        __u32 key = 0;
        int cfg_fd = bpf_map__fd(skel->maps.cfg_map);
        err = bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY);
        if (err) {
            fprintf(stderr, "bpf_map_update_elem(cfg_map) failed: %s\n", strerror(errno));
            goto cleanup;
        }
    }

    /* Attach to TC ingress */
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS,
    };
    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
        .handle = 1,
        .priority = 1,
        .prog_fd = bpf_program__fd(skel->progs.dynptr_tc_ingress),
    };

    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "bpf_tc_hook_create failed: %d\n", err);
        goto cleanup;
    }

    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "bpf_tc_attach failed: %d\n", err);
        goto cleanup;
    }

    struct ring_buffer *rb = NULL;
    if (cfg.enable_ringbuf) {
        rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "ring_buffer__new failed\n");
            goto cleanup_detach;
        }
    }

    printf("Attached to TC ingress of %s (ifindex=%d). Ctrl-C to exit.\n",
           ifname, ifindex);
    printf("blocked_port=%u snap_len=%u ringbuf=%u\n",
           cfg.blocked_port, cfg.snap_len, cfg.enable_ringbuf);

    while (!exiting) {
        if (rb) {
            err = ring_buffer__poll(rb, 100 /* ms */);
            if (err == -EINTR) break;
            if (err < 0) {
                fprintf(stderr, "ring_buffer__poll error: %d\n", err);
                break;
            }
        } else {
            usleep(100000);
        }
    }

    ring_buffer__free(rb);

cleanup_detach:
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);

cleanup:
    dynptr_tc_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
