// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* cgroup_guard.c - Userspace loader for cgroup eBPF policy guard
 *
 * This loader attaches three eBPF programs to a cgroup:
 * 1. cgroup/connect4 - TCP connection filtering
 * 2. cgroup/dev - Device access control
 * 3. cgroup/sysctl - Sysctl read/write control
 */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>

#include "cgroup_guard.skel.h"
#include "cgroup_guard.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "cgroup eBPF policy guard - demonstrates cgroup-based access control\n"
        "\n"
        "Options:\n"
        "  -c, --cgroup PATH           cgroup v2 path (default: /sys/fs/cgroup/ebpf_demo)\n"
        "  -p, --block-port PORT       block TCP connect() to this dst port (IPv4)\n"
        "  -d, --deny-device MAJ:MIN   deny device access for (major:minor), e.g. 1:3 (/dev/null)\n"
        "  -s, --deny-sysctl NAME      deny sysctl READ of this name, e.g. kernel/hostname\n"
        "  -h, --help                  show this help\n"
        "\n"
        "Examples:\n"
        "  # Block TCP port 9090, /dev/null (1:3), and reading kernel/hostname\n"
        "  sudo ./cgroup_guard -p 9090 -d 1:3 -s kernel/hostname\n"
        "\n"
        "  # Test from within the cgroup:\n"
        "  sudo bash -c 'echo $$ > /sys/fs/cgroup/ebpf_demo/cgroup.procs && curl http://127.0.0.1:9090'\n",
        prog);
}

static int mkdir_p_onelevel(const char *path)
{
    if (mkdir(path, 0755) == 0)
        return 0;
    if (errno == EEXIST)
        return 0;
    return -errno;
}

static int parse_maj_min(const char *s, int *maj, int *min)
{
    char *colon = strchr(s, ':');
    if (!colon)
        return -EINVAL;

    char a[32] = {0};
    char b[32] = {0};

    size_t la = (size_t)(colon - s);
    if (la == 0 || la >= sizeof(a))
        return -EINVAL;

    memcpy(a, s, la);
    snprintf(b, sizeof(b), "%s", colon + 1);

    char *end = NULL;
    long m1 = strtol(a, &end, 10);
    if (!end || *end != '\0' || m1 < 0)
        return -EINVAL;

    end = NULL;
    long m2 = strtol(b, &end, 10);
    if (!end || *end != '\0' || m2 < 0)
        return -EINVAL;

    *maj = (int)m1;
    *min = (int)m2;
    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    (void)data_sz;

    const struct event *e = (const struct event *)data;

    if (e->type == EVENT_CONNECT4) {
        char ip[INET_ADDRSTRLEN] = {0};
        struct in_addr addr = { .s_addr = e->connect4.daddr };
        inet_ntop(AF_INET, &addr, ip, sizeof(ip));

        printf("[DENY connect4] pid=%u comm=%s daddr=%s dport=%u proto=%u\n",
               e->pid, e->comm, ip, e->connect4.dport, e->connect4.proto);
    } else if (e->type == EVENT_DEVICE) {
        printf("[DENY device]   pid=%u comm=%s major=%u minor=%u access_type=0x%x\n",
               e->pid, e->comm, e->device.major, e->device.minor, e->device.access_type);
    } else if (e->type == EVENT_SYSCTL) {
        printf("[DENY sysctl]   pid=%u comm=%s write=%u name=%s\n",
               e->pid, e->comm, e->sysctl.write, e->sysctl.name);
    } else {
        printf("[UNKNOWN] type=%u pid=%u comm=%s\n", e->type, e->pid, e->comm);
    }

    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    const char *cgroup_path = "/sys/fs/cgroup/ebpf_demo";
    int block_port = 0;
    int dev_major = 0, dev_minor = 0;
    const char *deny_sysctl = NULL;

    static const struct option long_opts[] = {
        { "cgroup",      required_argument, NULL, 'c' },
        { "block-port",  required_argument, NULL, 'p' },
        { "deny-device", required_argument, NULL, 'd' },
        { "deny-sysctl", required_argument, NULL, 's' },
        { "help",        no_argument,       NULL, 'h' },
        {}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:p:d:s:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c':
            cgroup_path = optarg;
            break;
        case 'p':
            block_port = atoi(optarg);
            break;
        case 'd': {
            int err = parse_maj_min(optarg, &dev_major, &dev_minor);
            if (err) {
                fprintf(stderr, "Invalid --deny-device %s, expect MAJ:MIN\n", optarg);
                return 1;
            }
            break;
        }
        case 's':
            deny_sysctl = optarg;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    libbpf_set_print(libbpf_print_fn);

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        fprintf(stderr, "Warning: setrlimit(RLIMIT_MEMLOCK) failed: %s\n", strerror(errno));
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int err = mkdir_p_onelevel(cgroup_path);
    if (err) {
        fprintf(stderr, "mkdir(%s) failed: %s\n", cgroup_path, strerror(-err));
        return 1;
    }

    int cg_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY);
    if (cg_fd < 0) {
        fprintf(stderr, "open(%s) failed: %s\n", cgroup_path, strerror(errno));
        return 1;
    }

    struct cgroup_guard_bpf *skel = cgroup_guard_bpf__open();
    if (!skel) {
        fprintf(stderr, "cgroup_guard_bpf__open() failed\n");
        close(cg_fd);
        return 1;
    }

    /* Write .rodata configuration (must be before load) */
    if (block_port > 0 && block_port <= 65535)
        skel->rodata->blocked_tcp_dport = (__u16)block_port;

    if (dev_major > 0 || dev_minor > 0) {
        skel->rodata->blocked_dev_major = (__u32)dev_major;
        skel->rodata->blocked_dev_minor = (__u32)dev_minor;
    }

    if (deny_sysctl) {
        snprintf((char *)skel->rodata->denied_sysctl_name,
                 SYSCTL_NAME_LEN, "%s", deny_sysctl);
    }

    err = cgroup_guard_bpf__load(skel);
    if (err) {
        fprintf(stderr, "cgroup_guard_bpf__load() failed: %d\n", err);
        goto cleanup;
    }

    struct bpf_link *link_connect = NULL;
    struct bpf_link *link_dev = NULL;
    struct bpf_link *link_sysctl = NULL;

    link_connect = bpf_program__attach_cgroup(skel->progs.cg_connect4, cg_fd);
    err = libbpf_get_error(link_connect);
    if (err) {
        link_connect = NULL;
        fprintf(stderr, "attach cgroup/connect4 failed: %d\n", err);
        goto cleanup;
    }

    link_dev = bpf_program__attach_cgroup(skel->progs.cg_dev, cg_fd);
    err = libbpf_get_error(link_dev);
    if (err) {
        link_dev = NULL;
        fprintf(stderr, "attach cgroup/dev failed: %d\n", err);
        goto cleanup;
    }

    link_sysctl = bpf_program__attach_cgroup(skel->progs.cg_sysctl, cg_fd);
    err = libbpf_get_error(link_sysctl);
    if (err) {
        link_sysctl = NULL;
        fprintf(stderr, "attach cgroup/sysctl failed: %d\n", err);
        goto cleanup;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                                              handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new() failed\n");
        goto cleanup;
    }

    printf("Attached to cgroup: %s\n", cgroup_path);
    printf("Config: block_port=%d, deny_device=%d:%d, deny_sysctl_read=%s\n",
           block_port, dev_major, dev_minor, deny_sysctl ? deny_sysctl : "(none)");
    printf("Press Ctrl-C to stop.\n\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 200 /* ms */);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll() error: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    err = 0;

cleanup:
    if (link_sysctl)
        bpf_link__destroy(link_sysctl);
    if (link_dev)
        bpf_link__destroy(link_dev);
    if (link_connect)
        bpf_link__destroy(link_connect);

    cgroup_guard_bpf__destroy(skel);
    close(cg_fd);
    return err ? 1 : 0;
}
