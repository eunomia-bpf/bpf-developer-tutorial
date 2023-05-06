// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * tcpstates    Trace TCP session state changes with durations.
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on tcpstates(8) from BCC by Brendan Gregg.
 * 18-Dec-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>
// #include "btf_helpers.h"
#include "tcpstates.h"
#include "tcpstates.skel.h"
// #include "trace_helpers.h"

#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static bool emit_timestamp = false;
static short target_family = 0;
static char* target_sports = NULL;
static char* target_dports = NULL;
static bool wide_output = false;
static bool verbose = false;
static const char* tcp_states[] = {
    [1] = "ESTABLISHED", [2] = "SYN_SENT",   [3] = "SYN_RECV",
    [4] = "FIN_WAIT1",   [5] = "FIN_WAIT2",  [6] = "TIME_WAIT",
    [7] = "CLOSE",       [8] = "CLOSE_WAIT", [9] = "LAST_ACK",
    [10] = "LISTEN",     [11] = "CLOSING",   [12] = "NEW_SYN_RECV",
    [13] = "UNKNOWN",
};

const char* argp_program_version = "tcpstates 1.0";
const char* argp_program_bug_address =
    "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
    "Trace TCP session state changes and durations.\n"
    "\n"
    "USAGE: tcpstates [-4] [-6] [-T] [-L lport] [-D dport]\n"
    "\n"
    "EXAMPLES:\n"
    "    tcpstates                  # trace all TCP state changes\n"
    "    tcpstates -T               # include timestamps\n"
    "    tcpstates -L 80            # only trace local port 80\n"
    "    tcpstates -D 80            # only trace remote port 80\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"timestamp", 'T', NULL, 0, "Include timestamp on output"},
    {"ipv4", '4', NULL, 0, "Trace IPv4 family only"},
    {"ipv6", '6', NULL, 0, "Trace IPv6 family only"},
    {"wide", 'w', NULL, 0, "Wide column output (fits IPv6 addresses)"},
    {"localport", 'L', "LPORT", 0,
     "Comma-separated list of local ports to trace."},
    {"remoteport", 'D', "DPORT", 0,
     "Comma-separated list of remote ports to trace."},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

static error_t parse_arg(int key, char* arg, struct argp_state* state) {
    long port_num;
    char* port;

    switch (key) {
        case 'v':
            verbose = true;
            break;
        case 'T':
            emit_timestamp = true;
            break;
        case '4':
            target_family = AF_INET;
            break;
        case '6':
            target_family = AF_INET6;
            break;
        case 'w':
            wide_output = true;
            break;
        case 'L':
            if (!arg) {
                warn("No ports specified\n");
                argp_usage(state);
            }
            target_sports = strdup(arg);
            port = strtok(arg, ",");
            while (port) {
                port_num = strtol(port, NULL, 10);
                if (errno || port_num <= 0 || port_num > 65536) {
                    warn("Invalid ports: %s\n", arg);
                    argp_usage(state);
                }
                port = strtok(NULL, ",");
            }
            break;
        case 'D':
            if (!arg) {
                warn("No ports specified\n");
                argp_usage(state);
            }
            target_dports = strdup(arg);
            port = strtok(arg, ",");
            while (port) {
                port_num = strtol(port, NULL, 10);
                if (errno || port_num <= 0 || port_num > 65536) {
                    warn("Invalid ports: %s\n", arg);
                    argp_usage(state);
                }
                port = strtok(NULL, ",");
            }
            break;
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char* format,
                           va_list args) {
    if (level == LIBBPF_DEBUG && !verbose)
        return 0;

    return vfprintf(stderr, format, args);
}

static void sig_int(int signo) {
    exiting = 1;
}

static void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
    char ts[32], saddr[26], daddr[26];
    struct event* e = data;
    struct tm* tm;
    int family;
    time_t t;

    if (emit_timestamp) {
        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        printf("%8s ", ts);
    }

    inet_ntop(e->family, &e->saddr, saddr, sizeof(saddr));
    inet_ntop(e->family, &e->daddr, daddr, sizeof(daddr));
    if (wide_output) {
        family = e->family == AF_INET ? 4 : 6;
        printf(
            "%-16llx %-7d %-16s %-2d %-26s %-5d %-26s %-5d %-11s -> %-11s "
            "%.3f\n",
            e->skaddr, e->pid, e->task, family, saddr, e->sport, daddr,
            e->dport, tcp_states[e->oldstate], tcp_states[e->newstate],
            (double)e->delta_us / 1000);
    } else {
        printf(
            "%-16llx %-7d %-10.10s %-15s %-5d %-15s %-5d %-11s -> %-11s %.3f\n",
            e->skaddr, e->pid, e->task, saddr, e->sport, daddr, e->dport,
            tcp_states[e->oldstate], tcp_states[e->newstate],
            (double)e->delta_us / 1000);
    }
}

static void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
    warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

extern unsigned char _binary_min_core_btfs_tar_gz_start[] __attribute__((weak));
extern unsigned char _binary_min_core_btfs_tar_gz_end[] __attribute__((weak));


/* tar header from
 * https://github.com/tklauser/libtar/blob/v1.2.20/lib/libtar.h#L39-L60 */
struct tar_header {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char padding[12];
};

static char* tar_file_start(struct tar_header* tar,
                            const char* name,
                            int* length) {
    while (tar->name[0]) {
        sscanf(tar->size, "%o", length);
        if (!strcmp(tar->name, name))
            return (char*)(tar + 1);
        tar += 1 + (*length + 511) / 512;
    }
    return NULL;
}
#define FIELD_LEN 65
#define ID_FMT "ID=%64s"
#define VERSION_FMT "VERSION_ID=\"%64s"

struct os_info {
    char id[FIELD_LEN];
    char version[FIELD_LEN];
    char arch[FIELD_LEN];
    char kernel_release[FIELD_LEN];
};

static struct os_info* get_os_info() {
    struct os_info* info = NULL;
    struct utsname u;
    size_t len = 0;
    ssize_t read;
    char* line = NULL;
    FILE* f;

    if (uname(&u) == -1)
        return NULL;

    f = fopen("/etc/os-release", "r");
    if (!f)
        return NULL;

    info = calloc(1, sizeof(*info));
    if (!info)
        goto out;

    strncpy(info->kernel_release, u.release, FIELD_LEN);
    strncpy(info->arch, u.machine, FIELD_LEN);

    while ((read = getline(&line, &len, f)) != -1) {
        if (sscanf(line, ID_FMT, info->id) == 1)
            continue;

        if (sscanf(line, VERSION_FMT, info->version) == 1) {
            /* remove '"' suffix */
            info->version[strlen(info->version) - 1] = 0;
            continue;
        }
    }

out:
    free(line);
    fclose(f);

    return info;
}
#define INITIAL_BUF_SIZE (1024 * 1024 * 4) /* 4MB */

/* adapted from https://zlib.net/zlib_how.html */
static int inflate_gz(unsigned char* src,
                      int src_size,
                      unsigned char** dst,
                      int* dst_size) {
    size_t size = INITIAL_BUF_SIZE;
    size_t next_size = size;
    z_stream strm;
    void* tmp;
    int ret;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;

    ret = inflateInit2(&strm, 16 + MAX_WBITS);
    if (ret != Z_OK)
        return -EINVAL;

    *dst = malloc(size);
    if (!*dst)
        return -ENOMEM;

    strm.next_in = src;
    strm.avail_in = src_size;

    /* run inflate() on input until it returns Z_STREAM_END */
    do {
        strm.next_out = *dst + strm.total_out;
        strm.avail_out = next_size;
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END)
            goto out_err;
        /* we need more space */
        if (strm.avail_out == 0) {
            next_size = size;
            size *= 2;
            tmp = realloc(*dst, size);
            if (!tmp) {
                ret = -ENOMEM;
                goto out_err;
            }
            *dst = tmp;
        }
    } while (ret != Z_STREAM_END);

    *dst_size = strm.total_out;

    /* clean up and return */
    ret = inflateEnd(&strm);
    if (ret != Z_OK) {
        ret = -EINVAL;
        goto out_err;
    }
    return 0;

out_err:
    free(*dst);
    *dst = NULL;
    return ret;
}
struct btf *btf__load_vmlinux_btf(void);
void btf__free(struct btf *btf);
static bool vmlinux_btf_exists(void) {
    struct btf* btf;
    int err;

    btf = btf__load_vmlinux_btf();
    err = libbpf_get_error(btf);
    if (err)
        return false;

    btf__free(btf);
    return true;
}

static int ensure_core_btf(struct bpf_object_open_opts* opts) {
    char name_fmt[] = "./%s/%s/%s/%s.btf";
    char btf_path[] = "/tmp/bcc-libbpf-tools.btf.XXXXXX";
    struct os_info* info = NULL;
    unsigned char* dst_buf = NULL;
    char* file_start;
    int dst_size = 0;
    char name[100];
    FILE* dst = NULL;
    int ret;

    /* do nothing if the system provides BTF */
    if (vmlinux_btf_exists())
        return 0;

    /* compiled without min core btfs */
    if (!_binary_min_core_btfs_tar_gz_start)
        return -EOPNOTSUPP;

    info = get_os_info();
    if (!info)
        return -errno;

    ret = mkstemp(btf_path);
    if (ret < 0) {
        ret = -errno;
        goto out;
    }

    dst = fdopen(ret, "wb");
    if (!dst) {
        ret = -errno;
        goto out;
    }

    ret = snprintf(name, sizeof(name), name_fmt, info->id, info->version,
                   info->arch, info->kernel_release);
    if (ret < 0 || ret == sizeof(name)) {
        ret = -EINVAL;
        goto out;
    }

    ret = inflate_gz(
        _binary_min_core_btfs_tar_gz_start,
        _binary_min_core_btfs_tar_gz_end - _binary_min_core_btfs_tar_gz_start,
        &dst_buf, &dst_size);
    if (ret < 0)
        goto out;

    ret = 0;
    file_start = tar_file_start((struct tar_header*)dst_buf, name, &dst_size);
    if (!file_start) {
        ret = -EINVAL;
        goto out;
    }

    if (fwrite(file_start, 1, dst_size, dst) != dst_size) {
        ret = -ferror(dst);
        goto out;
    }

    opts->btf_custom_path = strdup(btf_path);
    if (!opts->btf_custom_path)
        ret = -ENOMEM;

out:
    free(info);
    fclose(dst);
    free(dst_buf);

    return ret;
}

static void cleanup_core_btf(struct bpf_object_open_opts* opts) {
    if (!opts)
        return;

    if (!opts->btf_custom_path)
        return;

    unlink(opts->btf_custom_path);
    free((void*)opts->btf_custom_path);
}

int main(int argc, char** argv) {
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    struct perf_buffer* pb = NULL;
    struct tcpstates_bpf* obj;
    int err, port_map_fd;
    short port_num;
    char* port;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    err = ensure_core_btf(&open_opts);
    if (err) {
        warn("failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
        return 1;
    }

    obj = tcpstates_bpf__open_opts(&open_opts);
    if (!obj) {
        warn("failed to open BPF object\n");
        return 1;
    }

    obj->rodata->filter_by_sport = target_sports != NULL;
    obj->rodata->filter_by_dport = target_dports != NULL;
    obj->rodata->target_family = target_family;

    err = tcpstates_bpf__load(obj);
    if (err) {
        warn("failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    if (target_sports) {
        port_map_fd = bpf_map__fd(obj->maps.sports);
        port = strtok(target_sports, ",");
        while (port) {
            port_num = strtol(port, NULL, 10);
            bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
            port = strtok(NULL, ",");
        }
    }
    if (target_dports) {
        port_map_fd = bpf_map__fd(obj->maps.dports);
        port = strtok(target_dports, ",");
        while (port) {
            port_num = strtol(port, NULL, 10);
            bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
            port = strtok(NULL, ",");
        }
    }

    err = tcpstates_bpf__attach(obj);
    if (err) {
        warn("failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                          handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        err = -errno;
        warn("failed to open perf buffer: %d\n", err);
        goto cleanup;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        warn("can't set signal handler: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    if (emit_timestamp)
        printf("%-8s ", "TIME(s)");
    if (wide_output)
        printf(
            "%-16s %-7s %-16s %-2s %-26s %-5s %-26s %-5s %-11s -> %-11s %s\n",
            "SKADDR", "PID", "COMM", "IP", "LADDR", "LPORT", "RADDR", "RPORT",
            "OLDSTATE", "NEWSTATE", "MS");
    else
        printf("%-16s %-7s %-10s %-15s %-5s %-15s %-5s %-11s -> %-11s %s\n",
               "SKADDR", "PID", "COMM", "LADDR", "LPORT", "RADDR", "RPORT",
               "OLDSTATE", "NEWSTATE", "MS");

    while (!exiting) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            warn("error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
        /* reset err to return 0 if exiting */
        err = 0;
    }

cleanup:
    perf_buffer__free(pb);
    tcpstates_bpf__destroy(obj);
    cleanup_core_btf(&open_opts);

    return err != 0;
}
