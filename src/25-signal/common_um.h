// SPDX-License-Identifier: BSD-3-Clause
#ifndef BAD_BPF_COMMON_UM_H
#define BAD_BPF_COMMON_UM_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>

static volatile sig_atomic_t exiting;

void sig_int(int signo)
{
    exiting = 1;
}

static bool setup_sig_handler() {
    // Add handlers for SIGINT and SIGTERM so we shutdown cleanly
    __sighandler_t sighandler = signal(SIGINT, sig_int);
    if (sighandler == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    sighandler = signal(SIGTERM, sig_int);
    if (sighandler == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static bool bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur    = RLIM_INFINITY,
        .rlim_max    = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit! (hint: run as root)\n");
        return false;
    }
    return true;
}


static bool setup() {
    // Set up libbpf errors and debug info callback 
    libbpf_set_print(libbpf_print_fn);

    // Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything 
    if (!bump_memlock_rlimit()) {
        return false;
    };

    // Setup signal handler so we exit cleanly
    if (!setup_sig_handler()) {
        return false;
    }

    return true;
}


#ifdef BAD_BPF_USE_TRACE_PIPE
static void read_trace_pipe(void) {
    int trace_fd;

    trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
    if (trace_fd == -1) {
        printf("Error opening trace_pipe: %s\n", strerror(errno));
        return;
    }

    while (!exiting) {
        static char buf[4096];
        ssize_t sz;

        sz = read(trace_fd, buf, sizeof(buf) -1);
        if (sz > 0) {
            buf[sz] = '\x00';
            puts(buf);
        }
    }
}
#endif  // BAD_BPF_USE_TRACE_PIPE

#endif  // BAD_BPF_COMMON_UM_H