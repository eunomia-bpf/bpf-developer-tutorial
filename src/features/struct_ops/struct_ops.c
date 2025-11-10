#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "struct_ops.skel.h"

static volatile bool exiting = false;

void handle_signal(int sig) {
    exiting = true;
}

static int trigger_struct_ops(const char *message) {
    int fd, ret;
    
    fd = open("/proc/bpf_testmod_trigger", O_WRONLY);
    if (fd < 0) {
        perror("open /proc/bpf_testmod_trigger");
        return -1;
    }
    
    ret = write(fd, message, strlen(message));
    if (ret < 0) {
        perror("write");
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    struct struct_ops_bpf *skel;
    struct bpf_link *link;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Open BPF application */
    skel = struct_ops_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load BPF programs */
    err = struct_ops_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Register struct_ops */
    link = bpf_map__attach_struct_ops(skel->maps.testmod_ops);
    if (!link) {
        fprintf(stderr, "Failed to attach struct_ops\n");
        err = -1;
        goto cleanup;
    }

    printf("Successfully loaded and attached BPF struct_ops!\n");
    printf("Triggering struct_ops callbacks...\n");
    
    /* Trigger the struct_ops by writing to proc file */
    if (trigger_struct_ops("Hello from userspace!") < 0) {
        printf("Failed to trigger struct_ops - is the kernel module loaded?\n");
        printf("Load it with: sudo insmod module/hello.ko\n");
    } else {
        printf("Triggered struct_ops successfully! Check dmesg for output.\n");
    }
    
    printf("\nPress Ctrl-C to exit...\n");

    /* Main loop - trigger periodically */
    while (!exiting) {
        sleep(2);
        if (!exiting && trigger_struct_ops("Periodic trigger") == 0) {
            printf("Triggered struct_ops again...\n");
        }
    }

    printf("\nDetaching struct_ops...\n");
    bpf_link__destroy(link);

cleanup:
    struct_ops_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
