#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include "kfunc.skel.h"  // Include the generated skeleton header

static volatile bool exiting = false;

// Signal handler for graceful termination
void handle_signal(int sig) {
    exiting = true;
}

int main(int argc, char **argv) {
    struct kfunc_bpf *skel;
    int err;

    // Handle SIGINT and SIGTERM for graceful shutdown
    signal(SIGINT, handle_signal);

    // Open the BPF application
    skel = kfunc_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load & verify the BPF program
    err = kfunc_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Attach the BPF program (e.g., attach kprobe)
    err = kfunc_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("BPF program loaded and attached successfully. Press Ctrl-C to exit.\n");

    // Optionally, read the trace_pipe to see bpf_printk outputs
    FILE *trace_pipe = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
    if (!trace_pipe) {
        perror("fopen trace_pipe");
        // Continue without reading trace_pipe
    }

    // Main loop
    while (!exiting) {
        if (trace_pipe) {
            char buffer[256];
            if (fgets(buffer, sizeof(buffer), trace_pipe)) {
                printf("%s", buffer);
            } else {
                if (errno == EINTR)
                    break;
            }
        } else {
            // If trace_pipe is not available, just sleep
            sleep(1);
        }
    }

    if (trace_pipe)
        fclose(trace_pipe);

cleanup:
    // Clean up and destroy the BPF program
    kfunc_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
