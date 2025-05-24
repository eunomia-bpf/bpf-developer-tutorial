// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>  /* For atoi() */
#include <time.h>
#include <sys/resource.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cuda_events.h"
#include "cuda_events.skel.h"

static struct env {
    bool verbose;
    bool print_timestamp;
    char *cuda_library_path;
    bool include_returns;
    int target_pid;  /* New field for target PID */
} env = {
    .print_timestamp = true,
    .include_returns = true,
    .cuda_library_path = NULL,
    .target_pid = -1,  /* Default to -1 (all PIDs) */
};

const char *argp_program_version = "cuda_events 0.1";
const char *argp_program_bug_address = "<your-email@example.com>";
const char argp_program_doc[] =
"CUDA events tracing tool using eBPF.\n"
"\n"
"It traces CUDA API calls and shows associated information\n"
"such as memory allocations, kernel launches, data transfers, etc.\n"
"\n"
"USAGE: ./cuda_events [-v] [--no-timestamp] [--cuda-path PATH] [--pid PID]\n";

static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "no-timestamp", 't', NULL, 0, "Don't print timestamps" },
    { "no-returns", 'r', NULL, 0, "Don't show function returns" },
    { "cuda-path", 'p', "CUDA_PATH", 0, "Path to CUDA runtime library" },
    { "pid", 'd', "PID", 0, "Trace only the specified PID" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'v':
        env.verbose = true;
        break;
    case 't':
        env.print_timestamp = false;
        break;
    case 'r':
        env.include_returns = false;
        break;
    case 'p':
        env.cuda_library_path = arg;
        break;
    case 'd':
        env.target_pid = atoi(arg);
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

/* Return human-readable event type */
static const char *event_type_str(enum cuda_event_type type)
{
    switch (type) {
    case CUDA_EVENT_MALLOC:         return "cudaMalloc";
    case CUDA_EVENT_FREE:           return "cudaFree";
    case CUDA_EVENT_MEMCPY:         return "cudaMemcpy";
    case CUDA_EVENT_LAUNCH_KERNEL:  return "cudaLaunchKernel";
    case CUDA_EVENT_STREAM_CREATE:  return "cudaStreamCreate";
    case CUDA_EVENT_STREAM_SYNC:    return "cudaStreamSynchronize";
    case CUDA_EVENT_GET_DEVICE:     return "cudaGetDevice";
    case CUDA_EVENT_SET_DEVICE:     return "cudaSetDevice";
    case CUDA_EVENT_EVENT_CREATE:   return "cudaEventCreate";
    case CUDA_EVENT_EVENT_RECORD:   return "cudaEventRecord";
    case CUDA_EVENT_EVENT_SYNC:     return "cudaEventSynchronize";
    default:                        return "Unknown";
    }
}

/* Return human-readable CUDA error code */
static const char *cuda_error_str(int error)
{
    switch (error) {
    case 0:  return "Success";
    case 1:  return "InvalidValue";
    case 2:  return "OutOfMemory";
    case 3:  return "NotInitialized";
    case 4:  return "Deinitialized";
    case 5:  return "ProfilerDisabled";
    case 6:  return "ProfilerNotInitialized";
    case 7:  return "ProfilerAlreadyStarted";
    case 8:  return "ProfilerAlreadyStopped";
    case 9:  return "InvalidConfiguration";
    case 10: return "InvalidPitchValue";
    case 11: return "InvalidSymbol";
    case 12: return "InvalidHostPointer";
    case 13: return "InvalidDevicePointer";
    case 14: return "InvalidTexture";
    case 15: return "InvalidTextureBinding";
    case 16: return "InvalidChannelDescriptor";
    case 17: return "InvalidMemcpyDirection";
    case 18: return "AddressOfConstant";
    case 19: return "TextureFetchFailed";
    case 20: return "TextureNotBound";
    case 21: return "SynchronizationError";
    case 22: return "InvalidFilterSetting";
    case 23: return "InvalidNormSetting";
    case 24: return "MixedDeviceExecution";
    case 25: return "NotYetImplemented";
    case 26: return "MemoryValueTooLarge";
    case 27: return "StubLibrary";
    case 28: return "InsufficientDriver";
    case 29: return "CallRequiresNewerDriver";
    case 30: return "InvalidSurface";
    case 31: return "DuplicateVariableName";
    case 32: return "DuplicateTextureName";
    case 33: return "DuplicateSurfaceName";
    case 34: return "DevicesUnavailable";
    case 35: return "IncompatibleDriverContext";
    case 36: return "MissingConfiguration";
    case 37: return "PriorLaunchFailure";
    case 38: return "LaunchMaxDepthExceeded";
    case 39: return "LaunchFileScopedTex";
    case 40: return "LaunchFileScopedSurf";
    case 41: return "SyncDepthExceeded";
    case 42: return "LaunchPendingCountExceeded";
    case 43: return "InvalidDeviceFunction";
    case 44: return "NoDevice";
    case 45: return "InvalidDevice";
    case 46: return "DeviceNotLicensed";
    case 47: return "SoftwareValidityNotEstablished";
    case 48: return "StartupFailure";
    case 49: return "InvalidKernelImage";
    case 50: return "DeviceUninitialized";
    case 51: return "MapBufferObjectFailed";
    case 52: return "UnmapBufferObjectFailed";
    case 53: return "ArrayIsMapped";
    case 54: return "AlreadyMapped";
    case 55: return "NoKernelImageForDevice";
    case 56: return "AlreadyAcquired";
    case 57: return "NotMapped";
    case 58: return "NotMappedAsArray";
    case 59: return "NotMappedAsPointer";
    case 60: return "ECCUncorrectable";
    case 61: return "UnsupportedLimit";
    case 62: return "DeviceAlreadyInUse";
    case 63: return "PeerAccessUnsupported";
    case 64: return "InvalidPtx";
    case 65: return "InvalidGraphicsContext";
    case 66: return "NvlinkUncorrectable";
    case 67: return "JitCompilerNotFound";
    case 68: return "UnsupportedPtxVersion";
    case 69: return "JitCompilationDisabled";
    case 70: return "UnsupportedExecAffinity";
    case 71: return "InvalidSource";
    case 72: return "FileNotFound";
    case 73: return "SharedObjectSymbolNotFound";
    case 74: return "SharedObjectInitFailed";
    case 75: return "OperatingSystem";
    case 76: return "InvalidResourceHandle";
    case 77: return "IllegalState";
    case 78: return "SymbolNotFound";
    case 79: return "NotReady";
    case 80: return "IllegalAddress";
    case 81: return "LaunchOutOfResources";
    case 82: return "LaunchTimeout";
    case 83: return "LaunchIncompatibleTexturing";
    case 84: return "PeerAccessAlreadyEnabled";
    case 85: return "PeerAccessNotEnabled";
    case 86: return "SetOnActiveProcess";
    case 87: return "ContextIsDestroyed";
    case 88: return "Assert";
    case 89: return "TooManyPeers";
    case 90: return "HostMemoryAlreadyRegistered";
    case 91: return "HostMemoryNotRegistered";
    case 92: return "HardwareStackError";
    case 93: return "IllegalInstruction";
    case 94: return "MisalignedAddress";
    case 95: return "InvalidAddressSpace";
    case 96: return "InvalidPc";
    case 97: return "LaunchFailure";
    case 98: return "CooperativeLaunchTooLarge";
    case 99: return "NotPermitted";
    case 100: return "NotSupported";
    case 101: return "SystemNotReady";
    case 102: return "SystemDriverMismatch";
    case 103: return "CompatNotSupportedOnDevice";
    case 104: return "StreamCaptureUnsupported";
    case 105: return "StreamCaptureInvalidated";
    case 106: return "StreamCaptureMerge";
    case 107: return "StreamCaptureUnmatched";
    case 108: return "StreamCaptureUnjoined";
    case 109: return "StreamCaptureIsolation";
    case 110: return "StreamCaptureImplicit";
    case 111: return "CapturedEvent";
    case 112: return "StreamCaptureWrongThread";
    case 113: return "Unknown";
    case 114: return "Timeout";
    case 115: return "GraphExecUpdateFailure";
    case 116: return "ExternalDevice";
    case 117: return "InvalidClusterSize";
    case 118: return "UnknownError";
    default: return "Unknown";
    }
}

/* Return human-readable details for the event */
static void get_event_details(const struct event *e, char *details, size_t len)
{
    switch (e->type) {
    case CUDA_EVENT_MALLOC:
        if (!e->is_return)
            snprintf(details, len, "size=%zu bytes", e->mem.size);
        else
            snprintf(details, len, "returned=%s", cuda_error_str(e->ret_val));
        break;
    
    case CUDA_EVENT_FREE:
        if (!e->is_return)
            snprintf(details, len, "ptr=%p", e->free_data.ptr);
        else
            snprintf(details, len, "returned=%s", cuda_error_str(e->ret_val));
        break;
    
    case CUDA_EVENT_MEMCPY:
        if (!e->is_return)
            snprintf(details, len, "size=%zu bytes, kind=%d", 
                    e->memcpy_data.size, e->memcpy_data.kind);
        else
            snprintf(details, len, "returned=%s", cuda_error_str(e->ret_val));
        break;
    
    case CUDA_EVENT_LAUNCH_KERNEL:
        if (!e->is_return)
            snprintf(details, len, "func=%p", e->launch.func);
        else
            snprintf(details, len, "returned=%s", cuda_error_str(e->ret_val));
        break;
    
    case CUDA_EVENT_SET_DEVICE:
        if (!e->is_return)
            snprintf(details, len, "device=%d", e->device.device);
        else
            snprintf(details, len, "returned=%s", cuda_error_str(e->ret_val));
        break;
    
    case CUDA_EVENT_STREAM_SYNC:
    case CUDA_EVENT_EVENT_RECORD:
    case CUDA_EVENT_EVENT_SYNC:
        if (!e->is_return)
            snprintf(details, len, "handle=%p", e->handle.handle);
        else
            snprintf(details, len, "returned=%s", cuda_error_str(e->ret_val));
        break;
    
    default:
        if (!e->is_return)
            snprintf(details, len, "");
        else
            snprintf(details, len, "returned=%s", cuda_error_str(e->ret_val));
        break;
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    char details[MAX_DETAILS_LEN];
    time_t t;

    /* Skip return probes if requested */
    if (e->is_return && !env.include_returns)
        return 0;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    get_event_details(e, details, sizeof(details));

    if (env.print_timestamp) {
        printf("%-8s ", ts);
    }

    printf("%-16s %-7d %-20s %8s %s\n", 
           e->comm, e->pid, 
           event_type_str(e->type),
           e->is_return ? "[EXIT]" : "[ENTER]",
           details);

    return 0;
}

/* Define CUDA API functions to trace */
struct cuda_api_func {
    const char *name;
    struct bpf_program *prog_entry;
    struct bpf_program *prog_exit;
};

/* Attach a uprobe to a CUDA API function */
static int attach_cuda_func(struct cuda_events_bpf *skel, const char *lib_path, 
                           const char *func_name, struct bpf_program *prog_entry,
                           struct bpf_program *prog_exit)
{
    int err;
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

    /* Skip attaching if program is NULL (might have been filtered out) */
    if (!prog_entry && !prog_exit)
        return 0;

    /* Attach entry uprobe */
    if (prog_entry) {
        uprobe_opts.func_name = func_name;
        struct bpf_link *link = bpf_program__attach_uprobe_opts(prog_entry, env.target_pid  , lib_path, 0, &uprobe_opts);
        if (!link) {
            fprintf(stderr, "Failed to attach entry uprobe for %s\n", func_name);
            return -1;
        }
    }

    /* Attach exit uprobe */
    if (prog_exit) {
        uprobe_opts.func_name = func_name;
        uprobe_opts.retprobe = true;  /* This is a return probe */
        struct bpf_link *link = bpf_program__attach_uprobe_opts(prog_exit, env.target_pid, lib_path, 0, &uprobe_opts);
        if (!link) {
            fprintf(stderr, "Failed to attach exit uprobe for %s\n", func_name);
            return -1;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct cuda_events_bpf *skel;
    int err;

    /* Default CUDA library path if not specified */
    const char *cuda_lib_path = "/usr/local/cuda/lib64/libcudart.so";

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Override CUDA library path if specified on command line */
    if (env.cuda_library_path)
        cuda_lib_path = env.cuda_library_path;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
    skel = cuda_events_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = cuda_events_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Define CUDA functions to trace and their corresponding programs */
    struct cuda_api_func cuda_funcs[] = {
        {"cudaMalloc", skel->progs.cuda_malloc_enter, skel->progs.cuda_malloc_exit},
        {"cudaFree", skel->progs.cuda_free_enter, skel->progs.cuda_free_exit},
        {"cudaMemcpy", skel->progs.cuda_memcpy_enter, skel->progs.cuda_memcpy_exit},
        {"cudaLaunchKernel", skel->progs.cuda_launch_kernel_enter, skel->progs.cuda_launch_kernel_exit},
        {"cudaStreamCreate", skel->progs.cuda_stream_create_enter, skel->progs.cuda_stream_create_exit},
        {"cudaStreamSynchronize", skel->progs.cuda_stream_sync_enter, skel->progs.cuda_stream_sync_exit},
        {"cudaGetDevice", skel->progs.cuda_get_device_enter, skel->progs.cuda_get_device_exit},
        {"cudaSetDevice", skel->progs.cuda_set_device_enter, skel->progs.cuda_set_device_exit},
        {"cudaEventCreate", skel->progs.cuda_event_create_enter, skel->progs.cuda_event_create_exit},
        {"cudaEventRecord", skel->progs.cuda_event_record_enter, skel->progs.cuda_event_record_exit},
        {"cudaEventSynchronize", skel->progs.cuda_event_sync_enter, skel->progs.cuda_event_sync_exit},
    };

    /* Print CUDA library path being used */
    printf("Using CUDA library: %s\n", cuda_lib_path);
    if (env.target_pid)
        printf("Filtering for PID: %d\n", env.target_pid);

    /* Attach to CUDA functions */
    for (size_t i = 0; i < sizeof(cuda_funcs) / sizeof(cuda_funcs[0]); i++) {
        err = attach_cuda_func(skel, cuda_lib_path, cuda_funcs[i].name, 
                              cuda_funcs[i].prog_entry, cuda_funcs[i].prog_exit);
        if (err) {
            fprintf(stderr, "Failed to attach to %s\n", cuda_funcs[i].name);
            goto cleanup;
        }
    }
    
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Process events */
    if (env.print_timestamp) {
        printf("%-8s ", "TIME");
    }
    printf("%-16s %-7s %-20s %8s %s\n",
           "PROCESS", "PID", "EVENT", "TYPE", "DETAILS");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    /* Clean up */
    ring_buffer__free(rb);
    cuda_events_bpf__destroy(skel);

    return err < 0 ? -err : 0;
} 