# eBPF Tutorial by Example 6: Capturing Signal Sending and Store State with Hash Maps

eBPF (Extended Berkeley Packet Filter) is a powerful network and performance analysis tool on the Linux kernel that allows developers to dynamically load, update, and run user-defined code at runtime.

This article is the sixth part of the eBPF Tutorial by Example. It mainly introduces how to implement an eBPF tool that captures a collection of system calls that send signals to processes and uses a hash map to store state.

## sigsnoop

The example code is as follows:

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

struct event {
 unsigned int pid;
 unsigned int tpid;
 int sig;
 int ret;
 char comm[TASK_COMM_LEN];
};

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, __u32);
 __type(value, struct event);
} values SEC(".maps");


static int probe_entry(pid_t tpid, int sig)
{
 struct event event = {};
 __u64 pid_tgid;
 __u32 tid;

 pid_tgid = bpf_get_current_pid_tgid();
 tid = (__u32)pid_tgid;
 event.pid = pid_tgid >> 32;
 event.tpid = tpid;
 event.sig = sig;
 bpf_get_current_comm(event.comm, sizeof(event.comm));
 bpf_map_update_elem(&values, &tid, &event, BPF_ANY);
 return 0;
}

static int probe_exit(void *ctx, int ret)
{
 __u64 pid_tgid = bpf_get_current_pid_tgid();
 __u32 tid = (__u32)pid_tgid;
 struct event *eventp;

 eventp = bpf_map_lookup_elem(&values, &tid);
 if (!eventp)
  return 0;

 eventp->ret = ret;
 bpf_printk("PID %d (%s) sent signal %d ",
           eventp->pid, eventp->comm, eventp->sig);
 bpf_printk("to PID %d, ret = %d",
           eventp->tpid, ret);

cleanup:
 bpf_map_delete_elem(&values, &tid);
 return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
 pid_t tpid = (pid_t)ctx->args[0];
 int sig = (int)ctx->args[1];

 return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
 return probe_exit(ctx, ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

This program tracks signal sending across entry and exit events. The challenge is that we need to correlate data from two separate events; when the syscall starts and when it finishes. That's where hash maps come in.

When `probe_entry` runs, we save the signal information in a hash map using the thread ID (TID) as the key. When `probe_exit` runs for the same thread, we look up the saved data, add the return value, and print everything together. This gives us complete information about each signal - who sent it, who received it, what signal it was, and whether it succeeded.

The hash map is keyed by TID rather than PID because threads make syscalls independently. Using TID ensures we don't accidentally mix up events from different threads in the same process.

Finally, we also need to use the SEC macro to define the probe and specify the name of the system call to be captured and the probe function to be executed.

We use eunomia-bpf to compile and run this example. You can install it from <https://github.com/eunomia-bpf/eunomia-bpf>.

Compile and run the above code:

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

or

```console
$ ecc sigsnoop.bpf.c
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
$ sudo ecli run package.json
Running eBPF program...
```

After running this program, you can view the output of the eBPF program by checking the /sys/kernel/debug/tracing/trace_pipe file:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
    systemd-journal-363     [000] d...1   672.563868: bpf_trace_printk: PID 363 (systemd-journal) sent signal 0
     systemd-journal-363     [000] d...1   672.563869: bpf_trace_printk: to PID 1400, ret = 0
     systemd-journal-363     [000] d...1   672.563870: bpf_trace_printk: PID 363 (systemd-journal) sent signal 0
     systemd-journal-363     [000] d...1   672.563870: bpf_trace_printk: to PID 1527, ret = -3
```

## Summary

This article mainly introduces how to implement an eBPF tool to capture the collection of system calls sent by processes using signals and save the state using a hash map. Using a hash map requires defining a struct:

```c
struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, __u32);
 __type(value, struct event);
} values SEC(".maps");
```

And using corresponding APIs for access, such as bpf_map_lookup_elem, bpf_map_update_elem, bpf_map_delete_elem, etc.

If you want to learn more about eBPF knowledge and practice, you can visit our tutorial code repository <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> to get more examples and complete tutorials.
