# Running eBPF After Application Exits: The Lifecycle of eBPF Programs

eBPF (Extended Berkeley Packet Filter) is a revolutionary technology in the Linux kernel that allows users to execute custom programs in kernel space without modifying the kernel source code or loading any kernel modules. This provides developers with great flexibility to observe, modify, and control the Linux system.

This article introduces the Lifecycle of eBPF Programs, how to run eBPF programs after user-space application exits, and how to use pin to share eBPF objects between processes. This article is part of the eBPF Developer Tutorial, more details can be found in <https://github.com/eunomia-bpf/bpf-developer-tutorial> and <https://eunomia.dev/tutorials>

By using the detach method to run eBPF programs, the user space loader can exit without stopping the eBPF program. Another common use case for pinning is sharing eBPF objects between processes. For example, one could create a Map from Go, pin it, and inspect it using `bpftool map dump pinned /sys/fs/bpf/my_map`.

## The Lifecycle of eBPF Programs

File descriptors and reference counters are used to manage BPF objects (progs, maps, and debug info). When a map is created, the kernel initializes its reference counter to 1 and returns a file descriptor to the user space process. If the process exits or crashes, the file descriptor is closed and the reference counter of the map is decremented. After the RCU grace period, the map is freed from memory.

BPF programs that use BPF maps are loaded in two phases. The maps are created and their file descriptors are stored in the program's 'imm' field. The kernel increments the reference counters of the maps used by the program and initializes the program's reference counter to 1. Even if the user space process closes the file descriptors associated with the maps, the maps will not disappear because the program is still "using" them. When the file descriptor of the program is closed and its reference counter reaches zero, the destruction logic decrements the reference counters of all maps used by the program. This allows the same map to be used by multiple programs at once.

When a program is attached to a hook, its reference counter is incremented. The user space process that created the maps and program can then exit, and the maps and program will remain alive as long as their reference counters are greater than zero. This is the lifecycle of a BPF object.

Not all attachment points are the same. XDP, tc's clsact, and cgroup-based hooks are global, meaning that programs will stay attached to them as long as the corresponding objects are alive. On the other hand, programs attached to kprobe, uprobe, tracepoint, perf_event, raw_tracepoint, socket filters, and so_reuseport hooks are local to the process. If the process crashes or closes the file descriptors associated with these hooks, the kernel will detach the BPF program and decrement its reference counter.

The file descriptor based interface provides auto-cleanup, meaning that if anything goes wrong with the user space process, the kernel will automatically clean up all BPF objects. This interface is useful for networking as well. The use of BPFFS (BPF File System) allows a process to pin a BPF program or map, which increments their reference counters and keeps them alive even if they are not attached or used by any program. This is useful when an admin wants to examine a map even when the associated program is not running.

Detach and replace are important aspects of the lifetime of a BPF program. The detach hook prevents the execution of a previously attached program from any future events, while the replace feature allows a program to be replaced in cgroup-based hooks. There is a window where the old and new programs can be executing on different CPUs, but the kernel guarantees that one of them will be processing events. Some BPF developers use a scheme where the new program is loaded with the same maps as the old program to ensure safe replacement.

Overall, understanding the lifetime of BPF programs and maps is crucial for users to use BPF safely and without surprises. The use of file descriptors, reference counters, and BPFFS helps manage the lifecycle of BPF objects, ensuring their proper creation, attachment, detachment, and replacement.

### eBPF in Kubernetes: Deploy eBPF Programs via Remote Procedure Call

In a Kubernetes environment, deploying eBPF programs often necessitates a higher level of system privileges. Typically, these applications require at least CAP_BPF permissions, and depending on the program type, they may need even more. This requirement poses a challenge in a multi-tenant Kubernetes environment where granting extensive privileges can be a security risk.

#### Using Pin to Mitigate Privilege Requirements

One way to address the privilege issue is through the use of pinning eBPF maps. Pinning allows eBPF objects to persist beyond the life of the process that created them, making them accessible to other processes. This method can be particularly useful in Kubernetes, where different containers might need to interact with the same eBPF objects.

For example, an eBPF map can be created and pinned by a privileged initializer container. Subsequent containers, which may run with fewer privileges, can then interact with the pinned eBPF objects. This approach limits the need for elevated privileges to the initialization phase, thereby enhancing overall security.

#### The Role of bpfman in eBPF Lifecycle Management

The bpfman project can play a crucial role in this context. bpfman, or BPF Daemon, is designed to manage the lifecycle of eBPF programs and maps in a more controlled and secure manner. It acts as a mediator between user space and kernel space, providing a mechanism to load and manage eBPF programs without granting extensive privileges to each individual container or application.

In Kubernetes, bpfman could be deployed as a privileged service, responsible for loading and managing eBPF programs across different nodes in the cluster. It can handle the intricacies of eBPF lifecycle management, such as loading, unloading, updating eBPF programs, and managing their state. This centralized approach simplifies the deployment and management of eBPF programs in a Kubernetes cluster, while adhering to security best practices.

## Use Detach to Replace by Any Program with eBPF After it Exits

In libbpf, the `bpf_object__pin_maps` function can be used to pin the maps in the BPF object, the programs and links has similar API.

Here we use similar programs as textreplace in the previous section to demonstrate the detach method, the pin eBPF code is like:

```c

int pin_program(struct bpf_program *prog, const char* path)
{
    int err;
    err = bpf_program__pin(prog, path);
        if (err) {
            fprintf(stdout, "could not pin prog %s: %d\n", path, err);
            return err;
        }
    return err;
}

int pin_map(struct bpf_map *map, const char* path)
{
    int err;
    err = bpf_map__pin(map, path);
        if (err) {
            fprintf(stdout, "could not pin map %s: %d\n", path, err);
            return err;
        }
    return err;
}

int pin_link(struct bpf_link *link, const char* path)
{
    int err;
    err = bpf_link__pin(link, path);
        if (err) {
            fprintf(stdout, "could not pin link %s: %d\n", path, err);
            return err;
        }
    return err;
}
```

## Running

Here, we still use the example of string replacement used in the previous application to demonstrate potential security risks. By using `--detach` to run the program, the user space loader can exit without stopping the eBPF program.

The code of This example can be found in <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/28-detach>

Compilation:

```bash
make
```

Before running, please make sure that the BPF file system has been mounted:

```bash
sudo mount bpffs -t bpf /sys/fs/bpf
mkdir /sys/fs/bpf/textreplace
```

Then, you can run text-replace2 with detach:

```bash
./textreplace2 -f /proc/modules -i 'joydev' -r 'cryptd' -d
```

This will create some eBPF link files under `/sys/fs/bpf/textreplace`. Once the loader is successfully running, you can check the log by running the following command:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
# Confirm that the link files exist
sudo ls -l /sys/fs/bpf/textreplace
```

Finally, to stop, simply delete the link files:

```bash
sudo rm -r /sys/fs/bpf/textreplace
```

## References

You can visit our tutorial code repository [at https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) or our website [at https://eunomia.dev/zh/tutorials/](https://eunomia.dev/zh/tutorials/) for more examples and a complete tutorial.

- <https://github.com/pathtofile/bad-bpf>
- <https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html>
- <https://bpfman.io/main/blog/2023/09/07/bpfman-a-novel-way-to-manage-ebpf>

> The original link of this article: <https://eunomia.dev/tutorials/28-detach>
