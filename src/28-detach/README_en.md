# Running eBPF Programs After User-Space Application Exits: The Lifecycle of eBPF Programs

By using the detach method to run eBPF programs, the user space loader can exit without stopping the eBPF program.

## The Lifecycle of eBPF Programs

First, we need to understand some key concepts, such as BPF objects (including programs, maps, and debug information), file descriptors (FDs), reference counting (refcnt), etc. In the eBPF system, user space accesses BPF objects through file descriptors, and each object has a reference count. When an object is created, its reference count is initialized to 1. If the object is no longer in use (i.e., no other programs or file descriptors reference it), its reference count will decrease to 0 and be cleaned up in memory after the RCU grace period.

Next, we need to understand the lifecycle of eBPF programs. First, when you create a BPF program and attach it to a "hook" (e.g., a network interface, a system call, etc.), its reference count increases. Then, even if the user space process that originally created and loaded the program exits, as long as the reference count of the BPF program is greater than 0, it will remain active. However, there is an important point in this process: not all hooks are equal. Some hooks are global, such as XDP, tc's clsact, and cgroup-based hooks. These global hooks keep the BPF program active until the objects themselves disappear. Some hooks are local and only run during the lifetime of the process that owns them.

For managing the lifecycle of BPF objects (programs or maps), another key operation is "detach." This operation prevents any future execution of the attached program. Then, in cases where you need to replace a BPF program, you can use the replace operation. This is a complex process because you need to ensure that during the replacement process, no events being processed are lost, and the old and new program may run simultaneously on different CPUs.

Finally, in addition to managing the lifecycle of BPF objects through file descriptors and reference counting, there is another method called BPFFS, which is the "BPF Filesystem." User space processes can "pin" a BPF program or map in BPFFS, which increases the reference count of the object, keeping the BPF object active even if the BPF program is not attached anywhere or the BPF map is not used by any program.

So when we talk about running eBPF programs in the background, we need to understand the meaning of this process. In some cases, even if the user space process has exited, we may still want the BPF program to keep running. This requires us to manage the lifecycle of BPF objects correctly.

## Running

Here, we still use the example of string replacement used in the previous application to demonstrate potential security risks. By using `--detach` to run the program, the user space loader can exit without stopping the eBPF program.

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

- <https://github.com/pathtofile/bad-bpf>
- <https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html>