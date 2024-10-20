# eBPF Tutorial by Example 19: Security Detection and Defense using LSM

eBPF (Extended Berkeley Packet Filter) is a powerful network and performance analysis tool widely used in the Linux kernel. eBPF allows developers to dynamically load, update, and run user-defined code without restarting the kernel or modifying the kernel source code. This feature enables eBPF to provide high flexibility and performance, making it widely applicable in network and system performance analysis. The same applies to eBPF applications in security, and this article will introduce how to use the eBPF LSM (Linux Security Modules) mechanism to implement a simple security check program.

## Background

LSM has been an official security framework in the Linux kernel since Linux 2.6, and security implementations based on it include SELinux and AppArmor. With the introduction of BPF LSM in Linux 5.7, system developers have been able to freely implement function-level security checks. This article provides an example of limiting access to a specific IPv4 address through the socket connect function using a BPF LSM program. (This demonstrates its high control precision.)

## Overview of LSM

LSM (Linux Security Modules) is a framework in the Linux kernel that supports various computer security models. LSM predefines a set of hook points on critical paths related to Linux kernel security, decoupling the kernel from security modules. This allows different security modules to be loaded/unloaded in the kernel freely without modifying the existing kernel code, thus enabling them to provide security inspection features.

In the past, using LSM mainly involved configuring existing security modules like SELinux and AppArmor or writing custom kernel modules. However, with the introduction of the BPF LSM mechanism in Linux 5.7, everything changed. Now, developers can write custom security policies using eBPF and dynamically load them into the LSM mount points in the kernel without configuring or writing kernel modules.

Some of the hook points currently supported by LSM include:

+ File open, creation, deletion, and movement;
+ Filesystem mounting;
+ Operations on tasks and processes;
+ Operations on sockets (creating, binding sockets, sending and receiving messages, etc.);

For more hook points, refer to [lsm_hooks.h](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hooks.h).

## Verifying BPF LSM Availability

First, please confirm that your kernel version is higher than 5.7. Next, you can use the following command to check if BPF LSM support is enabled:

```console
$ cat /boot/config-$(uname -r) | grep BPF_LSM
CONFIG_BPF_LSM=y
```

If the output contains `CONFIG_BPF_LSM=y`, BPF LSM is supported. Provided that the above conditions are met, you can use the following command to check if the output includes the `bpf` option:

```console
$ cat /sys/kernel/security/lsm
ndlock,lockdown,yama,integrity,apparmor
```

If the output does not include the `bpf` option (as in the example above), you can modify `/etc/default/grub`:

```conf
GRUB_CMDLINE_LINUX="lsm=ndlock,lockdown,yama,integrity,apparmor,bpf"
```

Then, update the grub configuration using the `update-grub2` command (the corresponding command may vary depending on the system), and restart the system.

## Writing eBPF Programs

```C
// lsm-connect.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2

const __u32 blockme = 16843009; // 1.1.1.1 -> int

SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    // Satisfying "cannot override a denial" rule
    if (ret != 0)
    {
        return ret;
    }

    // Only IPv4 in this example
    if (address->sa_family != AF_INET)
    {
        return 0;
    }

    // Cast the address to an IPv4 socket address
    struct sockaddr_in *addr = (struct sockaddr_in *)address;

    // Where do you want to go?
    __u32 dest = addr->sin_addr.s_addr;
    bpf_printk("lsm: found connect to %d", dest);

    if (dest == blockme)
    {
        bpf_printk("lsm: blocking %d", dest);
        return -EPERM;
    }
    return 0;
}
```

This is eBPF code implemented in C on the kernel side. It blocks all connection operations through a socket to 1.1.1.1. The following information is included:

+ The `SEC("lsm/socket_connect")` macro indicates the expected mount point for this program.
+ The program is defined by the `BPF_PROG` macro (see [tools/lib/bpf/bpf_tracing.h](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/lib/bpf/bpf_tracing.h) for details).
+ `restrict_connect` is the program name required by the `BPF_PROG` macro.
+ `ret` is the return value of the LSM check program (potential) before the current function on this mount point.

The overall idea of the program is not difficult to understand:

+ First, if the return value of other security check functions is non-zero (failed), there is no need to check further and the connection is rejected.
+ Next, it determines whether it is an IPv4 connection request and compares the address being connected to with 1.1.1.1.
+ If the requested address is 1.1.1.1, the connection is blocked; otherwise, the connection is allowed.

During the execution of the program, all connection operations through a socket will be output to `/sys/kernel/debug/tracing/trace_pipe`.

## Compilation and Execution

Compile using a container:

```console
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

Or compile using `ecc`:

```console
$ ecc lsm-connect.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

And run using `ecli`:

```shell
sudo ecli run package.json
```

Next, open another terminal and try to access 1.1.1.1:

```console
$ ping 1.1.1.1
ping: connect: Operation not permitted
$ curl 1.1.1.1
curl: (7) Couldn't connect to server
$ wget 1.1.1.1
--2023-04-23 08:41:18--  (try: 2)  http://1.1.1.1/
Connecting to 1.1.1.1:80... failed: Operation not permitted.
Retrying.
```

At the same time, we can view the output of `bpf_printk`:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            ping-7054    [000] d...1  6313.430872: bpf_trace_printk: lsm: found connect to 16843009
            ping-7054    [000] d...1  6313.430874: bpf_trace_printk: lsm: blocking 16843009
            curl-7058    [000] d...1  6316.346582: bpf_trace_printk: lsm: found connect to 16843009
            curl-7058    [000] d...1  6316.346584: bpf_trace_printk: lsm: blocking 16843009".```
wget-7061    [000] d...1  6318.800698: bpf_trace_printk: lsm: found connect to 16843009
wget-7061    [000] d...1  6318.800700: bpf_trace_printk: lsm: blocking 16843009
```

Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/19-lsm-connect>

## Summary

This article introduces how to use BPF LSM to restrict access to a specific IPv4 address through a socket. We can enable the LSM BPF mount point by modifying the GRUB configuration file. In the eBPF program, we define functions using the `BPF_PROG` macro and specify the mount point using the `SEC` macro. In the implementation of the function, we follow the principle of "cannot override a denial" in the LSM security-checking module and restrict the socket connection request based on the destination address of the request.

If you want to learn more about eBPF knowledge and practices, you can visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials.

## References

+ <https://github.com/leodido/demo-cloud-native-ebpf-day>
+ <https://aya-rs.dev/book/programs/lsm/#writing-lsm-bpf-program>

> The original link of this article: <https://eunomia.dev/tutorials/19-lsm-connect>
