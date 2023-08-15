# eBPF 入门实践教程：使用 LSM 进行安全检测防御

eBPF (扩展的伯克利数据包过滤器) 是一项强大的网络和性能分析工具，被广泛应用在 Linux 内核上。eBPF 使得开发者能够动态地加载、更新和运行用户定义的代码，而无需重启内核或更改内核源代码。这个特性使得 eBPF 能够提供极高的灵活性和性能，使其在网络和系统性能分析方面具有广泛的应用。安全方面的 eBPF 应用也是如此，本文将介绍如何使用 eBPF LSM（Linux Security Modules）机制实现一个简单的安全检查程序。

## 背景

LSM 从 Linux 2.6 开始成为官方内核的一个安全框架，基于此的安全实现包括 SELinux 和 AppArmor 等。在 Linux 5.7 引入 BPF LSM 后，系统开发人员已经能够自由地实现函数粒度的安全检查能力，本文就提供了这样一个案例：限制通过 socket connect 函数对特定 IPv4 地址进行访问的 BPF LSM 程序。（可见其控制精度是很高的）

## LSM 概述

LSM（Linux Security Modules）是 Linux 内核中用于支持各种计算机安全模型的框架。LSM 在 Linux 内核安全相关的关键路径上预置了一批 hook 点，从而实现了内核和安全模块的解耦，使不同的安全模块可以自由地在内核中加载/卸载，无需修改原有的内核代码就可以加入安全检查功能。

在过去，使用 LSM 主要通过配置已有的安全模块（如 SELinux 和 AppArmor）或编写自己的内核模块；而在 Linux 5.7 引入 BPF LSM 机制后，一切都变得不同了：现在，开发人员可以通过 eBPF 编写自定义的安全策略，并将其动态加载到内核中的 LSM 挂载点，而无需配置或编写内核模块。

现在 LSM 支持的 hook 点包括但不限于：

+ 对文件的打开、创建、删除和移动等；
+ 文件系统的挂载；
+ 对 task 和 process 的操作；
+ 对 socket 的操作（创建、绑定 socket，发送和接收消息等）；

更多 hook 点可以参考 [lsm_hooks.h](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hooks.h)。

## 确认 BPF LSM 是否可用

首先，请确认内核版本高于 5.7。接下来，可以通过

```console
$ cat /boot/config-$(uname -r) | grep BPF_LSM
CONFIG_BPF_LSM=y
```

判断是否内核是否支持 BPF LSM。上述条件都满足的情况下，可以通过

```console
$ cat /sys/kernel/security/lsm
ndlock,lockdown,yama,integrity,apparmor
```

查看输出是否包含 bpf 选项，如果输出不包含（像上面的例子），可以通过修改 `/etc/default/grub`：

```conf
GRUB_CMDLINE_LINUX="lsm=ndlock,lockdown,yama,integrity,apparmor,bpf"
```

并通过 `update-grub2` 命令更新 grub 配置（不同系统的对应命令可能不同），然后重启系统。

## 编写 eBPF 程序

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

这是一段 C 实现的 eBPF 内核侧代码，它会阻碍所有试图通过 socket 对 1.1.1.1 的连接操作，其中：

+ `SEC("lsm/socket_connect")` 宏指出该程序期望的挂载点；
+ 程序通过 `BPF_PROG` 宏定义（详情可查看 [tools/lib/bpf/bpf_tracing.h](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/lib/bpf/bpf_tracing.h)）；
+ `restrict_connect` 是 `BPF_PROG` 宏要求的程序名；
+ `ret` 是该挂载点上（潜在的）当前函数之前的 LSM 检查程序的返回值；

整个程序的思路不难理解：

+ 首先，若其他安全检查函数返回值不为 0（不通过），则无需检查，直接返回不通过；
+ 接下来，判断是否为 IPV4 的连接请求，并比较试图连接的地址是否为 1.1.1.1；
+ 若请求地址为 1.1.1.1 则拒绝连接，否则允许连接；

在程序运行期间，所有通过 socket 的连接操作都会被输出到 `/sys/kernel/debug/tracing/trace_pipe`。

## 编译运行

通过容器编译：

```console
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

或是通过 `ecc` 编译：

```console
$ ecc lsm-connect.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

并通过 `ecli` 运行：

```shell
sudo ecli run package.json
```

接下来，可以打开另一个 terminal，并尝试访问 1.1.1.1：

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

同时，我们可以查看 `bpf_printk` 的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            ping-7054    [000] d...1  6313.430872: bpf_trace_printk: lsm: found connect to 16843009
            ping-7054    [000] d...1  6313.430874: bpf_trace_printk: lsm: blocking 16843009
            curl-7058    [000] d...1  6316.346582: bpf_trace_printk: lsm: found connect to 16843009
            curl-7058    [000] d...1  6316.346584: bpf_trace_printk: lsm: blocking 16843009
            wget-7061    [000] d...1  6318.800698: bpf_trace_printk: lsm: found connect to 16843009
            wget-7061    [000] d...1  6318.800700: bpf_trace_printk: lsm: blocking 16843009
```

完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/19-lsm-connect>

## 总结

本文介绍了如何使用 BPF LSM 来限制通过 socket 对特定 IPv4 地址的访问。我们可以通过修改 GRUB 配置文件来开启 LSM 的 BPF 挂载点。在 eBPF 程序中，我们通过 `BPF_PROG` 宏定义函数，并通过 `SEC` 宏指定挂载点；在函数实现上，遵循 LSM 安全检查模块中 "cannot override a denial" 的原则，并根据 socket 连接请求的目的地址对该请求进行限制。

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。

## 参考

+ <https://github.com/leodido/demo-cloud-native-ebpf-day>
+ <https://aya-rs.dev/book/programs/lsm/#writing-lsm-bpf-program>
