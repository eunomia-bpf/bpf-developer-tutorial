# 在应用程序退出后运行 eBPF 程序：eBPF 程序的生命周期

eBPF（Extended Berkeley Packet Filter）是 Linux 内核中的一项重大技术创新，允许用户在内核空间中执行自定义程序，而无需修改内核源代码或加载任何内核模块。这为开发人员提供了极大的灵活性，可以观察、修改和控制 Linux 系统。

本文将介绍 eBPF 程序的生命周期，以及如何在用户空间应用程序退出后继续运行 eBPF 程序的方法，还将介绍如何使用 "pin" 在不同进程之间共享 eBPF 对象。本文是 eBPF 开发者教程的一部分，更多详细信息可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 和 <https://eunomia.dev/tutorials> 中找到。

通过使用 "detach" 方法来运行 eBPF 程序，用户空间加载程序可以在不停止 eBPF 程序的情况下退出。另外，使用 "pin" 的方法可以在进程之间共享 eBPF 对象，使其保持活动状态。

## eBPF 程序的生命周期

BPF对象（包括程序、映射和调试信息）通过文件描述符（FD）进行访问，并具有引用计数器。每个对象都有一个引用计数器，用于追踪对象被引用的次数。例如，当创建一个映射时，内核会分配一个struct bpf_map对象，并将其引用计数器初始化为1。然后，将映射的文件描述符返回给用户空间进程。如果进程退出或崩溃，文件描述符将被关闭，并且映射的引用计数将减少。当引用计数为零时，内存将被释放。

BPF程序使用 maps 有两个阶段。首先，创建 maps 并将其文件描述符存储为BPF_LD_IMM64指令的一部分。当内核验证程序时，它会增加程序使用的 maps 的引用计数，并将程序的引用计数初始化为1。此时，用户空间可以关闭与maps 相关的文件描述符，但 maps 不会被销毁，因为程序仍然在使用它们。当程序文件描述符关闭且引用计数为零时，销毁逻辑将减少 maps 的引用计数。这允许多个不同类型的程序同时使用同一个 maps。

当程序附加到一个挂钩时，程序的引用计数增加。用户空间进程创建 maps 和程序，然后加载程序并将其附加到挂钩上后，就可以退出了。此时，由用户空间创建的 maps 和程序将保持活动状态，因为引用计数>0。这就是BPF对象的生命周期。只要BPF对象的引用计数>0，内核将保持其活动状态。

然而，不同的附加点的行为不同。一些附加点（如XDP、tc的clsact和基于cgroup的hooks）是全局的，即使没有进程使用它们，程序也会继续处理数据包。另一些附加点（如kprobe、uprobe、tracepoint、perf_event、raw_tracepoint、socket过滤器和so_reuseport挂钩）只在持有事件的进程的生命周期内生效。当这些进程崩溃时，内核将分离BPF程序并减少其引用计数。

总结：XDP、tc、lwt和cgroup挂钩是全局的，而kprobe、uprobe、tracepoint、perf_event、raw_tracepoint、socket过滤器和so_reuseport挂钩是本地于进程的。基于文件描述符的API具有自动清理的优点，因此如果用户空间进程出现问题，内核将自动清理所有对象。在网络方面，基于文件描述符的API可以防止程序无限制地运行。

另一种保持 BPF 程序和映射活动的方法是 BPFFS，即BPF文件系统。通过将程序或 maps 固定(pin)到BPFFS中的某个位置，可以增加其引用计数，并使其保持活动状态，即使没有附加到任何位置或任何程序使用固定的BPF程序和 maps 。

了解BPF程序和 maps 的生命周期对于用户安全、可靠地使用BPF是非常重要的。文件描述符、引用计数器和 BPFFS 等机制有助于管理BPF对象的生命周期，确保它们的正确创建、附加、分离和替换。

### Kubernetes 中的 eBPF：通过远程过程调用（RPC）部署 eBPF 程序

在 Kubernetes 环境中，部署 eBPF 程序通常需要更高级别的系统权限。通常，这些应用程序需要至少 CAP_BPF 权限，根据程序类型的不同，可能还需要其他权限。在多租户的 Kubernetes 环境中，为每个容器或应用程序授予广泛的权限可能带来安全风险。

为了解决权限问题，一种方法是通过固定（pinning）eBPF 映射来减轻权限要求。固定允许 eBPF 对象在创建它们的进程的生命周期之外保持活动状态，以便其他进程可以访问它们。在 Kubernetes 中，不同的容器可能需要与相同的 eBPF 对象进行交互，因此固定对象很有用。

例如，可以使用特权的初始化器容器来创建并固定一个 eBPF 映射。随后的容器（可能以较低权限运行）可以与固定的 eBPF 对象进行交互。这种方法将权限要求限制在初始化阶段，增强了整体安全性。

在这种背景下，bpfman 项目发挥了关键作用。bpfman，即 BPF Daemon，旨在以更受控且更安全的方式管理 eBPF 程序和映射的生命周期。它充当用户空间与内核空间之间的中间层，提供加载和管理 eBPF 程序的机制，而无需为每个单独的容器或应用程序授予广泛的权限。

在 Kubernetes 中，bpfman 可以作为特权服务部署，负责在集群的不同节点上加载和管理 eBPF 程序。它可以处理 eBPF 生命周期管理的复杂性，如加载、卸载、更新 eBPF 程序，并对其状态进行管理。这种集中化的方法简化了在 Kubernetes 集群中部署和管理 eBPF 程序的过程，同时符合安全最佳实践。

## 使用 Detach 在应用程序退出后通过任何程序替换 eBPF

在 libbpf 中，可以使用 `bpf_object__pin_maps` 函数将映射固定到 BPF 对象中。对于程序和链接，也有类似的 API。

以下是一个示例，演示如何使用类似于前一节中的 textreplace 程序的字符串替换示例来展示 detach 方法。可以使用类似的代码将程序、映射和链接固定到 BPF 对象中：

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

## 运行示例

在这个示例中，我们将继续使用前一节中的字符串替换示例来演示在应用程序退出后运行 eBPF 程序的方法，并展示潜在的安全风险。通过使用 `--detach` 参数运行该程序，可以使用户空间加载程序在不停止 eBPF 程序的情况下退出。完整的示例代码可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/28-detach> 中找到。关于如何安装依赖，请参考：<https://eunomia.dev/tutorials/11-bootstrap/>

在运行之前，请确保已经挂载了 BPF 文件系统：

```bash
sudo mount bpffs -t bpf /sys/fs/bpf
mkdir /sys/fs/bpf/textreplace
```

然后，可以使用以下命令运行带有 detach 参数的 text-replace2 程序：

```bash
./textreplace2 -f /proc/modules -i 'joydev' -r 'cryptd' -d
```

这将在 `/sys/fs/bpf/textreplace` 目录下创建一些 eBPF 链接文件。加载程序成功运行后，可以使用以下命令检查日志：

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
# 确认链接文件是否存在
sudo ls -l /sys/fs/bpf/textreplace
```

最后，要停止程序，只需删除链接文件：

```bash
sudo rm -r /sys/fs/bpf/textreplace
```

## 参考资料

您可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。

- [bad-bpf](https://github.com/pathtofile/bad-bpf)
- [Object Lifetime in the Linux kernel](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html)
- [BPFMan: A Novel Way to Manage eBPF—Beyond Capsule Mode](https://bpfman.io/main/blog/2023/09/07/bpfman-a-novel-way-to-manage-ebpf)

> 原文地址：<https://eunomia.dev/zh/tutorials/28-detach/>
