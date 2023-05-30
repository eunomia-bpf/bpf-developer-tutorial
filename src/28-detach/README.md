# 在用户态应用退出后运行 eBPF 程序：eBPF 程序的生命周期

通过使用 detach 的方式运行 eBPF 程序，用户空间加载器可以退出，而不会停止 eBPF 程序。

## eBPF 程序的生命周期

首先，我们需要了解一些关键的概念，如 BPF 对象（包括程序，地图和调试信息），文件描述符 (FD)，引用计数（refcnt）等。在 eBPF 系统中，用户空间通过文件描述符访问 BPF 对象，而每个对象都有一个引用计数。当一个对象被创建时，其引用计数初始为1。如果该对象不再被使用（即没有其他程序或文件描述符引用它），它的引用计数将降至0，并在 RCU 宽限期后被内存清理。

接下来，我们需要了解 eBPF 程序的生命周期。首先，当你创建一个 BPF 程序，并将它连接到某个“钩子”（例如网络接口，系统调用等），它的引用计数会增加。然后，即使原始创建和加载该程序的用户空间进程退出，只要 BPF 程序的引用计数大于 0，它就会保持活动状态。然而，这个过程中有一个重要的点是：不是所有的钩子都是相等的。有些钩子是全局的，比如 XDP、tc's clsact 和 cgroup-based 钩子。这些全局钩子会一直保持 BPF 程序的活动状态，直到这些对象自身消失。而有些钩子是局部的，只在拥有它们的进程存活期间运行。

对于 BPF 对象（程序或映射）的生命周期管理，另一个关键的操作是“分离”（detach）。这个操作会阻止已附加程序的任何未来执行。然后，对于需要替换 BPF 程序的情况，你可以使用替换（replace）操作。这是一个复杂的过程，因为你需要确保在替换过程中，不会丢失正在处理的事件，而且新旧程序可能在不同的 CPU 上同时运行。

最后，除了通过文件描述符和引用计数来管理 BPF 对象的生命周期，还有一个叫做 BPFFS 的方法，也就是“BPF 文件系统”。用户空间进程可以在 BPFFS 中“固定”（pin）一个 BPF 程序或映射，这将增加对象的引用计数，使得即使 BPF 程序未附加到任何地方或 BPF 映射未被任何程序使用，该 BPF 对象也将保持活动状态。

所以，当我们谈论在后台运行 eBPF 程序时，我们需要清楚这个过程的含义。在某些情况下，即使用户空间进程已经退出，我们可能还希望 BPF 程序保持运行。这就需要我们正确地管理 BPF 对象的生命周期

## 运行

这里还是采用了上一个的字符串替换的应用，来体现对应可能的安全风险。通过使用 `--detach` 运行程序，用户空间加载器可以退出，而不会停止 eBPF 程序。

编译：

```bash
make
```

在运行前，请首先确保 bpf 文件系统已经被挂载：

```bash
sudo mount bpffs -t bpf /sys/fs/bpf
mkdir /sys/fs/bpf/textreplace
```

然后，你可以分离运行 text-replace2：

```bash
./textreplace2 -f /proc/modules -i 'joydev' -r 'cryptd' -d
```

这将在 `/sys/fs/bpf/textreplace` 下创建一些 eBPF 链接文件。
一旦加载器成功运行，你可以通过运行以下命令检查日志：

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
# 确认链接文件存在
sudo ls -l /sys/fs/bpf/textreplace
```

然后，要停止，只需删除链接文件即可：

```bash
sudo rm -r /sys/fs/bpf/textreplace
```

## 参考资料

- <https://github.com/pathtofile/bad-bpf>
- <https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html>
