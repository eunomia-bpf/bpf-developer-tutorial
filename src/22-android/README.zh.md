# 在 Android 上使用 eBPF 程序

> 本文主要记录了笔者在 Android Studio Emulator 中测试高版本 Android Kernel 对基于 libbpf 的 CO-RE 技术支持程度的探索过程、结果和遇到的问题。
> 测试采用的方式是在 Android Shell 环境下构建 Debian 环境，并基于此尝试构建 eunomia-bpf 工具链、运行其测试用例。

## 背景

截至目前（2023-04），Android 还未对 eBPF 程序的动态加载做出较好的支持，无论是以 bcc 为代表的带编译器分发方案，还是基于 btf 和 libbpf 的 CO-RE 方案，都在较大程度上离不开 Linux 环境的支持，无法在 Android 系统上很好地运行[^WeiShu]。

虽然如此，在 Android 平台上尝试 eBPF 也已经有了一些成功案例，除谷歌官方提供的修改 `Android.bp` 以将 eBPF 程序随整个系统一同构建并挂载的方案[^Google]，也有人提出基于 Android 内核构建 Linux 环境进而运行 eBPF 工具链的思路，并开发了相关工具。

目前已有的资料，大多基于 adeb/eadb 在 Android 内核基础上构建 Linux 沙箱，并对 bcc 和 bpftrace 相关工具链进行测试，而对 CO-RE 方案的测试工作较少。在 Android 上使用 bcc 工具目前有较多参考资料，如：

+ SeeFlowerX：<https://blog.seeflower.dev/category/eBPF/>
+ evilpan：<https://bbs.kanxue.com/thread-271043.htm>

其主要思路是利用 chroot 在 Android 内核上运行一个 Debian 镜像，并在其中构建整个 bcc 工具链，从而使用 eBPF 工具。如果想要使用 bpftrace，原理也是类似的。

事实上，高版本的 Android 内核已支持 btf 选项，这意味着 eBPF 领域中新兴的 CO-RE 技术也应当能够运用到基于 Android 内核的 Linux 系统中。本文将基于此对 eunomia-bpf 在模拟器环境下进行测试运行。

> [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) 是一个结合了 libbpf 和 WebAssembly 技术的开源项目，旨在简化 eBPF 程序的编写、编译和部署。该项目可被视作 CO-RE 的一种实践方式，其核心依赖是 libbpf，相信对 eunomia-bpf 的测试工作能够为其他 CO-RE 方案提供参考。

## 测试环境

+ Android Emulator（Android Studio Flamingo | 2022.2.1）
+ AVD: Pixel 6
+ Android Image: Tiramisu Android 13.0 x86_64（5.15.41-android13-8-00055-g4f5025129fe8-ab8949913）

## 环境搭建[^SeeFlowerX]

1. 从 [eadb 仓库](https://github.com/tiann/eadb) 的 releases 页面获取 `debianfs-amd64-full.tar.gz` 作为 Linux 环境的 rootfs，同时还需要获取该项目的 `assets` 目录来构建环境；
2. 从 Android Studio 的 Device Manager 配置并启动 Android Virtual Device；
3. 通过 Android Studio SDK 的 adb 工具将 `debianfs-amd64-full.tar.gz` 和 `assets` 目录推送到 AVD 中：
   + `./adb push debianfs-amd64-full.tar.gz /data/local/tmp/deb.tar.gz`
   + `./adb push assets /data/local/tmp/assets`
4. 通过 adb 进入 Android shell 环境并获取 root 权限：
   + `./adb shell`
   + `su`
5. 在 Android shell 中构建并进入 debian 环境：
   + `mkdir -p /data/eadb`
   + `mv /data/local/tmp/assets/* /data/eadb`
   + `mv /data/local/tmp/deb.tar.gz /data/eadb/deb.tar.gz`
   + `rm -r /data/local/tmp/assets`
   + `chmod +x /data/eadb/device-*`
   + `/data/eadb/device-unpack`
   + `/data/eadb/run /data/eadb/debian`

至此，测试 eBPF 所需的 Linux 环境已经构建完毕。此外，在 Android shell 中（未进入 debian 时）可以通过 `zcat /proc/config.gz` 并配合 `grep` 查看内核编译选项。

>目前，eadb 打包的 debian 环境存在 libc 版本低，缺少的工具依赖较多等情况；并且由于内核编译选项不同，一些 eBPF 功能可能也无法使用。

## 工具构建

在 debian 环境中将 eunomia-bpf 仓库 clone 到本地，具体的构建过程，可以参考仓库的 [build.md](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/documents/build.md)。在本次测试中，笔者选用了 `ecc` 编译生成 `package.json` 的方式，该工具的构建和使用方式请参考[仓库页面](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/compiler)。

>在构建过程中，可能需要自行安装包括但不限于 `curl`，`pkg-config`，`libssl-dev` 等工具。

## 结果

有部分 eBPF 程序可以成功在 Android 上运行，但也会有部分应用因为种种原因无法成功被执行。

### 成功案例

#### [bootstrap](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/bootstrap)

运行输出如下：

```console
TIME     PID     PPID    EXIT_CODE  DURATION_NS  COMM    FILENAME  EXIT_EVENT
09:09:19  10217  479     0          0            sh      /system/bin/sh 0
09:09:19  10217  479     0          0            ps      /system/bin/ps 0
09:09:19  10217  479     0          54352100     ps                1
09:09:21  10219  479     0          0            sh      /system/bin/sh 0
09:09:21  10219  479     0          0            ps      /system/bin/ps 0
09:09:21  10219  479     0          44260900     ps                1
```

#### [tcpstates](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/tcpstates)

开始监测后在 Linux 环境中通过 `wget` 下载 Web 页面：

```console
TIME     SADDR   DADDR   SKADDR  TS_US   DELTA_US  PID     OLDSTATE  NEWSTATE  FAMILY  SPORT   DPORT   TASK
09:07:46  0x4007000200005000000000000f02000a 0x5000000000000f02000a8bc53f77 18446635827774444352 3315344998 0 10115 7 2 2 0 80 wget
09:07:46  0x40020002d98e50003d99f8090f02000a 0xd98e50003d99f8090f02000a8bc53f77 18446635827774444352 3315465870 120872 0 2 1 2 55694 80 swapper/0
09:07:46  0x40010002d98e50003d99f8090f02000a 0xd98e50003d99f8090f02000a8bc53f77 18446635827774444352 3315668799 202929 10115 1 4 2 55694 80 wget
09:07:46  0x40040002d98e50003d99f8090f02000a 0xd98e50003d99f8090f02000a8bc53f77 18446635827774444352 3315670037 1237 0 4 5 2 55694 80 swapper/0
09:07:46  0x40050002000050003d99f8090f02000a 0x50003d99f8090f02000a8bc53f77 18446635827774444352 3315670225 188 0 5 7 2 55694 80 swapper/0
09:07:47  0x400200020000bb01565811650f02000a 0xbb01565811650f02000a6aa0d9ac 18446635828348806592 3316433261 0 2546 2 7 2 49970 443 ChromiumNet
09:07:47  0x400200020000bb01db794a690f02000a 0xbb01db794a690f02000aea2afb8e 18446635827774427776 3316535591 0 1469 2 7 2 37386 443 ChromiumNet
```

开始检测后在 Android Studio 模拟界面打开 Chrome 浏览器并访问百度页面：

```console
TIME     SADDR   DADDR   SKADDR  TS_US   DELTA_US  PID     OLDSTATE  NEWSTATE  FAMILY  SPORT   DPORT   TASK
07:46:58  0x400700020000bb01000000000f02000a 0xbb01000000000f02000aeb6f2270 18446631020066638144 192874641 0 3305 7 2 2 0 443 NetworkService
07:46:58  0x40020002d28abb01494b6ebe0f02000a 0xd28abb01494b6ebe0f02000aeb6f2270 18446631020066638144 192921938 47297 3305 2 1 2 53898 443 NetworkService
07:46:58  0x400700020000bb01000000000f02000a 0xbb01000000000f02000ae7e7e8b7 18446631020132433920 193111426 0 3305 7 2 2 0 443 NetworkService
07:46:58  0x40020002b4a0bb0179ff85e80f02000a 0xb4a0bb0179ff85e80f02000ae7e7e8b7 18446631020132433920 193124670 13244 3305 2 1 2 46240 443 NetworkService
07:46:58  0x40010002b4a0bb0179ff85e80f02000a 0xb4a0bb0179ff85e80f02000ae7e7e8b7 18446631020132433920 193185397 60727 3305 1 4 2 46240 443 NetworkService
07:46:58  0x40040002b4a0bb0179ff85e80f02000a 0xb4a0bb0179ff85e80f02000ae7e7e8b7 18446631020132433920 193186122 724 3305 4 5 2 46240 443 NetworkService
07:46:58  0x400500020000bb0179ff85e80f02000a 0xbb0179ff85e80f02000ae7e7e8b7 18446631020132433920 193186244 122 3305 5 7 2 46240 443 NetworkService
07:46:59  0x40010002d01ebb01d0c52f5c0f02000a 0xd01ebb01d0c52f5c0f02000a51449c27 18446631020103553856 194110884 0 5130 1 8 2 53278 443 ThreadPoolForeg
07:46:59  0x400800020000bb01d0c52f5c0f02000a 0xbb01d0c52f5c0f02000a51449c27 18446631020103553856 194121000 10116 3305 8 7 2 53278 443 NetworkService
07:46:59  0x400700020000bb01000000000f02000a 0xbb01000000000f02000aeb6f2270 18446631020099513920 194603677 0 3305 7 2 2 0 443 NetworkService
07:46:59  0x40020002d28ebb0182dd92990f02000a 0xd28ebb0182dd92990f02000aeb6f2270 18446631020099513920 194649313 45635 12 2 1 2 53902 443 ksoftirqd/0
07:47:00  0x400700020000bb01000000000f02000a 0xbb01000000000f02000a26f6e878 18446631020132433920 195193350 0 3305 7 2 2 0 443 NetworkService
07:47:00  0x40020002ba32bb01e0e09e3a0f02000a 0xba32bb01e0e09e3a0f02000a26f6e878 18446631020132433920 195206992 13642 0 2 1 2 47666 443 swapper/0
07:47:00  0x400700020000bb01000000000f02000a 0xbb01000000000f02000ae7e7e8b7 18446631020132448128 195233125 0 3305 7 2 2 0 443 NetworkService
07:47:00  0x40020002b4a8bb0136cac8dd0f02000a 0xb4a8bb0136cac8dd0f02000ae7e7e8b7 18446631020132448128 195246569 13444 3305 2 1 2 46248 443 NetworkService
07:47:00  0xf02000affff00000000000000000000 0x1aca06cffff00000000000000000000 18446631019225912320 195383897 0 947 7 2 10 0 80 Thread-11
07:47:00  0x40010002b4a8bb0136cac8dd0f02000a 0xb4a8bb0136cac8dd0f02000ae7e7e8b7 18446631020132448128 195421584 175014 3305 1 4 2 46248 443 NetworkService
07:47:00  0x40040002b4a8bb0136cac8dd0f02000a 0xb4a8bb0136cac8dd0f02000ae7e7e8b7 18446631020132448128 195422361 777 3305 4 5 2 46248 443 NetworkService
07:47:00  0x400500020000bb0136cac8dd0f02000a 0xbb0136cac8dd0f02000ae7e7e8b7 18446631020132448128 195422450 88 3305 5 7 2 46248 443 NetworkService
07:47:01  0x400700020000bb01000000000f02000a 0xbb01000000000f02000aea2afb8e 18446631020099528128 196321556 0 1315 7 2 2 0 443 ChromiumNet
```

### 一些可能的报错原因

#### [opensnoop](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/opensnoop)

例如 opensnoop 工具，可以在 Android 上成功构建，但运行报错：

```console
libbpf: failed to determine tracepoint 'syscalls/sys_enter_open' perf event ID: No such file or directory
libbpf: prog 'tracepoint__syscalls__sys_enter_open': failed to create tracepoint 'syscalls/sys_enter_open' perf event: No such file or directory
libbpf: prog 'tracepoint__syscalls__sys_enter_open': failed to auto-attach: -2
failed to attach skeleton
Error: BpfError("load and attach ebpf program failed")
```

后经查看发现内核未开启 `CONFIG_FTRACE_SYSCALLS` 选项，导致无法使用 syscalls 的 tracepoint。

## 总结

在 Android shell 中查看内核编译选项可以发现  `CONFIG_DEBUG_INFO_BTF` 默认是打开的，在此基础上 eunomia-bpf 项目提供的 example 已有一些能够成功运行的案例，例如可以监测 `exec` 族函数的执行和 tcp 连接的状态。

对于无法运行的一些，原因主要是以下两个方面：

1. 内核编译选项未支持相关 eBPF 功能；
2. eadb 打包的 Linux 环境较弱，缺乏必须依赖；

目前在 Android 系统中使用 eBPF 工具基本上仍然需要构建完整的 Linux 运行环境，但 Android 内核本身对 eBPF 的支持已较为全面，本次测试证明较高版本的 Android 内核支持 BTF 调试信息和依赖 CO-RE 的 eBPF 程序的运行。

Android 系统 eBPF 工具的发展需要官方新特性的加入，目前看来通过 Android APP 直接使用 eBPF 工具需要的工作量较大，同时由于 eBPF 工具需要 root 权限，普通 Android 用户的使用会面临较多困难。

如果希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。

## 参考

[^Google]:<https://source.android.google.cn/docs/core/architecture/kernel/bpf>
[^WeiShu]:<https://mp.weixin.qq.com/s/mul4n5D3nXThjxuHV7GpMA>
[^SeeFlowerX]:<https://blog.seeflower.dev/archives/138/>
