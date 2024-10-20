# eBPF Tutorial by Example: Using eBPF Programs on Android

> This article mainly documents the author's exploration process, results, and issues encountered while testing the level of support for CO-RE technology based on the libbpf library on high version Android kernels in the Android Studio Emulator.
> The test was conducted by building a Debian environment in the Android Shell environment and attempting to build the eunomia-bpf toolchain and run its test cases based on this.

## Background

As of now (2023-04), Android has not provided good support for dynamic loading of eBPF programs. Both the compiler distribution scheme represented by bcc and the CO-RE scheme based on btf and libbpf rely heavily on Linux environment support and cannot run well on the Android system.[^WeiShu]

However, there have been some successful cases of trying eBPF on the Android platform. In addition to the solution provided by Google to modify `Android.bp` to build and mount eBPF programs with the entire system[^Google], some people have proposed building a Linux environment based on the Android kernel and running the eBPF toolchain using this approach, and have developed related tools.

Currently available information mostly focuses on the testing of bcc and bpftrace toolchains based on the adeb/eadb sandbox built on the Android kernel, with less testing work on the CO-RE scheme. There is more reference material available for using the bcc tool on Android, such as:

+ SeeFlowerX: <https://blog.seeflower.dev/category/eBPF/>
+ evilpan: <https://bbs.kanxue.com/thread-271043.htm>

The main idea is to use chroot to run a Debian image on the Android kernel and build the entire bcc toolchain within it in order to use eBPF tools. The same principle applies to using bpftrace.

In fact, higher versions of the Android kernel already support the btf option, which means that the emerging CO-RE technology in the eBPF field should also be applicable to Linux systems based on the Android kernel. This article will test and run eunomia-bpf in the emulator environment based on this.

> [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) is an open-source project that combines libbpf and WebAssembly technology, aiming to simplify the writing, compilation, and deployment of eBPF programs. This project can be seen as a practical way of implementing CO-RE, with libbpf as its core dependency. It is believed that the testing work of eunomia-bpf can provide reference for other CO-RE schemes.

## Test Environment

+ Android Emulator (Android Studio Flamingo | 2022.2.1)
+ AVD: Pixel 6
+ Android Image: Tiramisu Android 13.0 x86_64 (5.15.41-android13-8-00055-g4f5025129fe8-ab8949913)

## Environment Setup[^SeeFlowerX]

1. Obtain `debianfs-amd64-full.tar.gz` from the releases page of the [eadb repository](https://github.com/tiann/eadb) as the rootfs of the Linux environment. Also, get the `assets` directory from this project to build the environment.
2. Configure and start the Android Virtual Device in the Android Studio Device Manager.
3. Push `debianfs-amd64-full.tar.gz` and the `assets` directory to the AVD using the adb tool from the Android Studio SDK:
   + `./adb push debianfs-amd64-full.tar.gz /data/local/tmp/deb.tar.gz`
   + `./adb push assets /data/local/tmp/assets`
4. Use adb to enter the Android shell environment and obtain root permissions:
   + `./adb shell`
   + `su`
5. Build and enter the debian environment in the Android shell:
   + `mkdir -p /data/eadb`
   + `mv /data/local/tmp/assets/* /data/eadb`
   + `mv /data/local/tmp/deb.tar.gz /data/eadb/deb.tar.gz`+ `rm -r /data/local/tmp/assets`
   + `chmod +x /data/eadb/device-*`
   + `/data/eadb/device-unpack`
   + `/data/eadb/run /data/eadb/debian`

At this point, the Linux environment required for testing eBPF has been set up. In addition, in the Android shell (before entering debian), you can use `zcat /proc/config.gz` in conjunction with `grep` to view kernel compilation options.

>Currently, the debian environment packaged by eadb has a low version of libc and lacks many tool dependencies. Additionally, due to different kernel compilation options, some eBPF features may not be available.

## Build Tools

Clone the eunomia-bpf repository into the local debian environment. For the specific build process, refer to the repository's [build.md](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/documents/build.md). In this test, I used the `ecc` compilation method to generate the `package.json`. Please refer to the [repository page](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/compiler) for the build and usage instructions for this tool.

>During the build process, you may need to manually install tools such as `curl`, `pkg-config`, `libssl-dev`, etc.

## Results

Some eBPF programs can be successfully executed on Android, but there are also some applications that cannot be executed successfully for various reasons.

### Success Cases

#### [bootstrap](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/bootstrap)

The output of running is as follows:

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

After starting monitoring, download a web page using `wget` in the Linux environment:

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

Start the detection and open the Chrome browser in the Android Studio simulation interface to access the Baidu page:

```console
TIME     SADDR   DADDR   SKADDR  TS_US   DELTA_US  PID     OLDSTATE  NEWSTATE  FAMILY  SPORT   DPORT   TASK
07:46:58  0x400700020000bb01000000000f02000a 0xbb01000000000f02000aeb6f2270 18446631020066638144 192874641 0 3305 7 2 2 0 443 NetworkService
07:46:58  0x40020002d28abb01494b6ebe0f02000a 0xd28abb01494b6ebe0f02000aeb6f2270 18446631020066638144 192921938 47297 3305 2 1 2 53898 443 NetworkService
07:46:58  0x400700020000bb01000000000f02000a 0xbb01000000000f02000ae7e7e8b7 18446631020132433920 193111426 0 3305 7 2 2 0 443 NetworkService
07:46:58  0x40020002b4a0bb0179ff85e80f02000a 0xb4a0bb0179ff85e80f02000ae7e7e8b7 18446631020132433920 193124670 13244 3305 2 1 2 46240 443 NetworkService
07:46:58  0x40010002b4a0bb0179ff85e80f02000a 0xb4a0bb0179ff85e80f02000ae7e7e8b7 18446631020132433920 193185397 60727 3305 1 4 2 46240 443 NetworkService
07:46:58  0x40040002b4a0bb0179ff85e80f02000a 0xb4a0bb0179ff85e80f02000ae7e7e8b7 18446631020132433920 193186122 724 3305 4 5 2 46240 443 NetworkService
07:46:58  0x400500020000bb0179ff85e80f02000a 0xbb0179ff85e80f02000ae7e7e8b7 18446631020132433920 193186244 122 3305 5 7 2 46240 443 NetworkService".07:46:59  0x40010002d01ebb01d0c52f5c0f02000a 0xd01ebb01d0c52f5c0f02000a51449c27 18446631020103553856 194110884 0 5130 1 8 2 53278 443 ThreadPoolForeg
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

Note: some error messages may appear in the Android shell during the test:

```console
libbpf: failed to determine tracepoint 'syscalls/sys_enter_open' perf event ID: No such file or directory
libbpf: prog 'tracepoint__syscalls__sys_enter_open': failed to create tracepoint 'syscalls/sys_enter_open' perf event: No such file or directory
libbpf: prog 'tracepoint__syscalls__sys_enter_open': failed to auto-attach: -2
failed to attach skeleton
Error: BpfError("load and attach ebpf program failed")
```

Later, after investigation, it was found that the kernel did not enable the `CONFIG_FTRACE_SYSCALLS` option, which resulted in the inability to use the tracepoint of syscalls.

## Summary

The `CONFIG_DEBUG_INFO_BTF` option is enabled by default when viewing the kernel compilation options in the Android shell. Based on this, the examples provided by the eunomia-bpf project already have some successful cases, such as monitoring the execution of the `exec` family of functions and the status of TCP connections.

For some cases that cannot run, the reasons are mainly the following:

1. The kernel compilation options do not support the relevant eBPF functionality;
2. The Linux environment packaged by eadb is weak and lacks necessary dependencies;

Currently, using eBPF tools in the Android system still requires building a complete Linux runtime environment. However, the Android kernel itself has comprehensive support for eBPF. This test proves that higher versions of the Android kernel support BTF debugging information and CO-RE dependent eBPF programs.

The development of eBPF tools in the Android system requires the addition of official new features. Currently, it seems that using eBPF tools directly through an Android app requires a lot of effort. At the same time, since eBPF tools require root privileges, ordinary Android users will encounter more difficulties in using them.

If you want to learn more about eBPF knowledge and practice, you can visit our tutorial code repository <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> to get more examples and complete tutorials.

## Reference

+ [Google android docs](https://source.android.google.cn/docs/core/architecture/kernel/bpf)
+ [weixin WeiShu](https://mp.weixin.qq.com/s/mul4n5D3nXThjxuHV7GpMA)
+ [SeeFlowerX](https://blog.seeflower.dev/archives/138/>)

> The original link of this article: <https://eunomia.dev/tutorials/22-android>
