# openssl_tracer

> openssl_tracer: 基于eBPF技术实现TLS加密的明文捕获。

该样例项目是基于eBPF来追踪OpenSSL动态库的例子，使用 libbpf 进行追踪。在eBPF 程序中，
由于 libbpf 方法内核已经支持了 BTF，不再需要引入众多的内核头文件来获取内核数据结构的定义，
取而代之的是 bpftool 生成的 vmlinux.h 头文件，其中包含内核数据结构的定义。

这个样例是为了配合“使用eBPF跟踪 SSL/TLS 连接” [这个 Blog](https://kiosk007.top/post/%E4%BD%BF%E7%94%A8ebpf%E8%B7%9F%E8%B8%AA-ssltls-%E8%BF%9E%E6%8E%A5/)
                                          
## OpenSSL Tracer using BPF

![](https://ebpf.io/static/overview-bf463455a5666fc3fb841b9240d588ff.png)


This is a basic example of how to trace the OpenSSL library using eBPF. This tracer uses BCC to deploy the eBPF probes. This demo was created to accompany the "Debugging with eBPF Part 3: Tracing SSL/TLS connections" blog post.


eBPF 程序能够加载到 trace points、内核及用户空间应用程序中的 probe points， 
这种能力使我们对应用程序的运行时行为（runtime behavior）和系统本身 （system itself）提供了史无前例的可观测性。

## Prerequisites
操作系统版本最好大于 5.x，本样例运行于 ubuntu 5.15.x 版本。 一些5.4版本以下的内核还会存在些许问题，详见 https://github.com/iovisor/bcc/issues/2948
```bash
$ uname -r
5.15.0-30-generic
```

`CONFIG_DEBUG_INFO_BTF = y`，新的 BPF 二进制文件仅在设置了此内核配置选项后才可用，Ubuntu 20.10 已经将此配置选项设置为默认选项

需要安装 libbpf 工具，在Ubuntu 上执行以下命令，
``` bash
$ sudo apt install libbpf-dev
```
其他操作系统有类似的命令。

## Build
执行以下命令
```bash
make ebpf
make build
```

## Run Demo Application
该 Demo 包含一个 ssl_client_server 的 ssl 通信的小程序。运行该小程序可以稳定的运行 ssl 通信数据。
``` bash
cd ssl_client_server; python3 ./server.py
cd ssl_client_server; python3 ./client.py
```

## Run Tracer
以下方式
```bash
sudo ./openssl_tracer <pid>
```
如果是追踪小程序，则可以

```bash
sudo ./openssl_tracer $(pgrep -f "./client.py")
```


