# eBPF 入门开发实践教程二：Hello World，基本框架和开发流程

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践教程的第二篇，主要介绍 eBPF 的基本框架和开发流程。

开发 eBPF 程序可以使用多种工具，如 BCC、eunomia-bpf 等。不同的工具有不同的特点，但基本流程大致相同。

## 开发 eBPF 程序的流程

下面以 BCC 工具为例，介绍 eBPF 程序的基本开发流程。

1. 安装编译环境和依赖。使用 BCC 开发 eBPF 程序需要安装 LLVM/Clang 和 bcc，以及其它的依赖库。
2. 编写 eBPF 程序。eBPF 程序主要由两部分构成：内核态部分和用户态部分。内核态部分包含 eBPF 程序的实际逻辑，用户态部分负责加载、运行和监控内核态程序。
3. 编译和加载 eBPF 程序。使用 bcc 工具将 eBPF 程序编译成机器码，然后使用用户态代码加载并运行该程序。
4. 运行程序并处理数据。eBPF 程序在内核运行时会触发事件，并将事件相关的信息传递给用户态程序。用户态程序负责处理这些信息并将结果输出。
5. 结束程序。当 eBPF 程序运行完成后，用户态程序可以卸载并结束运行。

通过这个过程，你可以开发出一个能够在内核中运行的 eBPF 程序。

## 使用 eunomia-bpf 开发 eBPF 程序

eunomia-bpf 是一个开源的 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。它基于 libbpf 的 CO-RE 轻量级开发框架，支持通过用户态 WASM 虚拟机控制 eBPF 程序的加载和执行，并将预编译的 eBPF 程序打包为通用的 JSON 或 WASM 模块进行分发。使用 eunomia-bpf 可以大幅简化 eBPF 程序的开发流程。

使用 eunomia-bpf 开发 eBPF 程序的流程也大致相同，只是细节略有不同。

1. 安装编译环境和依赖。使用 eunomia-bpf 开发 eBPF 程序需要安装 eunomia-bpf 工具链和运行时库，以及其它的依赖库。
2. 编写 eBPF 程序。eBPF 程序主要由两部分构成：内核态部分和用户态部分。内核态部分包含 eBPF 程序的实际逻辑，用户态部分负责加载、运行和监控内核态程序。使用 eunomia-bpf，只需编写内核态代码即可，无需编写用户态代码。
3. 编译和加载 eBPF 程序。使用 eunomia-bpf 工具链将 eBPF 程序编译成机器码，并将编译后的代码打包为可以在任何系统上运行的模块。然后使用 eunomia-bpf 运行时库加载并运行该模块。
4. 运行程序并处理数据。eBPF 程序在内核运行时会触发事件，并将事件相关的信息传递给用户态程序。eunomia-bpf 的运行时库负责处理这些信息并将结果输出。
5. 结束程序。当 eBPF 程序运行完成后，eunomia-bpf 的运行时库可以卸载并结束运行

## 下载安装 eunomia-bpf 开发工具

可以通过以下步骤下载和安装 eunomia-bpf：

下载 ecli 工具，用于运行 eBPF 程序：

```console
$ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
$ ./ecli -h
Usage: ecli [--help] [--version] [--json] [--no-cache] url-and-args
```

下载编译器工具链，用于将 eBPF 内核代码编译为 config 文件或 WASM 模块：

```console
$ wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
$ ./ecc -h
eunomia-bpf compiler
Usage: ecc [OPTIONS] <SOURCE_PATH> [EXPORT_EVENT_HEADER]
....
```

也可以使用 docker 镜像进行编译：

```console
$ docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest # 使用 docker 进行编译。`pwd` 应该包含 *.bpf.c 文件和 *.h 文件。
export PATH=PATH:~/.eunomia/bin
Compiling bpf object...
Packing ebpf object and config into /src/package.json...
```

## Hello World - minimal eBPF program

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
 pid_t pid = bpf_get_current_pid_tgid() >> 32;
 if (pid_filter && pid != pid_filter)
  return 0;
 bpf_printk("BPF triggered from PID %d.\n", pid);
 return 0;
}
```

这段程序通过定义一个 handle_tp 函数并使用 SEC 宏把它附加到 sys_enter_write tracepoint（即在进入 write 系统调用时执行）。该函数通过使用 bpf_get_current_pid_tgid 和 bpf_printk 函数获取调用 write 系统调用的进程 ID，并在内核日志中打印出来。

- `bpf_trace_printk()`： 一种将信息输出到trace_pipe(/sys/kernel/debug/tracing/trace_pipe)简单机制。 在一些简单用例中这样使用没有问题， but它也有一些限制：最多3 参数； 第一个参数必须是%s(即字符串)；同时trace_pipe在内核中全局共享，其他并行使用trace_pipe的程序有可能会将 trace_pipe 的输出扰乱。 一个更好的方式是通过 BPF_PERF_OUTPUT(), 稍后将会讲到。
- `void *ctx`：ctx本来是具体类型的参数， 但是由于我们这里没有使用这个参数，因此就将其写成void *类型。
- `return 0`;：必须这样，返回0 (如果要知道why, 参考 #139  <https://github.com/iovisor/bcc/issues/139>)。

要编译和运行这段程序，可以使用 ecc 工具和 ecli 命令。首先使用 ecc 编译程序：

```console
$ ecc hello.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

或使用 docker 镜像进行编译：

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

然后使用 ecli 运行编译后的程序：

```console
$ sudo ecli ./package.json
Runing eBPF program...
```

运行这段程序后，可以通过查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看 eBPF 程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: write system call from PID 3840345.
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: write system call from PID 3840345.
```

## eBPF 程序的基本框架

如上所述， eBPF 程序的基本框架包括：

- 包含头文件：需要包含 <linux/bpf.h> 和 <bpf/bpf_helpers.h> 等头文件。
- 定义许可证：需要定义许可证，通常使用 "Dual BSD/GPL"。
- 定义 BPF 函数：需要定义一个 BPF 函数，例如其名称为 handle_tp，其参数为 void *ctx，返回值为 int。通常用 C 语言编写。
- 使用 BPF 助手函数：在例如 BPF 函数中，可以使用 BPF 助手函数 bpf_get_current_pid_tgid() 和 bpf_printk()。
- 返回值

## tracepoints

跟踪点（tracepoints）是内核静态插桩技术，跟踪点在技术上只是放置在内核源代码中的跟踪函数，实际上就是在源码中插入的一些带有控制条件的探测点，这些探测点允许事后再添加处理函数。比如在内核中，最常见的静态跟踪方法就是 printk，即输出日志。又比如：在系统调用、调度程序事件、文件系统操作和磁盘 I/O 的开始和结束时都有跟踪点。 于 2009 年在 Linux 2.6.32 版本中首次提供。跟踪点是一种稳定的 API，数量有限。

## 总结

eBPF 程序的开发和使用流程可以概括为如下几个步骤：

- 定义 eBPF 程序的接口和类型：这包括定义 eBPF 程序的接口函数，定义和实现 eBPF 内核映射（maps）和共享内存（perf events），以及定义和使用 eBPF 内核帮助函数（helpers）。
- 编写 eBPF 程序的代码：这包括编写 eBPF 程序的主要逻辑，实现 eBPF 内核映射的读写操作，以及使用 eBPF 内核帮助函数。
- 编译 eBPF 程序：这包括使用 eBPF 编译器（例如 clang）将 eBPF 程序代码编译为 eBPF 字节码，并生成可执行的 eBPF 内核模块。ecc 本质上也是调用 clang 编译器来编译 eBPF 程序。
- 加载 eBPF 程序到内核：这包括将编译好的 eBPF 内核模块加载到 Linux 内核中，并将 eBPF 程序附加到指定的内核事件上。
- 使用 eBPF 程序：这包括监测 eBPF 程序的运行情况，并使用 eBPF 内核映射和共享内存进行数据交换和共享。
- 在实际开发中，还可能需要进行其他的步骤，例如配置编译和加载参数，管理 eBPF 内核模块和内核映射，以及使用其他高级功能等。

需要注意的是，BPF 程序的执行是在内核空间进行的，因此需要使用特殊的工具和技术来编写、编译和调试 BPF 程序。eunomia-bpf 是一个开源的 BPF 编译器和工具包，它可以帮助开发者快速和简单地编写和运行 BPF 程序。

完整的教程和源代码已经全部开源，可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 中查看。
