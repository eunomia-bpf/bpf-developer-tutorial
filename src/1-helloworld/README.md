# eBPF 入门开发实践教程一：Hello World，基本框架和开发流程

在本篇博客中，我们将深入探讨eBPF（Extended Berkeley Packet Filter）的基本框架和开发流程。eBPF是一种在Linux内核上运行的强大网络和性能分析工具，它为开发者提供了在内核运行时动态加载、更新和运行用户定义代码的能力。这使得开发者可以实现高效、安全的内核级别的网络监控、性能分析和故障排查等功能。

本文是eBPF入门开发实践教程的第二篇，我们将重点关注如何编写一个简单的eBPF程序，并通过实际例子演示整个开发流程。在阅读本教程之前，建议您先学习第一篇教程，以便对eBPF的基本概念有个大致的了解。

在开发eBPF程序时，有多种开发框架可供选择，如 BCC（BPF Compiler Collection）libbpf、cilium/ebpf、eunomia-bpf 等。虽然不同工具的特点各异，但它们的基本开发流程大致相同。在接下来的内容中，我们将深入了解这些流程，并以 Hello World 程序为例，带领读者逐步掌握eBPF开发的基本技巧。

本教程将帮助您了解eBPF程序的基本结构、编译和加载过程、用户空间与内核空间的交互方式以及调试与优化技巧。通过学习本教程，您将掌握eBPF开发的基本知识，并为后续进一步学习和实践奠定坚实的基础。

## eBPF开发环境准备与基本开发流程

在开始编写eBPF程序之前，我们需要准备一个合适的开发环境，并了解eBPF程序的基本开发流程。本部分将详细介绍这些内容。

### 安装必要的软件和工具

要开发eBPF程序，您需要安装以下软件和工具：

- Linux 内核：由于eBPF是内核技术，因此您需要具备较新版本的Linux内核（至少 4.8 及以上版本，建议至少在 5.15 以上），以支持eBPF功能。
  - 建议使用最新的 Ubuntu 版本（例如 Ubuntu 23.10）以获得最佳的学习体验，较旧的内核 eBPF 功能支持可能相对不全。
- LLVM 和 Clang：这些工具用于编译eBPF程序。安装最新版本的LLVM和Clang可以确保您获得最佳的eBPF支持。

eBPF 程序主要由两部分构成：内核态部分和用户态部分。内核态部分包含 eBPF 程序的实际逻辑，用户态部分负责加载、运行和监控内核态程序。

当您选择了合适的开发框架后，如BCC（BPF Compiler Collection）、libbpf、cilium/ebpf或eunomia-bpf等，您可以开始进行用户态和内核态程序的开发。以BCC工具为例，我们将介绍eBPF程序的基本开发流程：

1. 安装BCC工具：根据您的Linux发行版，按照BCC官方文档的指南安装BCC工具和相关依赖。
2. 编写eBPF程序（C语言）：使用C语言编写一个简单的eBPF程序，例如Hello World程序。该程序可以在内核空间执行并完成特定任务，如统计网络数据包数量。
3. 编写用户态程序（Python或C等）：使用Python、C等语言编写用户态程序，用于加载、运行eBPF程序以及与之交互。在这个程序中，您需要使用BCC提供的API来加载和操作内核态的eBPF程序。
4. 编译eBPF程序：使用BCC工具，将C语言编写的eBPF程序编译成内核可以执行的字节码。BCC会在运行时动态从源码编译eBPF程序。
5. 加载并运行eBPF程序：在用户态程序中，使用BCC提供的API加载编译好的eBPF程序到内核空间，然后运行该程序。
6. 与eBPF程序交互：用户态程序通过BCC提供的API与eBPF程序交互，实现数据收集、分析和展示等功能。例如，您可以使用BCC API读取eBPF程序中的map数据，以获取网络数据包统计信息。
7. 卸载eBPF程序：当不再需要eBPF程序时，用户态程序应使用BCC API将其从内核空间卸载。
8. 调试与优化：使用 bpftool 等工具进行eBPF程序的调试和优化，提高程序性能和稳定性。

通过以上流程，您可以使用BCC工具开发、编译、运行和调试eBPF程序。请注意，其他框架（如libbpf、cilium/ebpf和eunomia-bpf）的开发流程大致相似但略有不同，因此在选择框架时，请参考相应的官方文档和示例。

通过这个过程，你可以开发出一个能够在内核中运行的 eBPF 程序。eunomia-bpf 是一个开源的 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。它基于 libbpf 的 CO-RE 轻量级开发框架，支持通过用户态 WASM 虚拟机控制 eBPF 程序的加载和执行，并将预编译的 eBPF 程序打包为通用的 JSON 或 WASM 模块进行分发。我们会使用 eunomia-bpf 进行演示。

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
```

注：假如在 aarch64 平台上，请从 release 下载 [ecc-aarch64](https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc-aarch64) 和 [ecli-aarch64](https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli-aarch64).

也可以使用 docker 镜像进行编译：

```console
$ docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest # 使用 docker 进行编译。`pwd` 应该包含 *.bpf.c 文件和 *.h 文件。
export PATH=PATH:~/.eunomia/bin
Compiling bpf object...
Packing ebpf object and config into /src/package.json...
```

## Hello World - minimal eBPF program

我们会先从一个简单的 eBPF 程序开始，它会在内核中打印一条消息。我们会使用 eunomia-bpf 的编译器工具链将其编译为 bpf 字节码文件，然后使用 ecli 工具加载并运行该程序。作为示例，我们可以暂时省略用户态程序的部分。

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
 bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);
 return 0;
}
```

这段程序通过定义一个 handle_tp 函数并使用 SEC 宏把它附加到 sys_enter_write tracepoint（即在进入 write 系统调用时执行）。该函数通过使用 bpf_get_current_pid_tgid 和 bpf_printk 函数获取调用 write 系统调用的进程 ID，并在内核日志中打印出来。

- `bpf_printk()`： 一种将信息输出到trace_pipe(/sys/kernel/debug/tracing/trace_pipe)简单机制。 在一些简单用例中这样使用没有问题， but它也有一些限制：最多3 参数； 第一个参数必须是%s(即字符串)；同时trace_pipe在内核中全局共享，其他并行使用trace_pipe的程序有可能会将 trace_pipe 的输出扰乱。 一个更好的方式是通过 BPF_PERF_OUTPUT(), 稍后将会讲到。
- `void *ctx`：ctx本来是具体类型的参数， 但是由于我们这里没有使用这个参数，因此就将其写成void *类型。
- `return 0`;：必须这样，返回0 (如果要知道why, 参考 #139  <https://github.com/iovisor/bcc/issues/139>)。

要编译和运行这段程序，可以使用 ecc 工具和 ecli 命令。首先在 Ubuntu/Debian 上，执行以下命令：

```shell
sudo apt install clang llvm
```

使用 ecc 编译程序：

```console
$ ./ecc minimal.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

或使用 docker 镜像进行编译：

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

然后使用 ecli 运行编译后的程序：

```console
$ sudo ./ecli run package.json
Running eBPF program...
```

运行这段程序后，可以通过查看 /sys/kernel/debug/tracing/trace_pipe 文件来查看 eBPF 程序的输出：

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "BPF triggered sys_enter_write"
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: write system call from PID 3840345.
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: write system call from PID 3840345.
```

按 Ctrl+C 停止 ecli 进程之后，可以看到对应的输出也停止。

注意：如果正在使用的 Linux 发行版（例如 Ubuntu ）默认情况下没有启用跟踪子系统可能看不到任何输出，使用以下指令打开这个功能：

```console
$ sudo su
# echo 1 > /sys/kernel/debug/tracing/tracing_on
```

## eBPF 程序的基本框架

如上所述， eBPF 程序的基本框架包括：

- 包含头文件：需要包含 <linux/bpf.h> 和 <bpf/bpf_helpers.h> 等头文件。
- 定义许可证：需要定义许可证，通常使用 "Dual BSD/GPL"。
- 定义 BPF 函数：需要定义一个 BPF 函数，例如其名称为 handle_tp，其参数为 void *ctx，返回值为 int。通常用 C 语言编写。
- 使用 BPF 助手函数：在例如 BPF 函数中，可以使用 BPF 助手函数 bpf_get_current_pid_tgid() 和 bpf_printk()。
- 返回值

## tracepoints

跟踪点（tracepoints）是内核静态插桩技术，在技术上只是放置在内核源代码中的跟踪函数，实际上就是在源码中插入的一些带有控制条件的探测点，这些探测点允许事后再添加处理函数。比如在内核中，最常见的静态跟踪方法就是 printk，即输出日志。又比如：在系统调用、调度程序事件、文件系统操作和磁盘 I/O 的开始和结束时都有跟踪点。跟踪点于 2009 年在 Linux 2.6.32 版本中首次提供。跟踪点是一种稳定的 API，数量有限。

## GitHub 模板：轻松构建 eBPF 项目和开发环境

面对创建一个 eBPF 项目，您是否对如何开始搭建环境以及选择编程语言感到困惑？别担心，我们为您准备了一系列 GitHub 模板，以便您快速启动一个全新的eBPF项目。只需在GitHub上点击 `Use this template` 按钮，即可开始使用。

- <https://github.com/eunomia-bpf/libbpf-starter-template>：基于C语言和 libbpf 框架的eBPF项目模板
- <https://github.com/eunomia-bpf/cilium-ebpf-starter-template>：基于Go语言和cilium/ebpf框架的eBPF项目模板
- <https://github.com/eunomia-bpf/libbpf-rs-starter-template>：基于Rust语言和libbpf-rs框架的eBPF项目模板
- <https://github.com/eunomia-bpf/eunomia-template>：基于C语言和eunomia-bpf框架的eBPF项目模板

这些启动模板包含以下功能：

- 一个 Makefile，让您可以一键构建项目
- 一个 Dockerfile，用于为您的 eBPF 项目自动创建一个容器化环境并发布到 Github Packages
- GitHub Actions，用于自动化构建、测试和发布流程
- eBPF 开发所需的所有依赖项

> 通过将现有仓库设置为模板，您和其他人可以快速生成具有相同基础结构的新仓库，从而省去了手动创建和配置的繁琐过程。借助 GitHub 模板仓库，开发者可以专注于项目的核心功能和逻辑，而无需为基础设置和结构浪费时间。更多关于模板仓库的信息，请参阅官方文档：<https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-template-repository>

## 总结

eBPF 程序的开发和使用流程可以概括为如下几个步骤：

- 定义 eBPF 程序的接口和类型：这包括定义 eBPF 程序的接口函数，定义和实现 eBPF 内核映射（maps）和共享内存（perf events），以及定义和使用 eBPF 内核帮助函数（helpers）。
- 编写 eBPF 程序的代码：这包括编写 eBPF 程序的主要逻辑，实现 eBPF 内核映射的读写操作，以及使用 eBPF 内核帮助函数。
- 编译 eBPF 程序：这包括使用 eBPF 编译器（例如 clang）将 eBPF 程序代码编译为 eBPF 字节码，并生成可执行的 eBPF 内核模块。ecc 本质上也是调用 clang 编译器来编译 eBPF 程序。
- 加载 eBPF 程序到内核：这包括将编译好的 eBPF 内核模块加载到 Linux 内核中，并将 eBPF 程序附加到指定的内核事件上。
- 使用 eBPF 程序：这包括监测 eBPF 程序的运行情况，并使用 eBPF 内核映射和共享内存进行数据交换和共享。
- 在实际开发中，还可能需要进行其他的步骤，例如配置编译和加载参数，管理 eBPF 内核模块和内核映射，以及使用其他高级功能等。

需要注意的是，BPF 程序的执行是在内核空间进行的，因此需要使用特殊的工具和技术来编写、编译和调试 BPF 程序。eunomia-bpf 是一个开源的 BPF 编译器和工具包，它可以帮助开发者快速和简单地编写和运行 BPF 程序。

您还可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 以获取更多示例和完整的教程，全部内容均已开源。我们会继续分享更多有关 eBPF 开发实践的内容，帮助您更好地理解和掌握 eBPF 技术。

> 原文地址：<https://eunomia.dev/zh/tutorials/1-helloworld/> 转载请注明出处。
