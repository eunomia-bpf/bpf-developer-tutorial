# eBPF 实践：使用 Uprobe 追踪用户态 Rust 应用

eBPF，即扩展的Berkeley包过滤器（Extended Berkeley Packet Filter），是Linux内核中的一种革命性技术，它允许开发者在内核态中运行自定义的“微程序”，从而在不修改内核代码的情况下改变系统行为或收集系统细粒度的性能数据。

本文讨论如何使用 Uprobe 和 eBPF 追踪用户态 Rust 应用，包括如何获取符号名称并 attach、获取函数参数、获取返回值等。本文是 eBPF 开发者教程的一部分，更详细的内容可以在这里找到：<https://eunomia.dev/tutorials/> 源代码在 [GitHub 仓库](https://github.com/eunomia-bpf/bpf-developer-tutorial) 中开源。

## Uprobe

Uprobe是一种用户空间探针，uprobe探针允许在用户空间程序中动态插桩，插桩位置包括：函数入口、特定偏移处，以及函数返回处。当我们定义uprobe时，内核会在附加的指令上创建快速断点指令（x86机器上为int3指令），当程序执行到该指令时，内核将触发事件，程序陷入到内核态，并以回调函数的方式调用探针函数，执行完探针函数再返回到用户态继续执行后序的指令。

uprobe 适用于在用户态去解析一些内核态探针无法解析的流量，例如 http2 流量，https 流量，同时也可以分析程序运行时、业务逻辑等。关于 Uprobe 的更多信息，可以参考：

- [eBPF 实践教程：使用 uprobe 捕获多种库的 SSL/TLS 明文数据](../30-sslsniff/README.md)
- [eBPF 实践教程：使用 uprobe 捕获 Golang 的协程切换](../31-goroutine/README.md)
- [eBPF 实践教程：使用 uprobe 捕获用户态 http2 流量](../32-http2/README.md)

Uprobe 在内核态 eBPF 运行时，也可能产生比较大的性能开销，这时候也可以考虑使用用户态 eBPF 运行时，例如  [bpftime](https://github.com/eunomia-bpf/bpftime)。bpftime 是一个基于 LLVM JIT/AOT 的用户态 eBPF 运行时，它可以在用户态运行 eBPF Uprobe 程序，和内核态的 eBPF 兼容，由于避免了内核态和用户态之间的上下文切换，bpftime 的 Uprobe 开销比内核少约 10 倍，并且也更容易扩展。

## Rust

Rust 是一种开源的系统编程语言，注重安全、速度和并行性。它于2010年由Graydon Hoare在Mozilla研究中心开发，并于2015年发布了第一个稳定版本。Rust 语言的设计哲学旨在提供C++的性能优势，同时大幅减少内存安全漏洞。Rust在系统编程领域逐渐受到欢迎，特别是在需要高性能、安全性和可靠性的应用场景，例如操作系统、文件系统、游戏引擎、网络服务等领域。许多大型技术公司，包括Mozilla、Google、Microsoft和Amazon等，都在使用或支持Rust语言。

可以参考 [Rust 官方网站](https://www.rust-lang.org/) 了解更多 Rust 语言的信息，并安装 Rust 的工具链。

## 最简单的例子：Symbol name mangling

我们先来看一个简单的例子，使用 Uprobe 追踪 Rust 程序的 `main` 函数，代码如下：

```rust
pub fn hello() -> i32 {
    println!("Hello, world!");
    0
}

fn main() {
    hello();
}
```

构建和尝试获取符号：

```console
$ cd helloworld
$ cargo build
$ nm helloworld/target/release/helloworld | grep hello
0000000000008940 t _ZN10helloworld4main17h2dce92cb81426b91E
```

我们会发现，对应的符号被转换为了 `_ZN10helloworld4main17h2dce92cb81426b91E`，这是因为 rustc 使用 [Symbol name mangling](https://en.wikipedia.org/wiki/Name_mangling) 来为代码生成过程中使用的符号编码一个唯一的名称。编码后的名称会被链接器用于将名称与所指向的内容关联起来。可以使用 -C symbol-mangling-version 选项来控制符号名称的处理方法。

我们可以使用 [`rustfilt`](https://github.com/luser/rustfilt) 工具来解析和获取对应的符号。这个工具可以通过 `cargo install rustfilt` 安装：

```console
$ cargo install rustfilt
$ nm helloworld/target/release/helloworld > name.txt
$ rustfilt _ZN10helloworld4main17h2dce92cb81426b91E
helloworld::main
$ rustfilt -i name.txt | grep hello
0000000000008b60 t helloworld::main
```

接下来我们可以尝试使用 bpftrace 跟踪对应的函数：

```console
$ sudo bpftrace -e 'uprobe:helloworld/target/release/helloworld:_ZN10helloworld4main17h2dce92cb81426b91E { printf("Function hello-world called\n"); }'
Attaching 1 probe...
Function hello-world called
```

## 追踪多次调用的函数并获取返回值

对于一个更复杂的例子，包含多次调用并演示如何获取返回值：

```rust
use std::env;

pub fn hello(i: i32, len: usize) -> i32 {
    println!("Hello, world! {} in {}", i, len);
    i + len as i32
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Skip the first argument, which is the path to the binary, and iterate over the rest
    for arg in args.iter().skip(1) {
        match arg.parse::<i32>() {
            Ok(i) => {
                let ret = hello(i, args.len());
                println!("return value: {}", ret);
            }
            Err(_) => {
                eprintln!("Error: Argument '{}' is not a valid integer", arg);
            }
        }
    }
}
```

首先，我们需要使用 debug 模式构建，因为 `hello` 函数在 release 模式下会被内联，不会有自己的符号：

```console
$ cd args
$ cargo build
$ nm target/debug/helloworld | grep hello
0000000000016250 t _ZN10helloworld4main17ha3594bca2af541f6E
0000000000016540 t _ZN10helloworld5hello17h5f3a03dda56661e1E
```

注意，在 release 模式（`cargo build --release`）下，只会出现 `main` 函数符号，因为 `hello` 在优化过程中被内联了。

现在我们可以使用符号来追踪 `hello` 函数：

```console
$ sudo bpftrace -e 'uprobe:target/debug/helloworld:_ZN10helloworld5hello17h5f3a03dda56661e1E { printf("Function hello called\n"); }'
Attaching 1 probe...
Function hello called
Function hello called
Function hello called
Function hello called
```

当我们使用多个参数运行程序时，bpftrace 正确地捕获了所有对 `hello` 函数的调用：

```console
$ ./target/debug/helloworld 1 2 3 4
Hello, world! 1 in 5
return value: 6
Hello, world! 2 in 5
return value: 7
Hello, world! 3 in 5
return value: 8
Hello, world! 4 in 5
return value: 9
```

我们也可以使用 Uretprobe 来获取返回值：

```console
$ sudo bpftrace -e 'uretprobe:target/debug/helloworld:_ZN10helloworld5hello17h5f3a03dda56661e1E { printf("Function hello returned: %d\n", retval); }'
Attaching 1 probe...
Function hello returned: 6
Function hello returned: 7
Function hello returned: 8
Function hello returned: 9
```

注意：由于 Rust 的符号名称混淆，确切的符号名称在每次编译时都会变化。请使用 `nm` 命令来找到当前构建的符号名称。

## 参考资料

- <https://doc.rust-lang.org/rustc/symbol-mangling/index.html>
