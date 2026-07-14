# eBPF Practice: Tracing User Space Rust Applications with Uprobe

eBPF, or Extended Berkeley Packet Filter, is a revolutionary technology in the Linux kernel that allows developers to run custom "micro-programs" in kernel mode, thus changing system behavior or collecting granular performance data without modifying the kernel code.

This article discusses how to trace user space Rust applications with Uprobe and eBPF, including how to obtain symbol names and attach them, get function parameters, get return values, etc. This article is part of the eBPF developer tutorial, more detailed content can be found here: <https://eunomia.dev/tutorials/>

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/37-uprobe-rust>

## Uprobe

Uprobe is a user space probe. Uprobe probes allow dynamic instrumentation in user space programs, with instrumentation locations including: function entry points, specific offsets, and function return points. When we define a Uprobe, the kernel creates a fast breakpoint instruction (the int3 instruction on x86 machines) at the attached instruction. When the program executes this instruction, the kernel triggers an event, the program falls into kernel mode, and the probe function is called in a callback manner. After the probe function is executed, it returns to user mode to continue executing subsequent instructions.

Uprobe is useful for parsing traffic in user space that cannot be parsed by kernel probes, such as http2 traffic, https traffic, and can also analyze runtime program, business logic, etc. For more information about Uprobe, you can refer to:

- [eBPF practice tutorial: Use Uprobe to capture plaintext SSL/TLS data from various libraries](../30-sslsniff/README.md)
- [eBPF practice tutorial: Use Uprobe to capture Golang coroutine switching](../31-goroutine/README.md)

Running Uprobe in kernel mode eBPF might also produce significant performance overhead, in which case you might consider using user space eBPF runtime, such as [bpftime](https://github.com/eunomia-bpf/bpftime). bpftime is a user-space eBPF runtime based on LLVM JIT/AOT. It can run eBPF Uprobe programs in user mode and is compatible with kernel mode eBPF. Because it avoids context switching between user and kernel modes, bpftime's Uprobe overheads are about 10 times less than the kernel's, and it also more easy to extend.

## Rust

Rust is an open-source systems programming language that focuses on safety, speed, and concurrency. It was developed by Graydon Hoare at the Mozilla Research Center in 2010 and released its first stable version in 2015. The design philosophy of Rust language is to provide the performance advantages of C++ while greatly reducing memory safety vulnerabilities. Rust is gradually popular in the field of systems programming, especially in applications that require high performance, security, and reliability, such as operating systems, file systems, game engines, network services, etc. Many large technology companies, including Mozilla, Google, Microsoft, and Amazon, are using or supporting the Rust language.

You can refer to the [official Rust website](https://www.rust-lang.org/) for more information about Rust language and install the Rust toolchain.

## Simplest example: Symbol name mangling

Let's start with a simple example, tracing the `main` function of a Rust program with Uprobe, with the code as follows:

```rust
pub fn hello() -> i32 {
    println!("Hello, world!");
    0
}

fn main() {
    hello();
}
```

Build and try to get the symbol:

```console
$ cd helloworld
$ cargo build
$ nm -C target/debug/helloworld | grep 'helloworld::main'
0000000000013ec0 t helloworld::main
```

Rustc uses [symbol name mangling](https://en.wikipedia.org/wiki/Name_mangling) to encode unique linker names. Rust 1.97 uses v0 mangling by default, while `nm -C` prints the stable demangled name. Resolve the raw symbol through its address before passing it to bpftrace:

```console
$ main_address=$(nm -C target/debug/helloworld | awk '$2 ~ /^[tT]$/ && $3 ~ /^helloworld::main(::h[[:xdigit:]]+)?$/ && !matched { found = $1; matched = 1 } END { if (matched) print found }')
$ main_symbol=$(nm target/debug/helloworld | awk -v address="$main_address" '$1 == address && $2 ~ /^[tT]$/ && !matched { found = $3; matched = 1 } END { if (matched) print found }')
$ echo "$main_symbol"
_RNvCsiXtUZV4ocyZ_10helloworld4main
```

The `-C symbol-mangling-version` rustc option can select a mangling scheme, but resolving the current binary avoids depending on a particular scheme. We can now trace `main`:

```console
$ sudo bpftrace -e "uprobe:target/debug/helloworld:${main_symbol} { printf(\"Function hello-world called\n\"); }"
Attaching 1 probe...
Function hello-world called
```

## Tracing function calls with multiple invocations and getting return values

For a more complex example, which includes multiple calls and retrieving return values:

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

First, we need to build in debug mode because the `hello` function gets inlined in release mode and won't have its own symbol:

```console
$ cd args
$ cargo build
$ nm -C target/debug/helloworld | grep 'helloworld::hello'
0000000000016f90 t helloworld::hello
```

Note that in release mode (`cargo build --release`), only the `main` function symbol appears because `hello` gets inlined during optimization.

Rust 1.97 uses v0 symbol mangling by default. bpftrace needs the raw symbol, so resolve it from the address of the stable demangled name:

```console
$ hello_address=$(nm -C target/debug/helloworld | awk '$2 ~ /^[tT]$/ && $3 ~ /^helloworld::hello(::h[[:xdigit:]]+)?$/ && !matched { found = $1; matched = 1 } END { if (matched) print found }')
$ hello_symbol=$(nm target/debug/helloworld | awk -v address="$hello_address" '$1 == address && $2 ~ /^[tT]$/ && !matched { found = $3; matched = 1 } END { if (matched) print found }')
$ echo "$hello_symbol"
_RNvCsiXtUZV4ocyZ_10helloworld5hello
$ sudo bpftrace -e "uprobe:target/debug/helloworld:${hello_symbol} { printf(\"Function hello called\n\"); }"
Attaching 1 probe...
Function hello called
Function hello called
Function hello called
Function hello called
```

When we run the program with multiple arguments, bpftrace correctly catches all calls to the `hello` function:

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

We can also get the return value using Uretprobe and the same resolved symbol:

```console
$ sudo bpftrace -e "uretprobe:target/debug/helloworld:${hello_symbol} { printf(\"Function hello returned: %d\n\", retval); }"
Attaching 1 probe...
Function hello returned: 6
Function hello returned: 7
Function hello returned: 8
Function hello returned: 9
```

Resolving the raw symbol through its demangled name works with both legacy and v0 Rust mangling.

## References

- <https://doc.rust-lang.org/rustc/symbol-mangling/index.html>
