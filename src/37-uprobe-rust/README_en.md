# eBPF Practice: Tracing User Space Rust Applications with Uprobe

eBPF, or Extended Berkeley Packet Filter, is a revolutionary technology in the Linux kernel that allows developers to run custom "micro-programs" in kernel mode, thus changing system behavior or collecting granular performance data without modifying the kernel code.

This article discusses how to trace user space Rust applications with Uprobe and eBPF, including how to obtain symbol names and attach them, get function parameters, get return values, etc. This article is part of the eBPF developer tutorial, more detailed content can be found here: <https://eunomia.dev/tutorials/> The source code is open source in the [GitHub repository](https://github.com/eunomia-bpf/bpf-developer-tutorial).

## Uprobe

Uprobe is a user space probe. Uprobe probes allow dynamic instrumentation in user space programs, with instrumentation locations including: function entry points, specific offsets, and function return points. When we define a Uprobe, the kernel creates a fast breakpoint instruction (the int3 instruction on x86 machines) at the attached instruction. When the program executes this instruction, the kernel triggers an event, the program falls into kernel mode, and the probe function is called in a callback manner. After the probe function is executed, it returns to user mode to continue executing subsequent instructions.

Uprobe is useful for parsing traffic in user space that cannot be parsed by kernel probes, such as http2 traffic, https traffic, and can also analyze runtime program, business logic, etc. For more information about Uprobe, you can refer to:

- [eBPF practice tutorial: Use Uprobe to capture plaintext SSL/TLS data from various libraries](../30-sslsniff/README.md)
- [eBPF practice tutorial: Use Uprobe to capture Golang coroutine switching](../31-goroutine/README.md)
- [eBPF practice tutorial: Use Uprobe to capture user space http2 traffic](../32-http2/README.md)

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
$ nm helloworld/target/release/helloworld | grep hello
0000000000008940 t _ZN10helloworld4main17h2dce92cb81426b91E
```

We find that the corresponding symbol has been converted to `_ZN10helloworld4main17h2dce92cb81426b91E`. This is because rustc uses [Symbol name mangling](https://en.wikipedia.org/wiki/Name_mangling) to encode a unique name for the symbols used in the code generation process. The encoded name will be used by the linker to associate the name with the content it points to. The -C symbol-mangling-version option can be used to control the handling of symbol names.

We can use the [`rustfilt`](https://crates.io/crates/rustfilt) tool to parse and obtain the corresponding symbol:

```console
$ cargo install rustfilt
$ nm helloworld/target/release/helloworld > name.txt
$ rustfilt _ZN10helloworld4main17h2dce92cb81426b91E
helloworld::main
$ rustfilt -i name.txt | grep hello
0000000000008b60 t helloworld::main
```

Next we can try to use bpftrace to trace the corresponding function:

```console
$ sudo bpftrace -e 'uprobe:helloworld/target/release/helloworld:_ZN10helloworld4main17h2dce92cb81426b91E { printf("Function hello-world called\n"); }'
Attaching 1 probe...
Function hello-world called
```

## A strange phenomenon: multiple calls, getting parameters

For a more complex example, which includes multiple calls and parameter fetching:

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

We repeat a similar operation and notice a strange phenomenon:

```console
$ sudo bpftrace -e 'uprobe:args/target/release/helloworld:_ZN10helloworld4main17h2dce92cb81426b91E { printf("Function hello-world called\n"); }'
Attaching 1 probe...
Function hello-world called
```

At this point we expect the hello function to run several times, but bpftrace only prints out one call:

```console
$ args/target/release/helloworld 1 2 3 4
Hello, world! 1 in 5
return value: 6
Hello, world! 2 in 5
return value: 7
Hello, world! 3 in 5
return value: 8
Hello, world! 4 in 5
return value: 9
```

And it appears that bpftrace cannot correctly get the parameter:

```console
$ sudo bpftrace -e 'uprobe:args/target/release/helloworld:_ZN10helloworld4main17h2dce92cb81426b91E { printf("Function hello-world called %d\n"
, arg0); }'
Attaching 1 probe...
Function hello-world called 63642464
```

The Uretprobe did catch the return value of the first call:

```console
$ sudo bpftrace -e 'uretprobe:args/tar
get/release/helloworld:_ZN10helloworld4main17h2dce92
cb81426b91E { printf("Function hello-world called %d
\n", retval); }'
Attaching 1 probe...
Function hello-world called 6
```

This may due to Rust does not have a stable ABI. Rust, as it has existed so far, has reserved the right to order those struct members any way it wants. So the compiled version of the callee might order the members exactly as above, while the compiled version of the programming calling into the library might think its actually laid out like this:

TODO: Further analysis (to be continued)

## References

- <https://doc.rust-lang.org/rustc/symbol-mangling/index.html>
