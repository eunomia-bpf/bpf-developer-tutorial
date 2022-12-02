---
layout: post
title: fentry-link
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, examples, fentry, no-output]
summary: an example that uses fentry and fexit BPF programs for tracing a file is deleted
---

## Fentry

`fentry` is an example that uses fentry and fexit BPF programs for tracing. It
attaches `fentry` and `fexit` traces to `do_unlinkat()` which is called when a
file is deleted and logs the return value, PID, and filename to the
trace pipe.

Important differences, compared to kprobes, are improved performance and
usability. In this example, better usability is shown with the ability to
directly dereference pointer arguments, like in normal C, instead of using
various read helpers. The big distinction between **fexit** and **kretprobe**
programs is that fexit one has access to both input arguments and returned
result, while kretprobe can only access the result.

fentry and fexit programs are available starting from 5.5 kernels.

```console
$ sudo ecli  examples/bpftools/fentry-link/package.json
Runing eBPF program...
```

The `fentry` output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9290    [004] d..2  4637.798698: bpf_trace_printk: fentry: pid = 9290, filename = test_file
              rm-9290    [004] d..2  4637.798843: bpf_trace_printk: fexit: pid = 9290, filename = test_file, ret = 0
              rm-9290    [004] d..2  4637.798698: bpf_trace_printk: fentry: pid = 9290, filename = test_file2
              rm-9290    [004] d..2  4637.798843: bpf_trace_printk: fexit: pid = 9290, filename = test_file2, ret = 0
```

## Run

 

- Compile:

    ```console
    docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
    ```

    or

    ```console
    $ ecc fentry-link.bpf.c
    Compiling bpf object...
    Packing ebpf object and config into package.json...
    ```

- Run and help:

    ```console
    sudo ecli  examples/bpftools/fentry-link/package.json -h
    Usage: fentry_link_bpf [--help] [--version] [--verbose]

    A simple eBPF program

    Optional arguments:
    -h, --help    shows help message and exits 
    -v, --version prints version information and exits 
    --verbose     prints libbpf debug information 

    Built with eunomia-bpf framework.
    See https://github.com/eunomia-bpf/eunomia-bpf for more information.
    ```