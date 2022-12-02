---
layout: post
title: kprobe-link
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, examples, kprobe, no-output]
summary: an example of dealing with kernel-space entry and exit (return) probes, `kprobe` and `kretprobe` in libbpf lingo
---


`kprobe` is an example of dealing with kernel-space entry and exit (return)
probes, `kprobe` and `kretprobe` in libbpf lingo. It attaches `kprobe` and
`kretprobe` BPF programs to the `do_unlinkat()` function and logs the PID,
filename, and return result, respectively, using `bpf_printk()` macro.

```console
$ sudo ecli  examples/bpftools/kprobe-link/package.json
Runing eBPF program...
```

The `kprobe` demo output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9346    [005] d..3  4710.951696: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test1
              rm-9346    [005] d..4  4710.951819: bpf_trace_printk: KPROBE EXIT: ret = 0
              rm-9346    [005] d..3  4710.951852: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test2
              rm-9346    [005] d..4  4710.951895: bpf_trace_printk: KPROBE EXIT: ret = 0
```

## Run

 

Compile with docker:

```console
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

or compile with `ecc`:

```console
$ ecc kprobe-link.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

Run:

```console
sudo ecli examples/bpftools/kprobe-link/package.json
```