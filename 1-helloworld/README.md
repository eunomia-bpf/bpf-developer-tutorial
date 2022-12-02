---
layout: post
title: minimal
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, tracepoint, example, syscall]
summary: a minimal example of a BPF application installs a tracepoint handler which is triggered by write syscall
---


`minimal` is just that – a minimal practical BPF application example. It
doesn't use or require BPF CO-RE, so should run on quite old kernels. It
installs a tracepoint handler which is triggered once every second. It uses
`bpf_printk()` BPF helper to communicate with the world. 


```console
$ sudo ecli  examples/bpftools/minimal/package.json
Runing eBPF program...
```

To see it's output,
read `/sys/kernel/debug/tracing/trace_pipe` file as a root:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: BPF triggered from PID 3840345.
           <...>-3840345 [010] d... 3220702.101265: bpf_trace_printk: BPF triggered from PID 3840345.
```

`minimal` is great as a bare-bones experimental playground to quickly try out
new ideas or BPF features.

## Compile and Run

 

Compile:

```console
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

or compile with `ecc`:

```console
$ ecc minimal.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

Run:

```console
sudo ecli ./package.json
```