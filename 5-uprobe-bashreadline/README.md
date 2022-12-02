---
layout: post
title: bootstrap
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, examples, uprobe, perf event]
summary: an example of a simple (but realistic) BPF application prints bash commands from all running bash shells on the system. 
---



This prints bash commands from all running bash shells on the system. 

## System requirements:

- Linux kernel > 5.5
- Eunomia's [ecli](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/ecli) installed


## Run

- Compile:

  ```shell
  docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
  ```

  or

  ```shell
  ecc bashreadline.bpf.c bashreadline.h
  ```

- Run:

  ```console
  $ sudo ./ecli run eunomia-bpf/examples/bpftools/bootstrap/package.json
  TIME      PID    STR
  11:17:34  28796  whoami
  11:17:41  28796  ps -ef
  11:17:51  28796  echo "Hello eBPF!"
  ```

## details in bcc


```
Demonstrations of bashreadline, the Linux eBPF/bcc version.

This prints bash commands from all running bash shells on the system. For
example:

# ./bashreadline
TIME      PID    COMMAND
05:28:25  21176  ls -l
05:28:28  21176  date
05:28:35  21176  echo hello world
05:28:43  21176  foo this command failed
05:28:45  21176  df -h
05:29:04  3059   echo another shell
05:29:13  21176  echo first shell again

When running the script on Arch Linux, you may need to specify the location
of libreadline.so library:

# ./bashreadline -s /lib/libreadline.so
TIME      PID    COMMAND
11:17:34  28796  whoami
11:17:41  28796  ps -ef
11:17:51  28796  echo "Hello eBPF!"


The entered command may fail. This is just showing what command lines were
entered interactively for bash to process.

It works by tracing the return of the readline() function using uprobes
(specifically a uretprobe).
```