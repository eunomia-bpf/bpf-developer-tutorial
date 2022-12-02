---
layout: post
title: bindsnoop
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, syscall, kprobe, perf-event]
summary: This tool traces the kernel function performing socket binding and print socket options set before the system call.
---

## origin

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/bindsnoop.bpf.c

## Compile and Run

Compile:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Run:

```shell
sudo ./ecli run examples/bpftools/bindsnoop/package.json
```

## details in bcc

Demonstrations of bindsnoop, the Linux eBPF/bcc version.

This tool traces the kernel function performing socket binding and
print socket options set before the system call invocation that might
```console
    impact bind behavior and bound interface:
    SOL_IP     IP_FREEBIND              F....
    SOL_IP     IP_TRANSPARENT           .T...
    SOL_IP     IP_BIND_ADDRESS_NO_PORT  ..N..
    SOL_SOCKET SO_REUSEADDR             ...R.
    SOL_SOCKET SO_REUSEPORT             ....r
```
```console
# ./bindsnoop.py
Tracing binds ... Hit Ctrl-C to end
PID COMM         PROT ADDR            PORT   OPTS IF
3941081 test_bind_op TCP  192.168.1.102       0 F.N..  0
3940194 dig          TCP  ::              62087 .....  0
3940219 dig          UDP  ::              48665 .....  0
3940893 Acceptor Thr TCP  ::              35343 ...R.  0
```
The output shows four bind system calls:
two "test_bind_op" instances, one with IP_FREEBIND and IP_BIND_ADDRESS_NO_PORT
options, dig process called bind for TCP and UDP sockets,
and Acceptor called bind for TCP with SO_REUSEADDR option set.


The -t option prints a timestamp column
```console
# ./bindsnoop.py -t
TIME(s)        PID COMM         PROT ADDR            PORT   OPTS IF
0.000000   3956801 dig          TCP  ::              49611 .....  0
0.011045   3956822 dig          UDP  ::              56343 .....  0
2.310629   3956498 test_bind_op TCP  192.168.1.102   39609 F...r  0
```

The -U option prints a UID column:
```console
# ./bindsnoop.py -U
Tracing binds ... Hit Ctrl-C to end
   UID      PID COMM         PROT ADDR            PORT   OPTS IF
127072  3956498 test_bind_op TCP  192.168.1.102   44491 F...r  0
127072  3960261 Acceptor Thr TCP  ::              48869 ...R.  0
     0  3960729 Acceptor Thr TCP  ::              44637 ...R.  0
     0  3959075 chef-client  UDP  ::              61722 .....  0
```

The -u option filtering UID:
```console
# ./bindsnoop.py -Uu 0
Tracing binds ... Hit Ctrl-C to end
   UID      PID COMM         PROT ADDR            PORT   OPTS IF
     0  3966330 Acceptor Thr TCP  ::              39319 ...R.  0
     0  3968044 python3.7    TCP  ::1             59371 .....  0
     0    10224 fetch        TCP  0.0.0.0         42091 ...R.  0
```

The --cgroupmap option filters based on a cgroup set.
It is meant to be used with an externally created map.
```console
# ./bindsnoop.py --cgroupmap /sys/fs/bpf/test01
```
For more details, see docs/special_filtering.md


In order to track heavy bind usage one can use --count option
```console
# ./bindsnoop.py --count
Tracing binds ... Hit Ctrl-C to end
LADDR                                           LPORT     BINDS
0.0.0.0                                          6771     4
0.0.0.0                                          4433     4
127.0.0.1                                       33665     1
```