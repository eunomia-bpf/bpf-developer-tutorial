---
layout: post
title: tcpconnlat
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, syscall, network]
summary: Traces the kernel function performing active TCP connections(eg, via a connect() syscall; accept() are passive connections).  and show connection latency.
---

## origin

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpconnlat.bpf.c

## Compile and Run

Compile:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Run:

```shell
sudo ./ecli run package.json
```

TODO: support union in C

## details in bcc

Demonstrations of tcpconnect, the Linux eBPF/bcc version.


This tool traces the kernel function performing active TCP connections
(eg, via a connect() syscall; accept() are passive connections). Some example
output (IP addresses changed to protect the innocent):
```console
# ./tcpconnect
PID    COMM         IP SADDR            DADDR            DPORT
1479   telnet       4  127.0.0.1        127.0.0.1        23
1469   curl         4  10.201.219.236   54.245.105.25    80
1469   curl         4  10.201.219.236   54.67.101.145    80
1991   telnet       6  ::1              ::1              23
2015   ssh          6  fe80::2000:bff:fe82:3ac fe80::2000:bff:fe82:3ac 22
```
This output shows four connections, one from a "telnet" process, two from
"curl", and one from "ssh". The output details shows the IP version, source
address, destination address, and destination port. This traces attempted
connections: these may have failed.

The overhead of this tool should be negligible, since it is only tracing the
kernel functions performing connect. It is not tracing every packet and then
filtering.


The -t option prints a timestamp column:
```console
# ./tcpconnect -t
TIME(s)  PID    COMM         IP SADDR            DADDR            DPORT
31.871   2482   local_agent  4  10.103.219.236   10.251.148.38    7001
31.874   2482   local_agent  4  10.103.219.236   10.101.3.132     7001
31.878   2482   local_agent  4  10.103.219.236   10.171.133.98    7101
90.917   2482   local_agent  4  10.103.219.236   10.251.148.38    7001
90.928   2482   local_agent  4  10.103.219.236   10.102.64.230    7001
90.938   2482   local_agent  4  10.103.219.236   10.115.167.169   7101
```
The output shows some periodic connections (or attempts) from a "local_agent"
process to various other addresses. A few connections occur every minute.

The -d option tracks DNS responses and tries to associate each connection with
the a previous DNS query issued before it.  If a DNS response matching the IP
is found, it will be printed. If no match was found, "No DNS Query" is printed
in this column. Queries for 127.0.0.1 and ::1 are automatically associated with
"localhost". If the time between when the DNS response was received and a
connect call was traced exceeds 100ms, the tool will print the time delta
after the query name.  See below for www.domain.com for an example.
```console
# ./tcpconnect -d
PID    COMM         IP SADDR            DADDR            DPORT QUERY
1543   amazon-ssm-a 4  10.66.75.54      176.32.119.67    443   ec2messages.us-west-1.amazonaws.com
1479   telnet       4  127.0.0.1        127.0.0.1        23    localhost
1469   curl         4  10.201.219.236   54.245.105.25    80    www.domain.com (123.342ms)
1469   curl         4  10.201.219.236   54.67.101.145    80    No DNS Query
1991   telnet       6  ::1              ::1              23    localhost
2015   ssh          6  fe80::2000:bff:fe82:3ac fe80::2000:bff:fe82:3ac 22    anotherhost.org
```

The -L option prints a LPORT column:
```console
# ./tcpconnect -L
PID    COMM         IP SADDR            LPORT  DADDR            DPORT
3706   nc           4  192.168.122.205  57266  192.168.122.150  5000
3722   ssh          4  192.168.122.205  50966  192.168.122.150  22
3779   ssh          6  fe80::1          52328  fe80::2          22
```

The -U option prints a UID column:
```console
# ./tcpconnect -U
UID   PID    COMM         IP SADDR            DADDR            DPORT
0     31333  telnet       6  ::1              ::1              23
0     31333  telnet       4  127.0.0.1        127.0.0.1        23
1000  31322  curl         4  127.0.0.1        127.0.0.1        80
1000  31322  curl         6  ::1              ::1              80
```

The -u option filtering UID:
```console
# ./tcpconnect -Uu 1000
UID   PID    COMM         IP SADDR            DADDR            DPORT
1000  31338  telnet       6  ::1              ::1              23
1000  31338  telnet       4  127.0.0.1        127.0.0.1        23
```
To spot heavy outbound connections quickly one can use the -c flag. It will
count all active connections per source ip and destination ip/port.
```console
# ./tcpconnect.py -c
Tracing connect ... Hit Ctrl-C to end
^C
LADDR                 RADDR                      RPORT             CONNECTS
192.168.10.50         172.217.21.194             443               70
192.168.10.50         172.213.11.195             443               34
192.168.10.50         172.212.22.194             443               21
[...]
```

The --cgroupmap option filters based on a cgroup set. It is meant to be used
with an externally created map.
```console
# ./tcpconnect --cgroupmap /sys/fs/bpf/test01
```
For more details, see docs/special_filtering.md

