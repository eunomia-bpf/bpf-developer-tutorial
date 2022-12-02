---
layout: post
title: opensnoop
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, syscall]
summary: opensnoop traces the open() syscall system-wide, and prints various details.
---

## origin

The kernel code is origin from:

<https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c>

result:

```console
$ sudo ecli examples/bpftools/opensnoop/package.json -h
Usage: opensnoop_bpf [--help] [--version] [--verbose] [--pid_target VAR] [--tgid_target VAR] [--uid_target VAR] [--failed]

Trace open family syscalls.

Optional arguments:
  -h, --help    shows help message and exits 
  -v, --version prints version information and exits 
  --verbose     prints libbpf debug information 
  --pid_target  Process ID to trace 
  --tgid_target Thread ID to trace 
  --uid_target  User ID to trace 
  -f, --failed  trace only failed events 

Built with eunomia-bpf framework.
See https://github.com/eunomia-bpf/eunomia-bpf for more information.

$ sudo ecli examples/bpftools/opensnoop/package.json
TIME     TS      PID     UID     RET     FLAGS   COMM    FNAME   
20:31:50  0      1       0       51      524288  systemd /proc/614/cgroup
20:31:50  0      33182   0       25      524288  ecli    /etc/localtime
20:31:53  0      754     0       6       0       irqbalance /proc/interrupts
20:31:53  0      754     0       6       0       irqbalance /proc/stat
20:32:03  0      754     0       6       0       irqbalance /proc/interrupts
20:32:03  0      754     0       6       0       irqbalance /proc/stat
20:32:03  0      632     0       7       524288  vmtoolsd /etc/mtab
20:32:03  0      632     0       9       0       vmtoolsd /proc/devices

$ sudo ecli examples/bpftools/opensnoop/package.json --pid_target 754
TIME     TS      PID     UID     RET     FLAGS   COMM    FNAME   
20:34:13  0      754     0       6       0       irqbalance /proc/interrupts
20:34:13  0      754     0       6       0       irqbalance /proc/stat
20:34:23  0      754     0       6       0       irqbalance /proc/interrupts
20:34:23  0      754     0       6       0       irqbalance /proc/stat
```

## Compile and Run

Compile with docker:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

or compile with `ecc`:

```console
$ ecc opensnoop.bpf.c opensnoop.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```

Run:

```shell
sudo ./ecli run examples/bpftools/opensnoop/package.json
```

## details in bcc

Demonstrations of opensnoop, the Linux eBPF/bcc version.

opensnoop traces the open() syscall system-wide, and prints various details.
Example output:

```console
# ./opensnoop
PID    COMM      FD ERR PATH
17326  <...>      7   0 /sys/kernel/debug/tracing/trace_pipe
1576   snmpd      9   0 /proc/net/dev
1576   snmpd     11   0 /proc/net/if_inet6
1576   snmpd     11   0 /proc/sys/net/ipv4/neigh/eth0/retrans_time_ms
1576   snmpd     11   0 /proc/sys/net/ipv6/neigh/eth0/retrans_time_ms
1576   snmpd     11   0 /proc/sys/net/ipv6/conf/eth0/forwarding
1576   snmpd     11   0 /proc/sys/net/ipv6/neigh/eth0/base_reachable_time_ms
1576   snmpd     11   0 /proc/sys/net/ipv4/neigh/lo/retrans_time_ms
1576   snmpd     11   0 /proc/sys/net/ipv6/neigh/lo/retrans_time_ms
1576   snmpd     11   0 /proc/sys/net/ipv6/conf/lo/forwarding
1576   snmpd     11   0 /proc/sys/net/ipv6/neigh/lo/base_reachable_time_ms
1576   snmpd      9   0 /proc/diskstats
1576   snmpd      9   0 /proc/stat
1576   snmpd      9   0 /proc/vmstat
1956   supervise  9   0 supervise/status.new
1956   supervise  9   0 supervise/status.new
17358  run        3   0 /etc/ld.so.cache
17358  run        3   0 /lib/x86_64-linux-gnu/libtinfo.so.5
17358  run        3   0 /lib/x86_64-linux-gnu/libdl.so.2
17358  run        3   0 /lib/x86_64-linux-gnu/libc.so.6
17358  run       -1   6 /dev/tty
17358  run        3   0 /proc/meminfo
17358  run        3   0 /etc/nsswitch.conf
17358  run        3   0 /etc/ld.so.cache
17358  run        3   0 /lib/x86_64-linux-gnu/libnss_compat.so.2
17358  run        3   0 /lib/x86_64-linux-gnu/libnsl.so.1
17358  run        3   0 /etc/ld.so.cache
17358  run        3   0 /lib/x86_64-linux-gnu/libnss_nis.so.2
17358  run        3   0 /lib/x86_64-linux-gnu/libnss_files.so.2
17358  run        3   0 /etc/passwd
17358  run        3   0 ./run
^C
``
While tracing, the snmpd process opened various /proc files (reading metrics),
and a "run" process read various libraries and config files (looks like it
was starting up: a new process).

opensnoop can be useful for discovering configuration and log files, if used
during application startup.

```console
The -p option can be used to filter on a PID, which is filtered in-kernel. Here
I've used it with -T to print timestamps:

 ./opensnoop -Tp 1956
TIME(s)       PID    COMM               FD ERR PATH
0.000000000   1956   supervise           9   0 supervise/status.new
0.000289999   1956   supervise           9   0 supervise/status.new
1.023068000   1956   supervise           9   0 supervise/status.new
1.023381997   1956   supervise           9   0 supervise/status.new
2.046030000   1956   supervise           9   0 supervise/status.new
2.046363000   1956   supervise           9   0 supervise/status.new
3.068203997   1956   supervise           9   0 supervise/status.new
3.068544999   1956   supervise           9   0 supervise/status.new
```

This shows the supervise process is opening the status.new file twice every
second.

The -U option include UID on output:

```console
# ./opensnoop -U
UID   PID    COMM               FD ERR PATH
0     27063  vminfo              5   0 /var/run/utmp
103   628    dbus-daemon        -1   2 /usr/local/share/dbus-1/system-services
103   628    dbus-daemon        18   0 /usr/share/dbus-1/system-services
103   628    dbus-daemon        -1   2 /lib/dbus-1/system-services
```

The -u option filtering UID:

```console
# ./opensnoop -Uu 1000
UID   PID    COMM               FD ERR PATH
1000  30240  ls                  3   0 /etc/ld.so.cache
1000  30240  ls                  3   0 /lib/x86_64-linux-gnu/libselinux.so.1
1000  30240  ls                  3   0 /lib/x86_64-linux-gnu/libc.so.6
1000  30240  ls                  3   0 /lib/x86_64-linux-gnu/libpcre.so.3
1000  30240  ls                  3   0 /lib/x86_64-linux-gnu/libdl.so.2
1000  30240  ls                  3   0 /lib/x86_64-linux-gnu/libpthread.so.0
```

The -x option only prints failed opens:

```console
# ./opensnoop -x
PID    COMM      FD ERR PATH
18372  run       -1   6 /dev/tty
18373  run       -1   6 /dev/tty
18373  multilog  -1  13 lock
18372  multilog  -1  13 lock
18384  df        -1   2 /usr/share/locale/en_US.UTF-8/LC_MESSAGES/coreutils.mo
18384  df        -1   2 /usr/share/locale/en_US.utf8/LC_MESSAGES/coreutils.mo
18384  df        -1   2 /usr/share/locale/en_US/LC_MESSAGES/coreutils.mo
18384  df        -1   2 /usr/share/locale/en.UTF-8/LC_MESSAGES/coreutils.mo
18384  df        -1   2 /usr/share/locale/en.utf8/LC_MESSAGES/coreutils.mo
18384  df        -1   2 /usr/share/locale/en/LC_MESSAGES/coreutils.mo
18385  run       -1   6 /dev/tty
18386  run       -1   6 /dev/tty
```

This caught a df command failing to open a coreutils.mo file, and trying from
different directories.

The ERR column is the system error number. Error number 2 is ENOENT: no such
file or directory.

A maximum tracing duration can be set with the -d option. For example, to trace
for 2 seconds:

```console
# ./opensnoop -d 2
PID    COMM               FD ERR PATH
2191   indicator-multi    11   0 /sys/block
2191   indicator-multi    11   0 /sys/block
2191   indicator-multi    11   0 /sys/block
2191   indicator-multi    11   0 /sys/block
2191   indicator-multi    11   0 /sys/block

```

The -n option can be used to filter on process name using partial matches:

```console
# ./opensnoop -n ed

PID    COMM               FD ERR PATH
2679   sed                 3   0 /etc/ld.so.cache
2679   sed                 3   0 /lib/x86_64-linux-gnu/libselinux.so.1
2679   sed                 3   0 /lib/x86_64-linux-gnu/libc.so.6
2679   sed                 3   0 /lib/x86_64-linux-gnu/libpcre.so.3
2679   sed                 3   0 /lib/x86_64-linux-gnu/libdl.so.2
2679   sed                 3   0 /lib/x86_64-linux-gnu/libpthread.so.0
2679   sed                 3   0 /proc/filesystems
2679   sed                 3   0 /usr/lib/locale/locale-archive
2679   sed                -1   2
2679   sed                 3   0 /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
2679   sed                 3   0 /dev/null
2680   sed                 3   0 /etc/ld.so.cache
2680   sed                 3   0 /lib/x86_64-linux-gnu/libselinux.so.1
2680   sed                 3   0 /lib/x86_64-linux-gnu/libc.so.6
2680   sed                 3   0 /lib/x86_64-linux-gnu/libpcre.so.3
2680   sed                 3   0 /lib/x86_64-linux-gnu/libdl.so.2
2680   sed                 3   0 /lib/x86_64-linux-gnu/libpthread.so.0
2680   sed                 3   0 /proc/filesystems
2680   sed                 3   0 /usr/lib/locale/locale-archive
2680   sed                -1   2
^C
```

This caught the 'sed' command because it partially matches 'ed' that's passed
to the '-n' option.

The -e option prints out extra columns; for example, the following output
contains the flags passed to open(2), in octal:

```console
# ./opensnoop -e
PID    COMM               FD ERR FLAGS    PATH
28512  sshd               10   0 00101101 /proc/self/oom_score_adj
28512  sshd                3   0 02100000 /etc/ld.so.cache
28512  sshd                3   0 02100000 /lib/x86_64-linux-gnu/libwrap.so.0
28512  sshd                3   0 02100000 /lib/x86_64-linux-gnu/libaudit.so.1
28512  sshd                3   0 02100000 /lib/x86_64-linux-gnu/libpam.so.0
28512  sshd                3   0 02100000 /lib/x86_64-linux-gnu/libselinux.so.1
28512  sshd                3   0 02100000 /lib/x86_64-linux-gnu/libsystemd.so.0
28512  sshd                3   0 02100000 /usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.2
28512  sshd                3   0 02100000 /lib/x86_64-linux-gnu/libutil.so.1
```

The -f option filters based on flags to the open(2) call, for example:

```console
# ./opensnoop -e -f O_WRONLY -f O_RDWR
PID    COMM               FD ERR FLAGS    PATH
28084  clear_console       3   0 00100002 /dev/tty
28084  clear_console      -1  13 00100002 /dev/tty0
28084  clear_console      -1  13 00100001 /dev/tty0
28084  clear_console      -1  13 00100002 /dev/console
28084  clear_console      -1  13 00100001 /dev/console
28051  sshd                8   0 02100002 /var/run/utmp
28051  sshd                7   0 00100001 /var/log/wtmp
```

The --cgroupmap option filters based on a cgroup set. It is meant to be used
with an externally created map.

```console
# ./opensnoop --cgroupmap /sys/fs/bpf/test01
```

For more details, see docs/special_filtering.md
