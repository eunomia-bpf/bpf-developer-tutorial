---
layout: post
title: execsnoop
date: 2022-11-17 19:57
category: bpftools
author: yunwei37
tags: [bpftools, syscall]
summary: execsnoop traces the exec() syscall system-wide, and prints various details.
---

## origin

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/execsnoop.bpf.c

## Compile and Run

Compile:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Run:

```
$ sudo ./ecli run package.json

running and waiting for the ebpf events from perf event...
time pid ppid uid retval args_count args_size comm args 
23:07:35 32940 32783 1000 0 1 13 cat /usr/bin/cat 
23:07:43 32946 24577 1000 0 1 10 bash /bin/bash 
23:07:43 32948 32946 1000 0 1 18 lesspipe /usr/bin/lesspipe 
23:07:43 32949 32948 1000 0 2 36 basename /usr/bin/basename 
23:07:43 32951 32950 1000 0 2 35 dirname /usr/bin/dirname 
23:07:43 32952 32946 1000 0 2 22 dircolors /usr/bin/dircolors 
23:07:48 32953 32946 1000 0 2 25 ls /usr/bin/ls 
23:07:53 32957 32946 1000 0 2 17 sleep /usr/bin/sleep 
23:07:57 32959 32946 1000 0 1 17 oneko /usr/games/oneko 

```

## details in bcc

Demonstrations of execsnoop, the Linux eBPF/bcc version.

execsnoop traces the exec() syscall system-wide, and prints various details.
Example output:

```
# ./execsnoop
COMM            PID    PPID   RET ARGS
bash             33161  24577    0 /bin/bash
lesspipe         33163  33161    0 /usr/bin/lesspipe
basename         33164  33163    0 /usr/bin/basename /usr/bin/lesspipe
dirname          33166  33165    0 /usr/bin/dirname /usr/bin/lesspipe
dircolors        33167  33161    0 /usr/bin/dircolors -b
ls               33172  33161    0 /usr/bin/ls --color=auto
top              33173  33161    0 /usr/bin/top
oneko            33174  33161    0 /usr/games/oneko
systemctl        33175  2975     0 /bin/systemctl is-enabled -q whoopsie.path
apport-checkrep  33176  2975     0 /usr/share/apport/apport-checkreports
apport-checkrep  33177  2975     0 /usr/share/apport/apport-checkreports --system
apport-checkrep  33178  2975     0 /usr/share/apport/apport-checkreports --system

```

This shows process information when exec system call is called.

USAGE message:

```
usage: execsnoop [-h] [-T] [-t] [-x] [--cgroupmap CGROUPMAP]
                       [--mntnsmap MNTNSMAP] [-u USER] [-q] [-n NAME]
                       [-l LINE] [-U] [--max-args MAX_ARGS]
                       
Trace exec() syscalls

options:
  -h, --help            show this help message and exit
  -T, --time            include time column on output (HH:MM:SS)
  -t, --timestamp       include timestamp on output
  -x, --fails           include failed exec()s
  --cgroupmap CGROUPMAP
                        trace cgroups in this BPF map only
  --mntnsmap MNTNSMAP   trace mount namespaces in this BPF map only
  -u USER, --uid USER   trace this UID only
  -q, --quote           Add quotemarks (") around arguments.
  -n NAME, --name NAME  only print commands matching this name (regex), any
                        arg
  -l LINE, --line LINE  only print commands where arg contains this line
                        (regex)
  -U, --print-uid       print UID column
  --max-args MAX_ARGS   maximum number of arguments parsed and displayed,
                        defaults to 20
                        
examples:
    ./execsnoop           # trace all exec() syscalls
    ./execsnoop -x        # include failed exec()s
    ./execsnoop -T        # include time (HH:MM:SS)
    ./execsnoop -U        # include UID
    ./execsnoop -u 1000   # only trace UID 1000
    ./execsnoop -u user   # get user UID and trace only them
    ./execsnoop -t        # include timestamps
    ./execsnoop -q        # add "quotemarks" around arguments
    ./execsnoop -n main   # only print command lines containing "main"
    ./execsnoop -l tpkg   # only print command where arguments contains "tpkg"
    ./execsnoop --cgroupmap mappath  # only trace cgroups in this BPF map
    ./execsnoop --mntnsmap mappath   # only trace mount namespaces in the map


```

The -T and -t option include time and timestamps on output:

```
# ./execsnoop -T -t
TIME     TIME(s) PCOMM            PID    PPID   RET ARGS
23:35:25 4.335   bash             33360  24577    0 /bin/bash
23:35:25 4.338   lesspipe         33361  33360    0 /usr/bin/lesspipe
23:35:25 4.340   basename         33362  33361    0 /usr/bin/basename /usr/bin/lesspipe
23:35:25 4.342   dirname          33364  33363    0 /usr/bin/dirname /usr/bin/lesspipe
23:35:25 4.347   dircolors        33365  33360    0 /usr/bin/dircolors -b
23:35:40 19.327  touch            33367  33366    0 /usr/bin/touch /run/udev/gdm-machine-has-hardware-gpu
23:35:40 19.329  snap-device-hel  33368  33366    0 /usr/lib/snapd/snap-device-helper change snap_firefox_firefox /devices/pci0000:00/0000:00:02.0/drm/card0 226:0
23:35:40 19.331  snap-device-hel  33369  33366    0 /usr/lib/snapd/snap-device-helper change snap_firefox_geckodriver /devices/pci0000:00/0000:00:02.0/drm/card0 226:0
23:35:40 19.332  snap-device-hel  33370  33366    0 /usr/lib/snapd/snap-device-helper change snap_snap-store_snap-store /devices/pci0000:00/0000:00:02.0/drm/card0 226:0

```

The -u option filtering UID:

```
# ./execsnoop -Uu 1000
UID   PCOMM            PID    PPID   RET ARGS
1000  bash             33604  24577    0 /bin/bash
1000  lesspipe         33606  33604    0 /usr/bin/lesspipe
1000  basename         33607  33606    0 /usr/bin/basename /usr/bin/lesspipe
1000  dirname          33609  33608    0 /usr/bin/dirname /usr/bin/lesspipe
1000  dircolors        33610  33604    0 /usr/bin/dircolors -b
1000  sleep            33615  33604    0 /usr/bin/sleep
1000  sleep            33616  33604    0 /usr/bin/sleep 1
1000  clear            33617  33604    0 /usr/bin/clear

```

Report bugs to https://github.com/iovisor/bcc/tree/master/libbpf-tools.
