# bcc 教程

本教程介绍如何使用[bcc](https://github.com/iovisor/bcc)工具快速解决性能、故障排除和网络问题。如果你想开发新的bcc工具，请参考[tutorial_bcc_python_developer.md](tutorial_bcc_python_developer.md)教程。

本教程假设bcc已经安装好，并且你可以成功运行像execsnoop这样的工具。参见[INSTALL.md](https://github.com/iovisor/bcc/tree/master/INSTALL.md)。这些功能是在Linux 4.x系列中增加的。

## 可观察性

一些快速的收获。

### 0. 使用bcc之前

在使用bcc之前，你应该从Linux基础知识开始。可以参考[Linux Performance Analysis in 60,000 Milliseconds](https://netflixtechblog.com/linux-performance-analysis-in-60-000-milliseconds-accc10403c55)文章，其中介绍了以下命令：

1. uptime
1. dmesg | tail
1. vmstat 1
1. mpstat -P ALL 1
1. pidstat 1
1. iostat -xz 1
1. free -m
1. sar -n DEV 1
1. sar -n TCP,ETCP 1
1. top

### 1. 性能分析

这是一个用于性能调查的通用检查清单，首先有一个列表，然后详细描述：

1. execsnoop
1. opensnoop
1. ext4slower（或btrfs\*，xfs\*，zfs\*）
1. biolatency
1. biosnoop
1. cachestat
1. tcpconnect
1. tcpaccept
1. tcpretrans
1. runqlat
1. profile

这些工具可能已经安装在你的系统的/usr/share/bcc/tools目录下，或者你可以从bcc github仓库的/tools目录中运行它们，这些工具使用.py扩展名。浏览50多个可用的工具，获得更多的分析选项。

#### 1.1 execsnoop

```sh
# ./execsnoop
PCOMM            PID    RET ARGS
supervise        9660     0 ./run
supervise        9661     0 ./run
mkdir            9662     0 /bin/mkdir -p ./main
run              9663     0 ./run
[...]
```

execsnoop对于每个新进程打印一行输出。检查短生命周期的进程。这些进程可能会消耗CPU资源，但不会在大多数周期性运行的进程监控工具中显示出来。它通过跟踪`exec()`来工作，而不是`fork()`，所以它可以捕获许多类型的新进程，但不是所有类型（例如，它不会看到启动工作进程的应用程序，该应用程序没有`exec()`其他任何内容）。

更多[例子](https://github.com/iovisor/bcc/tree/master/tools/execsnoop_example.txt)。

#### 1.2. opensnoop

```sh
# ./opensnoop
PID    COMM               FD ERR PATH
1565   redis-server        5   0 /proc/1565/stat
1565   redis-server        5   0 /proc/1565/stat
1565   redis-server        5   0 /proc/1565/stat
1603   snmpd               9   0 /proc/net/dev
1603   snmpd              11   0 /proc/net/if_inet6
1603   snmpd              -1   2 /sys/class/net/eth0/device/vendor
1603   snmpd              11   0 /proc/sys/net/ipv4/neigh/eth0/retrans_time_ms
1603   snmpd              11   0 /proc/sys/net/ipv6/neigh/eth0/retrans_time_ms
1603   snmpd              11   0 /proc/sys/net/ipv6/conf/eth0/forwarding
[...]
```

opensnoop每次open() syscall执行时打印一行输出，包括详细信息。

打开的文件可以告诉你很多关于应用程序的工作方式的信息：它们的数据文件、配置文件和日志文件。有时候应用程序可能会表现不正常，当它们不断尝试读取不存在的文件时则会表现得很差。opensnoop能够快速帮助你查看。

更多[例子](https://github.com/iovisor/bcc/tree/master/tools/opensnoop_example.txt)。

#### 1.3. ext4slower（或btrfs\*，xfs\*，zfs\*）

```sh
# ./ext4slower
追踪超过10毫秒的ext4操作
时间     进程           进程ID    T 字节数   偏移KB   延迟(ms) 文件名
06:35:01 cron           16464  R 1249    0          16.05 common-auth
06:35:01 cron           16463  R 1249    0          16.04 common-auth
06:35:01 cron           16465  R 1249    0          16.03 common-auth
06:35:01 cron           16465  R 4096    0          10.62 login.defs
06:35:01 cron           16464  R 4096    0          10.61 login.defs
```

ext4slower跟踪ext4文件系统，并计时常见操作，然后只打印超过阈值的操作。这对于识别或证明一种性能问题非常方便：通过文件系统单独显示较慢的磁盘 I/O。磁盘以异步方式处理 I/O，很难将该层的延迟与应用程序所经历的延迟关联起来。在内核堆栈中更高层的追踪，即在 VFS -> 文件系统接口中，会更接近应用程序遭受的延迟。使用此工具来判断文件系统的延迟是否超过了给定的阈值。

在 bcc 中存在其他文件系统的类似工具：btrfsslower、xfsslower 和 zfsslower。还有一个名为 fileslower 的工具，它在 VFS 层工作并跟踪所有内容（尽管会有更高的开销）。

更多[示例](https://github.com/iovisor/bcc/tree/master/tools/ext4slower_example.txt)。

#### 1.4. biolatency

```sh
# ./biolatency
跟踪块设备的 I/O... 按 Ctrl-C 结束。
^C
     微秒             : 数量      分布
       0 -> 1        : 0        |                                      |
       2 -> 3        : 0        |                                      |
       4 -> 7        : 0        |                                      |
       8 -> 15       : 0        |                                      |
      16 -> 31       : 0        |                                      |
      32 -> 63       : 0        |                                      |
      64 -> 127      : 1        |                                      |
     128 -> 255      : 12       |********                              |
     256 -> 511      : 15       |**********                            |
     512 -> 1023     : 43       |*******************************       |
    1024 -> 2047     : 52       |**************************************|
    2048 -> 4095     : 47       |**********************************    |
    4096 -> 8191     : 52       |**************************************|
    8192 -> 16383    : 36       |**************************            |
   16384 -> 32767    : 15       |**********                            |。32768 -> 65535    : 2        |*                                     |
   65536 -> 131071   : 2        |*                                     |
```

biolatency跟踪磁盘I/O延迟（从设备执行到完成的时间），当工具结束（Ctrl-C，或给定的间隔）时，它会打印延迟的直方图摘要。

这对于了解超出iostat等工具提供的平均时间的磁盘I/O延迟非常有用。在分布的末尾将可见I/O延迟的异常值，以及多种模式的分布。

更多[示例](https://github.com/iovisor/bcc/tree/master/tools/biolatency_example.txt)。

#### 1.5. biosnoop

```sh
# ./biosnoop
TIME(s)        COMM           PID    DISK    T  SECTOR    BYTES   LAT(ms)
0.000004001    supervise      1950   xvda1   W  13092560  4096       0.74
0.000178002    supervise      1950   xvda1   W  13092432  4096       0.61
0.001469001    supervise      1956   xvda1   W  13092440  4096       1.24
0.001588002    supervise      1956   xvda1   W  13115128  4096       1.09
1.022346001    supervise      1950   xvda1   W  13115272  4096       0.98
1.022568002    supervise      1950   xvda1   W  13188496  4096       0.93
[...]
```

biosnoop为每个磁盘I/O打印一行输出，其中包括延迟（从设备执行到完成的时间）等详细信息。

这让您可以更详细地研究磁盘I/O，并寻找按时间排序的模式（例如，读取在写入后排队）。请注意，如果您的系统以高速率执行磁盘I/O，则输出将冗长。

更多[示例](https://github.com/iovisor/bcc/tree/master/tools/biosnoop_example.txt)。

#### 1.6. cachestat

```sh
# ./cachestat
    HITS   MISSES  DIRTIES  READ_HIT% WRITE_HIT%   BUFFERS_MB  CACHED_MB
    1074       44       13      94.9%       2.9%            1        223
    2195      170        8      92.5%       6.8%            1        143
     182       53       56      53.6%       1.3%            1        143
   62480    40960    20480      40.6%      19.8%            1        223"。
格式：仅返回翻译后的内容，不包括原始文本。```
7        2        5      22.2%      22.2%            1        223
     348        0        0     100.0%       0.0%            1        223
[...]
```

cachestat 每秒（或每个自定义时间间隔）打印一行摘要，显示文件系统缓存的统计信息。

可以用它来识别低缓存命中率和高缺失率，这是性能调优的线索之一。

更多 [示例](https://github.com/iovisor/bcc/tree/master/tools/cachestat_example.txt)。

#### 1.7. tcpconnect

```sh
# ./tcpconnect
PID    COMM         IP SADDR            DADDR            DPORT
1479   telnet       4  127.0.0.1        127.0.0.1        23
1469   curl         4  10.201.219.236   54.245.105.25    80
1469   curl         4  10.201.219.236   54.67.101.145    80
1991   telnet       6  ::1              ::1              23
2015   ssh          6  fe80::2000:bff:fe82:3ac fe80::2000:bff:fe82:3ac 22
[...]
```

tcpconnect 每个活动的 TCP 连接（例如通过 connect()）打印一行输出，包括源地址和目标地址的详细信息。

寻找可能指向应用程序配置问题或入侵者的意外连接。

更多 [示例](https://github.com/iovisor/bcc/tree/master/tools/tcpconnect_example.txt)。

#### 1.8. tcpaccept

```sh
# ./tcpaccept
PID    COMM         IP RADDR            LADDR            LPORT
907    sshd         4  192.168.56.1     192.168.56.102   22
907    sshd         4  127.0.0.1        127.0.0.1        22
5389   perl         6  1234:ab12:2040:5020:2299:0:5:0 1234:ab12:2040:5020:2299:0:5:0 7001
[...]
```

tcpaccept 每个被动的 TCP 连接（例如通过 accept()）打印一行输出，包括源地址和目标地址的详细信息。

寻找可能指向应用程序配置问题或入侵者的意外连接。

更多 [示例](https://github.com/iovisor/bcc/tree/master/tools/tcpaccept_example.txt)。

#### 1.9. tcpretrans

```sh
# ./tcpretrans".
```时间 PID IP LADDR:LPORT T> RADDR:RPORT 状态
01:55:05 0 4 10.153.223.157:22 R> 69.53.245.40:34619 已建立
01:55:05 0 4 10.153.223.157:22 R> 69.53.245.40:34619 已建立
01:55:17 0 4 10.153.223.157:22 R> 69.53.245.40:22957 已建立
[...]
```

tcpretrans为每个TCP重传数据包打印一行输出，其中包括源地址、目的地址以及TCP连接的内核状态。

TCP重传会导致延迟和吞吐量问题。对于已建立的重传，可以查找与网络有关的模式。对于SYN_SENT，可能指向目标内核CPU饱和和内核数据包丢失。

更多[示例](https://github.com/iovisor/bcc/tree/master/tools/tcpretrans_example.txt)。

#### 1.10. runqlat

```sh
# ./runqlat
跟踪运行队列延迟... 按Ctrl-C结束。
^C
     微秒数               : 计数     分布
         0 -> 1          : 233      |***********                             |
         2 -> 3          : 742      |************************************    |
         4 -> 7          : 203      |**********                              |
         8 -> 15         : 173      |********                                |
        16 -> 31         : 24       |*                                       |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 30       |*                                       |
       128 -> 255        : 6        |                                        |
       256 -> 511        : 3        |                                        |
       512 -> 1023       : 5        |                                        |
      1024 -> 2047       : 27       |*                                       |
      2048 -> 4095       : 30       |*                                       |
      4096 -> 8191       : 20       |                                        |
      8192 -> 16383      : 29       |*                                       |".16384 -> 32767      : 809      |****************************************|
32768 -> 65535      : 64       |***                                     |
```

这可以帮助量化在CPU饱和期间等待获取CPU的时间损失。

更多[示例](https://github.com/iovisor/bcc/tree/master/tools/runqlat_example.txt)。

#### 1.11. 分析

```sh
# ./profile
以每秒49次的频率对所有线程进行采样，包括用户和内核栈...按Ctrl-C结束。
^C
    00007f31d76c3251 [未知]
    47a2c1e752bf47f7 [未知]
    -                sign-file (8877)
        1

    ffffffff813d0af8 __clear_user
    ffffffff813d5277 iov_iter_zero
    ffffffff814ec5f2 read_iter_zero
    ffffffff8120be9d __vfs_read
    ffffffff8120c385 vfs_read
    ffffffff8120d786 sys_read
    ffffffff817cc076 entry_SYSCALL_64_fastpath
    00007fc5652ad9b0 read
    -                dd (25036)
        4

    0000000000400542 func_a
    0000000000400598 main
    00007f12a133e830 __libc_start_main
    083e258d4c544155 [未知]
    -                func_ab (13549)
        5

[...]

    ffffffff8105eb66 native_safe_halt
    ffffffff8103659e default_idle
    ffffffff81036d1f arch_cpu_idle
    ffffffff810bba5a default_idle_call
    ffffffff810bbd07 cpu_startup_entry
    ffffffff8104df55 start_secondary
    -                swapper/1 (0)
        75
```

profile是一个CPU分析工具，它在定时间隔内采样堆栈跟踪，并打印唯一堆栈跟踪的摘要及其出现次数。

使用此工具来了解消耗CPU资源的代码路径。

更多[示例](https://github.com/iovisor/bcc/tree/master/tools/profile_example.txt)。

### 2. 使用通用工具进行可观察性

除了上述用于性能调整的工具外，下面是一个bcc通用工具的清单，首先是一个列表，然后详细说明：

1. trace
1. argdist
1. funccount这些通用工具可能有助于解决您特定问题的可视化。

#### 2.1. 跟踪

##### 示例 1

假设您想要跟踪文件所有权更改。有三个系统调用，`chown`、`fchown`和`lchown`，用户可以使用它们来更改文件所有权。相应的系统调用入口是`SyS_[f|l]chown`。可以使用以下命令打印系统调用参数和调用进程的用户ID。您可以使用`id`命令查找特定用户的UID。

```sh
$ trace.py \
  'p::SyS_chown "file = %s, to_uid = %d, to_gid = %d, from_uid = %d", arg1, arg2, arg3, $uid' \
  'p::SyS_fchown "fd = %d, to_uid = %d, to_gid = %d, from_uid = %d", arg1, arg2, arg3, $uid' \
  'p::SyS_lchown "file = %s, to_uid = %d, to_gid = %d, from_uid = %d", arg1, arg2, arg3, $uid'
PID    TID    COMM         FUNC             -
1269255 1269255 python3.6    SyS_lchown       file = /tmp/dotsync-usisgezu/tmp, to_uid = 128203, to_gid = 100, from_uid = 128203
1269441 1269441 zstd         SyS_chown        file = /tmp/dotsync-vic7ygj0/dotsync-package.zst, to_uid = 128203, to_gid = 100, from_uid = 128203
1269255 1269255 python3.6    SyS_lchown       file = /tmp/dotsync-a40zd7ev/tmp, to_uid = 128203, to_gid = 100, from_uid = 128203
1269442 1269442 zstd         SyS_chown        file = /tmp/dotsync-gzp413o_/dotsync-package.zst, to_uid = 128203, to_gid = 100, from_uid = 128203
1269255 1269255 python3.6    SyS_lchown       file = /tmp/dotsync-whx4fivm/tmp/.bash_profile, to_uid = 128203, to_gid = 100, from_uid = 128203
```

##### 示例 2

假设您想要统计基于bpf的性能监控工具中的非自愿上下文切换（`nvcsw`），而您不知道正确的方法是什么。`/proc/<pid>/status`已经告诉您进程的非自愿上下文切换（`nonvoluntary_ctxt_switches`）的数量，并且您可以使用`trace.py`进行快速实验以验证您的方法。根据内核源代码，`nvcsw`在文件`linux/kernel/sched/core.c`的`__schedule`函数中计数，并满足以下条件：

```c
.!(!preempt && prev->state) // 即 preempt || !prev->state
```

`__schedule` 函数被标记为 `notrace` ，评估上述条件的最佳位置似乎在函数 `__schedule` 内部的 `sched/sched_switch` 跟踪点中，并且在 `linux/include/trace/events/sched.h` 中定义。`trace.py` 已经将 `args` 设置为跟踪点 `TP_STRUCT__entry` 的指针。函数 `__schedule` 中的上述条件可以表示为

```c
args->prev_state == TASK_STATE_MAX || args->prev_state == 0
```

可以使用以下命令来计算非自愿上下文切换（每个进程或每个进程ID），并与 `/proc/<pid>/status` 或 `/proc/<pid>/task/<task_id>/status` 进行比较，以确保正确性，因为在典型情况下，非自愿上下文切换并不常见。

```sh
$ trace.py -p 1134138 't:sched:sched_switch (args->prev_state == TASK_STATE_MAX || args->prev_state == 0)'
PID    TID    COMM         FUNC
1134138 1134140 contention_test sched_switch
1134138 1134142 contention_test sched_switch
...
$ trace.py -L 1134140 't:sched:sched_switch (args->prev_state == TASK_STATE_MAX || args->prev_state == 0)'
PID    TID    COMM         FUNC
1134138 1134140 contention_test sched_switch
1134138 1134140 contention_test sched_switch
...
```

##### 示例 3

此示例与问题 [1231](https://github.com/iovisor/bcc/issues/1231) 和 [1516](https://github.com/iovisor/bcc/issues/1516) 相关，其中在某些情况下，uprobes 完全无法工作。首先，你可以执行以下 `strace`

```sh
$ strace trace.py 'r:bash:readline "%s", retval'
...
perf_event_open(0x7ffd968212f0, -1, 0, -1, 0x8 /* PERF_FLAG_??? */) = -1 EIO (Input/output error)
...
```

`perf_event_open`系统调用返回`-EIO`。在`/kernel/trace`和`/kernel/events`目录中查找与`EIO`相关的内核uprobe代码，函数`uprobe_register`最可疑。让我们找出是否调用了这个函数，如果调用了，返回值是什么。在一个终端中使用以下命令打印出`uprobe_register`的返回值：

```sh
trace.py 'r::uprobe_register "ret = %d", retval'
```

在另一个终端中运行相同的bash uretprobe跟踪示例，您应该得到：

```sh
$ trace.py 'r::uprobe_register "ret = %d", retval'
PID    TID    COMM         FUNC             -
1041401 1041401 python2.7    uprobe_register  ret = -5
```

错误代码`-5`是EIO。这证实了函数`uprobe_register`中的以下代码是最可疑的罪魁祸首。

```c
 if (!inode->i_mapping->a_ops->readpage && !shmem_mapping(inode->i_mapping))
        return -EIO;
```

`shmem_mapping`函数定义如下：

```c
bool shmem_mapping(struct address_space *mapping)
{
        return mapping->a_ops == &shmem_aops;
}
```

为了确认这个理论，使用以下命令找出`inode->i_mapping->a_ops`的值：

```sh
$ trace.py -I 'linux/fs.h' 'p::uprobe_register(struct inode *inode) "a_ops = %llx", inode->i_mapping->a_ops'
PID    TID    COMM         FUNC             -
814288 814288 python2.7    uprobe_register  a_ops = ffffffff81a2adc0
^C$ grep ffffffff81a2adc0 /proc/kallsyms
ffffffff81a2adc0 R empty_aops
```

内核符号`empty_aops`没有定义`readpage`，因此上述可疑条件为真。进一步检查内核源代码显示，`overlayfs`没有提供自己的`a_ops`，而其他一些文件系统（例如ext4）定义了自己的`a_ops`（例如`ext4_da_aops`），并且`ext4_da_aops`定义了`readpage`。因此，uprobe对于ext4正常工作，但在overlayfs上不正常工作。

更多[示例](https://github.com/iovisor/bcc/tree/master/tools/trace_example.txt)。

#### 2.2. argdist"。更多[示例](https://github.com/iovisor/bcc/tree/master/tools/argdist_example.txt)

#### 2.3. funccount

更多[示例](https://github.com/iovisor/bcc/tree/master/tools/funccount_example.txt).

## 网络

To do.
