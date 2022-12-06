## eBPF 入门实践教程：

## origin

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqslower.bpf.c

result:

```
$ sudo ecli/build/bin/Release/ecli run examples/bpftools/runqslower/package.json

running and waiting for the ebpf events from perf event...
time task prev_task delta_us pid prev_pid 
20:11:59 gnome-shell swapper/0 32 2202 0 
20:11:59 ecli swapper/3 23 3437 0 
20:11:59 rcu_sched swapper/1 1 14 0 
20:11:59 gnome-terminal- swapper/1 13 2714 0 
20:11:59 ecli swapper/3 2 3437 0 
20:11:59 kworker/3:3 swapper/3 3 215 0 
20:11:59 containerd swapper/1 8 1088 0 
20:11:59 ecli swapper/2 5 3437 0 
20:11:59 HangDetector swapper/3 6 854 0 
20:11:59 ecli swapper/2 60 3437 0 
20:11:59 rcu_sched swapper/1 26 14 0 
20:11:59 kworker/0:1 swapper/0 26 3414 0 
20:11:59 ecli swapper/2 6 3437 0 
```

这段代码定义了一个 eBPF 程序，该程序用于跟踪进程在运行队列中的等待时间。它通过使用 tracepoint 和 perf event 输出来实现。

程序首先定义了两个 BPF 内核映射：start 映射用于存储每个进程在被调度运行之前的时间戳，events 映射用于存储 perf 事件。

然后，程序定义了一些帮助函数，用于跟踪每个进程的调度状态。 trace_enqueue 函数用于在进程被调度运行之前记录时间戳， handle_switch 函数用于处理进程切换，并计算进程在队列中等待的时间。

接下来，程序定义了五个 tracepoint 程序，用于捕获不同的调度器事件。 sched_wakeup 和 sched_wakeup_new 程序用于捕获新进程被唤醒的事件， sched_switch 程序用于捕获进程切换事件， handle_sched_wakeup 和 handle_sched_wakeup_new 程序用于捕获 raw tracepoint 事件。这些 tracepoint 程序调用了前面定义的帮助函数来跟踪进程的调度状态。

最后，程序将计算得到的等待时间输出到 perf 事件中，供用户空间工具进行捕获和分析。

## Compile and Run

Compile:

```
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Run:

```
sudo ./ecli run examples/bpftools/runqslower/package.json
```

## details in bcc

Demonstrations of runqslower, the Linux eBPF/bcc version.

runqslower traces high scheduling delays between tasks being ready to run and them running on CPU after that. Example output:

```
# ./runqslower
Tracing run queue latency higher than 10000 us
TIME     COMM             TID           LAT(us)
13:11:43 b'kworker/0:2'   8680            10250
13:12:18 b'irq/16-vmwgfx' 422             10838
13:12:18 b'systemd-oomd'  753             11012
13:12:18 b'containerd'    8272            11254
13:12:18 b'HangDetector'  764             12042
^C
``
This measures the time a task spends waiting on a run queue for a turn on-CPU, and shows this time as a individual events. This time should be small, but a task may need to wait its turn due to CPU load.

This measures two types of run queue latency:
1. The time from a task being enqueued on a run queue to its context switch and execution. This traces ttwu_do_wakeup(), wake_up_new_task() -> finish_task_switch() with either raw tracepoints (if supported) or kprobes and instruments the run queue latency after a voluntary context switch.
2. The time from when a task was involuntary context switched and still in the runnable state, to when it next executed. This is instrumented from finish_task_switch() alone.

The overhead of this tool may become significant for  some  workloads:  see  the  OVERHEAD section.

This  works  by tracing various kernel scheduler functions using dynamic tracing, and will need updating to match any changes to these functions.

Since this uses BPF, only the root user can use this tool.

```console
Usage: runqslower [-h] [-p PID | -t TID | -P] [min_us]
```

The min_us option sets the latency of the run queue to track:

```
# ./runqslower 100
Tracing run queue latency higher than 100 us
TIME     COMM             TID           LAT(us)
20:48:26 b'gnome-shell'   3005              201
20:48:26 b'gnome-shell'   3005              202
20:48:26 b'gnome-shell'   3005              254
20:48:26 b'gnome-shell'   3005              208
20:48:26 b'gnome-shell'   3005              132
20:48:26 b'gnome-shell'   3005              213
20:48:26 b'gnome-shell'   3005              205
20:48:26 b'python3'       5224              127
20:48:26 b'gnome-shell'   3005              214
20:48:26 b'gnome-shell'   3005              126
20:48:26 b'gnome-shell'   3005              285
20:48:26 b'Xorg'          2869              296
20:48:26 b'gnome-shell'   3005              119
20:48:26 b'gnome-shell'   3005              206
```

The -p PID option only traces this PID:

```
# ./runqslower -p 3005
Tracing run queue latency higher than 10000 us
TIME     COMM             TID           LAT(us)
20:46:22 b'gnome-shell'   3005            16024
20:46:45 b'gnome-shell'   3005            11494
20:46:45 b'gnome-shell'   3005            21430
20:46:45 b'gnome-shell'   3005            14948
20:47:16 b'gnome-shell'   3005            10164
20:47:16 b'gnome-shell'   3005            18070
20:47:17 b'gnome-shell'   3005            13272
20:47:18 b'gnome-shell'   3005            10451
20:47:18 b'gnome-shell'   3005            15010
20:47:18 b'gnome-shell'   3005            19449
20:47:22 b'gnome-shell'   3005            19327
20:47:23 b'gnome-shell'   3005            13178
20:47:23 b'gnome-shell'   3005            13483
20:47:23 b'gnome-shell'   3005            15562
20:47:23 b'gnome-shell'   3005            13655
20:47:23 b'gnome-shell'   3005            19571
```

The -P option also shows previous task name and TID:

```
# ./runqslower -P
Tracing run queue latency higher than 10000 us
TIME     COMM             TID           LAT(us) PREV COMM        PREV TID
20:42:48 b'sysbench'      5159            10562 b'sysbench'      5152  
20:42:48 b'sysbench'      5159            10367 b'sysbench'      5152  
20:42:49 b'sysbench'      5158            11818 b'sysbench'      5159  
20:42:49 b'sysbench'      5160            16913 b'sysbench'      5153  
20:42:49 b'sysbench'      5157            13742 b'sysbench'      5160  
20:42:49 b'sysbench'      5152            13746 b'sysbench'      5160  
20:42:49 b'sysbench'      5153            13731 b'sysbench'      5160  
20:42:49 b'sysbench'      5158            14688 b'sysbench'      5161  
20:42:50 b'sysbench'      5155            10468 b'sysbench'      5152  
20:42:50 b'sysbench'      5156            17695 b'sysbench'      5158  
20:42:50 b'sysbench'      5155            11251 b'sysbench'      5152  
20:42:50 b'sysbench'      5154            13283 b'sysbench'      5152  
20:42:50 b'sysbench'      5158            22278 b'sysbench'      5157  
```

For more details, see docs/special_filtering.md