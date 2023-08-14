# bcc 参考指南

用于搜索 (Ctrl-F) 和参考。如需教程，请从 [tutorial.md](tutorial.md) 开始。

该指南尚未完成。如果感觉有遗漏的内容，请查看 bcc 和内核源码。如果确认确实有遗漏，请发送拉取请求进行修复，并协助所有人。

## 目录

- [bcc 参考指南](#bcc-参考指南)
  - [目录](#目录)
- [BPF C](#bpf-c)
  - [Events \& Arguments](#events--arguments)
    - [1. kprobes](#1-kprobes)
    - [2. kretprobes](#2-kretprobes)
    - [3. Tracepoints](#3-tracepoints)
    - [4. uprobes](#4-uprobes)
    - [6. USDT探测点](#6-usdt探测点)
    - [7. 原始跟踪点](#7-原始跟踪点)
    - [8. 系统调用跟踪点](#8-系统调用跟踪点)
    - [9. kfuncs](#9-kfuncs)
    - [10. kretfuncs](#10-kretfuncs)
    - [11. LSM Probes](#11-lsm-probes)
    - [12. BPF迭代器](#12-bpf迭代器)
  - [数据](#数据)
    - [1. bpf\_probe\_read\_kernel()](#1-bpf_probe_read_kernel)
    - [2. bpf\_probe\_read\_kernel\_str()".\`\`\`shell](#2-bpf_probe_read_kernel_strshell)
    - [3. bpf\_ktime\_get\_ns()](#3-bpf_ktime_get_ns)
    - [4. bpf\_get\_current\_pid\_tgid()](#4-bpf_get_current_pid_tgid)
    - [5. bpf\_get\_current\_uid\_gid()](#5-bpf_get_current_uid_gid)
    - [6. bpf\_get\_current\_comm()](#6-bpf_get_current_comm)
    - [7. bpf\_get\_current\_task()](#7-bpf_get_current_task)
    - [8. bpf\_log2l()](#8-bpf_log2l)
    - [9. bpf\_get\_prandom\_u32()](#9-bpf_get_prandom_u32)
    - [10. bpf\_probe\_read\_user()](#10-bpf_probe_read_user)
    - [11. bpf\_probe\_read\_user\_str()](#11-bpf_probe_read_user_str)
    - [12. bpf\_get\_ns\_current\_pid\_tgid()](#12-bpf_get_ns_current_pid_tgid)
  - [调试](#调试)
    - [1. bpf\_override\_return()](#1-bpf_override_return)
  - [输出](#输出)
    - [1. bpf\_trace\_printk()](#1-bpf_trace_printk)
    - [2. BPF\_PERF\_OUTPUT](#2-bpf_perf_output)
    - [3. perf\_submit()](#3-perf_submit)
    - [4. perf\_submit\_skb()](#4-perf_submit_skb)
    - [5. BPF\_RINGBUF\_OUTPUT](#5-bpf_ringbuf_output)
    - [6. ringbuf\_output（）](#6-ringbuf_output)
    - [7. ringbuf\_reserve()](#7-ringbuf_reserve)
    - [8. ringbuf\_submit（）](#8-ringbuf_submit)
    - [9. ringbuf\_discard()](#9-ringbuf_discard)
  - [Maps](#maps)
    - [1. BPF\_TABLE](#1-bpf_table)
      - [固定映射](#固定映射)
    - [2. BPF\_HASH](#2-bpf_hash)
    - [3. BPF\_ARRAY](#3-bpf_array)
    - [4. BPF\_HISTOGRAM](#4-bpf_histogram)
    - [5. BPF\_STACK\_TRACE](#5-bpf_stack_trace)
    - [6. BPF\_PERF\_ARRAY](#6-bpf_perf_array)
    - [7. BPF\_PERCPU\_HASH](#7-bpf_percpu_hash)
    - [8. BPF\_PERCPU\_ARRAY](#8-bpf_percpu_array)
    - [9. BPF\_LPM\_TRIE](#9-bpf_lpm_trie)
    - [10. BPF\_PROG\_ARRAY](#10-bpf_prog_array)
    - [11. BPF\_DEVMAP](#11-bpf_devmap)
    - [12. BPF\_CPUMAP](#12-bpf_cpumap)
    - [13. BPF\_XSKMAP](#13-bpf_xskmap)
    - [14. BPF\_ARRAY\_OF\_MAPS](#14-bpf_array_of_maps)
    - [15. BPF\_HASH\_OF\_MAPS](#15-bpf_hash_of_maps)
    - [16. BPF\_STACK](#16-bpf_stack)
    - [17. BPF\_QUEUE](#17-bpf_queue)
    - [18. BPF\_SOCKHASH](#18-bpf_sockhash)
    - [19. map.lookup()](#19-maplookup)
    - [20. map.lookup\_or\_try\_init()](#20-maplookup_or_try_init)
    - [21. map.delete()](#21-mapdelete)
    - [22. map.update()](#22-mapupdate)
    - [23. map.insert()](#23-mapinsert)
    - [24. map.increment()](#24-mapincrement)
    - [25. map.get\_stackid()](#25-mapget_stackid)
    - [26. map.perf\_read()](#26-mapperf_read)
    - [27. map.call()](#27-mapcall)
    - [28. map.redirect\_map()](#28-mapredirect_map)
    - [29. map.push()](#29-mappush)
    - [30. map.pop()](#30-mappop)
    - [31. map.peek()](#31-mappeek)
    - [32. map.sock\_hash\_update()](#32-mapsock_hash_update)
    - [33. map.msg\_redirect\_hash()](#33-mapmsg_redirect_hash)
    - [34. map.sk\_redirect\_hash()](#34-mapsk_redirect_hash)
  - [许可证](#许可证)
  - [Rewriter](#rewriter)
- [bcc Python](#bcc-python)
  - [初始化](#初始化)
    - [1. BPF](#1-bpf)
  - [事件](#事件)
    - [1. attach\_kprobe()](#1-attach_kprobe)
    - [2. attach\_kretprobe()](#2-attach_kretprobe)
    - [3. attach\_tracepoint()](#3-attach_tracepoint)
    - [4. attach\_uprobe()](#4-attach_uprobe)
    - [5. attach\_uretprobe()](#5-attach_uretprobe)
    - [6. USDT.enable\_probe()](#6-usdtenable_probe)
    - [7. attach\_raw\_tracepoint()](#7-attach_raw_tracepoint)
    - [8. attach\_raw\_socket()](#8-attach_raw_socket)
    - [9. attach\_xdp()](#9-attach_xdp)
      - [1. XDP\_FLAGS\_UPDATE\_IF\_NOEXIST](#1-xdp_flags_update_if_noexist)
      - [2. XDP\_FLAGS\_SKB\_MODE](#2-xdp_flags_skb_mode)
      - [3. XDP\_FLAGS\_DRV\_MODE](#3-xdp_flags_drv_mode)
      - [4. XDP\_FLAGS\_HW\_MODE](#4-xdp_flags_hw_mode)
    - [10. attach\_func()](#10-attach_func)
    - [12. detach\_kprobe()](#12-detach_kprobe)
    - [13. detach\_kretprobe()](#13-detach_kretprobe)
  - [调试输出](#调试输出)
    - [1. trace\_print()](#1-trace_print)
    - [2. trace\_fields()](#2-trace_fields)
  - [输出 API](#输出-api)
    - [1. perf\_buffer\_poll()](#1-perf_buffer_poll)
    - [2. ring\_buffer\_poll()](#2-ring_buffer_poll)
    - [3. ring\_buffer\_consume()](#3-ring_buffer_consume)
  - [Map APIs](#map-apis)
    - [1. get\_table()](#1-get_table)
    - [2. open\_perf\_buffer()](#2-open_perf_buffer)
    - [4. values()](#4-values)
    - [5. clear()](#5-clear)
    - [6. items\_lookup\_and\_delete\_batch()](#6-items_lookup_and_delete_batch)
    - [7. items\_lookup\_batch()](#7-items_lookup_batch)
    - [8. items\_delete\_batch()](#8-items_delete_batch)
    - [9. items\_update\_batch()](#9-items_update_batch)
    - [11. print\_linear\_hist()".语法: ```table.print_linear_hist(val_type="value", section_header="Bucket ptr", section_print_fn=None)```](#11-print_linear_hist语法-tableprint_linear_histval_typevalue-section_headerbucket-ptr-section_print_fnnone)
    - [12. open\_ring\_buffer()](#12-open_ring_buffer)
    - [13. push()](#13-push)
    - [14. pop()](#14-pop)
    - [15. peek()](#15-peek)
  - [辅助方法](#辅助方法)
    - [1. ksym()](#1-ksym)
    - [2. ksymname()](#2-ksymname)
    - [3. sym()](#3-sym)
    - [4. num\_open\_kprobes()](#4-num_open_kprobes)
    - [5. get\_syscall\_fnname()](#5-get_syscall_fnname)
- [BPF 错误](#bpf-错误)
  - [1. Invalid mem access](#1-invalid-mem-access)
  - [2. 无法从专有程序调用 GPL-only 函数](#2-无法从专有程序调用-gpl-only-函数)
- [环境变量](#环境变量)
  - [1. 内核源代码目录](#1-内核源代码目录)
  - [2. 内核版本覆盖](#2-内核版本覆盖)

# BPF C

本节介绍了 bcc 程序的 C 部分。

## Events & Arguments

### 1. kprobes

语法：kprobe__*kernel_function_name*

```kprobe__``` 是一个特殊的前缀，用于创建一个 kprobe（对内核函数调用的动态跟踪），后面跟着的是内核函数的名称。你也可以通过声明一个普通的 C 函数，然后使用 Python 的 ```BPF.attach_kprobe()```（稍后会介绍）将其与一个内核函数关联起来来使用 kprobe。

参数在函数声明中指定：kprobe__*kernel_function_name*(struct pt_regs *ctx [, *argument1* ...])

例如：

```c
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    [...]
}
```

这会使用 kprobe 对 tcp_v4_connect() 内核函数进行插装，并使用以下参数：

- ```struct pt_regs *ctx```: 寄存器和 BPF 上下文。
- ```struct sock *sk```: tcp_v4_connect() 的第一个参数。

第一个参数始终是 ```struct pt_regs *```，其余的是函数的参数（如果你不打算使用它们，则不需要指定）。

示例代码：
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/tcpv4connect.py#L28)（[输出结果](https://github.com/iovisor/bcc/blob/5bd0eb21fd148927b078deb8ac29fff2fb044b66/examples/tracing/tcpv4connect_example.txt#L8)),"."[code](https://github.com/iovisor/bcc/commit/310ab53710cfd46095c1f6b3e44f1dbc8d1a41d8#diff-8cd1822359ffee26e7469f991ce0ef00R26) （[output](https://github.com/iovisor/bcc/blob/3b9679a3bd9b922c736f6061dc65cb56de7e0250/examples/tracing/bitehist_example.txt#L6))

<!--- 这里无法添加搜索链接，因为GitHub目前无法处理"kprobe__"所需的部分词搜索--->

### 2. kretprobes

语法: kretprobe__*kernel_function_name*

```kretprobe__```是一个特殊的前缀，它创建了一个kretprobe（对提供的内核函数名进行动态追踪，跟踪内核函数的返回）。您也可以通过声明一个普通的C函数，然后使用Python的```BPF.attach_kretprobe()```（稍后介绍）将其与内核函数关联起来，来使用kretprobes。

返回值可用作```PT_REGS_RC(ctx)```，给定函数声明为：kretprobe__*kernel_function_name*(struct pt_regs *ctx)

例如:

```C
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    [...]
}
```

这个例子使用kretprobe来对tcp_v4_connect()内核函数的返回进行检测，并将返回值存储在```ret```中。

现有的用法示例:
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/tcpv4connect.py#L38) （[output](https://github.com/iovisor/bcc/blob/5bd0eb21fd148927b078deb8ac29fff2fb044b66/examples/tracing/tcpv4connect_example.txt#L8))

### 3. Tracepoints

语法: TRACEPOINT_PROBE(*category*, *event*)

这是一个宏，用于对由*category*:*event*定义的tracepoint进行追踪。

tracepoint名称为`<category>:<event>`。
probe函数名为`tracepoint__<category>__<event>`。

参数在一个```args```结构体中可用，这些参数是tracepoint的参数。列出这些参数的一种方法是在/sys/kernel/debug/tracing/events/*category*/*event*/format下查看相关的格式文件。"`args` 结构体可用于替代 `ctx`，作为需要上下文作为参数的每个函数中的参数。这包括特别是 [perf_submit()](#3-perf_submit)。

例如：

```C
TRACEPOINT_PROBE(random, urandom_read) {
    // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
```

这会给 `random:urandom_read` 追踪点注入代码，并打印出追踪点参数 `got_bits`。
在使用 Python API 时，此探针会自动附加到正确的追踪点目标上。
对于 C++，可以通过明确指定追踪点目标和函数名来附加此追踪点探针：
`BPF::attach_tracepoint("random:urandom_read", "tracepoint__random__urandom_read")`
注意，上面定义的探针函数的名称是 `tracepoint__random__urandom_read`。

实际示例：
[code](https://github.com/iovisor/bcc/blob/a4159da8c4ea8a05a3c6e402451f530d6e5a8b41/examples/tracing/urandomread.py#L19) ([output](https://github.com/iovisor/bcc/commit/e422f5e50ecefb96579b6391a2ada7f6367b83c4#diff-41e5ecfae4a3b38de5f4e0887ed160e5R10))，
[search /examples](https://github.com/iovisor/bcc/search?q=TRACEPOINT_PROBE+path%3Aexamples&type=Code)，
[search /tools](https://github.com/iovisor/bcc/search?q=TRACEPOINT_PROBE+path%3Atools&type=Code)

### 4. uprobes

这些是通过在 C 中声明一个普通函数，然后在 Python 中通过 `BPF.attach_uprobe()` 将其关联为 uprobes 探针来进行注入的（稍后会介绍）。

可以使用 `PT_REGS_PARM` 宏来检查参数。

例如：

```C
int count(struct pt_regs *ctx) {
    char buf[64];
    bpf_probe_read_user(&buf, sizeof(buf), (void *)PT_REGS_PARM1(ctx));
    bpf_trace_printk("%s %d", buf, PT_REGS_PARM2(ctx));
    return(0);
}
```

这将读取第一个参数作为字符串，然后用第二个参数作为整数打印出来。

实际示例：
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/strlen_count.py#L26)。### 5。uretprobes

这些是通过在C中声明一个普通函数，然后在Python中通过```BPF.attach_uretprobe()```将其关联为uretprobe探测点（稍后详述）来进行插装的。

返回值可以通过```PT_REGS_RC(ctx)```访问，前提是有一个如下声明的函数：*function_name*(struct pt_regs *ctx)

例如：

```C
BPF_HISTOGRAM(dist);
int count(struct pt_regs *ctx) {
    dist.increment(PT_REGS_RC(ctx));
    return 0;
}
```

这会递增由返回值索引的```dist```直方图中的存储桶。

现场演示示例：
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/strlen_hist.py#L39) ([output](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/strlen_hist.py#L15)),
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/tools/bashreadline.py) ([output](https://github.com/iovisor/bcc/commit/aa87997d21e5c1a6a20e2c96dd25eb92adc8e85d#diff-2fd162f9e594206f789246ce97d62cf0R7))

### 6. USDT探测点

这些是用户静态定义追踪（USDT）探测点，可以放置在某些应用程序或库中，以提供用户级别等效的跟踪点。用于USDT支持的主要BPF方法是```enable_probe()```。通过在C中声明一个普通函数，然后在Python中通过```USDT.enable_probe()```将其关联为USDT探测点来进行插装。

可以通过以下方式读取参数：bpf_usdt_readarg(*index*, ctx, &addr)

例如：

```C
int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char path[128];
    bpf_usdt_readarg(6, ctx, &addr);
    bpf_probe_read_user(&path, sizeof(path), (void *)addr);
    bpf_trace_printk("path:%s\\n", path);
    return 0;
};
```

这会读取第六个USDT参数，然后将其作为字符串存储到```path```中。当使用C API中的```BPF::init```的第三个参数进行USDT的初始化时，如果任何USDT无法进行```init```，则整个```BPF::init```都会失败。如果您对一些USDT无法进行```init```感到满意，则在调用```BPF::init```之前使用```BPF::init_usdt```。

### 7. 原始跟踪点

语法：RAW_TRACEPOINT_PROBE(*event*)

这是一个宏，用于仪表化由*event*定义的原始跟踪点。

该参数是指向结构体```bpf_raw_tracepoint_args```的指针，该结构体定义在[bpf.h](https://github.com/iovisor/bcc/blob/master/src/cc/compat/linux/virtual_bpf.h)中。结构体字段```args```包含了原始跟踪点的所有参数，可以在[include/trace/events](https://github.com/torvalds/linux/tree/master/include/trace/events)目录中找到。

例如：

```C
RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next= (struct task_struct *)ctx->args[2];
    s32 prev_tgid, next_tgid;

    bpf_probe_read_kernel(&prev_tgid, sizeof(prev->tgid), &prev->tgid);
    bpf_probe_read_kernel(&next_tgid, sizeof(next->tgid), &next->tgid);
    bpf_trace_printk("%d -> %d\\n", prev_tgid, next_tgid);
}
```

这将仪表化sched:sched_switch跟踪点，并打印prev和next tgid。

### 8. 系统调用跟踪点

语法：```syscall__SYSCALLNAME```。```syscall__```是一个特殊的前缀，用于为提供的系统调用名称创建一个kprobe。您可以通过声明一个普通的C函数，然后使用Python的```BPF.get_syscall_fnname(SYSCALLNAME)```和```BPF.attach_kprobe()```来使用它。

参数在函数声明中指定: ```syscall__SYSCALLNAME(struct pt_regs *ctx, [, argument1 ...])```.

例如：

```C
int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    [...]
}
```

这将对execve系统调用进行探查。

第一个参数始终是```struct pt_regs *```，其余的参数是函数的参数（如果您不打算使用它们，则无需指定）。

相应的Python代码：

```Python
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
```

示例：
[code](https://github.com/iovisor/bcc/blob/552658edda09298afdccc8a4b5e17311a2d8a771/tools/execsnoop.py#L101) ([output](https://github.com/iovisor/bcc/blob/552658edda09298afdccc8a4b5e17311a2d8a771/tools/execsnoop_example.txt#L8))

### 9. kfuncs

语法：KFUNC_PROBE(*function*, typeof(arg1) arg1, typeof(arg2) arge ...)

这是一个通过跳板来在内核函数执行**之前**对其进行探查的宏。它由*function*名称和*argX*定义的函数参数组成。

例如：

```C
KFUNC_PROBE(do_sys_open, int dfd, const char *filename, int flags, int mode)
{
    ...
}
```

这将对do_sys_open内核函数进行探查，并将其参数作为标准参数值访问。

示例：
[search /tools](https://github.com/iovisor/bcc/search?q=KFUNC_PROBE+path%3Atools&type=Code)

### 10. kretfuncs

语法：KRETFUNC_PROBE(*event*, typeof(arg1) arg1, typeof(arg2) arge ..., int ret)

这是一个通过跳板来在内核函数执行**之前**探查的宏。
格式：仅返回翻译后的内容，不包括原始文本。*在*函数执行之后。它由*函数*名称和定义为*argX*的函数参数定义。

探针的最后一个参数是检测函数的返回值。

例如：

```C
KRETFUNC_PROBE(do_sys_open, int dfd, const char *filename, int flags, int mode, int ret)
{
    ...
```

这会对do_sys_open内核函数进行检测，并将其参数作为标准参数值一起与其返回值一起提取。

原地示例：
[搜索 /tools](https://github.com/iovisor/bcc/search?q=KRETFUNC_PROBE+path%3Atools&type=Code)

### 11. LSM Probes

语法：LSM_PROBE(*hook*, typeof(arg1) arg1, typeof(arg2) arg2 ...)

这是一种将LSM挂钩作为BPF程序进行检测的宏。它可以用于审计安全事件和实施BPF中的MAC安全策略。
它通过指定挂钩名及其参数来定义。

可以在
[include/linux/security.h](https://github.com/torvalds/linux/blob/v5.15/include/linux/security.h#L260)
中找到挂钩名称，方法是取security_hookname之类的函数名，然后只保留`hookname`部分。
例如，`security_bpf`仅变成了`bpf`。

与其他BPF程序类型不同，LSM探针中指定的返回值是很重要的。返回值为0表示挂钩成功，而
任何非零的返回值都会导致挂钩失败和拒绝安全操作。

以下示例对一个拒绝所有未来BPF操作的挂钩进行了检测：

```C
LSM_PROBE(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    return -EPERM;
}
```

这会对`security_bpf`挂钩进行检测，并导致其返回`-EPERM`。
将`return -EPERM`更改为`return 0`会导致BPF程序允许该操作。

LSM探针需要至少一个5.7+内核，并设置了以下配置选项：

- `CONFIG_BPF_LSM=y`
- `CONFIG_LSM` 逗号分隔的字符串必须包含"bpf"（例如，
  `CONFIG_LSM="lockdown,yama,bpf"`)

原地示例："[搜索/tests](https://github.com/iovisor/bcc/search?q=LSM_PROBE+path%3Atests&type=Code)

### 12. BPF迭代器

语法: BPF_ITER(target)

这是一个宏，用于定义一个bpf迭代器程序的程序签名。参数 *target* 指定要迭代的内容。

目前，内核没有接口来发现支持哪些目标。一个好的查找支持内容的地方是在 [tools/testing/selftests/bpf/prog_test/bpf_iter.c](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/bpf_iter.c) ，一些示例bpf迭代器程序位于 [tools/testing/selftests/bpf/progs](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf/progs) ，其中文件名以 *bpf_iter* 为前缀。

以下示例为 *task* 目标定义了一个程序，该程序遍历内核中的所有任务。

```C
BPF_ITER(task)
{
  struct seq_file *seq = ctx->meta->seq;
  struct task_struct *task = ctx->task;

  if (task == (void *)0)
    return 0;

  ... task->pid, task->tgid, task->comm, ...
  return 0;
}
```

在5.8内核中引入了BPF迭代器，可以用于任务（task）、任务文件（task_file）、bpf map、netlink_sock和ipv6_route。在5.9中，对tcp/udp socket和bpf map元素（hashmap、arraymap和sk_local_storage_map）遍历添加了支持。

## 数据

### 1. bpf_probe_read_kernel()

语法: ```int bpf_probe_read_kernel(void *dst, int size, const void*src)```

返回值: 成功时返回0

该函数将从内核地址空间复制size字节到BPF堆栈，以便BPF之后可以对其进行操作。为了安全起见，所有内核内存读取都必须通过bpf_probe_read_kernel()进行。在某些情况下，比如解引用内核变量时，这会自动发生，因为bcc会重新编写BPF程序以包含所需的bpf_probe_read_kernel()。

现场示例：
[搜索 /examples](https://github.com/iovisor/bcc/search?q=bpf_probe_read_kernel+path%3Aexamples&type=Code),
[搜索 /tools](https://github.com/iovisor/bcc/search?q=bpf_probe_read_kernel+path%3Atools&type=Code)

### 2. bpf_probe_read_kernel_str()".```shell

语法：```int bpf_probe_read_kernel_str(void *dst, int size, const void*src)```

返回值：

- \> 0 成功时字符串长度（包括结尾的NULL字符）
- \< 0 出错

该函数将一个以`NULL`结尾的字符串从内核地址空间复制到BPF堆栈中，以便BPF以后可以对其进行操作。如果字符串的长度小于size，则目标不会用更多的`NULL`字节进行填充。如果字符串的长度大于size，则只会复制`size - 1`个字节，并将最后一个字节设置为`NULL`。

示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=bpf_probe_read_kernel_str+path%3Aexamples&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=bpf_probe_read_kernel_str+path%3Atools&type=Code)

### 3. bpf_ktime_get_ns()

语法：```u64 bpf_ktime_get_ns(void)```

返回值：u64 纳秒数。从系统启动时间开始计数，但在挂起期间停止计数。

示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=bpf_ktime_get_ns+path%3Aexamples&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=bpf_ktime_get_ns+path%3Atools&type=Code)

### 4. bpf_get_current_pid_tgid()

语法：```u64 bpf_get_current_pid_tgid(void)```

返回值：```current->tgid << 32 | current->pid```

返回进程ID位于低32位（内核视图的PID，在用户空间通常表示为线程ID），线程组ID位于高32位（在用户空间通常被认为是PID）。通过直接设置为u32类型，我们丢弃了高32位。

示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=bpf_get_current_pid_tgid+path%3Aexamples&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=bpf_get_current_pid_tgid+path%3Atools&type=Code)

### 5. bpf_get_current_uid_gid()

语法：```u64 bpf_get_current_uid_gid(void)```

返回值：```current_gid << 32 | current_uid```

返回用户ID和组ID。

示例：[搜索/examples](https://github.com/iovisor/bcc/search?q=bpf_get_current_uid_gid+path%3Aexamples&type=Code), [搜索/tools](https://github.com/iovisor/bcc/search?q=bpf_get_current_uid_gid+path%3Atools&type=Code)

### 6. bpf_get_current_comm()

语法: ```bpf_get_current_comm(char *buf, int size_of_buf)```

返回值: 成功时返回0

将当前进程的名称填充到第一个参数地址中。它应该是一个指向字符数组的指针，大小至少为TASK_COMM_LEN，该变量在linux/sched.h中定义。例如:

```C
#include <linux/sched.h>

int do_trace(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
[...]
```

现有示例:
[搜索/examples](https://github.com/iovisor/bcc/search?q=bpf_get_current_comm+path%3Aexamples&type=Code), [搜索/tools](https://github.com/iovisor/bcc/search?q=bpf_get_current_comm+path%3Atools&type=Code)

### 7. bpf_get_current_task()

语法: ```bpf_get_current_task()```

返回值: 返回指向当前任务的struct task_struct指针。

返回指向当前任务的task_struct对象的指针。该辅助函数可用于计算进程的CPU时间，标识内核线程，获取当前CPU的运行队列或检索许多其他信息。

在Linux 4.13中，由于字段随机化的问题，您可能需要在包含之前定义两个#define指令:

```C
#define randomized_struct_fields_start  struct {
#define randomized_struct_fields_end    };
#include <linux/sched.h>

int do_trace(void *ctx) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
[...]
```

现有示例:
[搜索/examples](https://github.com/iovisor/bcc/search?q=bpf_get_current_task+path%3Aexamples&type=Code), [搜索/tools](https://github.com/iovisor/bcc/search?q=bpf_get_current_task+path%3Atools&type=Code)

### 8. bpf_log2l()

语法: ```unsigned int bpf_log2l(unsigned long v)```

返回提供的值的log-2。这通常用于创建直方图的索引，以构建2的幂次直方图。在原地示例：

[搜索/示例](https://github.com/iovisor/bcc/search?q=bpf_log2l+path%3Aexamples&type=Code)，
[搜索/工具](https://github.com/iovisor/bcc/search?q=bpf_log2l+path%3Atools&type=Code)

### 9. bpf_get_prandom_u32()

语法：```u32 bpf_get_prandom_u32()```

返回一个伪随机的 u32。

在原地示例：

[搜索/示例](https://github.com/iovisor/bcc/search?q=bpf_get_prandom_u32+path%3Aexamples&type=Code)，
[搜索/工具](https://github.com/iovisor/bcc/search?q=bpf_get_prandom_u32+path%3Atools&type=Code)

### 10. bpf_probe_read_user()

语法：```int bpf_probe_read_user(void *dst, int size, const void*src)```

返回值：成功时返回0

该函数尝试安全地从用户地址空间读取size个字节到BPF栈中，以便BPF之后可以操作它。为确保安全，所有用户地址空间内存读取必须通过bpf_probe_read_user()。

在原地示例：

[搜索/示例](https://github.com/iovisor/bcc/search?q=bpf_probe_read_user+path%3Aexamples&type=Code)，
[搜索/工具](https://github.com/iovisor/bcc/search?q=bpf_probe_read_user+path%3Atools&type=Code)

### 11. bpf_probe_read_user_str()

语法：```int bpf_probe_read_user_str(void *dst, int size, const void*src)```

返回值：

- \> 0 成功时返回字符串长度（包括结尾的NULL）
- \< 0 错误

该函数将一个以`NULL`结尾的字符串从用户地址空间复制到BPF栈中，以便BPF之后可以操作它。如果字符串长度小于size，则目标不会用额外的`NULL`字节填充。如果字符串长度大于size，则只会复制`size - 1`字节，并将最后一字节设置为`NULL`。

在原地示例：

[搜索/示例](https://github.com/iovisor/bcc/search?q=bpf_probe_read_user_str+path%3Aexamples&type=Code)，
[搜索/工具](https://github.com/iovisor/bcc/search?q=bpf_probe_read_user_str+path%3Atools&type=Code)

### 12. bpf_get_ns_current_pid_tgid()

语法：```u32 bpf_get_ns_current_pid_tgid(u64 dev, u64 ino, struct bpf_pidns_info*nsdata, u32 size)```。从当前**命名空间**中看到的*pid*和*tgid*的值将在*nsdata*中返回。

成功返回0，失败时返回以下之一：

- 如果提供的dev和inum与当前任务的nsfs的dev_t和inode号不匹配，或者dev转换为dev_t丢失了高位，则返回**-EINVAL**。

- 如果当前任务的pidns不存在，则返回**-ENOENT**。

原地示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=bpf_get_ns_current_pid_tgid+path%3Aexamples&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=bpf_get_ns_current_pid_tgid+path%3Atools&type=Code)

## 调试

### 1. bpf_override_return()

语法：```int bpf_override_return(struct pt_regs *, unsigned long rc)```

返回值：成功时返回0

当用于附加到函数入口的程序时，会导致该函数的执行被跳过，立即返回`rc`。这用于目标错误注入。

仅当允许错误注入时，bpf_override_return才有效。白名单列表中需要在内核源代码中给一个函数打上 `ALLOW_ERROR_INJECTION()` 的标签；参考 `io_ctl_init` 的示例。如果该函数未被加入白名单，bpf程序将无法附加，出现 `ioctl(PERF_EVENT_IOC_SET_BPF): Invalid argument` 错误。

```C
int kprobe__io_ctl_init(void *ctx) {
 bpf_override_return(ctx, -ENOMEM);
 return 0;
}
```

## 输出

### 1. bpf_trace_printk()

语法：```int bpf_trace_printk(const char *fmt, ...)```

返回值：成功时返回0

对于通常的trace_pipe (/sys/kernel/debug/tracing/trace_pipe)提供了一个简单的内核printf()功能。这对于一些快速示例是可以接受的，但有一些限制：最多3个参数，只有一个%s，而且trace_pipe是全局共享的，所以并发程序会有冲突输出。更好的接口是通过BPF_PERF_OUTPUT()。注意，与原始内核版本相比，调用这个辅助函数变得更简单，它的第二个参数已经是 ```fmt_size```。

原地示例："[搜索 /示例](https://github.com/iovisor/bcc/search?q=bpf_trace_printk+path%3Aexamples&type=Code), [搜索 /工具](https://github.com/iovisor/bcc/search?q=bpf_trace_printk+path%3Atools&type=Code)

### 2. BPF_PERF_OUTPUT

语法：```BPF_PERF_OUTPUT(name)```

创建一个BPF表格，通过性能环形缓冲区将自定义事件数据推送到用户空间。这是将每个事件数据推送到用户空间的首选方法。

例如：

```C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
```

输出表格名为```events```，数据通过```events.perf_submit()```推送到该表格。

示例中包含以下内容：
[搜索 /示例](https://github.com/iovisor/bcc/search?q=BPF_PERF_OUTPUT+path%3Aexamples&type=Code), [搜索 /工具](https://github.com/iovisor/bcc/search?q=BPF_PERF_OUTPUT+path%3Atools&type=Code)

### 3. perf_submit()

语法：```int perf_submit((void *)ctx, (void*)data, u32 data_size)```

返回值：成功返回0

这是BPF_PERF_OUTPUT表格的一种方法，用于向用户空间提交自定义事件数据。参见BPF_PERF_OUTPUT条目（最终调用bpf_perf_event_output()）。

```ctx```参数在[kprobes](#1-kprobes)或[kretprobes](#2-kretprobes)中提供。对于```SCHED_CLS```或```SOCKET_FILTER```程序，必须使用```struct __sk_buff *skb```。

示例中包含以下内容：
[搜索 /示例](https://github.com/iovisor/bcc/search?q=perf_submit+path%3Aexamples&type=Code), [搜索 /工具](https://github.com/iovisor/bcc/search?q=perf_submit+path%3Atools&type=Code)

### 4. perf_submit_skb()

语法：```int perf_submit_skb((void *)ctx, u32 packet_size, (void*)data, u32 data_size)```

返回值：成功返回0".一种在网络程序类型中可用的BPF_PERF_OUTPUT表的方法，用于将自定义事件数据和数据包缓冲区的前```packet_size```字节一起提交到用户空间。请参阅BPF_PERF_OUTPUT条目。（最终调用bpf_perf_event_output()函数。）

现场示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=perf_submit_skb+path%3Aexamples&type=Code)
[搜索/tools](https://github.com/iovisor/bcc/search?q=perf_submit_skb+path%3Atools&type=Code)

### 5. BPF_RINGBUF_OUTPUT

语法：```BPF_RINGBUF_OUTPUT(name, page_cnt)```

创建一个BPF表，通过一个环形缓冲区将自定义事件数据推送到用户空间。
```BPF_RINGBUF_OUTPUT```相较于```BPF_PERF_OUTPUT```具有以下几个优点：

- 缓冲区在所有CPU之间共享，即每个CPU不需要单独分配
- 支持两种BPF程序的API
  - ```map.ringbuf_output()```类似于```map.perf_submit()```（在[ringbuf_output](#6-ringbuf_output)中介绍）
  - ```map.ringbuf_reserve()```/```map.ringbuf_submit()```/```map.ringbuf_discard()```将保留缓冲区空间和提交事件的过程分为两步（在[ringbuf_reserve](#7-ringbuf_reserve)、[ringbuf_submit](#8-ringbuf_submit)和[ringbuf_discard](#9-ringbuf_discard)中介绍）
- BPF API不需要访问CPU ctx参数
- 通过共享的环形缓冲区管理器，在用户空间中具有更高的性能和更低的延迟
- 支持两种在用户空间中消费数据的方式

从Linux 5.8开始，这应该是将事件数据推送到用户空间的首选方法。

输出表命名为'事件'。数据通过'事件'。ringbuf_reserve（）分配，并通过'事件'。ringbuf_submit（）推送到其中。

在situ示例：<!-- TODO -->
[搜索/示例](https://github.com/iovisor/bcc/search?q=BPF_RINGBUF_OUTPUT+path%3Aexamples&type=Code)，

### 6. ringbuf_output（）

语法：int ringbuf_output（（void *）data，u64 data_size，u64 flags）

返回：成功返回0

标志：

- ```BPF_RB_NO_WAKEUP```：不发送新数据可用的通知
- ```BPF_RB_FORCE_WAKEUP```：无条件发送新数据可用的通知

BPF_RINGBUF_OUTPUT表的方法，用于将自定义事件数据提交给用户空间。此方法类似于```perf_submit（）```，但不需要ctx参数。

在situ示例：<!-- TODO -->
[搜索/示例](https://github.com/iovisor/bcc/search?q=ringbuf_output+path%3Aexamples&type=Code)，

### 7. ringbuf_reserve()

语法：void * ringbuf_reserve（u64 data_size）

返回：成功时返回数据结构的指针，失败时返回NULL

BPF_RINGBUF_OUTPUT表的方法，用于在环形缓冲区中保留空间并同时分配一个用于输出的数据结构。必须与```ringbuf_submit```或```ringbuf_discard```之一配合使用。

在situ示例：<!-- TODO -->
[搜索/示例]（<https://github.com/iovisor/bcc/search?q=ringbuf_reserve+path%3Aexamples&type=Code），>

### 8. ringbuf_submit（）

语法：void ringbuf_submit（（void *）data，u64 flags）

返回：无，始终成功

标志：- ```BPF_RB_NO_WAKEUP```: 不发送新数据可用的通知

- ```BPF_RB_FORCE_WAKEUP```: 无条件发送新数据可用的通知

BPF_RINGBUF_OUTPUT表的方法，用于将自定义事件数据提交到用户态。必须在调用```ringbuf_reserve()```之前调用，以为数据预留空间。

现场示例：<!-- TODO -->
[搜索/examples](https://github.com/iovisor/bcc/search?q=ringbuf_submit+path%3Aexamples&type=Code),

### 9. ringbuf_discard()

语法: ```void ringbuf_discard((void *)data, u64 flags)```

返回值: 无，始终成功

标志:

- ```BPF_RB_NO_WAKEUP```: 不发送新数据可用的通知
- ```BPF_RB_FORCE_WAKEUP```: 无条件发送新数据可用的通知

BPF_RINGBUF_OUTPUT表的方法，用于丢弃自定义事件数据；用户空间将忽略与丢弃事件相关联的数据。必须在调用```ringbuf_reserve()```之前调用，以为数据预留空间。

现场示例：<!-- TODO -->
[搜索/examples](https://github.com/iovisor/bcc/search?q=ringbuf_submit+path%3Aexamples&type=Code),

## Maps

Maps是BPF数据存储，是更高级对象类型（包括表、哈希和直方图）的基础。

### 1. BPF_TABLE

语法: ```BPF_TABLE(_table_type,_key_type, _leaf_type,_name, _max_entries)```

创建名为```_name```的映射。大多数情况下，这将通过更高级的宏（如BPF_HASH、BPF_ARRAY、BPF_HISTOGRAM等）使用。

`BPF_F_TABLE`是一个变体，最后一个参数采用标志。`BPF_TABLE(https://github.com/iovisor/bcc/tree/master.)`实际上是`BPF_F_TABLE(<https://github.com/iovisor/bcc/tree/master>., 0 /*flag*/)```的包装。

方法（稍后讨论）：map.lookup()、map.lookup_or_try_init()、map.delete()、map.update()、map.insert()、map.increment()。

现场示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=BPF_TABLE+path%3Aexamples&type=Code),"[搜索 /工具](https://github.com/iovisor/bcc/search?q=BPF_TABLE+path%3Atools&type=Code)

#### 固定映射

语法: ```BPF_TABLE_PINNED(_table_type,_key_type, _leaf_type,_name, _max_entries, "/sys/fs/bpf/xyz")```

如果映射不存在，则创建一个新的映射并将其固定到bpffs作为文件；否则使用已固定到bpffs的映射。类型信息不强制执行，实际的映射类型取决于固定到位置的映射。

例如:

```C
BPF_TABLE_PINNED("hash", u64, u64, ids, 1024, "/sys/fs/bpf/ids");
```

### 2. BPF_HASH

语法: ```BPF_HASH(name [, key_type [, leaf_type [, size]]])```

创建一个哈希映射（关联数组），名称为```name```，具有可选参数。

默认值: ```BPF_HASH(name, key_type=u64, leaf_type=u64, size=10240)```

例如:

```C
BPF_HASH(start, struct request *);
```

这将创建一个名为```start```的哈希，其中关键字为```struct request *```，值默认为u64。此哈希由disksnoop.py示例用于保存每个I/O请求的时间戳，其中关键字是指向struct request的指针，而值是时间戳。

这是`BPF_TABLE("hash", ...)`的包装宏。

方法（稍后涵盖）：map.lookup()，map.lookup_or_try_init()，map.delete()，map.update()，map.insert()，map.increment()。

示例中的原位置链接：[搜索 /示例](https://github.com/iovisor/bcc/search?q=BPF_HASH+path%3Aexamples&type=Code),
[搜索 /工具](https://github.com/iovisor/bcc/search?q=BPF_HASH+path%3Atools&type=Code)

### 3. BPF_ARRAY

语法: ```BPF_ARRAY(name [, leaf_type [, size]])```

创建一个以整数索引的数组，最快速的查找和更新为优化，名称为```name```，具有可选参数。

默认值: ```BPF_ARRAY(name, leaf_type=u64, size=10240)```

例如:

```C
BPF_ARRAY(counts, u64, 32);
```

这将创建一个名为```counts```的数组，其中有32个存储桶和64位整数值。funccount.py示例使用此数组保存每个函数的调用计数。".这是一个 `BPF_TABLE("array", ...)` 的包装宏。

方法（稍后介绍）：map.lookup()、map.update()、map.increment()。注意，所有数组元素都预先分配为零值，无法删除。

在当前位置的示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=BPF_ARRAY+path%3Aexamples&type=Code)，
[搜索/tools](https://github.com/iovisor/bcc/search?q=BPF_ARRAY+path%3Atools&type=Code)

### 4. BPF_HISTOGRAM

语法：```BPF_HISTOGRAM(name [, key_type [, size ]])```

创建一个名为 ```name``` 的直方图映射，包含可选参数。

默认值：```BPF_HISTOGRAM(name, key_type=int, size=64)```

例如：

```C
BPF_HISTOGRAM(dist);
```

这创建了一个名为 ```dist``` 的直方图，默认有 64 个桶，以 int 类型的键索引。

这是一个 `BPF_TABLE("histgram", ...)` 的包装宏。

方法（稍后介绍）：map.increment()。

在当前位置的示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=BPF_HISTOGRAM+path%3Aexamples&type=Code)，
[搜索/tools](https://github.com/iovisor/bcc/search?q=BPF_HISTOGRAM+path%3Atools&type=Code)

### 5. BPF_STACK_TRACE

语法：```BPF_STACK_TRACE(name, max_entries)```

创建一个名为 ```name``` 的堆栈跟踪映射，提供最大条目数。这些映射用于存储堆栈跟踪。

例如：

```C
BPF_STACK_TRACE(stack_traces, 1024);
```

这创建了一个名为 ```stack_traces``` 的堆栈跟踪映射，最大堆栈跟踪条目数为 1024。

这是一个 `BPF_TABLE("stacktrace", ...)` 的包装宏。

方法（稍后介绍）：map.get_stackid()。

在当前位置的示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=BPF_STACK_TRACE+path%3Aexamples&type=Code)，
[搜索/tools](https://github.com/iovisor/bcc/search?q=BPF_STACK_TRACE+path%3Atools&type=Code)

### 6. BPF_PERF_ARRAY

语法：```BPF_PERF_ARRAY(name, max_entries)```

创建一个名为 ```name``` 的 perf 数组，提供最大条目数，该数必须等于系统 CPU 的数量。这些映射用于获取硬件性能计数器。例如：

```C
text="""
BPF_PERF_ARRAY(cpu_cycles, NUM_CPUS);
"""
b = bcc.BPF(text=text, cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
b["cpu_cycles"].open_perf_event(b["cpu_cycles"].HW_CPU_CYCLES)
```

这将创建一个名为```cpu_cycles```的性能数组，条目数量等于CPU核心数。该数组被配置为，稍后调用```map.perf_read()```将返回从过去某一时刻开始计算的硬件计数器的周期数。每个表只能配置一种类型的硬件计数器。

方法（稍后介绍）：```map.perf_read()```。

现场示例：
[搜索 /tests](https://github.com/iovisor/bcc/search?q=BPF_PERF_ARRAY+path%3Atests&type=Code)

### 7. BPF_PERCPU_HASH

语法：```BPF_PERCPU_HASH(name [, key_type [, leaf_type [, size]]])```

创建NUM_CPU个以int索引的哈希映射（关联数组），名为```name```，具有可选参数。每个CPU都会有一个单独的该数组副本。这些副本不以任何方式进行同步。

请注意，由于内核中定义的限制（位于linux/mm/percpu.c中），```leaf_type```的大小不能超过32KB。
换句话说，```BPF_PERCPU_HASH```元素的大小不能超过32KB。

默认值：```BPF_PERCPU_HASH(name, key_type=u64, leaf_type=u64, size=10240)```

例如：

```C
BPF_PERCPU_HASH(start, struct request *);
```

这将创建名为```start```的NUM_CPU个哈希，其中键为```struct request *```，值默认为u64。

这是对```BPF_TABLE("percpu_hash", ...)```的包装宏。

方法（稍后介绍）：```map.lookup()```、```map.lookup_or_try_init()```、```map.delete()```、```map.update()```、```map.insert()```、```map.increment()```。

现场示例：
[搜索 /examples](https://github.com/iovisor/bcc/search?q=BPF_PERCPU_HASH+path%3Aexamples&type=Code),
[搜索 /tools](https://github.com/iovisor/bcc/search?q=BPF_PERCPU_HASH+path%3Atools&type=Code)

### 8. BPF_PERCPU_ARRAY

语法：```BPF_PERCPU_ARRAY(name [, leaf_type [, size]])```。创建```name```的NUM_CPU个按整数索引优化的数组，以实现最快的查找和更新，具有可选参数。每个CPU都会有一个单独的副本。这些副本不能以任何方式同步。

请注意，由于内核（在linux/mm/percpu.c中）定义的限制，```leaf_type```的大小不能超过32KB。
换句话说，```BPF_PERCPU_ARRAY```元素的大小不能超过32KB。

默认值：```BPF_PERCPU_ARRAY(name, leaf_type=u64, size=10240)```

例如：

```C
BPF_PERCPU_ARRAY(counts, u64, 32);
```

这将创建NUM_CPU个名为```counts```的数组，其中每个数组有32个桶和64位整数值。

这是```BPF_TABLE("percpu_array", ...)```的包装宏。

方法（稍后介绍）：map.lookup()，map.update()，map.increment()。请注意，所有数组元素都预先分配为零值，并且不能被删除。

In situ示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=BPF_PERCPU_ARRAY+path%3Aexamples&type=Code)，
[搜索/tools](https://github.com/iovisor/bcc/search?q=BPF_PERCPU_ARRAY+path%3Atools&type=Code)

### 9. BPF_LPM_TRIE

语法：```BPF_LPM_TRIE(name [, key_type [, leaf_type [, size]]])```

创建一个名为```name```的最长前缀匹配字典树映射，带有可选参数。

默认值：```BPF_LPM_TRIE(name, key_type=u64, leaf_type=u64, size=10240)```

例如：

```c
BPF_LPM_TRIE(trie, struct key_v6);
```

这将创建一个名为```trie```的LPM字典树映射，其中键是```struct key_v6```，值默认为u64。

这是一个对```BPF_F_TABLE("lpm_trie", ..., BPF_F_NO_PREALLOC)```的包装宏。

方法（稍后介绍）：map.lookup()，map.lookup_or_try_init()，map.delete()，map.update()，map.insert()，map.increment()。

In situ示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=BPF_LPM_TRIE+path%3Aexamples&type=Code)，
[搜索/tools](https://github.com/iovisor/bcc/search?q=BPF_LPM_TRIE+path%3Atools&type=Code)

### 10. BPF_PROG_ARRAY

语法：```BPF_PROG_ARRAY(name, size)```。创建一个名为 ```name``` 的程序数组，其中包含 ```size``` 个条目。数组的每个条目要么是指向一个 bpf 程序的文件描述符，要么是 ```NULL```。该数组作为一个跳转表，以便 bpf 程序可以“尾调用”其他 bpf 程序。

这是一个 ```BPF_TABLE("prog", ...)``` 的包装宏。

方法（稍后介绍）：map.call()。

实时示例：
[搜索 /examples](https://github.com/iovisor/bcc/search?q=BPF_PROG_ARRAY+path%3Aexamples&type=Code),
[搜索 /tests](https://github.com/iovisor/bcc/search?q=BPF_PROG_ARRAY+path%3Atests&type=Code),
[分配 fd](https://github.com/iovisor/bcc/blob/master/examples/networking/tunnel_monitor/monitor.py#L24-L26)

### 11. BPF_DEVMAP

语法：```BPF_DEVMAP(name, size)```

这创建了一个名为 ```name``` 的设备映射，其中包含 ```size``` 个条目。映射的每个条目都是一个网络接口的 `ifindex`。此映射仅在 XDP 中使用。

例如：

```C
BPF_DEVMAP(devmap, 10);
```

方法（稍后介绍）：map.redirect_map()。

实时示例：
[搜索 /examples](https://github.com/iovisor/bcc/search?q=BPF_DEVMAP+path%3Aexamples&type=Code),

### 12. BPF_CPUMAP

语法：```BPF_CPUMAP(name, size)```

这创建了一个名为 ```name``` 的 CPU 映射，其中包含 ```size``` 个条目。映射的索引表示 CPU 的 ID，每个条目是为 CPU 分配的环形缓冲区的大小。此映射仅在 XDP 中使用。

例如：

```C
BPF_CPUMAP(cpumap, 16);
```

方法（稍后介绍）：map.redirect_map()。

实时示例：
[搜索 /examples](https://github.com/iovisor/bcc/search?q=BPF_CPUMAP+path%3Aexamples&type=Code),

### 13. BPF_XSKMAP

语法：```BPF_XSKMAP(name, size [, "/sys/fs/bpf/xyz"])```。这将创建一个名为```name```的xsk映射，带有```size```个条目，并将其固定到bpffs作为一个文件。每个条目表示一个NIC的队列ID。该映射仅在XDP中用于将数据包重定向到AF_XDP套接字。如果AF_XDP套接字绑定到与当前数据包的队列ID不同的队列，则数据包将被丢弃。对于内核v5.3及更高版本，“lookup”方法可用于检查当前数据包的队列ID是否可用于AF_XDP套接字。有关详细信息，请参阅[AF_XDP](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)。

例如：

```C
BPF_XSKMAP(xsks_map, 8);
```

方法（稍后涵盖）：map.redirect_map()。map.lookup()

现场示例：
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_XSKMAP+path%3Aexamples&type=Code),

### 14. BPF_ARRAY_OF_MAPS

语法：```BPF_ARRAY_OF_MAPS(name, inner_map_name, size)```

这将创建一个带有映射内部类型（BPF_MAP_TYPE_HASH_OF_MAPS）的数组映射，名称为```name```，包含```size```个条目。映射的内部元数据由映射```inner_map_name```提供，可以是除了```BPF_MAP_TYPE_PROG_ARRAY```、```BPF_MAP_TYPE_CGROUP_STORAGE```和```BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE```之外的大多数数组或哈希映射。

例如：

```C
BPF_TABLE("hash", int, int, ex1, 1024);
BPF_TABLE("hash", int, int, ex2, 1024);
BPF_ARRAY_OF_MAPS(maps_array, "ex1", 10);
```

### 15. BPF_HASH_OF_MAPS

语法：```BPF_HASH_OF_MAPS(name, key_type, inner_map_name, size)```

这将创建一个带有映射内部类型（BPF_MAP_TYPE_HASH_OF_MAPS）的哈希映射，名称为```name```，包含```size```个条目。映射的内部元数据由映射```inner_map_name```提供，可以是除了```BPF_MAP_TYPE_PROG_ARRAY```、```BPF_MAP_TYPE_CGROUP_STORAGE```和```BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE```之外的大多数数组或哈希映射。

例如：

```C
BPF_ARRAY(ex1, int, 1024);
BPF_ARRAY(ex2, int, 1024);
BPF_HASH_OF_MAPS(maps_hash, struct custom_key, "ex1", 10);
```

### 16. BPF_STACK

语法：```BPF_STACK(name, leaf_type, max_entries[, flags])```。创建一个名为 `name` 的堆栈，其值类型为 `leaf_type`，最大条目数为 `max_entries`。
堆栈和队列映射仅适用于 Linux 4.20+。

例如:

```C
BPF_STACK(stack, struct event, 10240);
```

这将创建一个名为 `stack` 的堆栈，其值类型为 `struct event`，最多可容纳 10240 个条目。

方法（后面会涉及）：map.push()、map.pop()、map.peek()。

示例：

在 [search /tests](https://github.com/iovisor/bcc/search?q=BPF_STACK+path%3Atests&type=Code) 中。

### 17. BPF_QUEUE

语法：```BPF_QUEUE(name, leaf_type, max_entries[, flags])```

创建一个名为 `name` 的队列，其值类型为 `leaf_type`，最大条目数为 `max_entries`。
堆栈和队列映射仅适用于 Linux 4.20+。

例如：

```C
BPF_QUEUE(queue, struct event, 10240);
```

这将创建一个名为 `queue` 的队列，其值类型为 `struct event`，最多可容纳 10240 个条目。

方法（后面会涉及）：map.push()、map.pop()、map.peek()。

示例：

在 [search /tests](https://github.com/iovisor/bcc/search?q=BPF_QUEUE+path%3Atests&type=Code) 中。

### 18. BPF_SOCKHASH

语法：```BPF_SOCKHASH(name[, key_type [, max_entries)```

创建一个名为 `name` 的哈希，带有可选参数。sockhash仅适用于Linux 4.18+。

默认值：```BPF_SOCKHASH(name, key_type=u32, max_entries=10240)```

例如：

```C
struct sock_key {
  u32 remote_ip4;
  u32 local_ip4;
  u32 remote_port;
  u32 local_port;
};
BPF_HASH(skh, struct sock_key, 65535);
```

这将创建一个名为 `skh` 的哈希表，其中键是 `struct sock_key`。

sockhash是一种BPF映射类型，它保存对sock结构体的引用。然后，通过使用新的sk/msg重定向BPF辅助函数，BPF程序可以使用该映射在套接字之间重定向skbs/msgs（`map.sk_redirect_hash()/map.msg_redirect_hash()`）。```BPF_SOCKHASH```和```BPF_SOCKMAP```的区别在于```BPF_SOCKMAP```是基于数组实现的，并且强制键为四个字节。
而```BPF_SOCKHASH```是基于哈希表实现的，并且键的类型可以自由指定。

方法（稍后介绍）：map.sock_hash_update()，map.msg_redirect_hash()，map.sk_redirect_hash()。

[搜索/tests](https://github.com/iovisor/bcc/search?q=BPF_SOCKHASH+path%3Atests&type=Code)

### 19. map.lookup()

语法：```*val map.lookup(&key)```

在映射中查找键，如果存在则返回指向其值的指针，否则返回NULL。我们将键作为指针的地址传入。

示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=lookup+path%3Aexamples&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=lookup+path%3Atools&type=Code)

### 20. map.lookup_or_try_init()

语法：```*val map.lookup_or_try_init(&key, &zero)```

在映射中查找键，如果存在则返回指向其值的指针，否则将键的值初始化为第二个参数。通常用于将值初始化为零。如果无法插入键（例如映射已满），则返回NULL。

示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=lookup_or_try_init+path%3Aexamples&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=lookup_or_try_init+path%3Atools&type=Code)

注意：旧的map.lookup_or_init()可能导致函数返回，因此建议使用lookup_or_try_init()，它没有这种副作用。

### 21. map.delete()

语法：```map.delete(&key)```

从哈希表中删除键。

示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=delete+path%3Aexamples&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=delete+path%3Atools&type=Code)

### 22. map.update()

语法：```map.update(&key, &val)```

将第二个参数中的值与键关联，覆盖任何先前的值。

示例："[搜索/examples](https://github.com/iovisor/bcc/search?q=update+path%3Aexamples&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=update+path%3Atools&type=Code)

### 23. map.insert()

语法: ```map.insert(&key, &val)```

将第二个参数中的值与键相关联，仅在之前没有值的情况下。

现场示例:
[搜索/examples](https://github.com/iovisor/bcc/search?q=insert+path%3Aexamples&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=insert+path%3Atools&type=Code)

### 24. map.increment()

语法: ```map.increment(key[, increment_amount])```

通过 `increment_amount`（默认为1）增加键的值。用于柱状图。

```map.increment()```不是原子操作。在并发情况下，如果要获得更准确的结果，请使用 ```map.atomic_increment()``` 而不是 ```map.increment()```。```map.increment()``` 和 ```map.atomic_increment()``` 的开销相似。

注意. 当使用 ```map.atomic_increment()``` 操作类型为 ```BPF_MAP_TYPE_HASH``` 的 BPF map 时，如果指定的键不存在，则 ```map.atomic_increment()``` 无法保证操作的原子性。

现场示例:
[搜索/examples](https://github.com/iovisor/bcc/search?q=increment+path%3Aexamples&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=increment+path%3Atools&type=Code)

### 25. map.get_stackid()

语法: ```int map.get_stackid(void *ctx, u64 flags)```

这会遍历在 ```ctx``` 中找到的 struct pt_regs 中的堆栈，将其保存在堆栈跟踪 map 中，并返回一个唯一的堆栈跟踪 ID。

现场示例:
[搜索/examples](https://github.com/iovisor/bcc/search?q=get_stackid+path%3Aexamples&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=get_stackid+path%3Atools&type=Code)

### 26. map.perf_read()

语法: ```u64 map.perf_read(u32 cpu)```

现场示例:""[搜索/tests](https://github.com/iovisor/bcc/search?q=perf_read+path%3Atests&type=Code)

### 27. map.call()

语法：```void map.call(void *ctx, int index)```

这将调用```bpf_tail_call()```来尾调用[BPF_PROG_ARRAY](#10-bpf_prog_array)中指向```index```入口的bpf程序。尾调用与普通调用不同。它在跳转到另一个bpf程序后重用当前的栈帧，并且不会返回。如果```index```入口为空，它将不会跳转到任何地方，程序的执行将会继续进行。

例如：

```C
BPF_PROG_ARRAY(prog_array, 10);

int tail_call(void *ctx) {
    bpf_trace_printk("尾调用\n");
    return 0;
}

int do_tail_call(void *ctx) {
    bpf_trace_printk("原始的程序\n");
    prog_array.call(ctx, 2);
    return 0;
}
```

```Python
b = BPF(src_file="example.c")
tail_fn = b.load_func("tail_call", BPF.KPROBE)
prog_array = b.get_table("prog_array")
prog_array[c_int(2)] = c_int(tail_fn.fd)
b.attach_kprobe(event="some_kprobe_event", fn_name="do_tail_call")
```

这将```tail_call()```分配给```prog_array[2]```。在```do_tail_call()```的最后，```prog_array.call(ctx, 2)```尾调用```tail_call()```并执行它。

**注意：**为了防止无限循环，尾调用的最大数量是32（[```MAX_TAIL_CALL_CNT```](https://github.com/torvalds/linux/search?l=C&q=MAX_TAIL_CALL_CNT+path%3Ainclude%2Flinux&type=Code)）。

在现场示例中：
[搜索/examples](https://github.com/iovisor/bcc/search?l=C&q=call+path%3Aexamples&type=Code),
[搜索/tests](https://github.com/iovisor/bcc/search?l=C&q=call+path%3Atests&type=Code)

### 28. map.redirect_map()

语法：```int map.redirect_map(int index, int flags)```".这将根据 ```index``` 条目重定向传入的数据包。如果映射是 [BPF_DEVMAP](#11-bpf_devmap)，数据包将被发送到该条目指向的网络接口的传输队列。如果映射是 [BPF_CPUMAP](#12-bpf_cpumap)，数据包将被发送到```index``` CPU的环形缓冲区，并稍后由CPU处理。如果映射是 [BPF_XSKMAP](#13-bpf_xskmap)，数据包将被发送到连接到队列的 AF_XDP 套接字。

如果数据包成功被重定向，该函数将返回 XDP_REDIRECT。否则，将返回 XDP_ABORTED 以丢弃该数据包。

例如：

```C
BPF_DEVMAP(devmap, 1);

int redirect_example(struct xdp_md *ctx) {
    return devmap.redirect_map(0, 0);
}
int xdp_dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}
```

```Python
ip = pyroute2.IPRoute()
idx = ip.link_lookup(ifname="eth1")[0]

b = bcc.BPF(src_file="example.c")

devmap = b.get_table("devmap")
devmap[c_uint32(0)] = c_int(idx)

in_fn = b.load_func("redirect_example", BPF.XDP)
out_fn = b.load_func("xdp_dummy", BPF.XDP)
b.attach_xdp("eth0", in_fn, 0)
b.attach_xdp("eth1", out_fn, 0)
```

示例位置：
[搜索 /examples](https://github.com/iovisor/bcc/search?l=C&q=redirect_map+path%3Aexamples&type=Code),

### 29. map.push()

语法：```int map.push(&val, int flags)```

将元素推入堆栈或队列表。将 BPF_EXIST 作为标志传递会导致队列或堆栈在已满时丢弃最旧的元素。成功返回0，失败返回负错误值。

示例位置：
[搜索 /tests](https://github.com/iovisor/bcc/search?q=push+path%3Atests&type=Code),

### 30. map.pop()

语法：```int map.pop(&val)```

从堆栈或队列表中弹出一个元素。```*val```被填充为结果。与查看不同，弹出操作会移除该元素。成功返回0，失败返回负错误值。

示例位置：
[搜索 /tests](https://github.com/iovisor/bcc/search?q=pop+path%3Atests&type=Code),

### 31. map.peek()

语法：```int map.peek(&val)```查看堆栈或队列表头的元素。```*val```将被结果填充。
与弹出不同，查看不会删除元素。
成功返回0，失败返回负错误。

实例：
[搜索/tests](https://github.com/iovisor/bcc/search?q=peek+path%3Atests&type=Code)

### 32. map.sock_hash_update()

语法：```int map.sock_hash_update(struct bpf_sock_ops *skops, &key, int flags)```

向sockhash映射添加条目或更新条目。skops用作与键相关联的条目的新值。flags为以下之一：

```sh
BPF_NOEXIST：映射中不得存在key的条目。
BPF_EXIST：映射中必须已存在key的条目。
BPF_ANY：对于key的条目是否存在，没有条件。
```

如果映射具有eBPF程序（解析器和判决器），则这些程序将被添加的套接字继承。如果套接字已经附加到eBPF程序，则会出错。

成功返回0，失败返回负错误。

实例：
[搜索/tests](https://github.com/iovisor/bcc/search?q=sock_hash_update+path%3Atests&type=Code)

### 33. map.msg_redirect_hash()

语法：```int map.msg_redirect_hash(struct sk_msg_buff *msg, void*key, u64 flags)```

该辅助程序用于在套接字级别实施策略的程序中。如果消息msg被允许通过（即判决eBPF程序返回SK_PASS），则使用哈希键将其重定向到映射引用的套接字（类型为BPF_MAP_TYPE_SOCKHASH）。可以使用入站和出站接口进行重定向。标志中的BPF_F_INGRESS值用于区分（如果存在该标志，则选择入站路径，否则选择出站路径）。目前，这是唯一支持的标志。

成功返回SK_PASS，发生错误返回SK_DROP。

实例：
[搜索/tests](https://github.com/iovisor/bcc/search?q=msg_redirect_hash+path%3Atests&type=Code)

### 34. map.sk_redirect_hash()

语法：```int map.sk_redirect_hash(struct sk_buff *skb, void*key, u64 flags)```".This helper is used in programs implementing policies at the skb socket level.
If the sk_buff skb is allowed to pass (i.e. if the verdict eBPF program returns SK_PASS), redirect it to the socket referenced by map (of type BPF_MAP_TYPE_SOCKHASH) using hash key.
Both ingress and egress interfaces can be used for redirection.
The BPF_F_INGRESS value in flags is used to make the distinction (ingress path is selected if the flag is present, egress otherwise).
This is the only flag supported for now.

Return SK_PASS on success, or SK_DROP on error.

Examples in situ:
\[搜索/tests\]\(<https://github.com/iovisor/bcc/search?q=sk_redirect_hash+path%3Atests&type=Code\>),

## 许可证

Depending on which \[BPF helpers\]\(kernel-versions.md#helpers\) are used, a GPL-compatible license is required.

The special BCC macro `BPF_LICENSE` specifies the license of the BPF program.
You can set the license as a comment in your source code, but the kernel has a special interface to specify it programmatically.
If you need to use GPL-only helpers, it is recommended to specify the macro in your C code so that the kernel can understand it:

```C
// SPDX-License-Identifier: GPL-2.0+
#define BPF_LICENSE GPL
```

Otherwise, the kernel may reject loading your program (see the \[错误描述\](#2-cannot-call-gpl-only-function-from-proprietary-program) below).
Note that it supports multiple words and quotes are not necessary:

```C
// SPDX-License-Identifier: GPL-2.0+ OR BSD-2-Clause
#define BPF_LICENSE Dual BSD/GPL
```

Check the \[BPF helpers reference\]\(kernel-versions.md#helpers\) to see which helpers are GPL-only and what the kernel understands as GPL-compatible.

**If the macro is not specified, BCC will automatically define the license of the program as GPL.**

## Rewriter

一个重写器的工作是使用内核辅助程序将隐式内存访问转换为显式内存访问。最近的内核引入了一个配置选项ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE，该选项将被设置为使用用户地址空间和内核地址空间不重叠的体系结构。x86和arm设置了这个配置选项，而s390没有。如果没有设置ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE，bpf旧帮助函数`bpf_probe_read()`将不可用。一些现有的用户可能有隐式内存访问来访问用户内存，所以使用`bpf_probe_read_kernel()`会导致他们的应用程序失败。因此，对于非s390，重写器将对这些隐式内存访问使用`bpf_probe_read()`。对于s390，默认使用`bpf_probe_read_kernel()`，用户在访问用户内存时应显式使用`bpf_probe_read_user()`

# bcc Python

## 初始化

构造函数。

### 1. BPF

语法: ```BPF({text=BPF_program | src_file=filename} [, usdt_contexts=[USDT_object, ...]] [, cflags=[arg1, ...]] [, debug=int])```

创建一个BPF对象。这是定义BPF程序并与其输出交互的主要对象。

必须提供`text`或`src_file`之一，不能两者都提供。

`cflags`指定要传递给编译器的额外参数，例如`-DMACRO_NAME=value`或`-I/include/path`。参数以数组形式传递，每个元素为一个额外的参数。注意，字符串不会按空格拆分，所以每个参数必须是数组的不同元素，例如`["-include", "header.h"]`。

`debug`标志控制调试输出，可以使用或运算:

- `DEBUG_LLVM_IR = 0x1` 编译后的LLVM IR
- `DEBUG_BPF = 0x2` 加载的BPF字节码和分支时的寄存器状态
- `DEBUG_PREPROCESSOR = 0x4` 预处理器的结果
- `DEBUG_SOURCE = 0x8` 嵌入源码的ASM指令
- `DEBUG_BPF_REGISTER_STATE = 0x10` 所有指令的寄存器状态，额外打印DEBUG_BPF的信息
- `DEBUG_BTF = 0x20` 打印来自`libbpf`库的消息。

示例:

```Python"# 定义整个BPF程序在一行中:
BPF(text='int do_trace(void *ctx) { bpf_trace_printk("命中！\\n"); return 0; }');

# 定义程序为一个变量:
prog = """
int hello(void *ctx) {
    bpf_trace_printk("你好，世界！\\n");
    return 0;
}
"""
b = BPF(text=prog)

# 源文件:
b = BPF(src_file = "vfsreadlat.c")

# 包括一个USDT对象:
u = USDT(pid=int(pid))
[...]
b = BPF(text=bpf_text, usdt_contexts=[u])

# 添加包含路径:
u = BPF(text=prog, cflags=["-I/path/to/include"])


在原地的示例:
[搜索 /examples](https://github.com/iovisor/bcc/search?q=BPF+path%3Aexamples+language%3Apython&type=Code),
[搜索 /tools](https://github.com/iovisor/bcc/search?q=BPF+path%3Atools+language%3Apython&type=Code)

### 2. USDT

语法: ```USDT({pid=pid | path=path})```

创建一个对象以检测用户静态定义的跟踪(USDT)探针。它的主要方法是```enable_probe()```。

参数:

- pid: 附加到该进程ID。
- path: 从此二进制路径检测USDT探针。

示例:

```Python
# 包括一个USDT对象:
u = USDT(pid=int(pid))
[...]
b = BPF(text=bpf_text, usdt_contexts=[u])
```

在原地的示例:
[搜索 /examples](https://github.com/iovisor/bcc/search?q=USDT+path%3Aexamples+language%3Apython&type=Code),
[搜索 /tools](https://github.com/iovisor/bcc/search?q=USDT+path%3Atools+language%3Apython&type=Code)

## 事件

### 1. attach_kprobe()

语法: ```BPF.attach_kprobe(event="event", fn_name="name")```

通过内核动态跟踪函数入口，来检测内核函数```event()```，并将我们的C定义的函数```name()```附加到每次调用内核函数时被调用。

例如:

```Python
b.attach_kprobe(event="sys_clone", fn_name="do_trace")
```

这将检测内核```sys_clone()```函数，并在每次调用时运行我们定义的BPF函数```do_trace()```。

您可以多次调用attach_kprobe()，并将您的BPF函数附加到多个内核函数上。您也可以多次调用attach_kprobe()函数将多个BPF函数附加到同一个内核函数。

有关如何从BPF中提取参数的详细信息，请参阅前面的kprobes部分。

示例：
[查找/examples](https://github.com/iovisor/bcc/search?q=attach_kprobe+path%3Aexamples+language%3Apython&type=Code),
[查找/tools](https://github.com/iovisor/bcc/search?q=attach_kprobe+path%3Atools+language%3Apython&type=Code)

### 2. attach_kretprobe()

语法：BPF.attach_kretprobe(event="事件", fn_name="名称" [, maxactive=int])

使用内核动态跟踪函数返回来检测内核函数event()的返回，并附加我们定义的C函数name()在内核函数返回时调用。

例如：

```Python
b.attach_kretprobe(event="vfs_read", fn_name="do_return")
```

这将检测内核的vfs_read()函数，每次调用该函数时都会执行我们定义的BPF函数do_return()。

您可以多次调用attach_kretprobe()函数，并将您的BPF函数附加到多个内核函数的返回值。
您也可以多次调用attach_kretprobe()函数将多个BPF函数附加到同一个内核函数的返回值。

当在内核函数上安装kretprobe时，它可以捕获的并行调用次数存在限制。您可以使用maxactive参数更改该限制。有关默认值，请参阅kprobes文档。

有关如何从BPF中提取返回值的详细信息，请参阅前面的kretprobes部分。

示例：
[查找/examples](https://github.com/iovisor/bcc/search?q=attach_kretprobe+path%3Aexamples+language%3Apython&type=Code),
[查找/tools](https://github.com/iovisor/bcc/search?q=attach_kretprobe+path%3Atools+language%3Apython&type=Code)

### 3. attach_tracepoint()

语法：BPF.attach_tracepoint(tp="追踪点", fn_name="名称")

检测由tracepoint描述的内核追踪点，并在命中时运行BPF函数name()。这是一种显式方式来操控 tracepoints。在前面的 tracepoints 部分讲解过的 ```TRACEPOINT_PROBE``` 语法是另一种方法，其优点是自动声明一个包含 tracepoint 参数的 ```args``` 结构体。在使用 ```attach_tracepoint()``` 时，tracepoint 参数需要在 BPF 程序中声明。

例如：

```Python
# 定义 BPF 程序
bpf_text = """
#include <uapi/linux/ptrace.h>

struct urandom_read_args {
    // 来自 /sys/kernel/debug/tracing/events/random/urandom_read/format
    u64 __unused__;
    u32 got_bits;
    u32 pool_left;
    u32 input_left;
};

int printarg(struct urandom_read_args *args) {
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
};
"""

# 加载 BPF 程序
b = BPF(text=bpf_text)
b.attach_tracepoint("random:urandom_read", "printarg")
```

注意，```printarg()``` 的第一个参数现在是我们定义的结构体。

代码示例：
[code](https://github.com/iovisor/bcc/blob/a4159da8c4ea8a05a3c6e402451f530d6e5a8b41/examples/tracing/urandomread-explicit.py#L41),
[search /examples](https://github.com/iovisor/bcc/search?q=attach_tracepoint+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=attach_tracepoint+path%3Atools+language%3Apython&type=Code)

### 4. attach_uprobe()

语法：```BPF.attach_uprobe(name="location", sym="symbol", fn_name="name" [, sym_off=int])```, ```BPF.attach_uprobe(name="location", sym_re="regex", fn_name="name")```, ```BPF.attach_uprobe(name="location", addr=int, fn_name="name")```

用于操控位于 ```location``` 中的库或二进制文件中的用户级别函数 ```symbol()```，使用用户级别动态跟踪该函数的入口，并将我们定义的 C 函数 ```name()``` 附加为在用户级别函数被调用时调用的函数。如果给定了 ```sym_off```，则该函数将附加到符号的偏移量上。真实的地址```addr```可以替代```sym```，在这种情况下，```sym```必须设置为其默认值。如果文件是非PIE可执行文件，则```addr```必须是虚拟地址，否则它必须是相对于文件加载地址的偏移量。

可以在```sym_re```中提供普通表达式来代替符号名称。然后，uprobes将附加到与提供的正则表达式匹配的符号。

在名字参数中可以给出库名而不带lib前缀，或者给出完整路径（/usr/lib/...）。只能通过完整路径（/bin/sh）给出二进制文件。

例如:

```Python
b.attach_uprobe(name="c", sym="strlen", fn_name="count")
```

这将在libc中对```strlen()```函数进行插装，并在调用该函数时调用我们的BPF函数```count()```。请注意，在```libc```中的```libc```中的"lib"是不必要的。

其他例子:

```Python
b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="do_entry")
b.attach_uprobe(name="/usr/bin/python", sym="main", fn_name="do_main")
```

您可以多次调用attach_uprobe()，并将BPF函数附加到多个用户级函数。

有关如何从BPF工具获取参数的详细信息，请参见上一节uprobes。

原址示例：
[search /examples](https://github.com/iovisor/bcc/search?q=attach_uprobe+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=attach_uprobe+path%3Atools+language%3Apython&type=Code)

### 5. attach_uretprobe()

语法: ```BPF.attach_uretprobe(name="location", sym="symbol", fn_name="name")```

使用用户级动态跟踪从名为```location```的库或二进制文件中的用户级函数```symbol()```返回值的方式仪器化，并将我们定义的C函数```name()```附加到用户级函数返回时调用。

例如:

```Python
b.attach_uretprobe(name="c", sym="strlen", fn_name="count")
```。这将使用libc库对```strlen()```函数进行插装，并在其返回时调用我们的BPF函数```count()```。

其他示例：

```Python
b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="do_return")
b.attach_uretprobe(name="/usr/bin/python", sym="main", fn_name="do_main")
```

您可以多次调用attach_uretprobe()，并将您的BPF函数附加到多个用户级函数上。

有关如何对BPF返回值进行插装的详细信息，请参阅前面的uretprobes部分。

内部示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=attach_uretprobe+path%3Aexamples+language%3Apython&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=attach_uretprobe+path%3Atools+language%3Apython&type=Code)

### 6. USDT.enable_probe()

语法：```USDT.enable_probe(probe=probe, fn_name=name)```

将BPF C函数```name```附加到USDT探针```probe```。

示例：

```Python
# 根据给定的PID启用USDT探针
u = USDT(pid=int(pid))
u.enable_probe(probe="http__server__request", fn_name="do_trace")
```

要检查您的二进制文件是否具有USDT探针以及它们的详细信息，可以运行```readelf -n binary```并检查stap调试部分。

内部示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=enable_probe+path%3Aexamples+language%3Apython&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=enable_probe+path%3Atools+language%3Apython&type=Code)

### 7. attach_raw_tracepoint()

语法：```BPF.attach_raw_tracepoint(tp="tracepoint", fn_name="name")```

对由```tracepoint```（仅```event```，无```category```）描述的内核原始跟踪点进行插装，并在命中时运行BPF函数```name()```。

这是一种明确的插装跟踪点的方法。早期原始跟踪点部分介绍的```RAW_TRACEPOINT_PROBE```语法是一种替代方法。

例如：

```Python
b.attach_raw_tracepoint("sched_switch", "do_trace")
```

内部示例："."[搜索 /工具](https://github.com/iovisor/bcc/search?q=attach_raw_tracepoint+path%3Atools+language%3Apython&type=Code)

### 8. attach_raw_socket()

语法: ```BPF.attach_raw_socket(fn, dev)```

将一个BPF函数附加到指定的网络接口。

```fn``` 必须是 ```BPF.function``` 类型，并且 bpf_prog 类型需要是 ```BPF_PROG_TYPE_SOCKET_FILTER```  (```fn=BPF.load_func(func_name, BPF.SOCKET_FILTER)```)

```fn.sock``` 是一个非阻塞原始套接字，已经创建并绑定到 ```dev```。

所有处理 ```dev``` 的网络数据包都会在经过 bpf_prog 处理后，被复制到 ```fn.sock``` 的 ```recv-q``` 中。可以使用 ```recv/recvfrom/recvmsg``` 来从 ```fn.sock``` 接收数据包。需要注意的是，如果在 ```recv-q``` 满了之后没有及时读取，复制的数据包将会被丢弃。

可以使用这个功能来像 ```tcpdump``` 一样捕获网络数据包。

可以使用```ss --bpf --packet -p```来观察 ```fn.sock```。

示例:

```Python
BPF.attach_raw_socket(bpf_func, ifname)
```

示例位置:
[搜索 /示例](https://github.com/iovisor/bcc/search?q=attach_raw_socket+path%3Aexamples+language%3Apython&type=Code)

### 9. attach_xdp()

语法: ```BPF.attach_xdp(dev="device", fn=b.load_func("fn_name",BPF.XDP), flags)```

改装由 ```dev``` 描述的网络驱动程序，然后接收数据包，并使用标志运行 BPF 函数 ```fn_name()```。

以下是可选的标志列表。

```Python
# from xdp_flags uapi/linux/if_link.h
XDP_FLAGS_UPDATE_IF_NOEXIST = (1 << 0)
XDP_FLAGS_SKB_MODE = (1 << 1)
XDP_FLAGS_DRV_MODE = (1 << 2)
XDP_FLAGS_HW_MODE = (1 << 3)
XDP_FLAGS_REPLACE = (1 << 4)
```

您可以像这样使用标志: ```BPF.attach_xdp(dev="device", fn=b.load_func("fn_name",BPF.XDP), flags=BPF.XDP_FLAGS_UPDATE_IF_NOEXIST)```

标志的默认值为0。这意味着如果没有带有 `device` 的xdp程序，fn将在该设备上运行。如果有一个正在运行的xdp程序与设备关联，旧程序将被新的fn程序替换。".当前，bcc不支持XDP_FLAGS_REPLACE标志。以下是其他标志的描述。

#### 1. XDP_FLAGS_UPDATE_IF_NOEXIST

如果已经将XDP程序附加到指定的驱动程序上，再次附加XDP程序将失败。

#### 2. XDP_FLAGS_SKB_MODE

驱动程序不支持XDP，但内核模拟支持它。
XDP程序可以工作，但没有真正的性能优势，因为数据包无论如何都会传递给内核堆栈，然后模拟XDP - 这通常适用于家用电脑，笔记本电脑和虚拟化硬件所使用的通用网络驱动程序。

#### 3. XDP_FLAGS_DRV_MODE

驱动程序具有XDP支持，并且可以将数据包直接传递给XDP，无需内核堆栈交互 - 少数驱动程序可以支持此功能，通常用于企业级硬件。

#### 4. XDP_FLAGS_HW_MODE

XDP可以直接在NIC上加载和执行 - 只有少数NIC支持这一功能。

例如：

```Python
b.attach_xdp(dev="ens1", fn=b.load_func("do_xdp", BPF.XDP))
```

这将为网络设备```ens1```安装工具，并在接收数据包时运行我们定义的BPF函数```do_xdp()```。

不要忘记在最后调用```b.remove_xdp("ens1")```！

示例：
[搜索/examples](https://github.com/iovisor/bcc/search?q=attach_xdp+path%3Aexamples+language%3Apython&type=Code),
[搜索/tools](https://github.com/iovisor/bcc/search?q=attach_xdp+path%3Atools+language%3Apython&type=Code)

### 10. attach_func()

语法：```BPF.attach_func(fn, attachable_fd, attach_type [, flags])```

将指定类型的BPF函数附加到特定的```attachable_fd```上。如果```attach_type```是```BPF_FLOW_DISSECTOR```，则预期该函数将附加到当前的网络命名空间，并且```attachable_fd```必须为0。

例如：

```Python
b.attach_func(fn, cgroup_fd, BPFAttachType.CGROUP_SOCK_OPS)
b.attach_func(fn, map_fd, BPFAttachType.SK_MSG_VERDICT)
```注意。当附加到“全局”钩子（xdp、tc、lwt、cgroup）时。如果程序终止后不再需要“BPF 函数”，请确保在程序退出时调用 `detach_func`。

示例中的内部代码：

[search /examples](https://github.com/iovisor/bcc/search?q=attach_func+path%3Aexamples+language%3Apython&type=Code),

### 11. detach_func()

语法：```BPF.detach_func(fn, attachable_fd, attach_type)```

断开指定类型的 BPF 函数。

例如：

```Python
b.detach_func(fn, cgroup_fd, BPFAttachType.CGROUP_SOCK_OPS)  // 断开 cgroup_fd 上的 fn 函数
b.detach_func(fn, map_fd, BPFAttachType.SK_MSG_VERDICT)  // 断开 map_fd 上的 fn 函数
```

示例中的内部代码：

[search /examples](https://github.com/iovisor/bcc/search?q=detach_func+path%3Aexamples+language%3Apython&type=Code),

### 12. detach_kprobe()

语法：```BPF.detach_kprobe(event="event", fn_name="name")```

断开指定事件的 kprobe 处理函数。

例如：

```Python
b.detach_kprobe(event="__page_cache_alloc", fn_name="trace_func_entry")  // 断开 "__page_cache_alloc" 事件上的 "trace_func_entry" 函数
```

### 13. detach_kretprobe()

语法：```BPF.detach_kretprobe(event="event", fn_name="name")```

断开指定事件的 kretprobe 处理函数。

例如：

```Python
b.detach_kretprobe(event="__page_cache_alloc", fn_name="trace_func_return")  // 断开 "__page_cache_alloc" 事件上的 "trace_func_return" 函数
```

## 调试输出

### 1. trace_print()

语法：```BPF.trace_print(fmt="fields")```

该方法持续读取全局共享的 `/sys/kernel/debug/tracing/trace_pipe` 文件并打印其内容。可以通过 BPF 和 `bpf_trace_printk()` 函数将数据写入该文件，但该方法存在限制，包括缺乏并发跟踪支持。更推荐使用前面介绍的 BPF_PERF_OUTPUT 机制。

参数：

- ```fmt```: 可选，可以包含字段格式化字符串，默认为 ```None```。

示例：

```Python
# 将 trace_pipe 输出原样打印：
b.trace_print()

# 打印 PID 和消息：
b.trace_print(fmt="{1} {5}")
```

示例中的内部代码：
[search /examples](https://github.com/iovisor/bcc/search?q=trace_print+path%3Aexamples+language%3Apython&type=Code)。"[搜索 /工具](https://github.com/iovisor/bcc/search?q=trace_print+path%3Atools+language%3Apython&type=Code)

### 2. trace_fields()

语法: ```BPF.trace_fields(nonblocking=False)```

该方法从全局共享的 /sys/kernel/debug/tracing/trace_pipe 文件中读取一行，并将其作为字段返回。该文件可以通过 BPF 和 bpf_trace_printk() 函数进行写入，但该方法有一些限制，包括缺乏并发追踪支持。我们更推荐使用之前介绍的 BPF_PERF_OUTPUT 机制。

参数:

- ```nonblocking```: 可选参数，默认为 ```False```。当设置为 ```True``` 时，程序将不会阻塞等待输入。

示例:

```Python
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    [...]
```

内联示例:
[搜索 /示例](https://github.com/iovisor/bcc/search?q=trace_fields+path%3Aexamples+language%3Apython&type=Code),
[搜索 /工具](https://github.com/iovisor/bcc/search?q=trace_fields+path%3Atools+language%3Apython&type=Code)

## 输出 API

BPF 程序的正常输出有两种方式:

- 每个事件: 使用 PERF_EVENT_OUTPUT、open_perf_buffer() 和 perf_buffer_poll()。
- map 汇总: 使用 items() 或 print_log2_hist()，在 Maps 部分有介绍。

### 1. perf_buffer_poll()

语法: ```BPF.perf_buffer_poll(timeout=T)```

该方法从所有打开的 perf 环形缓冲区中轮询，并对每个条目调用在调用 open_perf_buffer 时提供的回调函数。

timeout 参数是可选的，并以毫秒为单位计量。如果未提供，则轮询将无限期进行。

示例:

```Python
# 循环调用带有回调函数 print_event 的 open_perf_buffer
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
```

内联示例:
[代码](https://github.com/iovisor/bcc/blob/v0.9.0/examples/tracing/hello_perf_output.py#L55)"."[搜索 /示例](https://github.com/iovisor/bcc/search?q=perf_buffer_poll+path%3Aexamples+language%3Apython&type=Code),
[搜索 /工具](https://github.com/iovisor/bcc/search?q=perf_buffer_poll+path%3Atools+language%3Apython&type=Code)

### 2. ring_buffer_poll()

语法: ```BPF.ring_buffer_poll(timeout=T)```

这个方法从所有已打开的ringbuf环形缓冲区中轮询数据，对每个条目调用在调用open_ring_buffer时提供的回调函数。

timeout参数是可选的，以毫秒为单位测量。如果没有指定，轮询将持续到没有更多的数据或回调函数返回负值。

示例:

```Python
# 循环使用回调函数print_event
b["events"].open_ring_buffer(print_event)
while 1:
    try:
        b.ring_buffer_poll(30)
    except KeyboardInterrupt:
        exit();
```

示例：
[搜索 /示例](https://github.com/iovisor/bcc/search?q=ring_buffer_poll+path%3Aexamples+language%3Apython&type=Code),

### 3. ring_buffer_consume()

语法: ```BPF.ring_buffer_consume()```

这个方法从所有已打开的ringbuf环形缓冲区中消费数据，对每个条目调用在调用open_ring_buffer时提供的回调函数。

与```ring_buffer_poll```不同，这个方法在尝试消费数据之前**不会轮询数据**。这样可以减少延迟，但会增加CPU消耗。如果不确定使用哪种方法，建议使用```ring_buffer_poll```。

示例:

```Python
# 循环使用回调函数print_event
b["events"].open_ring_buffer(print_event)
while 1:
    try:
        b.ring_buffer_consume()
    except KeyboardInterrupt:
        exit();
```

示例：
[搜索 /示例](https://github.com/iovisor/bcc/search?q=ring_buffer_consume+path%3Aexamples+language%3Apython&type=Code),

## Map APIs

Maps是BPF数据存储器，在bcc中用于实现表、哈希和直方图等更高层次的对象。

### 1. get_table()

语法: ```BPF.get_table(name)```".返回一个table对象。由于可以将表格作为BPF项进行读取，因此此功能不再使用。例如：`BPF[name]`。

示例：

```Python
counts = b.get_table("counts")

counts = b["counts"]
```

这两者是等价的。

### 2. open_perf_buffer()

语法：`table.open_perf_buffers(callback, page_cnt=N, lost_cb=None)`

此操作基于BPF中定义的表格（`BPF_PERF_OUTPUT()`），将回调Python函数`callback`关联到在perf环形缓冲区中有数据可用时调用。这是从内核传输每个事件的数据到用户空间的推荐机制的一部分。可以通过`page_cnt`参数指定perf环形缓冲区的大小，默认为8个页面，必须是页数的2的幂次方。如果回调函数不能快速处理数据，则可能丢失某些提交的数据。`lost_cb`用于记录/监视丢失的计数。如果`lost_cb`是默认的`None`值，则只会打印一行消息到`stderr`。

示例：

```Python
# 处理事件
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    [...]

# 循环通过回调函数打印事件
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
```

请注意，传输的数据结构需要在BPF程序中以C方式声明。例如：

```C
// 在C中定义输出数据结构
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);
[...]
```

在Python中，您可以让bcc自动生成C声明中的数据结构（建议方法）：

```Python
def print_event(cpu, data, size):
    event = b["events"].event(data)
[...]
```

或者手动定义：

```Python
# 在Python中定义输出数据结构
TASK_COMM_LEN = 16    # linux/sched.h
class Data(ct.Structure):
    _fields_ = [("pid", ct.c_ulonglong),
                ("ts", ct.c_ulonglong),
                ("comm", ct.c_char * TASK_COMM_LEN)]"。def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
[...]


在此处的示例中：
[code](https://github.com/iovisor/bcc/blob/v0.9.0/examples/tracing/hello_perf_output.py#L52),
[search /examples](https://github.com/iovisor/bcc/search?q=open_perf_buffer+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=open_perf_buffer+path%3Atools+language%3Apython&type=Code)

### 3. items()

语法: ```table.items()```

返回一个表中的键数组。它可以与BPF_HASH映射一起使用，从而获取并迭代键。

示例:

```Python
# 打印输出
print("%10s %s" % ("COUNT", "STRING"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    print("%10d \"%s\"" % (v.value, k.c.encode('string-escape')))
```

此示例还使用```sorted()```方法按值排序。

在此处的示例中：
[search /examples](https://github.com/iovisor/bcc/search?q=items+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=items+path%3Atools+language%3Apython&type=Code)。

### 4. values()

语法: ```table.values()```

返回一个表中的值数组。

### 5. clear()

语法: ```table.clear()```

清除表：删除所有条目。

示例:

```Python
# 每秒打印映射摘要：
while True:
    time.sleep(1)
    print("%-8s\n" % time.strftime("%H:%M:%S"), end="")
    dist.print_log2_hist(sym + " return:")
    dist.clear()
```

在此处的示例中:
[search /examples](https://github.com/iovisor/bcc/search?q=clear+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=clear+path%3Atools+language%3Apython&type=Code)。

### 6. items_lookup_and_delete_batch()

语法: ```table.items_lookup_and_delete_batch()```。返回一个使用一次BPF系统调用在表中的键的数组。可以与BPF_HASH映射一起使用以获取和迭代键。还会清除表：删除所有条目。
您应该使用table.items_lookup_and_delete_batch()而不是table.items()后跟table.clear()。它需要内核v5.6。

示例:

```Python
# 每秒打印调用率:
print("%9s-%9s-%8s-%9s" % ("PID", "COMM", "fname", "counter"))
while True:
    for k, v in sorted(b['map'].items_lookup_and_delete_batch(), key=lambda kv: (kv[0]).pid):
        print("%9s-%9s-%8s-%9d" % (k.pid, k.comm, k.fname, v.counter))
    sleep(1)
```

### 7. items_lookup_batch()

语法: ```table.items_lookup_batch()```

使用一次BPF系统调用返回表中的键数组。可以与BPF_HASH映射一起使用以获取和迭代键。
您应该使用table.items_lookup_batch()而不是table.items()。它需要内核v5.6。

示例:

```Python
# 打印映射的当前值:
print("%9s-%9s-%8s-%9s" % ("PID", "COMM", "fname", "counter"))
while True:
    for k, v in sorted(b['map'].items_lookup_batch(), key=lambda kv: (kv[0]).pid):
        print("%9s-%9s-%8s-%9d" % (k.pid, k.comm, k.fname, v.counter))
```

### 8. items_delete_batch()

语法: ```table.items_delete_batch(keys)```

当keys为None时，它会清除BPF_HASH映射的所有条目。它比table.clear()更有效，因为它只生成一个系统调用。您可以通过给出一个键数组来删除映射的一个子集。这些键及其关联值将被删除。它需要内核v5.6。

参数:

- keys是可选的，默认为None。

### 9. items_update_batch()

语法: ```table.items_update_batch(keys, values)```

使用新值更新所有提供的键。两个参数必须具有相同的长度并且在映射限制之内（在1到最大条目之间）。它需要内核v5.6。

参数:

- keys是要更新的键列表
- values是包含新值的列表。### 10. print_log2_hist()

语法: ```table.print_log2_hist(val_type="value", section_header="Bucket ptr", section_print_fn=None)```

以ASCII的形式打印一个表格作为log2直方图。该表必须以log2的形式存储，可使用BPF函数```bpf_log2l()```完成。

参数:

- val_type: 可选，列标题。
- section_header: 如果直方图有一个辅助键，多个表格将被打印，并且section_header可以用作每个表格的标题描述。
- section_print_fn: 如果section_print_fn不为None，则将传递给bucket值。

示例:

```Python
b = BPF(text="""
BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req)
{
 dist.increment(bpf_log2l(req->__data_len / 1024));
 return 0;
}
""")
[...]

b["dist"].print_log2_hist("kbytes")
```

输出:

```sh
     kbytes          : count     distribution
       0 -> 1        : 3        |                                      |
       2 -> 3        : 0        |                                      |
       4 -> 7        : 211      |**********                            |
       8 -> 15       : 0        |                                      |
      16 -> 31       : 0        |                                      |
      32 -> 63       : 0        |                                      |
      64 -> 127      : 1        |                                      |
     128 -> 255      : 800      |**************************************|
```

这个输出显示了一个多模式分布，最大模式是128->255 kbytes，计数为800。

这是一种高效的数据概括方法，因为概括是在内核中执行的，只有计数列被传递到用户空间。

实际示例:
[搜索 /examples](https://github.com/iovisor/bcc/search?q=print_log2_hist+path%3Aexamples+language%3Apython&type=Code),
[搜索 /tools](https://github.com/iovisor/bcc/search?q=print_log2_hist+path%3Atools+language%3Apython&type=Code)

### 11. print_linear_hist()".语法: ```table.print_linear_hist(val_type="value", section_header="Bucket ptr", section_print_fn=None)```

以ASCII字符形式打印一个线性直方图的表格。此功能旨在可视化小的整数范围，例如0到100。

参数:

- val_type: 可选，列标题。
- section_header: 如果直方图有一个二级键，则会打印多个表格，并且section_header可以用作每个表格的头部描述。
- section_print_fn: 如果section_print_fn不为None，则会将bucket的值传递给它。

示例:

```Python
b = BPF(text="""
BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req)
{
 dist.increment(req->__data_len / 1024);
 return 0;
}
""")
[...]

b["dist"].print_linear_hist("kbytes")
```

输出:

```sh
     kbytes        : count     distribution
        0          : 3        |******                                  |
        1          : 0        |                                        |
        2          : 0        |                                        |
        3          : 0        |                                        |
        4          : 19       |****************************************|
        5          : 0        |                                        |
        6          : 0        |                                        |
        7          : 0        |                                        |
        8          : 4        |********                                |
        9          : 0        |                                        |
        10         : 0        |                                        |
        11         : 0        |                                        |
        12         : 0        |                                        |
        13         : 0        |                                        |
        14         : 0        |                                        |
        15         : 0        |                                        |。
```### 16         : 2        |****                                    |
[...]
```

这是一种高效的数据汇总方式，因为汇总是在内核中执行的，只有计数列中的值传递到用户空间。

现场示例:
[搜索 /examples](https://github.com/iovisor/bcc/search?q=print_linear_hist+path%3Aexamples+language%3Apython&type=Code),
[搜索 /tools](https://github.com/iovisor/bcc/search?q=print_linear_hist+path%3Atools+language%3Apython&type=Code)

### 12. open_ring_buffer()

语法: ```table.open_ring_buffer(callback, ctx=None)```

此操作用于在BPF中定义为BPF_RINGBUF_OUTPUT()的表，并将Python回调函数```callback```与ringbuf环形缓冲区中有可用数据时调用相连。这是从内核向用户空间传输每个事件数据的新（Linux 5.8+）推荐机制的一部分。不同于perf缓冲区，ringbuf大小在BPF程序中指定，作为```BPF_RINGBUF_OUTPUT```宏的一部分。如果回调函数处理数据不够快，可能会丢失一些提交的数据。在这种情况下，事件应该更频繁地进行轮询和/或增加环形缓冲区的大小。

示例:

```Python
# 处理事件
def print_event(ctx, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    [...]

# 循环并使用print_event回调函数
b["events"].open_ring_buffer(print_event)
while 1:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()
```

请注意，在BPF程序中，传输的数据结构需要在C中声明。例如:

```C
// 在C中定义输出数据结构
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_RINGBUF_OUTPUT(events, 8);
[...]
```

在Python中，您可以让bcc自动从C的声明中生成数据结构（推荐）:

```Python
def print_event(ctx, data, size):
    event = b["events"].event(data)
[...]
```

或者手动定义:

```Python".# 在Python中定义输出数据结构
TASK_COMM_LEN = 16    # linux/sched.h
class Data(ct.Structure):
    _fields_ = [("pid", ct.c_ulonglong),
                ("ts", ct.c_ulonglong),
                ("comm", ct.c_char * TASK_COMM_LEN)]

def print_event(ctx, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
[...]

```

在原地的示例:
[在/examples中搜索](https://github.com/iovisor/bcc/search?q=open_ring_buffer+path%3Aexamples+language%3Apython&type=Code),

### 13. push()

语法: ```table.push(leaf, flags=0)```

将元素推入堆栈或队列表。如果操作不成功，会引发异常。传递QueueStack.BPF_EXIST作为标志会使队列或堆栈丢弃最旧的元素，如果表已满。

在原地的示例:
[在/tests中搜索](https://github.com/iovisor/bcc/search?q=push+path%3Atests+language%3Apython&type=Code),

### 14. pop()

语法: ```leaf = table.pop()```

从堆栈或队列表中弹出一个元素。与```peek()```不同，```pop()```在返回元素之前会将其从表中移除。如果操作不成功，会引发KeyError异常。

在原地的示例:
[在/tests中搜索](https://github.com/iovisor/bcc/search?q=pop+path%3Atests+language%3Apython&type=Code),

### 15. peek()

语法: ```leaf = table.peek()```

查看堆栈或队列表头部的元素。与```pop()```不同，```peek()```不会将元素从表中移除。如果操作不成功，会引发异常。

在原地的示例:
[在/tests中搜索](https://github.com/iovisor/bcc/search?q=peek+path%3Atests+language%3Apython&type=Code),

## 辅助方法

一些由bcc提供的辅助方法。请注意，因为我们在Python中，我们可以导入任何Python库及其方法，包括例如argparse、collections、ctypes、datetime、re、socket、struct、subprocess、sys和time等库。

### 1. ksym()

语法: ```BPF.ksym(addr)```

将内核内存地址转换为内核函数名称，并返回该名称。

示例:

```Python"。
格式: 只返回转换后的内容，不包括原始文本。```markdown
print("内核函数：" + b.ksym(addr))
```

例子：
[搜索 /examples](https://github.com/iovisor/bcc/search?q=ksym+path%3Aexamples+language%3Apython&type=Code),
[搜索 /tools](https://github.com/iovisor/bcc/search?q=ksym+path%3Atools+language%3Apython&type=Code)

### 2. ksymname()

语法：```BPF.ksymname(name)```

将内核名称翻译为地址。这是ksym的反向过程。当函数名称未知时，返回-1。

例子：

```Python
print("内核地址：%x" % b.ksymname("vfs_read"))
```

例子：
[搜索 /examples](https://github.com/iovisor/bcc/search?q=ksymname+path%3Aexamples+language%3Apython&type=Code),
[搜索 /tools](https://github.com/iovisor/bcc/search?q=ksymname+path%3Atools+language%3Apython&type=Code)

### 3. sym()

语法：```BPF.sym(addr, pid, show_module=False, show_offset=False)```

将内存地址翻译为pid的函数名称，并返回。小于零的pid将访问内核符号缓存。`show_module`和`show_offset`参数控制是否显示函数所在的模块以及是否显示从符号开头的指令偏移量。这些额外参数的默认值为`False`。

例子：

```python
print("函数：" + b.sym(addr, pid))
```

例子：
[搜索 /examples](https://github.com/iovisor/bcc/search?q=sym+path%3Aexamples+language%3Apython&type=Code),
[搜索 /tools](https://github.com/iovisor/bcc/search?q=sym+path%3Atools+language%3Apython&type=Code)

### 4. num_open_kprobes()

语法：```BPF.num_open_kprobes()```

返回打开的k[ret]probe的数量。当使用event_re附加和分离探测点时，可以发挥作用。不包括perf_events读取器。

例子：

```python
b.attach_kprobe(event_re=pattern, fn_name="trace_count")
matched = b.num_open_kprobes()
if matched == 0:
    print("0个函数与\"%s\"匹配。程序退出。" % args.pattern)
    exit()
```

例子："[搜索 /示例](https://github.com/iovisor/bcc/search?q=num_open_kprobes+path%3Aexamples+language%3Apython&type=Code),
[搜索 /工具](https://github.com/iovisor/bcc/search?q=num_open_kprobes+path%3Atools+language%3Apython&type=Code)

### 5. get_syscall_fnname()

语法: ```BPF.get_syscall_fnname(name : str)```

返回系统调用的相应内核函数名。该辅助函数将尝试不同的前缀，并与系统调用名连接起来。请注意，返回值可能在不同版本的Linux内核中有所不同，有时会引起问题。 （见 [#2590](https://github.com/iovisor/bcc/issues/2590)）

示例:

```python
print("在内核中，%s 的函数名是 %s" % ("clone", b.get_syscall_fnname("clone")))
# sys_clone 或 __x64_sys_clone 或 ...
```

现场示例:
[搜索 /示例](https://github.com/iovisor/bcc/search?q=get_syscall_fnname+path%3Aexamples+language%3Apython&type=Code),
[搜索 /工具](https://github.com/iovisor/bcc/search?q=get_syscall_fnname+path%3Atools+language%3Apython&type=Code)

# BPF 错误

请参阅内核源码中的“Understanding eBPF verifier messages”部分，位于 Documentation/networking/filter.txt。

## 1. Invalid mem access

这可能是因为试图直接读取内存，而不是操作BPF堆栈上的内存。所有对内核内存的读取必须通过 bpf_probe_read_kernel() 传递，以将内核内存复制到BPF堆栈中，在一些简单关联的情况下，bcc 重写器可以自动完成。bpf_probe_read_kernel() 执行所有必要的检查。

示例:

```sh
bpf: Permission denied
0: (bf) r6 = r1
1: (79) r7 = *(u64 *)(r6 +80)
2: (85) call 14
3: (bf) r8 = r0
[...]
23: (69) r1 = *(u16 *)(r7 +16)
R7 invalid mem access 'inv'

Traceback (most recent call last):
  File "./tcpaccept", line 179, in <module>
    b = BPF(text=bpf_text)
  File "/usr/lib/python2.7/dist-packages/bcc/__init__.py", line 172, in __init__
    self._trace_autoload()".
/usr/lib/python2.7/dist-packages/bcc/__init__.py"，第 612 行，_trace_autoload 中：
    fn = self.load_func(func_name, BPF.KPROBE)
  文件 "/usr/lib/python2.7/dist-packages/bcc/__init__.py"，第 212 行，load_func 中：
    raise Exception("加载 BPF 程序 %s 失败" % func_name)
Exception: 加载 BPF 程序 kretprobe__inet_csk_accept 失败
```

## 2. 无法从专有程序调用 GPL-only 函数

当非 GPL BPF 程序调用 GPL-only 辅助函数时，会出现此错误。要修复此错误，请勿在专有 BPF 程序中使用 GPL-only 辅助函数，或者将 BPF 程序重新授权为 GPL-compatible 许可证。请查看哪些 [BPF helpers](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#helpers) 是 GPL-only 的，并且哪些许可证被视为 GPL-compatible。

示例，从专有程序（`#define BPF_LICENSE Proprietary`）调用 `bpf_get_stackid()`，一种 GPL-only 的 BPF helper：

```sh
bpf: 加载程序失败：无效参数
[...]
8: (85) 调用 bpf_get_stackid#27
无法从专有程序调用 GPL-only 函数
```

# 环境变量

## 1. 内核源代码目录

eBPF 程序编译需要内核源代码或已编译的内核头。如果你的内核源代码位于无法被 BCC 找到的非标准位置，可以通过将 `BCC_KERNEL_SOURCE` 设置为该路径的绝对路径来为 BCC 提供所需的位置信息。

## 2. 内核版本覆盖

默认情况下，BCC 将 `LINUX_VERSION_CODE` 存储在生成的 eBPF 对象中，并在加载 eBPF 程序时传递给内核。有时，这可能非常不方便，尤其是当内核略有更新时，比如 LTS 内核发布。微小的不匹配几乎不会导致加载的 eBPF 程序出现任何问题。通过将 `BCC_LINUX_VERSION_CODE` 设置为正在运行的内核版本，可以绕过验证内核版本的检查。这对于程序是必需的。使用kprobes的程序需要以`(VERSION * 65536) + (PATCHLEVEL * 256) + SUBLEVEL`的格式进行编码。例如，如果当前运行的内核是`4.9.10`，则可以设置`export BCC_LINUX_VERSION_CODE=264458`以成功地覆盖内核版本检查。
