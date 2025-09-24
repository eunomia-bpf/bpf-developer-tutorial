# 特殊过滤

某些工具具有特殊的过滤能力，主要用例是跟踪运行在容器中的进程，但这些机制是通用的，也可以在其他情况下使用。

## 按 cgroups过滤

某些工具有一个通过引用外部管理的固定的BPF哈希映射来按cgroup过滤的选项。

命令示例：

```sh
# ./opensnoop --cgroupmap /sys/fs/bpf/test01
# ./execsnoop --cgroupmap /sys/fs/bpf/test01
# ./tcpconnect --cgroupmap /sys/fs/bpf/test01
# ./tcpaccept --cgroupmap /sys/fs/bpf/test01
# ./tcptracer --cgroupmap /sys/fs/bpf/test01
```

上述命令将仅显示属于一个或多个cgroup的进程的结果，这些cgroup的ID由`bpf_get_current_cgroup_id()`返回，并存在固定的BPF哈希映射中。

通过以下方式创建BPF哈希映射：

```sh
# bpftool map create /sys/fs/bpf/test01 type hash key 8 value 8 entries 128 \
        name cgroupset flags 0
```

要在新cgroup中获取一个shell，可以使用：

```sh
# systemd-run --pty --unit test bash
```

该shell将在cgroup`/sys/fs/cgroup/unified/system.slice/test.service`中运行。

可以使用`name_to_handle_at()`系统调用来发现cgroup ID。在examples/cgroupid中，您可以找到一个获取cgroup ID的程序示例。

```sh
# cd examples/cgroupid
# make
# ./cgroupid hex /sys/fs/cgroup/unified/system.slice/test.service
```

或者，使用Docker：

```sh
# cd examples/cgroupid
# docker build -t cgroupid .
# docker run --rm --privileged -v /sys/fs/cgroup:/sys/fs/cgroup \
 cgroupid cgroupid hex /sys/fs/cgroup/unified/system.slice/test.service
```

这将以主机的字节序(hexadecimal string)打印出cgroup ID，例如`77 16 00 00 01 00 00 00`。

```sh
# FILE=/sys/fs/bpf/test01
# CGROUPID_HEX="77 16 00 00 01 00 00 00"
# bpftool map update pinned $FILE key hex $CGROUPID_HEX value hex 00 00 00 00 00 00 00 00 any
```

现在，通过systemd-run启动的shell的cgroup ID已经存在于BPF哈希映射中，bcc工具将显示来自该shell的结果。可以添加和。从BPF哈希映射中删除而不重新启动bcc工具。

这个功能对于将bcc工具集成到外部项目中非常有用。

## 按命名空间选择挂载点进行过滤

BPF哈希映射可以通过以下方式创建：

```sh
# bpftool map create /sys/fs/bpf/mnt_ns_set type hash key 8 value 4 entries 128 \
        name mnt_ns_set flags 0
```

仅执行`execsnoop`工具，过滤挂载命名空间在`/sys/fs/bpf/mnt_ns_set`中：

```sh
# tools/execsnoop.py --mntnsmap /sys/fs/bpf/mnt_ns_set
```

在新的挂载命名空间中启动一个终端：

```sh
# unshare -m bash
```

使用上述终端的挂载命名空间ID更新哈希映射：

```sh
FILE=/sys/fs/bpf/mnt_ns_set
if [ $(printf '\1' | od -dAn) -eq 1 ]; then
 HOST_ENDIAN_CMD=tac
else
  HOST_ENDIAN_CMD=cat
fi

NS_ID_HEX="$(printf '%016x' $(stat -Lc '%i' /proc/self/ns/mnt) | sed 's/.\{2\}/&\n/g' | $HOST_ENDIAN_CMD)"
bpftool map update pinned $FILE key hex $NS_ID_HEX value hex 00 00 00 00 any
```

在这个终端中执行命令：

```sh
# ping kinvolk.io
```

你会看到在上述你启动的`execsnoop`终端中，这个调用被记录下来：

```sh
# tools/execsnoop.py --mntnsmap /sys/fs/bpf/mnt_ns_set
[sudo] password for mvb:
PCOMM            PID    PPID   RET ARGS
ping             8096   7970     0 /bin/ping kinvolk.io
```。
