# 后台运行 eBPF 程序

通过使用 `--detach` 运行程序，用户空间加载器可以退出，而不会停止 eBPF 程序。

编译：

```bash
make
```

在运行前，请首先确保 bpf 文件系统已经被挂载：

```bash
sudo mount bpffs -t bpf /sys/fs/bpf
mkdir /sys/fs/bpf/textreplace
```

然后，你可以分离运行 text-replace2：

```bash
./textreplace2 -f /proc/modules -i 'joydev' -r 'cryptd' -d
```

这将在 `/sys/fs/bpf/textreplace` 下创建一些 eBPF 链接文件。
一旦加载器成功运行，你可以通过运行以下命令检查日志：

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
# 确认链接文件存在
sudo ls -l /sys/fs/bpf/textreplace
```

然后，要停止，只需删除链接文件即可：

```bash
sudo rm -r /sys/fs/bpf/textreplace
```

## 参考资料

- <https://github.com/pathtofile/bad-bpf>