# 用 bpf_send_signal 发送信号终止恶意进程

编译：

```bash
make
```

使用方式：

```bash
sudo ./bpfdos
```

这个程序会对任何试图使用 `ptrace` 系统调用的程序，例如 `strace`，发出 `SIG_KILL` 信号。
一旦 bpf-dos 开始运行，你可以通过运行以下命令进行测试：

```bash
strace /bin/whoami
```

## 参考资料

- <https://github.com/pathtofile/bad-bpf>
