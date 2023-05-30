# 使用 eBPF 隐藏进程或文件信息

## 隐藏 PID

编译：

```bash
make
```

使用方式：

```sh
sudo ./pidhide --pid-to-hide 2222
```

这个程序将匹配这个 pid 的进程隐藏，使得像 `ps` 这样的工具无法看到。

它通过挂接 `getdents64` 系统调用来工作，因为 `ps` 是通过查找 `/proc/` 的每个子文件夹来工作的。PidHide 解除了与 PID 匹配的文件夹的链接，因此 `ps` 只能看到它之前和之后的文件夹。
