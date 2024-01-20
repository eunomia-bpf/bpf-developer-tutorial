# 使用 eBPF 添加 sudo 用户

本文完整的源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/26-sudo>

关于如何安装依赖，请参考：<https://eunomia.dev/tutorials/11-bootstrap/>

编译：

```bash
make
```

使用方式：

```sh
sudo ./sudoadd --username lowpriv-user
```

这个程序允许一个通常权限较低的用户使用 `sudo` 成为 root。

它通过拦截 `sudo` 读取 `/etc/sudoers` 文件，并将第一行覆盖为 `<username> ALL=(ALL:ALL) NOPASSWD:ALL #` 的方式工作。这欺骗了 sudo，使其认为用户被允许成为 root。其他程序如 `cat` 或 `sudoedit` 不受影响，所以对于这些程序来说，文件未改变，用户并没有这些权限。行尾的 `#` 确保行的其余部分被当作注释处理，因此不会破坏文件的逻辑。

## 参考资料

- <https://github.com/pathtofile/bad-bpf>
