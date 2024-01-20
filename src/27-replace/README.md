# 使用 eBPF 替换任意程序读取或写入的文本

完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/27-replace> 

关于如何安装依赖，请参考：<https://eunomia.dev/tutorials/11-bootstrap/>

编译：

```bash
make
```

使用方式：

```sh
sudo ./replace --filename /path/to/file --input foo --replace bar
```

这个程序将文件中所有与 `input` 匹配的文本替换为 `replace` 文本。
这有很多用途，例如：

隐藏内核模块 `joydev`，避免被如 `lsmod` 这样的工具发现：

```bash
./replace -f /proc/modules -i 'joydev' -r 'cryptd'
```

伪造 `eth0` 接口的 MAC 地址：

```bash
./replace -f /sys/class/net/eth0/address -i '00:15:5d:01:ca:05' -r '00:00:00:00:00:00'
```

恶意软件进行反沙箱检查可能会检查 MAC 地址，寻找是否正在虚拟机或沙箱内运行，而不是在“真实”的机器上运行的迹象。

**注意：** `input` 和 `replace` 的长度必须相同，以避免在文本块的中间添加 NULL 字符。在 bash 提示符下输入换行符，使用 `$'\n'`，例如 `--replace $'text\n'`。

## 参考资料

- <https://github.com/pathtofile/bad-bpf>
