# 使用 eBPF 替换任意程序读取或写入的文本

```sh
sudo ./replace --filename /path/to/file --input foo --replace bar
```

This program replaces all text matching `input` in the file with the `replace` text.
This has a number of uses, for example:

To hide kernel module `joydev` from tools such as `lsmod`:

```bash
./replace -f /proc/modules -i 'joydev' -r 'cryptd'
```

Spoof the MAC address of the `eth0` interface:

```bash
./replace -f /sys/class/net/eth0/address -i '00:15:5d:01:ca:05' -r '00:00:00:00:00:00'
```

Malware conducting anti-sandbox checks might check the MAC address to look for signs it is
running inside a Virtual Machine or Sandbox, and not on a 'real' machine.

**NOTE:** Both `input` and `replace` must be the same length, to avoid adding NULL characters to the
middle of a block of text. To enter a newline from a bash prompt, use `$'\n'`, e.g. `--replace $'text\n'`.
