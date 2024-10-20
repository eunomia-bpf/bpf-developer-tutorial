# Replace Text Read or Written by Any Program with eBPF

See <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/27-replace> for the full source code.

Compile:

```bash
make
```

Usage:

```sh
sudo ./replace --filename /path/to/file --input foo --replace bar
```

This program will replace all text in the file that matches 'input' with 'replace' text.
There are many use cases for this, such as:

Hiding the kernel module 'joydev' to avoid detection by tools like 'lsmod':

```bash
./replace -f /proc/modules -i 'joydev' -r 'cryptd'
```

Spoofing the MAC address of the 'eth0' interface:

```bash
./replace -f /sys/class/net/eth0/address -i '00:15:5d:01:ca:05' -r '00:00:00:00:00:00'
```

Malware performing anti-sandbox checks may look for MAC addresses as an indication of whether it is running in a virtual machine or sandbox, rather than on a "real" machine.

**Note:** The lengths of 'input' and 'replace' must be the same to avoid introducing NULL characters in the middle of the text block. To input a newline character at a bash prompt, use `$'\n'`, for example `--replace $'text\n'`.

## References

- <https://github.com/pathtofile/bad-bpf>.