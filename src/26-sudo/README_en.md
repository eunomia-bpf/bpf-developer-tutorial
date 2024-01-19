# Using eBPF to add sudo user

The full source code for this article can be found at <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/26-sudo>

Compilation:

```bash
make
```

Usage:

```sh
sudo ./sudoadd --username lowpriv-user
```

This program allows a user with lower privileges to become root using `sudo`.

It works by intercepting `sudo` reading the `/etc/sudoers` file and overwriting the first line with `<username> ALL=(ALL:ALL) NOPASSWD:ALL #`. This tricks `sudo` into thinking that the user is allowed to become root. Other programs like `cat` or `sudoedit` are not affected, so the file remains unchanged and the user does not have these permissions. The `#` at the end of the line ensures that the rest of the line is treated as a comment, so it does not break the logic of the file.

## References

- [https://github.com/pathtofile/bad-bpf](https://github.com/pathtofile/bad-bpf)