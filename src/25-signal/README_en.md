# Terminate Malicious Processes Using bpf_send_signal

Compile:

```bash
make
```

Usage:

```bash
sudo ./bpfdos
```

This program sends a `SIG_KILL` signal to any program that tries to use the `ptrace` system call, such as `strace`.
Once bpf-dos starts running, you can test it by running the following command:

```bash
strace /bin/whoami
```

## References

- <https://github.com/pathtofile/bad-bpf>.