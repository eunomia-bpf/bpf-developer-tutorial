# ebpf modify syscall parameters

## modify open filename

```bash
make
./victim
```

```bash
sudo ./ecli run package.json -- --rewrite --target_pid=$(pidof victim)
```

## modify exec commands

TODO

## reference

- <https://github.com/pathtofile/bad-bpf/blob/main/src/exechijack.bpf.c>
