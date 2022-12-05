## eBPF 入门实践教程：

## run

```console
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

or compile with `ecc`:

```console
$ ecc lsm-connect.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

Run:

```console
sudo ecli  examples/bpftools/lsm-connect/package.json
```

## reference

<https://github.com/leodido/demo-cloud-native-ebpf-day>