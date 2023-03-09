# eBPF 入门实践教程：使用 LSM 进行安全检测防御

## 背景

TODO

## LSM 概述

TODO

## 编写 eBPF 程序

TODO

## 编译运行

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

## 总结

TODO

参考：<https://github.com/leodido/demo-cloud-native-ebpf-day>
