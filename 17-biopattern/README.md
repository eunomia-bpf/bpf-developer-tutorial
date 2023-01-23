# eBPF 入门实践教程：编写 eBPF 程序 Biopattern: 统计随机/顺序磁盘 I/O

## 背景

Biopattern 可以统计随机/顺序磁盘I/O次数的比例。

TODO

## 实现原理

Biopattern 的ebpf代码在 tracepoint/block/block_rq_complete 挂载点下实现。在磁盘完成IO请求
后，程序会经过此挂载点。Biopattern 内部存有一张以设备号为主键的哈希表，当程序经过挂载点时, Biopattern
会获得操作信息，根据哈希表中该设备的上一次操作记录来判断本次操作是随机IO还是顺序IO，并更新操作计数。

## 编写 eBPF 程序

TODO

### 总结

Biopattern 可以展现随机/顺序磁盘I/O次数的比例，对于开发者把握整体I/O情况有较大帮助。

TODO
