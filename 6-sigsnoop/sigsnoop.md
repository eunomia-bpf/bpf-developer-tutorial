## eBPF 入门实践教程：编写 eBPF 程序 sigsnoop 工具监控全局 signal 事件

### 背景

### 实现原理

`sigsnoop` 在利用了linux的tracepoint挂载点，其在syscall进入和退出的各个关键挂载点均挂载了执行函数。
```c

```


### Eunomia中使用方式

![result](../imgs/sigsnoop.png)
![result](../imgs/sigsnoop-prometheus.png)

### 总结
