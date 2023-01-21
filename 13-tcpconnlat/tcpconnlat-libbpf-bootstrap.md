## eBPF入门实践教程：使用 libbpf-bootstrap 开发程序统计 TCP 连接延时

## 来源

修改自 https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpconnlat.bpf.c

## 编译运行

- ```git clone https://github.com/libbpf/libbpf-bootstrap libbpf-bootstrap-cloned```
- 将 [libbpf-bootstrap](libbpf-bootstrap)目录下的文件复制到 ```libbpf-bootstrap-cloned/examples/c```下
- 修改 ```libbpf-bootstrap-cloned/examples/c/Makefile``` ，在其 ```APPS``` 项后添加 ```tcpconnlat```
- 在 ```libbpf-bootstrap-cloned/examples/c``` 下运行 ```make tcpconnlat```
- ```sudo ./tcpconnlat```

## 效果
```
root@yutong-VirtualBox:~/libbpf-bootstrap/examples/c# ./tcpconnlat 
PID    COMM         IP SADDR            DADDR            DPORT LAT(ms)
222564 wget         4  192.168.88.15    110.242.68.3     80    25.29
222684 wget         4  192.168.88.15    167.179.101.42   443   246.76
222726 ssh          4  192.168.88.15    167.179.101.42   22    241.17
222774 ssh          4  192.168.88.15    1.15.149.151     22    25.31
```

对于输出的详细解释，详见 [README.md](README.md)

对于源代码的详解，具体见 [tcpconnlat.md](tcpconnlat.md)
