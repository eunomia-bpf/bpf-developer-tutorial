# eBPF Development tutorial: implement XDP load balancer

expplanation

```txt
    +---------------------------+          
    |      Local Machine         |
    |  IP: 10.0.0.1 (veth0)      |
    |  MAC: DE:AD:BE:EF:00:01    |
    +------------+---------------+
             |
             | (veth1)
             |
    +--------+---------------+       
    |    Load Balancer       |
    |  IP: 10.0.0.10 (veth6) |
    |  MAC: DE:AD:BE:EF:00:10|
    +--------+---------------+       
             | 
   +---------+----------------------------+            
   |                                      |
(veth2)                                (veth4)    
   |                                      | 
+--+---------------+             +--------+---------+
| h2               |             | h3               |
| IP:              |             | IP:              |
|10.0.0.2 (veth3)  |             |10.0.0.3 (veth5)  |
| MAC:             |             | MAC:             |
|DE:AD:BE:EF:00:02 |             |DE:AD:BE:EF:00:03 |
+------------------+             +------------------+
```

Setup:

```sh
sudo ./setup.sh
```

Teardown:

```sh
sudo ./teardown.sh
```

Test with ping:

## Run

```sh
$ sudo ip netns exec lb ./xdp_lb veth6 10.0.0.2 de:ad:be:ef:00:02 10.0.0.3 de:ad:be:ef:00:03
XDP load balancer configured with backends:
Backend 1 - IP: 10.0.0.2, MAC: de:ad:be:ef:00:02
Backend 2 - IP: 10.0.0.3, MAC: de:ad:be:ef:00:03
Press Ctrl+C to exit...
```
