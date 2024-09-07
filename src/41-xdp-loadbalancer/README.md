# eBPF Development tutorial: implement XDP load balancer

expplanation

```txt
   +------------------+
   |  Local Machine   |
   |  IP: 10.0.0.1    |
   +--------+---------+
            |
            |
            |
   +--------+---------+
   |   Load Balancer  |
   |  IP: 10.0.0.10   |
   +--------+---------+
            |
    +-------+-------+
    |               |
    |               |
+---+---+       +---+---+
|  h2   |       |  h3   |
| IP:   |       | IP:   |
| 10.0.0.2      | 10.0.0.3 
+-------+       +-------+
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

