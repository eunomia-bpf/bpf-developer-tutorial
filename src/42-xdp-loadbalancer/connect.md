# Network setup for bpf-developer-tutorial

In this tutorial, we will set up a simple network topology that simulates a load balancer using eBPF/XDP (Express Data Path). The setup includes a local machine, a load balancer (which can be enhanced with an XDP program), and two backend servers (`h2` and `h3`). The local machine routes packets to the load balancer, which then distributes traffic between the backend servers.

# Simple XDP Load Balancer Tutorial

This tutorial will guide you in setting up a simple virtual network to simulate a load balancer using eBPF/XDP.

## Network Topology

```txt
   +------------------+
   |  Local Machine   |
   |  IP: 10.0.0.1    |
   +--------+---------+
            |
   +--------+---------+
   |   Load Balancer  |
   |  IP: 10.0.0.10   |
   +--------+---------+
            |
    +-------+-------+
    |               |
+---+---+       +---+---+
|  h2   |       |  h3   |
|10.0.0.2|       |10.0.0.3|
+-------+       +-------+
```

- **Local Machine**: Simulates a client (`10.0.0.1`) sending traffic.
- **Load Balancer**: Distributes traffic to backend servers (`10.0.0.10`).
- **h2** and **h3**: Simulate backend servers (`10.0.0.2` and `10.0.0.3`).

### Setup Steps

This script creates virtual network namespaces and sets up IP addresses for the local machine, load balancer, and backend servers.

```bash
sudo ./setup.sh
```

To clean up the setup after testing:

```bash
sudo ./teardown.sh
```

### Testing the Network

You can test the network connectivity using `ping` commands:

Ping Between Backend Servers (`h2` to `h3`)

```bash
sudo ip netns exec h2 ping -c 3 10.0.0.3
```

Ping from Backend Server (`h2`) to Load Balancer

```bash
sudo ip netns exec h2 ping -c 3 10.0.0.10
```

Ping from Local Machine to Load Balancer

```bash
ping -c 3 10.0.0.10
```

That's it! This simple setup lets you simulate a load balancer using eBPF/XDP. You can extend it by adding custom XDP programs to control the traffic distribution between `h2` and `h3`.
