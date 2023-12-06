#!/bin/bash
set -x


# detach and clear the bpf programs
sudo bpftool cgroup detach "/sys/fs/cgroup/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"  && \
bpftool prog detach pinned /sys/fs/bpf/bpf_redir msg_verdict pinned /sys/fs/bpf/sock_ops_map && \
sudo unlink /sys/fs/bpf/bpf_sockops && \
sudo unlink /sys/fs/bpf/sock_ops_map && \
sudo unlink /sys/fs/bpf/bpf_redir 

