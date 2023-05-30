#!/bin/bash
set -x

# UnLoad the bpf_redir program
sudo bpftool prog detach pinned "/sys/fs/bpf/bpf_redir" msg_verdict pinned "/sys/fs/bpf/sock_ops_map"
sudo rm "/sys/fs/bpf/bpf_redir"

# UnLoad the bpf_sockops program
sudo bpftool cgroup detach "/sys/fs/cgroup/unified/" sock_ops pinned "/sys/fs/bpf/bpf_sockop"
sudo rm "/sys/fs/bpf/bpf_sockop"

# Delete the map
sudo rm "/sys/fs/bpf/sock_ops_map"
