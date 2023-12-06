#!/bin/bash
set -x
set -e

sudo mount -t bpf bpf /sys/fs/bpf/

# check if old program already loaded
if [ -e "/sys/fs/bpf/bpf_sockops" ]; then
    echo ">>> bpf_sockops already loaded, uninstalling..."
    ./unload.sh
    echo ">>> old program already deleted..."
fi

# load and attach sock_ops program
sudo bpftool prog load bpf_contrack.bpf.o /sys/fs/bpf/bpf_sockops type sockops pinmaps /sys/fs/bpf/
sudo bpftool cgroup attach "/sys/fs/cgroup/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"

# load and attach sk_msg program 
sudo bpftool prog load bpf_redirect.bpf.o "/sys/fs/bpf/bpf_redir" map name sock_ops_map pinned "/sys/fs/bpf/sock_ops_map"
sudo bpftool prog attach pinned /sys/fs/bpf/bpf_redir msg_verdict pinned /sys/fs/bpf/sock_ops_map
