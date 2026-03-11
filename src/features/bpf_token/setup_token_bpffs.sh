#!/usr/bin/env bash
set -euo pipefail

MOUNTPOINT="${1:-/tmp/bpf-token}"
OPTIONS="delegate_cmds=prog_load:map_create:btf_load:link_create,delegate_maps=array,delegate_progs=xdp:socket_filter,delegate_attachs=any"

mkdir -p "${MOUNTPOINT}"

if mountpoint -q "${MOUNTPOINT}"; then
    echo "bpffs is already mounted at ${MOUNTPOINT}"
    exit 0
fi

mount -t bpf bpf "${MOUNTPOINT}" -o "${OPTIONS}"
echo "Mounted delegated bpffs at ${MOUNTPOINT}"
echo "Note: a bpffs mount in init_user_ns is useful for inspection, but token creation itself must happen from the same non-init user namespace as the bpffs instance."
grep " ${MOUNTPOINT} " /proc/mounts || true
