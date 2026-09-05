#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  run-in-kvm.sh --check
  run-in-kvm.sh [options] -- COMMAND [ARG...]

Build tutorial artifacts on the host, then use this wrapper only for the
runtime command that must execute in the bpf-benchmark KVM kernel.

Options:
  --check               Validate KVM, vng, and the benchmark kernel, then exit.
  --cwd PATH            Guest working directory (default: current directory).
  --cpus N              Guest vCPU count (default: 2).
  --memory SIZE         Guest RAM accepted by vng/QEMU (default: 4G).
  --timeout SECONDS     Host-side wall-clock limit (default: 120).
  --network MODE        none, user, or loop (default: none).
  --rwdir PATH          Explicit host path writable by guest root; repeatable.
  --append ARGS         Additional kernel command-line string; repeatable.
  --dry-run             Print vng's QEMU command without booting.
  --verbose             Show the guest boot console and vng details.
  -h, --help            Show this help.

Environment:
  BPF_BENCHMARK_ROOT    Default: bpf-benchmark next to this repository
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_positive_integer() {
    local name=$1 value=$2
    [[ $value =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer: $value"
}

quote_for_posix_shell() {
    local value=$1
    value=${value//\'/\'\\\'\'}
    REPLY="'$value'"
}

benchmark_root=${BPF_BENCHMARK_ROOT:-}
cwd=$PWD
cpus=2
memory=4G
wall_timeout=120
network=none
check_only=false
dry_run=false
verbose=false
declare -a rwdirs=()
declare -a extra_append=()

while (($#)); do
    case $1 in
        --check)
            check_only=true
            shift
            ;;
        --cwd)
            (($# >= 2)) || die "--cwd requires a path"
            cwd=$2
            shift 2
            ;;
        --cpus)
            (($# >= 2)) || die "--cpus requires a value"
            cpus=$2
            shift 2
            ;;
        --memory)
            (($# >= 2)) || die "--memory requires a value"
            memory=$2
            shift 2
            ;;
        --timeout)
            (($# >= 2)) || die "--timeout requires seconds"
            wall_timeout=$2
            shift 2
            ;;
        --network)
            (($# >= 2)) || die "--network requires a mode"
            network=$2
            shift 2
            ;;
        --rwdir)
            (($# >= 2)) || die "--rwdir requires a path"
            rwdirs+=("$2")
            shift 2
            ;;
        --append)
            (($# >= 2)) || die "--append requires a kernel command-line string"
            extra_append+=("$2")
            shift 2
            ;;
        --dry-run)
            dry_run=true
            shift
            ;;
        --verbose)
            verbose=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            die "unknown option before --: $1"
            ;;
    esac
done

require_positive_integer "--cpus" "$cpus"
require_positive_integer "--timeout" "$wall_timeout"
[[ $memory =~ ^[1-9][0-9]*([KkMmGgTt])?$ ]] || die "invalid --memory value: $memory"
case $network in
    none|user|loop) ;;
    *) die "--network must be none, user, or loop: $network" ;;
esac

for command_name in file flock git mktemp realpath sha256sum timeout vng; do
    require_command "$command_name"
done

if [[ -z $benchmark_root ]]; then
    skill_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
    tutorial_root=$(git -C "$skill_dir" rev-parse --show-toplevel)
    benchmark_root=$(dirname -- "$tutorial_root")/bpf-benchmark
fi

[[ $(uname -m) == x86_64 ]] || die "the reused artifact is x86_64, host is $(uname -m)"
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || \
    die "/dev/kvm is not available with read/write permission; refusing a TCG fallback"

benchmark_root=$(realpath -e -- "$benchmark_root")
kernel_build=$benchmark_root/vendor/build/x86/linux
kernel_source_link=$kernel_build/source
kernel_image=$kernel_build/arch/x86/boot/bzImage
kernel_config=$kernel_build/.config
kernel_release_file=$kernel_build/include/config/kernel.release

[[ -e $kernel_source_link ]] || die "kernel build source link is missing: $kernel_source_link"
kernel_source=$(realpath -e -- "$kernel_source_link")
[[ -d $kernel_source ]] || die "kernel build source directory is missing: $kernel_source"
[[ -s $kernel_image ]] || die "built benchmark kernel is missing: $kernel_image"
[[ -r $kernel_config ]] || die "kernel config is missing: $kernel_config"
[[ -r $kernel_release_file ]] || die "kernel release file is missing: $kernel_release_file"
file -- "$kernel_image" | grep -q 'Linux kernel x86 boot executable bzImage' || \
    die "artifact is not an x86 bzImage: $kernel_image"
git -C "$kernel_source" rev-parse --verify HEAD >/dev/null 2>&1 || \
    die "kernel source Git worktree is invalid: $kernel_source"

required_config=(
    CONFIG_BPF=y
    CONFIG_BPF_SYSCALL=y
    CONFIG_BPF_JIT=y
    CONFIG_CGROUP_BPF=y
    CONFIG_KPROBES=y
    CONFIG_UPROBES=y
    CONFIG_FTRACE=y
    CONFIG_DEBUG_INFO_BTF=y
)
for symbol in "${required_config[@]}"; do
    grep -qxF "$symbol" "$kernel_config" || die "required kernel config is absent: $symbol"
done

kernel_release=$(<"$kernel_release_file")
[[ -n $kernel_release ]] || die "kernel release file is empty: $kernel_release_file"
kernel_commit=$(git -C "$kernel_source" rev-parse HEAD)
kernel_subject=$(git -C "$kernel_source" show -s --format=%s HEAD)
kernel_dirty=no
if [[ -n $(git -C "$kernel_source" status --porcelain --untracked-files=normal) ]]; then
    kernel_dirty=yes
fi
kernel_sha256=$(sha256sum "$kernel_image" | awk '{print $1}')
config_sha256=$(sha256sum "$kernel_config" | awk '{print $1}')
vng_version=$(vng --version | head -n 1)

printf '%s\n' \
    'KVM preflight: OK' \
    "benchmark_root=$benchmark_root" \
    "kernel_image=$kernel_image" \
    "kernel_source=$kernel_source" \
    "kernel_release=$kernel_release" \
    "kernel_sha256=$kernel_sha256" \
    "kernel_config_sha256=$config_sha256" \
    "kernel_source_commit=$kernel_commit" \
    "kernel_source_dirty=$kernel_dirty" \
    "kernel_source_subject=$kernel_subject" \
    "vng_version=$vng_version"

if $check_only; then
    (($# == 0)) || die "--check does not accept a guest command"
    exit 0
fi

(($# > 0)) || die "missing guest command; place it after --"
[[ -d $cwd ]] || die "guest working directory does not exist: $cwd"
cwd=$(realpath -e -- "$cwd")

declare -a normalized_rwdirs=()
cwd_is_rw=false
for path in "${rwdirs[@]}"; do
    [[ -d $path ]] || die "--rwdir is not a directory: $path"
    path=$(realpath -e -- "$path")
    normalized_rwdirs+=("$path")
    if [[ $path == "$cwd" ]]; then
        cwd_is_rw=true
    fi
done

quote_for_posix_shell "$kernel_release"
quoted_release=$REPLY
quote_for_posix_shell "$cwd"
quoted_cwd=$REPLY
quoted_command=
for argument in "$@"; do
    quote_for_posix_shell "$argument"
    quoted_command+="$REPLY "
done

guest_script=$'#!/bin/sh\nset -eu\n'
guest_script+=$'mount_if_needed() {\n'
guest_script+=$'    source=$1 type=$2 target=$3\n'
guest_script+=$'    mkdir -p -- "$target"\n'
guest_script+=$'    grep -qs " $target " /proc/mounts || mount -t "$type" "$source" "$target"\n'
guest_script+=$'}\n'
guest_script+=$'mount_if_needed bpf bpf /sys/fs/bpf\n'
guest_script+=$'mount_if_needed debugfs debugfs /sys/kernel/debug\n'
guest_script+=$'mount_if_needed tracefs tracefs /sys/kernel/tracing\n'
guest_script+=$'mount_if_needed none cgroup2 /sys/fs/cgroup\n'
guest_script+=$'ulimit -l unlimited\n'
guest_script+="expected_release=$quoted_release"$'\n'
guest_script+=$'actual_release=$(uname -r)\n'
guest_script+=$'if [ "$actual_release" != "$expected_release" ]; then\n'
guest_script+=$'    echo "ERROR: guest kernel mismatch: expected=$expected_release actual=$actual_release" >&2\n'
guest_script+=$'    exit 1\n'
guest_script+=$'fi\n'
guest_script+=$'printf "guest_kernel=%s\\nguest_identity=%s\\n" "$actual_release" "$(id)"\n'
guest_script+="cd -- $quoted_cwd"$'\n'
guest_script+="exec $quoted_command"$'\n'

lock_file=${TMPDIR:-/tmp}/test-bpf-tutorial-kvm.lock
exec {lock_fd}>"$lock_file"
flock -w 5 "$lock_fd" || die "another tutorial KVM run holds $lock_file"

host_script_dir=$(mktemp -d /tmp/test-bpf-tutorial-kvm.XXXXXX)
host_script_path=$host_script_dir/guest-command.sh
guest_script_dir=/tmp/${host_script_dir##*/}
guest_script_path=$guest_script_dir/guest-command.sh
cleanup() {
    rm -f -- "$host_script_path"
    rmdir -- "$host_script_dir" 2>/dev/null || true
}
trap cleanup EXIT
printf '%s' "$guest_script" >"$host_script_path"
chmod 0555 "$host_script_path"

declare -a vng_command=(
    vng
    --run "$kernel_image"
    --cwd "$cwd"
    --disable-monitor
    --cpus "$cpus"
    --memory "$memory"
    --overlay-rwdir /tmp
    '--qemu-opts=-machine accel=kvm'
    --append 'loglevel=4 panic=30 oops=panic'
    --rodir "$guest_script_dir=$host_script_dir"
    --exec "$guest_script_path"
)

if ! $cwd_is_rw; then
    vng_command+=(--rodir "$cwd")
fi
for path in "${normalized_rwdirs[@]}"; do
    vng_command+=(--rwdir "$path")
done
if [[ $network != none ]]; then
    vng_command+=(--network "$network")
fi
for args in "${extra_append[@]}"; do
    vng_command+=(--append "$args")
done
if $verbose; then
    vng_command+=(--verbose)
else
    vng_command+=(--quiet)
fi
if $dry_run; then
    vng_command+=(--dry-run)
fi

printf 'guest_cwd=%s\n' "$cwd"
printf 'guest_network=%s\n' "$network"
printf 'guest_command='
printf '%q ' "$@"
printf '\n'
if ((${#normalized_rwdirs[@]})); then
    printf 'WARNING: guest root has host write access to:' >&2
    printf ' %q' "${normalized_rwdirs[@]}" >&2
    printf '\n' >&2
fi

if $dry_run; then
    "${vng_command[@]}"
else
    timeout --foreground --signal=TERM --kill-after=10s "${wall_timeout}s" \
        "${vng_command[@]}"
fi
