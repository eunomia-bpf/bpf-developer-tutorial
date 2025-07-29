# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the eBPF Developer Tutorial repository - a comprehensive learning resource for eBPF development. It provides 48+ practical examples progressing from beginner to advanced topics using modern eBPF frameworks like libbpf, Cilium eBPF, and libbpf-rs.

## Common Development Tasks

### Building eBPF Examples

Most examples use libbpf and follow this pattern:
```bash
cd src/<example-number>-<example-name>
make
```

For Rust examples (in src/37-uprobe-rust/):
```bash
cd src/37-uprobe-rust/<example>
cargo build
```

### Running Examples

Most examples require root privileges:
```bash
sudo ./<binary-name>
# or with timeout for continuous monitoring tools:
sudo timeout -s 2 3 ./<binary-name>
```

### Clean Build Artifacts
```bash
make clean
```

## Architecture

### Build System
- **Framework**: GNU Make with libbpf
- **BPF Compilation**: Clang/LLVM compiles `.bpf.c` → `.bpf.o`
- **Skeleton Generation**: bpftool generates `.skel.h` from BPF objects
- **User Space**: GCC compiles C programs linking with libbpf
- **Dependencies**: All in `src/third_party/` (libbpf, bpftool, blazesym, vmlinux headers)

### Directory Structure
- `src/0-10`: Basic eBPF concepts (kprobes, uprobes, tracepoints)
- `src/11-18`: Advanced libbpf development
- `src/19-21,29,41-42`: Networking (LSM, TC, XDP, sockops)
- `src/22-28,34`: Security topics
- `src/31,37`: Language integration (Go, Rust)
- `src/44-45`: BPF schedulers
- `src/47`: GPU tracing
- Each tutorial has its own Makefile and README

### Key Components
1. **vmlinux headers**: Pre-generated for x86, arm, arm64, riscv, powerpc, loongarch
2. **CO-RE (Compile Once, Run Everywhere)**: Uses BTF for kernel compatibility
3. **Multiple frameworks**: libbpf (primary), eunomia-bpf, Cilium eBPF, libbpf-rs