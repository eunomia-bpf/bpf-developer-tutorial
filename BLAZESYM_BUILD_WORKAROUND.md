# Blazesym Build Workaround for ARM64 Platforms

This document provides workarounds for the blazesym build issue reported in [issue #148](https://github.com/eunomia-bpf/bpf-developer-tutorial/issues/148).

## Issue Description

When building blazesym with the `cheader` feature on ARM64 (aarch64) platforms, you may encounter the following error:

```
/usr/bin/ld: discarded output section: `.got.plt'
collect2: error: ld returned 1 exit status
```

This error occurs because the linker script used for generating test files is too aggressive in discarding sections, including the `.got.plt` section which is essential on ARM64 platforms.

## Workarounds

### Option 1: Skip Test File Generation (Recommended)

The easiest workaround is to build blazesym with the `dont-generate-test-files` feature flag:

```bash
cd src/third_party/blazesym
cargo build --features=cheader,dont-generate-test-files
```

This flag skips the generation of test files that cause the linker issue.

### Option 2: Install LLVM Tools

If you want to build with test files, ensure you have `llvm-gsymutil` installed:

```bash
# On Ubuntu/Debian:
sudo apt install llvm

# On other systems, install LLVM development tools
```

### Option 3: Use Fixed Linker Script

The linker script has been improved to be less aggressive about discarding sections. The fixed script avoids discarding essential sections like `.got.plt` that are needed on ARM64.

## For Developers

If you're working on examples that don't require blazesym's C header generation, you can simply build without the `cheader` feature:

```bash
cd src/third_party/blazesym
cargo build
```

## Additional Notes

- This issue is specific to ARM64 platforms and certain linker versions
- The workaround does not affect the core functionality of blazesym
- Test file generation is only needed for blazesym's internal testing, not for normal usage

## References

- [Issue #148](https://github.com/eunomia-bpf/bpf-developer-tutorial/issues/148)
- [Blazesym Repository](https://github.com/libbpf/blazesym)