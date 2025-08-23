# Blazesym Build Workaround for ARM64 Platforms

This document provides workarounds for the blazesym build issue reported in [issue #148](https://github.com/eunomia-bpf/bpf-developer-tutorial/issues/148).

## Issue Description

When building blazesym with the `cheader` feature on ARM64 (aarch64) platforms, you may encounter the following error:

```
/usr/bin/ld: discarded output section: `.got.plt'
collect2: error: ld returned 1 exit status
```

This error occurs because the linker script used for generating test files is too aggressive in discarding sections, including the `.got.plt` section which is essential on ARM64 platforms.

## Solution

**The tutorial repository already includes a workaround for this issue.** The examples that use blazesym (like `src/12-profile` and `src/16-memleak`) are configured to use the `dont-generate-test-files` feature flag when building blazesym.

You can see this in their Makefiles:
```makefile
$(LIBBLAZESYM_SRC)/target/release/libblazesym.a::
	$(Q)cd $(LIBBLAZESYM_SRC) && $(CARGO) build --features=cheader,dont-generate-test-files --release
```

## If You Encounter This Issue

### For Tutorial Examples
Simply use the provided Makefiles:
```bash
cd src/12-profile  # or src/16-memleak
make
```

### For Manual Blazesym Building
If you need to build blazesym manually, use the `dont-generate-test-files` feature:

```bash
cd src/third_party/blazesym
cargo build --features=cheader,dont-generate-test-files
```

### Alternative Workarounds

1. **Skip C Header Generation** (if you don't need C headers):
   ```bash
   cd src/third_party/blazesym
   cargo build
   ```

2. **Install LLVM Tools** (if you want full test support):
   ```bash
   # On Ubuntu/Debian:
   sudo apt install llvm
   
   # Then build normally:
   cargo build --features=cheader
   ```

## Technical Details

The issue is caused by the linker script in `data/test-gsym.ld` being too aggressive in discarding sections. On ARM64 platforms, the `.got.plt` section is essential and cannot be discarded.

The `dont-generate-test-files` feature flag bypasses the generation of test files that require this problematic linker script, allowing blazesym to build successfully while maintaining all core functionality.

## Impact

- **Core blazesym functionality**: ✅ Not affected
- **C header generation**: ✅ Works with the workaround
- **Test file generation**: ⚠️ Skipped on problematic platforms
- **Symbol resolution**: ✅ Works normally

## References

- [Issue #148](https://github.com/eunomia-bpf/bpf-developer-tutorial/issues/148)
- [Blazesym Repository](https://github.com/libbpf/blazesym)
- [ARM64 GOT/PLT Documentation](https://developer.arm.com/documentation/dui0803/j/ELF-features/Global-Offset-Table--GOT-)