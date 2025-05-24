# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath ../third_party/libbpf/src)
BPFTOOL_SRC := $(abspath ../third_party/bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBLAZESYM_SRC := $(abspath ../third_party/blazesym/)
LIBBLAZESYM_OBJ := $(abspath $(OUTPUT)/libblazesym.a)
LIBBLAZESYM_HEADER := $(abspath $(OUTPUT)/blazesym.h)
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
VMLINUX := ../third_party/vmlinux/$(ARCH)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I../third_party/libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall -D_GNU_SOURCE
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

# Default CUDA library path
CUDA_LIB_PATH ?= /usr/local/cuda/lib64/libcudart.so

# NVIDIA CUDA Compiler
NVCC ?= nvcc

# Auto-detect CUDA architecture if possible
CUDA_DETECT_SCRIPT := $(OUTPUT)/detect_cuda_arch.sh
CUDA_ARCH_FLAGS ?= $(shell if [ -f $(CUDA_DETECT_SCRIPT) ]; then bash $(CUDA_DETECT_SCRIPT); else echo "-arch=sm_61"; fi)
NVCC_FLAGS = -O3 $(CUDA_ARCH_FLAGS)

APPS = cuda_events # minimal minimal_legacy uprobe kprobe fentry usdt sockfilter tc ksyscall
CUDA_APPS = basic02 bench

CARGO ?= $(shell which cargo)
ifeq ($(strip $(CARGO)),)
BZS_APPS :=
else
BZS_APPS := # profile
APPS += $(BZS_APPS)
# Required by libblazesym
ALL_LDFLAGS += -lrt -ldl -lpthread -lm
endif

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: cuda_events basic02 bench

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS) $(CUDA_APPS)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Create a script to detect CUDA architecture
$(CUDA_DETECT_SCRIPT): | $(OUTPUT)
	$(call msg,SCRIPT,$@)
	$(Q)echo '#!/bin/bash' > $@
	$(Q)echo 'CUDA_VERSION=$$($(NVCC) --version | grep "release" | sed "s/.*release //" | sed "s/,.*//")' >> $@
	$(Q)echo 'if [ -x "$$(command -v nvidia-smi)" ]; then' >> $@
	$(Q)echo '  CUDA_ARCH=$$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | sed -e "s/\.//")' >> $@
	$(Q)echo '  if [ -n "$$CUDA_ARCH" ]; then' >> $@
	$(Q)echo '    echo "-arch=sm_$$CUDA_ARCH"' >> $@
	$(Q)echo '    exit 0' >> $@
	$(Q)echo '  fi' >> $@
	$(Q)echo 'fi' >> $@
	$(Q)echo 'echo "-arch=sm_61"' >> $@
	$(Q)chmod +x $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build CUDA examples
$(CUDA_APPS): %: %.cu $(CUDA_DETECT_SCRIPT)
	$(call msg,NVCC,$@)
	$(Q)$(NVCC) $(NVCC_FLAGS) -o $@ $<
	$(Q)@echo "Compiling for architecture: $(CUDA_ARCH_FLAGS)"

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(patsubst %,$(OUTPUT)/%.o,$(BZS_APPS)): $(LIBBLAZESYM_HEADER)

$(BZS_APPS): $(LIBBLAZESYM_OBJ)

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# Benchmarking targets
.PHONY: benchmark benchmark-no-trace benchmark-with-trace

# Run benchmark without tracing
benchmark-no-trace:
	$(call msg,BENCH,"without tracing")
	$(Q)./bench

# Run benchmark with tracing
benchmark-with-trace:
	$(call msg,BENCH,"with tracing")
	$(Q)(sudo ./cuda_events -p ./bench > /dev/null 2>&1 &); \
		sleep 1; \
		./bench; \
		sudo pkill -f "./cuda_events -p ./bench" || true

# Run both benchmarks and compare
benchmark: bench cuda_events
	$(call msg,BENCH,"benchmark comparison")
	$(Q)echo "============================================="
	$(Q)echo "Running benchmark WITHOUT tracing..."
	$(Q)echo "============================================="
	$(Q)./bench
	$(Q)echo ""
	$(Q)echo "============================================="
	$(Q)echo "Running benchmark WITH tracing..."
	$(Q)echo "============================================="
	$(Q)(sudo ./cuda_events -p ./bench > /dev/null 2>&1 &); \
		sleep 1; \
		./bench; \
		sudo pkill -f "./cuda_events -p ./bench" || true
	$(Q)echo ""
	$(Q)echo "Benchmark complete. Compare the results to see the tracing overhead."

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
