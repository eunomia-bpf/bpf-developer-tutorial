APP := python-stack
DISCOVER := python_discover

THIRD_PARTY_PATH := ../../third_party

# Architecture detection
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# VMLINUX header path
VMLINUX_DIR := $(THIRD_PARTY_PATH)/vmlinux/$(ARCH)
VMLINUX_BTF_H := $(VMLINUX_DIR)/vmlinux.h

# Libbpf
LIBBPF_SRC := $(abspath $(THIRD_PARTY_PATH)/libbpf/src)
LIBBPF_OBJ := $(abspath $(THIRD_PARTY_PATH)/libbpf/src/staticobjs/libbpf.a)
LIBBPF_OBJDIR := $(abspath $(THIRD_PARTY_PATH)/libbpf/src/staticobjs)

# BPF Code
CLANG ?= clang
BPFTOOL ?= $(abspath $(THIRD_PARTY_PATH)/bpftool/src/bpftool)

INCLUDES := -I$(LIBBPF_SRC) -I$(THIRD_PARTY_PATH)/bpftool/include/uapi -I$(VMLINUX_DIR)
CFLAGS := -g -Wall

ALL_LDFLAGS := $(LDFLAGS)

APPS = $(APP)

# BPF source
BPF_SRC := $(APP).bpf.c

# BPF object and skeleton
BPF_OBJ := $(APP).bpf.o
BPF_SKEL := $(APP).skel.h

# Userspace source
USER_SRC := $(APP).c
USER_OBJ := $(APP).o

.PHONY: all
all: $(APP) $(DISCOVER)

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.c) $(wildcard $(LIBBPF_SRC)/*.h)
	@echo "Building libbpf..."
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 OBJDIR=$(LIBBPF_OBJDIR)

# Build bpftool
$(BPFTOOL):
	@echo "Building bpftool..."
	$(MAKE) -C $(THIRD_PARTY_PATH)/bpftool/src

# Generate vmlinux.h if needed
$(VMLINUX_BTF_H):
	@if [ ! -f $(VMLINUX_BTF_H) ]; then \
		echo "Generating $(VMLINUX_BTF_H)..."; \
		mkdir -p $(VMLINUX_DIR); \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_BTF_H); \
	fi

# Build BPF object
$(BPF_OBJ): $(BPF_SRC) $(LIBBPF_OBJ) $(VMLINUX_BTF_H)
	@echo "Building BPF object: $(BPF_OBJ)"
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(BPF_SRC) -o $(BPF_OBJ)

# Generate BPF skeleton
$(BPF_SKEL): $(BPF_OBJ) $(BPFTOOL)
	@echo "Generating BPF skeleton: $(BPF_SKEL)"
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

# Build userspace program
$(USER_OBJ): $(USER_SRC) $(BPF_SKEL)
	@echo "Building userspace object: $(USER_OBJ)"
	$(CC) $(CFLAGS) $(INCLUDES) -c $(USER_SRC) -o $(USER_OBJ)

# Link final binary
$(APP): $(USER_OBJ) $(LIBBPF_OBJ)
	@echo "Linking $(APP)..."
	$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# Build Python discovery helper
$(DISCOVER): python_discover.c
	@echo "Building $(DISCOVER)..."
	$(CC) $(CFLAGS) $< -o $@

# Clean
.PHONY: clean
clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(USER_OBJ) $(APP) $(DISCOVER)
	rm -f *.o *.skel.h

# Help
.PHONY: help
help:
	@echo "Makefile for $(APP)"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build everything (default)"
	@echo "  clean    - Remove generated files"
	@echo "  help     - Show this help"
