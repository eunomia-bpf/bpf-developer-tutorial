# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
CARGO ?= cargo
TARGET_DIR := target/release
BINARY_NAME := profile
LIBBPF_SRC := $(abspath ../third_party/libbpf/src)
BPFTOOL_SRC := $(abspath ../third_party/bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
VMLINUX := ../third_party/vmlinux/$(ARCH)/vmlinux.h

# Get Clang's default includes on this system
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

INCLUDES := -I$(OUTPUT) -I../third_party/libbpf/include/uapi -I$(dir $(VMLINUX))

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

.PHONY: all
all: $(BINARY_NAME)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(TARGET_DIR) $(BINARY_NAME)
	$(Q)$(CARGO) clean

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

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

# Build BPF object files from C source
$(OUTPUT)/%.bpf.o: src/bpf/%.bpf.c $(LIBBPF_OBJ) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $< -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons (if needed for Rust)
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build the Rust binary
$(BINARY_NAME): $(OUTPUT)/profile.bpf.o | $(OUTPUT)
	$(call msg,CARGO,$@)
	$(Q)$(CARGO) build --release
	$(Q)cp $(TARGET_DIR)/$(BINARY_NAME) ./

# Build in debug mode
.PHONY: debug
debug: $(OUTPUT)/profile.bpf.o | $(OUTPUT)
	$(call msg,CARGO,debug)
	$(Q)$(CARGO) build
	$(Q)cp target/debug/$(BINARY_NAME) ./$(BINARY_NAME)-debug

# Run cargo check
.PHONY: check
check: $(OUTPUT)/profile.bpf.o | $(OUTPUT)
	$(call msg,CARGO,check)
	$(Q)$(CARGO) check

# Run cargo test
.PHONY: test
test: $(OUTPUT)/profile.bpf.o | $(OUTPUT)
	$(call msg,CARGO,test)
	$(Q)$(CARGO) test

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY: