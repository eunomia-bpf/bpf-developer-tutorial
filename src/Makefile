# Master Makefile for eBPF tutorials
# Detects subdirectories with Makefiles and builds them

# Find all subdirectories containing a Makefile
SUBDIRS := $(shell find . -mindepth 2 -maxdepth 2 -name Makefile -exec dirname {} \; | sort)

# Default target
all: $(SUBDIRS)

# Build each subdirectory
$(SUBDIRS):
	@echo "Building $@"
	@$(MAKE) -C $@

# Clean all subdirectories
clean:
	@for dir in $(SUBDIRS); do \
		echo "Cleaning $$dir"; \
		$(MAKE) -C $$dir clean; \
	done

# Phony targets
.PHONY: all clean $(SUBDIRS)