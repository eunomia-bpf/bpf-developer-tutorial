obj-m += hello.o  # hello.o is the target

# Enable BTF generation
KBUILD_CFLAGS += -g -O2
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	# Compile the module
	+$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	+$(MAKE) -C $(KDIR) M=$(CURDIR) clean
