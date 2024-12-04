obj-m += hello.o  # hello.o is the target

# Enable BTF generation
KBUILD_CFLAGS += -g -O2
ccflags-y += -DCONFIG_BPF_SYSCALL
KBUILD_MODPOST_WARN=1
all:
	# Compile the module with BTF information
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
