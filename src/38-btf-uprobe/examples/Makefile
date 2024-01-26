# BPF compiler
BPF_CC = clang
# BPF C flags
BPF_CFLAGS = -O2 -target bpf -c -g
# BPF source files
BPF_SRCS = $(wildcard *.bpf.c)
# BPF object files
BPF_OBJS = $(BPF_SRCS:.c=.o)

all: $(BPF_OBJS) base.btf btf-base btf-base-new base-new.btf

%.bpf.o: %.bpf.c
	$(BPF_CC) $(BPF_CFLAGS) $< -o $@

btf-base.o: btf-base.c
	clang -g -c btf-base.c -o btf-base.o

btf-base-new.o: btf-base-new.c
	clang -g -c btf-base-new.c -o btf-base-new.o

base.btf: btf-base.o
	pahole --btf_encode_detached base.btf btf-base.o

base-new.btf: btf-base-new.o
	pahole --btf_encode_detached base-new.btf btf-base-new.o

btf-base: btf-base.o
	clang -g btf-base.o -o btf-base

btf-base-new: btf-base-new.o
	clang -g btf-base-new.o -o btf-base-new
	

clean:
	rm -f *.o *.btf btf-base btf-base-new
