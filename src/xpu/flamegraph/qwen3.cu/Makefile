# choose your compiler, e.g. gcc/clang
# example override to clang: make run CC=clang
CC = gcc
# For CUDA compile
CUDA_INSTALL_PATH ?= /usr/local/cuda-12.9
NVCC := "$(CUDA_INSTALL_PATH)/bin/nvcc"
INCLUDES := -I"$(CUDA_INSTALL_PATH)/include"
LIB_PATH ?= $(CUDA_INSTALL_PATH)/lib64

# compile the Cuda version (with dynamic libcudart for eBPF uprobe profiling)
# Use -Xcompiler to pass frame pointer flag to host compiler for eBPF stack unwinding
.PHONY: runcu
runcu: runcu.cu
	$(NVCC) $(INCLUDES) -O2 -Xcompiler -fno-omit-frame-pointer -Wno-deprecated-gpu-targets --no-device-link -o runcu runcu.cu -L $(LIB_PATH) -lcudart -lm
# compile cublas included
.PHONY: runcublas
runcublas: runcu.cu
	$(NVCC) $(INCLUDES) -O3 -Wno-deprecated-gpu-targets --no-device-link -DUSE_CUBLAS -o runcublas runcu.cu -L $(LIB_PATH) -lcudart -lm -lcublas

# download the model
.PHONY: download-model
download-model:
	@if [ -f Qwen3-0.6B-FP32.gguf ] && [ $$(stat -c%s Qwen3-0.6B-FP32.gguf) -gt 1000000 ]; then \
		echo "Model already exists (size: $$(du -h Qwen3-0.6B-FP32.gguf | cut -f1))"; \
	else \
		echo "Downloading Qwen3-0.6B model (3GB - this will take a while)..."; \
		wget -c https://huggingface.co/huggit0000/Qwen3-0.6B-GGUF-FP32/resolve/main/Qwen3-0.6B-FP32.gguf -O Qwen3-0.6B-FP32.gguf || \
		curl -L -C - https://huggingface.co/huggit0000/Qwen3-0.6B-GGUF-FP32/resolve/main/Qwen3-0.6B-FP32.gguf -o Qwen3-0.6B-FP32.gguf; \
		echo "Model downloaded successfully (size: $$(du -h Qwen3-0.6B-FP32.gguf | cut -f1))"; \
	fi

# =========================
# The below is not used hree.


# the most basic way of building that is most likely to work on most systems
.PHONY: run
run: run.c
	$(CC) -O3 -o run run.c -lm

# useful for a debug build, can then e.g. analyze with valgrind, example:
# $ valgrind --leak-check=full ./run out/model.bin -n 3
rundebug: run.c
	$(CC) -g -o run run.c -lm

# https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html
# https://simonbyrne.github.io/notes/fastmath/
# -Ofast enables all -O3 optimizations.
# Disregards strict standards compliance.
# It also enables optimizations that are not valid for all standard-compliant programs.
# It turns on -ffast-math, -fallow-store-data-races and the Fortran-specific
# -fstack-arrays, unless -fmax-stack-var-size is specified, and -fno-protect-parens.
# It turns off -fsemantic-interposition.
# In our specific application this is *probably* okay to use
#.PHONY: run
#runfast: run.c
#	$(CC) -O3 -o run -fopenmp -march=native run.c -lm

# additionally compiles with OpenMP, allowing multithreaded runs
# make sure to also enable multiple threads when running, e.g.:
# OMP_NUM_THREADS=4 ./run out/model.bin
.PHONY: runomp
runomp: run.c
	$(CC) -O3 -fopenmp -march=native run.c  -lm  -o run


.PHONY: clean
clean:
	rm -f run runcu runcublas
