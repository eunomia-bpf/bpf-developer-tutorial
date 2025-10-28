#
# Makefile for mock LLM inference application
#
ifndef OS
    OS   := $(shell uname)
    HOST_ARCH := $(shell uname -m)
endif

CUDA_INSTALL_PATH ?= /usr/local/cuda-12.9
NVCC := "$(CUDA_INSTALL_PATH)/bin/nvcc"
INCLUDES := -I"$(CUDA_INSTALL_PATH)/include"

ifeq ($(OS),Windows_NT)
    LIB_PATH ?= ..\..\lib64
else
    LIB_PATH ?= $(CUDA_INSTALL_PATH)/lib64
endif

# Point to the necessary cross-compiler.
NVCCFLAGS :=

ifneq ($(TARGET_ARCH), $(HOST_ARCH))
    ifeq ($(TARGET_ARCH), aarch64)
        ifeq ($(TARGET_OS), linux)
            HOST_COMPILER ?= aarch64-linux-gnu-g++
        else ifeq ($(TARGET_OS),qnx)
            ifeq ($(QNX_HOST),)
                $(error ERROR - QNX_HOST must be passed to the QNX host toolchain)
            endif
            ifeq ($(QNX_TARGET),)
                $(error ERROR - QNX_TARGET must be passed to the QNX target toolchain)
            endif
            HOST_COMPILER ?= $(QNX_HOST)/usr/bin/q++
            ifndef QPP_CONFIG_VERSION
                QPP_CONFIG_VERSION = 12.2.0
            endif
            $(info QPP_CONFIG_VERSION = $(QPP_CONFIG_VERSION))
            NVCCFLAGS += --qpp-config $(QPP_CONFIG_VERSION),gcc_ntoaarch64le -lsocket
        endif
    endif

    ifdef HOST_COMPILER
        NVCC_COMPILER := -ccbin $(HOST_COMPILER)
    endif
endif

all: llm-inference

llm-inference: llm-inference.cu
	$(NVCC) $(NVCC_COMPILER) $(INCLUDES) -o llm-inference llm-inference.cu -L $(LIB_PATH) -lcudart -std=c++17 -Wno-deprecated-gpu-targets --no-device-link

clean:
	rm -f llm-inference *.o *.bak
