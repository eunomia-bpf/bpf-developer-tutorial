#include <stdio.h>
#include <cuda_runtime.h>

// Define a simple PTX inline assembly function that multiplies a number by 2
__device__ int multiplyByTwo(int x) {
    int result;
    asm("mul.lo.s32 %0, %1, 2;" : "=r"(result) : "r"(x));
    return result;
}

// CUDA kernel using PTX inline assembly
__global__ void vectorMultiplyByTwoPTX(int* input, int* output, int n) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < n) {
        output[idx] = multiplyByTwo(input[idx]);
    }
}

// Host function to initialize data and launch kernel
void vectorMultiplyByTwo(int* h_input, int* h_output, int n) {
    int *d_input, *d_output;
    
    // Allocate device memory
    cudaMalloc(&d_input, n * sizeof(int));
    cudaMalloc(&d_output, n * sizeof(int));
    
    // Copy input data to device
    cudaMemcpy(d_input, h_input, n * sizeof(int), cudaMemcpyHostToDevice);
    
    // Launch kernel
    int blockSize = 256;
    int numBlocks = (n + blockSize - 1) / blockSize;
    vectorMultiplyByTwoPTX<<<numBlocks, blockSize>>>(d_input, d_output, n);
    
    // Copy result back to host
    cudaMemcpy(h_output, d_output, n * sizeof(int), cudaMemcpyDeviceToHost);
    
    // Free device memory
    cudaFree(d_input);
    cudaFree(d_output);
}

int main() {
    const int n = 1000;
    int h_input[n];
    int h_output[n];
    
    // Initialize input data
    for (int i = 0; i < n; i++) {
        h_input[i] = i;
    }
    
    // Perform vector multiplication
    vectorMultiplyByTwo(h_input, h_output, n);
    
    // Verify results
    printf("First 10 results:\n");
    for (int i = 0; i < 10; i++) {
        printf("%d * 2 = %d\n", h_input[i], h_output[i]);
    }
    
    return 0;
} 