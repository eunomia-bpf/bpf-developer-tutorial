/* CUDA benchmark for measuring tracing overhead
 * This program performs a series of CUDA operations repeatedly and
 * measures the execution time to analyze tracing overhead.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <cuda_runtime.h>

// Number of iterations for the benchmark
#define NUM_ITERATIONS 10000
// Size of test data in bytes
#define DATA_SIZE (1024 * 1024)  // 1MB

// CUDA kernel that performs a simple operation (multiply by 2)
__global__ void multiplyBy2Kernel(float *data, int n) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < n) {
        data[idx] = data[idx] * 2.0f;
    }
}

// Function to check CUDA errors
void checkCudaError(cudaError_t err, const char *msg) {
    if (err != cudaSuccess) {
        fprintf(stderr, "CUDA Error: %s: %s\n", msg, cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
}

// Function to measure the execution time of a CUDA operation
double measureOperation(const char *name, int iterations, void (*operation)(void)) {
    cudaEvent_t start, stop;
    checkCudaError(cudaEventCreate(&start), "cudaEventCreate start");
    checkCudaError(cudaEventCreate(&stop), "cudaEventCreate stop");
    
    // Warm-up run
    operation();
    
    // Synchronize device before timing
    cudaDeviceSynchronize();
    
    // Start timing
    checkCudaError(cudaEventRecord(start), "cudaEventRecord start");
    
    // Run the operation multiple times
    for (int i = 0; i < iterations; i++) {
        operation();
    }
    
    // Stop timing
    checkCudaError(cudaEventRecord(stop), "cudaEventRecord stop");
    checkCudaError(cudaEventSynchronize(stop), "cudaEventSynchronize");
    
    float milliseconds = 0;
    checkCudaError(cudaEventElapsedTime(&milliseconds, start, stop), "cudaEventElapsedTime");
    
    // Calculate average time per operation in microseconds
    double microseconds_per_op = (milliseconds * 1000.0) / iterations;
    
    printf("%-20s: %10.2f µs per operation (total: %.2f ms for %d iterations)\n", 
           name, microseconds_per_op, milliseconds, iterations);
    
    // Cleanup
    checkCudaError(cudaEventDestroy(start), "cudaEventDestroy start");
    checkCudaError(cudaEventDestroy(stop), "cudaEventDestroy stop");
    
    return microseconds_per_op;
}

// CUDA operations to benchmark

// Memory allocation benchmark
float *d_data = NULL;
void cudaMallocOperation() {
    if (d_data != NULL) {
        cudaFree(d_data);
        d_data = NULL;
    }
    cudaMalloc((void**)&d_data, DATA_SIZE);
}

// Memory copy (host to device) benchmark
float *h_data = NULL;
void cudaMemcpyHToDOperation() {
    if (h_data == NULL) {
        h_data = (float*)malloc(DATA_SIZE);
        for (int i = 0; i < DATA_SIZE / sizeof(float); i++) {
            h_data[i] = (float)i;
        }
    }
    if (d_data == NULL) {
        cudaMalloc((void**)&d_data, DATA_SIZE);
    }
    cudaMemcpy(d_data, h_data, DATA_SIZE, cudaMemcpyHostToDevice);
}

// Kernel launch benchmark
void cudaKernelLaunchOperation() {
    if (d_data == NULL) {
        cudaMalloc((void**)&d_data, DATA_SIZE);
        if (h_data == NULL) {
            h_data = (float*)malloc(DATA_SIZE);
            for (int i = 0; i < DATA_SIZE / sizeof(float); i++) {
                h_data[i] = (float)i;
            }
        }
        cudaMemcpy(d_data, h_data, DATA_SIZE, cudaMemcpyHostToDevice);
    }
    
    int numElements = DATA_SIZE / sizeof(float);
    int blockSize = 256;
    int numBlocks = (numElements + blockSize - 1) / blockSize;
    
    multiplyBy2Kernel<<<numBlocks, blockSize>>>(d_data, numElements);
    cudaDeviceSynchronize();
}

// Memory copy (device to host) benchmark
void cudaMemcpyDToHOperation() {
    if (d_data == NULL) {
        cudaMalloc((void**)&d_data, DATA_SIZE);
        if (h_data == NULL) {
            h_data = (float*)malloc(DATA_SIZE);
            for (int i = 0; i < DATA_SIZE / sizeof(float); i++) {
                h_data[i] = (float)i;
            }
        }
        cudaMemcpy(d_data, h_data, DATA_SIZE, cudaMemcpyHostToDevice);
        
        int numElements = DATA_SIZE / sizeof(float);
        int blockSize = 256;
        int numBlocks = (numElements + blockSize - 1) / blockSize;
        
        multiplyBy2Kernel<<<numBlocks, blockSize>>>(d_data, numElements);
        cudaDeviceSynchronize();
    }
    
    cudaMemcpy(h_data, d_data, DATA_SIZE, cudaMemcpyDeviceToHost);
}

// Memory free benchmark
void cudaFreeOperation() {
    if (d_data != NULL) {
        cudaFree(d_data);
        d_data = NULL;
    }
}

// Full operation (malloc + memcpy H2D + kernel + memcpy D2H + free)
void fullOperation() {
    // Allocate device memory
    float *d_temp;
    cudaMalloc((void**)&d_temp, DATA_SIZE);
    
    // Allocate and initialize host data if needed
    if (h_data == NULL) {
        h_data = (float*)malloc(DATA_SIZE);
        for (int i = 0; i < DATA_SIZE / sizeof(float); i++) {
            h_data[i] = (float)i;
        }
    }
    
    // Copy data to device
    cudaMemcpy(d_temp, h_data, DATA_SIZE, cudaMemcpyHostToDevice);
    
    // Launch kernel
    int numElements = DATA_SIZE / sizeof(float);
    int blockSize = 256;
    int numBlocks = (numElements + blockSize - 1) / blockSize;
    
    multiplyBy2Kernel<<<numBlocks, blockSize>>>(d_temp, numElements);
    cudaDeviceSynchronize();
    
    // Copy data back to host
    cudaMemcpy(h_data, d_temp, DATA_SIZE, cudaMemcpyDeviceToHost);
    
    // Free device memory
    cudaFree(d_temp);
}

int main(int argc, char **argv) {
    printf("CUDA Benchmark for Tracing Overhead\n");
    printf("-----------------------------------\n");
    printf("Data size: %d bytes (%d KB)\n", DATA_SIZE, DATA_SIZE / 1024);
    printf("Iterations: %d\n\n", NUM_ITERATIONS);
    
    // Run benchmarks
    double malloc_time = measureOperation("cudaMalloc", NUM_ITERATIONS, cudaMallocOperation);
    double memcpy_h2d_time = measureOperation("cudaMemcpyH2D", NUM_ITERATIONS, cudaMemcpyHToDOperation);
    double kernel_time = measureOperation("cudaLaunchKernel", NUM_ITERATIONS, cudaKernelLaunchOperation);
    double memcpy_d2h_time = measureOperation("cudaMemcpyD2H", NUM_ITERATIONS, cudaMemcpyDToHOperation);
    double free_time = measureOperation("cudaFree", NUM_ITERATIONS, cudaFreeOperation);
    double full_time = measureOperation("Full Operation", NUM_ITERATIONS, fullOperation);
    
    // Print summary
    printf("\nSummary (average time per operation):\n");
    printf("-----------------------------------\n");
    printf("cudaMalloc:       %10.2f µs\n", malloc_time);
    printf("cudaMemcpyH2D:    %10.2f µs\n", memcpy_h2d_time);
    printf("cudaLaunchKernel: %10.2f µs\n", kernel_time);
    printf("cudaMemcpyD2H:    %10.2f µs\n", memcpy_d2h_time);
    printf("cudaFree:         %10.2f µs\n", free_time);
    printf("Full Operation:   %10.2f µs\n", full_time);
    
    // Free host memory
    if (h_data != NULL) {
        free(h_data);
    }
    
    // Make sure device memory is freed
    if (d_data != NULL) {
        cudaFree(d_data);
    }
    
    return 0;
} 