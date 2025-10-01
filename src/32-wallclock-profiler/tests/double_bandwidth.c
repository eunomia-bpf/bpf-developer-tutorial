/**
 * double_bandwidth.c - CXL double bandwidth microbenchmark
 * 
 * This microbenchmark measures the bandwidth of CXL memory
 * using reader and writer threads.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <stdatomic.h>
#include <stdint.h>

typedef struct {
    size_t bytes_processed;
    size_t operations;
} ThreadStats;

typedef struct {
    void* buffer;
    size_t buffer_size;
    size_t block_size;
    atomic_bool* stop_flag;
    ThreadStats* stats;
} ThreadArgs;

void* reader_thread(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    char* local_buffer = (char*)malloc(args->block_size);
    if (!local_buffer) return NULL;
    
    size_t offset = 0;
    
    while (!atomic_load(args->stop_flag)) {
        // Read block from the buffer
        memcpy(local_buffer, (char*)args->buffer + offset, args->block_size);
        
        // Move to next block with wrap-around
        offset = (offset + args->block_size) % (args->buffer_size - args->block_size);
        
        // Update statistics
        args->stats->bytes_processed += args->block_size;
        args->stats->operations++;
    }
    
    free(local_buffer);
    return NULL;
}

void* writer_thread(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    char* local_buffer = (char*)malloc(args->block_size);
    if (!local_buffer) return NULL;
    
    // Fill with 'W' for writers
    memset(local_buffer, 'W', args->block_size);
    size_t offset = 0;
    
    while (!atomic_load(args->stop_flag)) {
        // Write block to the buffer
        memcpy((char*)args->buffer + offset, local_buffer, args->block_size);
        // for (size_t i = 0; i < args->block_size; i++) {
        //     ((char*)args->buffer)[offset + i] = local_buffer[i];
        // }
        
        // Move to next block with wrap-around
        offset = (offset + args->block_size) % (args->buffer_size - args->block_size);
        
        // Update statistics
        args->stats->bytes_processed += args->block_size;
        args->stats->operations++;
    }
    
    free(local_buffer);
    return NULL;
}

int main() {
    // Basic configuration
    size_t buffer_size = 1 * 1024 * 1024 * 1024UL;  // 1GB
    size_t block_size = 4096;                         // 4KB
    int duration = 100;                                // 10 seconds
    int num_readers = 2;                              // 2 reader threads
    int num_writers = 2;                              // 2 writer threads
    int total_threads = num_readers + num_writers;
    
    printf("=== CXL Double Bandwidth Microbenchmark ===\n");
    printf("Buffer size: %zu bytes\n", buffer_size);
    printf("Block size: %zu bytes\n", block_size);
    printf("Duration: %d seconds\n", duration);
    printf("Reader threads: %d\n", num_readers);
    printf("Writer threads: %d\n", num_writers);
    printf("\nStarting benchmark...\n");
    
    // Allocate memory buffer
    void* buffer = aligned_alloc(4096, buffer_size);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    
    // Initialize buffer with some data
    memset(buffer, 'A', buffer_size);
    
    // Prepare threads and resources
    pthread_t* threads = (pthread_t*)malloc(total_threads * sizeof(pthread_t));
    ThreadStats* thread_stats = (ThreadStats*)calloc(total_threads, sizeof(ThreadStats));
    ThreadArgs* thread_args = (ThreadArgs*)malloc(total_threads * sizeof(ThreadArgs));
    atomic_bool stop_flag = ATOMIC_VAR_INIT(0);
    
    if (!threads || !thread_stats || !thread_args) {
        fprintf(stderr, "Failed to allocate thread resources\n");
        free(buffer);
        return 1;
    }
    
    // Initialize thread arguments
    for (int i = 0; i < total_threads; i++) {
        thread_args[i].buffer = buffer;
        thread_args[i].buffer_size = buffer_size;
        thread_args[i].block_size = block_size;
        thread_args[i].stop_flag = &stop_flag;
        thread_args[i].stats = &thread_stats[i];
    }
    
    // Create reader threads
    for (int i = 0; i < num_readers; i++) {
        if (pthread_create(&threads[i], NULL, reader_thread, &thread_args[i]) != 0) {
            fprintf(stderr, "Failed to create reader thread %d\n", i);
            return 1;
        }
    }
    
    // Create writer threads
    for (int i = 0; i < num_writers; i++) {
        if (pthread_create(&threads[num_readers + i], NULL, writer_thread, &thread_args[num_readers + i]) != 0) {
            fprintf(stderr, "Failed to create writer thread %d\n", i);
            return 1;
        }
    }
    
    // Run the benchmark for the specified duration
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    sleep(duration);
    atomic_store(&stop_flag, 1);
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    
    // Wait for all threads to finish
    for (int i = 0; i < total_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Calculate elapsed time
    double elapsed_seconds = (end_time.tv_sec - start_time.tv_sec) + 
                           (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    
    // Calculate total stats
    size_t total_read_bytes = 0;
    size_t total_read_ops = 0;
    size_t total_write_bytes = 0;
    size_t total_write_ops = 0;
    
    for (int i = 0; i < num_readers; i++) {
        total_read_bytes += thread_stats[i].bytes_processed;
        total_read_ops += thread_stats[i].operations;
    }
    
    for (int i = 0; i < num_writers; i++) {
        total_write_bytes += thread_stats[num_readers + i].bytes_processed;
        total_write_ops += thread_stats[num_readers + i].operations;
    }
    
    // Print results
    printf("\n=== Results ===\n");
    printf("Test duration: %.2f seconds\n", elapsed_seconds);
    
    double read_bandwidth_mbps = (total_read_bytes / (1024.0 * 1024.0)) / elapsed_seconds;
    double read_iops = total_read_ops / elapsed_seconds;
    printf("Read bandwidth: %.2f MB/s\n", read_bandwidth_mbps);
    printf("Read IOPS: %.2f ops/s\n", read_iops);
    
    double write_bandwidth_mbps = (total_write_bytes / (1024.0 * 1024.0)) / elapsed_seconds;
    double write_iops = total_write_ops / elapsed_seconds;
    printf("Write bandwidth: %.2f MB/s\n", write_bandwidth_mbps);
    printf("Write IOPS: %.2f ops/s\n", write_iops);
    
    double total_bandwidth_mbps = ((total_read_bytes + total_write_bytes) / (1024.0 * 1024.0)) / elapsed_seconds;
    double total_iops = (total_read_ops + total_write_ops) / elapsed_seconds;
    printf("Total bandwidth: %.2f MB/s\n", total_bandwidth_mbps);
    printf("Total IOPS: %.2f ops/s\n", total_iops);
    
    // Clean up resources
    free(threads);
    free(thread_stats);
    free(thread_args);
    free(buffer);
    
    return 0;
}