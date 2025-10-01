/**
 * double_bandwidth.cpp - CXL double bandwidth microbenchmark
 * 
 * This microbenchmark measures the bandwidth of CXL by adjusting 
 * the ratio of readers to writers, simulating bidirectional traffic.
 */

#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

// Default parameters
constexpr size_t DEFAULT_BUFFER_SIZE = 1 * 1024 * 1024 * 1024UL; // 1GB
constexpr size_t DEFAULT_BLOCK_SIZE = 4096;                      // 4KB
constexpr int DEFAULT_DURATION = 1000;                             // seconds
constexpr int DEFAULT_NUM_THREADS = 20;                           // total threads
constexpr float DEFAULT_READ_RATIO = 0.5;                        // 50% readers, 50% writers

struct ThreadStats {
    size_t bytes_processed = 0;
    size_t operations = 0;
};

struct BenchmarkConfig {
    size_t buffer_size = DEFAULT_BUFFER_SIZE;
    size_t block_size = DEFAULT_BLOCK_SIZE;
    int duration = DEFAULT_DURATION;
    int num_threads = DEFAULT_NUM_THREADS;
    float read_ratio = DEFAULT_READ_RATIO;
    std::string device_path;
    bool use_mmap = false;
    bool is_cxl_mem = false;
};

void print_usage(const char* prog_name) {
    std::cerr << "Usage: " << prog_name << " [OPTIONS]\n"
              << "Options:\n"
              << "  -b, --buffer-size=SIZE    Total buffer size in bytes (default: 1GB)\n"
              << "  -s, --block-size=SIZE     Block size for read/write operations (default: 4KB)\n"
              << "  -t, --threads=NUM         Total number of threads (default: 4)\n"
              << "  -d, --duration=SECONDS    Test duration in seconds (default: 10)\n"
              << "  -r, --read-ratio=RATIO    Ratio of readers (0.0-1.0, default: 0.5)\n"
              << "  -D, --device=PATH         CXL device path (if not specified, memory is used)\n"
              << "  -m, --mmap                Use mmap instead of read/write syscalls\n"
              << "  -c, --cxl-mem             Indicate the device is CXL memory\n"
              << "  -h, --help                Show this help message\n";
}

BenchmarkConfig parse_args(int argc, char* argv[]) {
    BenchmarkConfig config;
    
    static struct option long_options[] = {
        {"buffer-size", required_argument, 0, 'b'},
        {"block-size",  required_argument, 0, 's'},
        {"threads",     required_argument, 0, 't'},
        {"duration",    required_argument, 0, 'd'},
        {"read-ratio",  required_argument, 0, 'r'},
        {"device",      required_argument, 0, 'D'},
        {"mmap",        no_argument,       0, 'm'},
        {"cxl-mem",     no_argument,       0, 'c'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "b:s:t:d:r:D:mch", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'b':
                config.buffer_size = std::stoull(optarg);
                break;
            case 's':
                config.block_size = std::stoull(optarg);
                break;
            case 't':
                config.num_threads = std::stoi(optarg);
                break;
            case 'd':
                config.duration = std::stoi(optarg);
                break;
            case 'r':
                config.read_ratio = std::stof(optarg);
                if (config.read_ratio < 0.0 || config.read_ratio > 1.0) {
                    std::cerr << "Read ratio must be between 0.0 and 1.0\n";
                    exit(1);
                }
                break;
            case 'D':
                config.device_path = optarg;
                break;
            case 'm':
                config.use_mmap = true;
                break;
            case 'c':
                config.is_cxl_mem = true;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }
    
    return config;
}

void reader_thread(void* buffer, size_t buffer_size, size_t block_size, 
                   std::atomic<bool>& stop_flag, ThreadStats& stats) {
    std::vector<char> local_buffer(block_size);
    size_t offset = 0;
    
    while (!stop_flag.load(std::memory_order_relaxed)) {
        // Read block from the buffer
        std::memcpy(local_buffer.data(), static_cast<char*>(buffer) + offset, block_size);
        
        // Move to next block with wrap-around
        offset = (offset + block_size) % (buffer_size - block_size);
        
        // Update statistics
        stats.bytes_processed += block_size;
        stats.operations++;
    }
}

void writer_thread(void* buffer, size_t buffer_size, size_t block_size, 
                  std::atomic<bool>& stop_flag, ThreadStats& stats) {
    std::vector<char> local_buffer(block_size, 'W');  // Fill with 'W' for writers
    size_t offset = 0;
    
    while (!stop_flag.load(std::memory_order_relaxed)) {
        // Write block to the buffer
        std::memcpy(static_cast<char*>(buffer) + offset, local_buffer.data(), block_size);
        
        // Move to next block with wrap-around
        offset = (offset + block_size) % (buffer_size - block_size);
        
        // Update statistics
        stats.bytes_processed += block_size;
        stats.operations++;
    }
}

void device_reader_thread(int fd, size_t file_size, size_t block_size, 
                         std::atomic<bool>& stop_flag, ThreadStats& stats) {
    std::vector<char> local_buffer(block_size);
    size_t offset = 0;
    
    while (!stop_flag.load(std::memory_order_relaxed)) {
        // Seek to the position
        lseek(fd, offset, SEEK_SET);
        
        // Read block from the device
        ssize_t bytes_read = read(fd, local_buffer.data(), block_size);
        if (bytes_read <= 0) {
            std::cerr << "Error reading from device: " << strerror(errno) << std::endl;
            break;
        }
        
        // Move to next block with wrap-around
        offset = (offset + block_size) % (file_size - block_size);
        
        // Update statistics
        stats.bytes_processed += bytes_read;
        stats.operations++;
    }
}

void device_writer_thread(int fd, size_t file_size, size_t block_size, 
                         std::atomic<bool>& stop_flag, ThreadStats& stats) {
    std::vector<char> local_buffer(block_size, 'W');  // Fill with 'W' for writers
    size_t offset = 0;
    
    while (!stop_flag.load(std::memory_order_relaxed)) {
        // Seek to the position
        lseek(fd, offset, SEEK_SET);
        
        // Write block to the device
        ssize_t bytes_written = write(fd, local_buffer.data(), block_size);
        if (bytes_written <= 0) {
            std::cerr << "Error writing to device: " << strerror(errno) << std::endl;
            break;
        }
        
        // Move to next block with wrap-around
        offset = (offset + block_size) % (file_size - block_size);
        
        // Update statistics
        stats.bytes_processed += bytes_written;
        stats.operations++;
    }
}

void mmap_reader_thread(void* mapped_area, size_t file_size, size_t block_size, 
                       std::atomic<bool>& stop_flag, ThreadStats& stats) {
    std::vector<char> local_buffer(block_size);
    size_t offset = 0;
    
    while (!stop_flag.load(std::memory_order_relaxed)) {
        // Read block from the mapped area
        std::memcpy(local_buffer.data(), static_cast<char*>(mapped_area) + offset, block_size);
        
        // Move to next block with wrap-around
        offset = (offset + block_size) % (file_size - block_size);
        
        // Update statistics
        stats.bytes_processed += block_size;
        stats.operations++;
    }
}

void mmap_writer_thread(void* mapped_area, size_t file_size, size_t block_size, 
                       std::atomic<bool>& stop_flag, ThreadStats& stats) {
    std::vector<char> local_buffer(block_size, 'W');  // Fill with 'W' for writers
    size_t offset = 0;
    
    while (!stop_flag.load(std::memory_order_relaxed)) {
        // Write block to the mapped area
        std::memcpy(static_cast<char*>(mapped_area) + offset, local_buffer.data(), block_size);
        
        // Move to next block with wrap-around
        offset = (offset + block_size) % (file_size - block_size);
        
        // Update statistics
        stats.bytes_processed += block_size;
        stats.operations++;
    }
}

int main(int argc, char* argv[]) {
    BenchmarkConfig config = parse_args(argc, argv);
    
    // Calculate reader and writer thread counts
    int num_readers = static_cast<int>(config.num_threads * config.read_ratio);
    int num_writers = config.num_threads - num_readers;
    
    std::cout << "=== CXL Double Bandwidth Microbenchmark ===" << std::endl;
    std::cout << "Buffer size: " << config.buffer_size << " bytes" << std::endl;
    std::cout << "Block size: " << config.block_size << " bytes" << std::endl;
    std::cout << "Duration: " << config.duration << " seconds" << std::endl;
    std::cout << "Total threads: " << config.num_threads << std::endl;
    std::cout << "Read ratio: " << config.read_ratio << " (" << num_readers << " readers, " 
              << num_writers << " writers)" << std::endl;
    
    if (!config.device_path.empty()) {
        std::cout << "Device: " << config.device_path << std::endl;
        std::cout << "Access method: " << (config.use_mmap ? "mmap" : "read/write") << std::endl;
        std::cout << "Memory type: " << (config.is_cxl_mem ? "CXL memory" : "Regular device") << std::endl;
    } else {
        std::cout << "Using system memory for testing" << std::endl;
    }
    
    std::cout << "\nStarting benchmark..." << std::endl;
    
    // Prepare threads and resources
    std::vector<std::thread> threads;
    std::vector<ThreadStats> thread_stats(config.num_threads);
    std::atomic<bool> stop_flag(false);
    
    void* buffer = nullptr;
    int fd = -1;
    void* mapped_area = nullptr;
    
    try {
        if (config.device_path.empty()) {
            // Allocate memory buffer
            buffer = aligned_alloc(4096, config.buffer_size);
            if (!buffer) {
                std::cerr << "Failed to allocate memory: " << strerror(errno) << std::endl;
                return 1;
            }
            
            // Initialize buffer with some data
            std::memset(buffer, 'A', config.buffer_size);
            
            // Create reader and writer threads for memory
            for (int i = 0; i < num_readers; i++) {
                threads.emplace_back(reader_thread, buffer, config.buffer_size, 
                                   config.block_size, std::ref(stop_flag), 
                                   std::ref(thread_stats[i]));
            }
            
            for (int i = 0; i < num_writers; i++) {
                threads.emplace_back(writer_thread, buffer, config.buffer_size, 
                                   config.block_size, std::ref(stop_flag), 
                                   std::ref(thread_stats[num_readers + i]));
            }
        } else {
            // Open the device
            fd = open(config.device_path.c_str(), O_RDWR | O_DIRECT);
            if (fd < 0) {
                std::cerr << "Failed to open device " << config.device_path 
                        << ": " << strerror(errno) << std::endl;
                return 1;
            }
            
            if (config.use_mmap) {
                // Use mmap for device access
                mapped_area = mmap(NULL, config.buffer_size, PROT_READ | PROT_WRITE, 
                                 MAP_SHARED, fd, 0);
                if (mapped_area == MAP_FAILED) {
                    std::cerr << "Failed to mmap device: " << strerror(errno) << std::endl;
                    close(fd);
                    return 1;
                }
                
                // Create reader and writer threads for mmap
                for (int i = 0; i < num_readers; i++) {
                    threads.emplace_back(mmap_reader_thread, mapped_area, config.buffer_size, 
                                       config.block_size, std::ref(stop_flag), 
                                       std::ref(thread_stats[i]));
                }
                
                for (int i = 0; i < num_writers; i++) {
                    threads.emplace_back(mmap_writer_thread, mapped_area, config.buffer_size, 
                                       config.block_size, std::ref(stop_flag), 
                                       std::ref(thread_stats[num_readers + i]));
                }
            } else {
                // Use read/write for device access
                for (int i = 0; i < num_readers; i++) {
                    threads.emplace_back(device_reader_thread, fd, config.buffer_size, 
                                       config.block_size, std::ref(stop_flag), 
                                       std::ref(thread_stats[i]));
                }
                
                for (int i = 0; i < num_writers; i++) {
                    threads.emplace_back(device_writer_thread, fd, config.buffer_size, 
                                       config.block_size, std::ref(stop_flag), 
                                       std::ref(thread_stats[num_readers + i]));
                }
            }
        }
        
        // Run the benchmark for the specified duration
        auto start_time = std::chrono::steady_clock::now();
        std::this_thread::sleep_for(std::chrono::seconds(config.duration));
        stop_flag.store(true, std::memory_order_relaxed);
        auto end_time = std::chrono::steady_clock::now();
        
        // Wait for all threads to finish
        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        
        // Calculate total stats
        double elapsed_seconds = std::chrono::duration<double>(end_time - start_time).count();
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
        std::cout << "\n=== Results ===" << std::endl;
        std::cout << "Test duration: " << elapsed_seconds << " seconds" << std::endl;
        
        if (num_readers > 0) {
            double read_bandwidth_mbps = (total_read_bytes / (1024.0 * 1024.0)) / elapsed_seconds;
            double read_iops = total_read_ops / elapsed_seconds;
            std::cout << "Read bandwidth: " << read_bandwidth_mbps << " MB/s" << std::endl;
            std::cout << "Read IOPS: " << read_iops << " ops/s" << std::endl;
        }
        
        if (num_writers > 0) {
            double write_bandwidth_mbps = (total_write_bytes / (1024.0 * 1024.0)) / elapsed_seconds;
            double write_iops = total_write_ops / elapsed_seconds;
            std::cout << "Write bandwidth: " << write_bandwidth_mbps << " MB/s" << std::endl;
            std::cout << "Write IOPS: " << write_iops << " ops/s" << std::endl;
        }
        
        double total_bandwidth_mbps = ((total_read_bytes + total_write_bytes) / (1024.0 * 1024.0)) / elapsed_seconds;
        double total_iops = (total_read_ops + total_write_ops) / elapsed_seconds;
        std::cout << "Total bandwidth: " << total_bandwidth_mbps << " MB/s" << std::endl;
        std::cout << "Total IOPS: " << total_iops << " ops/s" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    // Clean up resources
    if (mapped_area && mapped_area != MAP_FAILED) {
        munmap(mapped_area, config.buffer_size);
    }
    
    if (fd >= 0) {
        close(fd);
    }
    
    if (buffer) {
        free(buffer);
    }
    
    return 0;
}