#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/eventfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

// Configuration
#define NUM_WORKER_THREADS 4
#define REQUEST_QUEUE_SIZE 100
#define SIMULATION_DURATION 6000  // seconds
#define BUFFER_SIZE 4096

// Global state
volatile int running = 1;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

// Pipe for blocking operations
int blocking_pipe[2];
int dummy_eventfd;

// Request queue simulation
typedef struct {
    int request_id;
    int request_type; // 0=cpu_math, 1=cpu_string, 2=cpu_sort, 3=file_io, 4=network, 5=poll_wait
    struct timespec arrival_time;
} request_t;

request_t request_queue[REQUEST_QUEUE_SIZE];
int queue_head = 0;
int queue_tail = 0;
int queue_size = 0;

// Statistics
volatile long total_requests_generated = 0;
volatile long total_requests_processed = 0;
volatile long cpu_math_requests = 0;
volatile long cpu_string_requests = 0;
volatile long cpu_sort_requests = 0;
volatile long file_io_requests = 0;
volatile long network_requests = 0;
volatile long poll_wait_requests = 0;

// Signal handler
void signal_handler(int sig) {
    printf("\n🛑 Received signal %d, shutting down gracefully...\n", sig);
    running = 0;
}

// Get current timestamp
void get_timestamp(struct timespec *ts) {
    clock_gettime(CLOCK_MONOTONIC, ts);
}

// Calculate time difference in microseconds
long time_diff_us(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) * 1000000 + 
           (end->tv_nsec - start->tv_nsec) / 1000;
}

// Enqueue request
int enqueue_request(request_t *req) {
    pthread_mutex_lock(&queue_mutex);
    
    if (queue_size >= REQUEST_QUEUE_SIZE) {
        pthread_mutex_unlock(&queue_mutex);
        return -1; // Queue full
    }
    
    request_queue[queue_tail] = *req;
    queue_tail = (queue_tail + 1) % REQUEST_QUEUE_SIZE;
    queue_size++;
    
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
    return 0;
}

// Dequeue request
int dequeue_request(request_t *req) {
    pthread_mutex_lock(&queue_mutex);
    
    while (queue_size == 0 && running) {
        pthread_cond_wait(&queue_cond, &queue_mutex);
    }
    
    if (!running && queue_size == 0) {
        pthread_mutex_unlock(&queue_mutex);
        return -1; // Shutting down
    }
    
    *req = request_queue[queue_head];
    queue_head = (queue_head + 1) % REQUEST_QUEUE_SIZE;
    queue_size--;
    
    pthread_mutex_unlock(&queue_mutex);
    return 0;
}

// CPU-intensive: Mathematical computation
void simulate_cpu_math_work(int request_id, int intensity) {
    volatile double result = 0.0;
    int iterations = intensity * 50000;
    
    // Complex mathematical operations
    for (int i = 1; i < iterations; i++) {
        result += sin(i) * cos(i) + sqrt(i);
        result += log(i + 1) * exp(i % 100 / 100.0);
        
        // Matrix-like operations
        double matrix[4][4];
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 4; k++) {
                matrix[j][k] = sin(i + j + k) * result;
            }
        }
        
        if (i % 10000 == 0) {
            __asm__("" : "+g" (result) : :); // Prevent optimization
        }
    }
    
    // Prime number computation
    for (int n = 2; n < intensity * 1000; n++) {
        int is_prime = 1;
        for (int d = 2; d * d <= n; d++) {
            if (n % d == 0) {
                is_prime = 0;
                break;
            }
        }
        if (is_prime) result += n;
    }
}

// CPU-intensive: String processing
void simulate_cpu_string_work(int request_id, int intensity) {
    char *buffer = malloc(BUFFER_SIZE * intensity);
    char *temp = malloc(BUFFER_SIZE);
    
    // String generation and manipulation
    for (int i = 0; i < intensity * 1000; i++) {
        snprintf(temp, BUFFER_SIZE, 
                "Request_%d_Processing_String_Operation_%d_With_Data_%d", 
                request_id, i, rand());
        
        // String operations
        strcat(buffer, temp);
        char *found = strstr(buffer, "Processing");
        if (found) {
            memmove(found, found + 10, strlen(found + 10) + 1);
        }
        
        // Base64-like encoding simulation
        for (char *p = temp; *p; p++) {
            *p = (*p + i) % 128;
        }
        
        if (strlen(buffer) > BUFFER_SIZE * intensity - 1000) {
            buffer[0] = '\0'; // Reset buffer
        }
    }
    
    // Pattern matching
    const char *patterns[] = {"Request", "Processing", "Data", "Operation"};
    for (int i = 0; i < 4; i++) {
        char *pos = buffer;
        while ((pos = strstr(pos, patterns[i])) != NULL) {
            pos++;
        }
    }
    
    free(buffer);
    free(temp);
}

// CPU-intensive: Sorting and data structures
void simulate_cpu_sort_work(int request_id, int intensity) {
    int size = intensity * 500;
    int *array = malloc(size * sizeof(int));
    
    // Generate random data
    for (int i = 0; i < size; i++) {
        array[i] = rand() % (size * 10);
    }
    
    // Bubble sort (intentionally inefficient for CPU load)
    for (int i = 0; i < size - 1; i++) {
        for (int j = 0; j < size - i - 1; j++) {
            if (array[j] > array[j + 1]) {
                int temp = array[j];
                array[j] = array[j + 1];
                array[j + 1] = temp;
            }
        }
        
        // Add some computation every 100 iterations
        if (i % 100 == 0) {
            volatile long hash = 0;
            for (int k = 0; k < 1000; k++) {
                hash = hash * 31 + array[k % size];
            }
        }
    }
    
    // Binary search operations
    int target = array[size / 2];
    for (int search = 0; search < intensity * 100; search++) {
        int left = 0, right = size - 1;
        while (left <= right) {
            int mid = (left + right) / 2;
            if (array[mid] == target) break;
            else if (array[mid] < target) left = mid + 1;
            else right = mid - 1;
        }
    }
    
    free(array);
}

// Blocking I/O: File operations with real syscalls
void simulate_file_io(int request_id) {
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/webserver_test_%d_%ld.tmp", 
             request_id, time(NULL));
    
    // Write operation with multiple syscalls
    int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        char data[4096];
        for (int i = 0; i < 200; i++) {
            snprintf(data, sizeof(data), 
                    "Request %d chunk %d: Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n", 
                    request_id, i);
            
            ssize_t written = write(fd, data, strlen(data));
            if (written > 0) {
                fsync(fd); // Force disk write - blocking syscall
            }
            
            // Add some file metadata operations
            struct stat st;
            fstat(fd, &st);
        }
        close(fd);
    }
    
    // Read operation with blocking
    fd = open(filename, O_RDONLY);
    if (fd >= 0) {
        char buffer[1024];
        ssize_t bytes_read;
        while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
            // Process data with some CPU work
            for (int i = 0; i < bytes_read; i++) {
                buffer[i] = buffer[i] ^ 0x55; // Simple XOR
            }
        }
        close(fd);
    }
    
    // File system operations
    chmod(filename, 0755);
    access(filename, R_OK | W_OK);
    
    // Cleanup
    unlink(filename);
    __sync_fetch_and_add(&file_io_requests, 1);
}

// Blocking I/O: Network operations
void simulate_network_operation(int request_id, int op_type) {
    if (op_type % 4 == 0) {
        // TCP socket creation and connection attempt
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd >= 0) {
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(80);
            addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Local connection
            
            // Non-blocking socket for controlled timing
            fcntl(sockfd, F_SETFL, O_NONBLOCK);
            connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)); // Will likely fail
            
            // Use poll to wait
            struct pollfd pfd = {sockfd, POLLOUT, 0};
            poll(&pfd, 1, 10 + (request_id % 50)); // 10-60ms timeout
            
            close(sockfd);
        }
    } else if (op_type % 4 == 1) {
        // UDP socket operations
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd >= 0) {
            char buffer[1024];
            snprintf(buffer, sizeof(buffer), "Request %d data", request_id);
            
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(12345);
            addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            
            sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr*)&addr, sizeof(addr));
            
            // Try to receive (will block briefly)
            struct pollfd pfd = {sockfd, POLLIN, 0};
            poll(&pfd, 1, 5 + (request_id % 20)); // 5-25ms timeout
            
            close(sockfd);
        }
    } else {
        // Pipe operations for blocking
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "data_%d", request_id);
        
        // Write to pipe (might block if full)
        write(blocking_pipe[1], buffer, strlen(buffer));
        
        // Read from pipe (blocking operation)
        char read_buf[256];
        struct pollfd pfd = {blocking_pipe[0], POLLIN, 0};
        if (poll(&pfd, 1, 1 + (request_id % 10)) > 0) { // 1-11ms timeout
            read(blocking_pipe[0], read_buf, sizeof(read_buf));
        }
    }
    
    __sync_fetch_and_add(&network_requests, 1);
}

// Blocking I/O: Poll/select operations
void simulate_poll_wait(int request_id) {
    // Create multiple file descriptors
    int fds[3];
    fds[0] = eventfd(0, EFD_NONBLOCK);
    fds[1] = blocking_pipe[0];
    fds[2] = open("/dev/null", O_RDONLY);
    
    struct pollfd pollfds[3];
    for (int i = 0; i < 3; i++) {
        pollfds[i].fd = fds[i];
        pollfds[i].events = POLLIN;
        pollfds[i].revents = 0;
    }
    
    // Poll with timeout - real blocking syscall
    int timeout = 20 + (request_id % 80); // 20-100ms
    int result = poll(pollfds, 3, timeout);
    
    if (result > 0) {
        // Process any ready file descriptors
        for (int i = 0; i < 3; i++) {
            if (pollfds[i].revents & POLLIN) {
                char dummy[256];
                read(pollfds[i].fd, dummy, sizeof(dummy));
            }
        }
    }
    
    // Cleanup
    if (fds[0] >= 0) close(fds[0]);
    if (fds[2] >= 0) close(fds[2]);
    
    __sync_fetch_and_add(&poll_wait_requests, 1);
}

// Worker thread function
void* worker_thread(void* arg) {
    int thread_id = *(int*)arg;
    char thread_name[32];
    snprintf(thread_name, sizeof(thread_name), "worker-%d", thread_id);
    pthread_setname_np(pthread_self(), thread_name);
    
    printf("🔧 Worker thread %d started\n", thread_id);
    
    while (running) {
        request_t req;
        if (dequeue_request(&req) < 0) break;
        
        struct timespec start, end;
        get_timestamp(&start);
        
        // Process based on request type
        switch (req.request_type) {
            case 0: // CPU-intensive math
                simulate_cpu_math_work(req.request_id, 2 + rand() % 4);
                __sync_fetch_and_add(&cpu_math_requests, 1);
                break;
            case 1: // CPU-intensive string processing
                simulate_cpu_string_work(req.request_id, 1 + rand() % 3);
                __sync_fetch_and_add(&cpu_string_requests, 1);
                break;
            case 2: // CPU-intensive sorting
                simulate_cpu_sort_work(req.request_id, 1 + rand() % 2);
                __sync_fetch_and_add(&cpu_sort_requests, 1);
                break;
            case 3: // File I/O
            case 4: // File I/O
            case 5:
                simulate_file_io(req.request_id);
                break;
            case 6: // Network operations
            case 7:
            case 8:
                simulate_network_operation(req.request_id, req.request_id);
                break;
            case 9: // Poll/wait operations
            case 10:
            case 11:
                simulate_poll_wait(req.request_id);
                break;
        }
        
        get_timestamp(&end);
        long processing_time = time_diff_us(&req.arrival_time, &end);
        
        __sync_fetch_and_add(&total_requests_processed, 1);
        
        if (req.request_id % 500 == 0) {
            printf("📊 Worker %d processed request %d (type %d) in %ld μs\n", 
                   thread_id, req.request_id, req.request_type, processing_time);
        }
    }
    
    printf("🔧 Worker thread %d finished\n", thread_id);
    return NULL;
}

// Request generator thread
void* request_generator(void* arg) {
    pthread_setname_np(pthread_self(), "req-generator");
    printf("📈 Request generator started\n");
    
    int request_id = 0;
    while (running) {
        request_t req;
        req.request_id = request_id++;
        req.request_type = rand() % 12; // 6 different request types
        get_timestamp(&req.arrival_time);
        
        if (enqueue_request(&req) < 0) {
            // Queue full, use nanosleep for backpressure
            struct timespec ts = {0, 1000000}; // 1ms
            // nanosleep(&ts, NULL);
            continue;
        }
        
        __sync_fetch_and_add(&total_requests_generated, 1);
        
        // Variable request rate using nanosleep
        struct timespec delay = {0, (500000 + rand() % 2000000)}; // 0.5-2.5ms
        // nanosleep(&delay, NULL);
    }
    
    printf("📈 Request generator finished\n");
    return NULL;
}

// Statistics thread
void* stats_thread(void* arg) {
    pthread_setname_np(pthread_self(), "stats-monitor");
    printf("📊 Statistics monitor started\n");
    
    while (running) {
        sleep(5); // Real sleep syscall
        printf("\n=== Statistics ===\n");
        printf("Generated: %ld, Processed: %ld, Queue: %d\n", 
               total_requests_generated, total_requests_processed, queue_size);
        printf("Math: %ld, String: %ld, Sort: %ld\n",
               cpu_math_requests, cpu_string_requests, cpu_sort_requests);
        printf("File I/O: %ld, Network: %ld, Poll: %ld\n",
               file_io_requests, network_requests, poll_wait_requests);
        printf("=================\n\n");
    }
    
    printf("📊 Statistics monitor finished\n");
    return NULL;
}

int main() {
    printf("🚀 Multi-threaded Web Server Simulation Starting...\n");
    printf("Configuration:\n");
    printf("  - PID: %d\n", getpid());
    printf("  - Worker threads: %d\n", NUM_WORKER_THREADS);
    printf("  - Simulation duration: %d seconds\n", SIMULATION_DURATION);
    printf("  - Request types: Math CPU, String CPU, Sort CPU, File I/O, Network, Poll\n\n");
    
    // Setup signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    srand(time(NULL));
    
    // Initialize blocking mechanisms
    if (pipe(blocking_pipe) < 0) {
        perror("pipe");
        exit(1);
    }
    
    // Make pipe non-blocking for controlled behavior
    fcntl(blocking_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(blocking_pipe[1], F_SETFL, O_NONBLOCK);
    
    // Create threads
    pthread_t threads[NUM_WORKER_THREADS + 2]; // +2 for generator and stats
    int thread_ids[NUM_WORKER_THREADS];
    
    // Start request generator
    pthread_create(&threads[0], NULL, request_generator, NULL);
    
    // Start statistics monitor
    pthread_create(&threads[1], NULL, stats_thread, NULL);
    
    // Start worker threads
    for (int i = 0; i < NUM_WORKER_THREADS; i++) {
        thread_ids[i] = i;
        pthread_create(&threads[i + 2], NULL, worker_thread, &thread_ids[i]);
    }
    
    printf("✅ All threads started. Running for %d seconds...\n", SIMULATION_DURATION);
    printf("   Press Ctrl+C to stop early\n\n");
    
    // Run for specified duration
    sleep(SIMULATION_DURATION);
    
    // Shutdown
    printf("\n🛑 Simulation time completed, initiating shutdown...\n");
    running = 0;
    
    // Wake up any waiting threads
    pthread_cond_broadcast(&queue_cond);
    
    // Wait for all threads to finish
    for (int i = 0; i < NUM_WORKER_THREADS + 2; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Cleanup
    close(blocking_pipe[0]);
    close(blocking_pipe[1]);
    
    // Final statistics
    printf("\n");
    printf("==================================================\n");
    printf("FINAL STATISTICS\n");
    printf("==================================================\n");
    printf("Total requests generated: %ld\n", total_requests_generated);
    printf("Total requests processed: %ld\n", total_requests_processed);
    printf("Request breakdown:\n");
    printf("  - Math CPU ops:     %ld\n", cpu_math_requests);
    printf("  - String CPU ops:   %ld\n", cpu_string_requests);
    printf("  - Sort CPU ops:     %ld\n", cpu_sort_requests);
    printf("  - File I/O ops:     %ld\n", file_io_requests);
    printf("  - Network ops:      %ld\n", network_requests);
    printf("  - Poll/wait ops:    %ld\n", poll_wait_requests);
    printf("==================================================\n");
    
    printf("✅ Web server simulation completed successfully!\n");
    return 0;
} 