#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>

// Global statistics
static volatile int running = 1;
static long total_cpu_time_ns = 0;
static long total_sleep_time_ns = 0;
static int total_iterations = 0;
static struct timespec program_start;

// Signal handler for clean exit
void signal_handler(int sig) {
    running = 0;
    printf("\n🛑 Interrupted! Generating profiling expectations...\n");
}

// Get current time in nanoseconds
long get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

// CPU-intensive function with configurable work
void cpu_work(int intensity) {
    volatile long sum = 0;
    int iterations = intensity * 10000000; // Scale work by intensity (1-10)
    
    for (int i = 0; i < iterations; i++) {
        sum += i * i + (i % 3) * (i % 7); // More complex computation
        if (i % 1000000 == 0 && !running) break; // Check for interruption
    }
}

// Blocking function with configurable sleep time
void blocking_work(int sleep_ms) {
    usleep(sleep_ms * 1000); // Convert ms to microseconds
}

// Perform one iteration of work and measure times
void do_work_iteration(int cpu_intensity, int sleep_ms) {
    struct timespec start, end;
    
    // Measure CPU work
    clock_gettime(CLOCK_MONOTONIC, &start);
    cpu_work(cpu_intensity);
    clock_gettime(CLOCK_MONOTONIC, &end);
    long cpu_time = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    
    // Measure sleep time
    clock_gettime(CLOCK_MONOTONIC, &start);
    blocking_work(sleep_ms);
    clock_gettime(CLOCK_MONOTONIC, &end);
    long sleep_time = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    
    // Update statistics
    total_cpu_time_ns += cpu_time;
    total_sleep_time_ns += sleep_time;
    total_iterations++;
    
    printf("Iteration %3d: CPU=%3ldms, Sleep=%3ldms, Total=%3ldms\n", 
           total_iterations, 
           cpu_time / 1000000, 
           sleep_time / 1000000,
           (cpu_time + sleep_time) / 1000000);
}

// Display current statistics and profiler expectations
void show_statistics() {
    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);
    
    long program_runtime_ns = (current_time.tv_sec - program_start.tv_sec) * 1000000000L + 
                             (current_time.tv_nsec - program_start.tv_nsec);
    
    double program_runtime_s = program_runtime_ns / 1000000000.0;
    double total_cpu_s = total_cpu_time_ns / 1000000000.0;
    double total_sleep_s = total_sleep_time_ns / 1000000000.0;
    double measured_time_s = total_cpu_s + total_sleep_s;
    
    printf("\n============================================================\n");
    printf("📊 PROFILING STATISTICS (PID: %d)\n", getpid());
    printf("============================================================\n");
    printf("Program runtime:     %.3f seconds\n", program_runtime_s);
    printf("Total iterations:    %d\n", total_iterations);
    printf("Measured work time:  %.3f seconds (%.1f%% of runtime)\n", 
           measured_time_s, (measured_time_s / program_runtime_s) * 100.0);
    
    printf("\n🔥 ON-CPU TIME (computation):\n");
    printf("  Total:             %.3f seconds\n", total_cpu_s);
    printf("  Percentage:        %.1f%% of measured time\n", (total_cpu_s / measured_time_s) * 100.0);
    printf("  Average per iter:  %.1f ms\n", (total_cpu_s * 1000.0) / total_iterations);
    
    printf("\n❄️  OFF-CPU TIME (blocking/sleep):\n");
    printf("  Total:             %.3f seconds\n", total_sleep_s);
    printf("  Percentage:        %.1f%% of measured time\n", (total_sleep_s / measured_time_s) * 100.0);
    printf("  Average per iter:  %.1f ms\n", (total_sleep_s * 1000.0) / total_iterations);
    
    printf("\n🎯 EXPECTED PROFILER OUTPUT:\n");
    printf("  Wall clock coverage: ~%.1f%% (if profiler captures full runtime)\n", 
           (measured_time_s / program_runtime_s) * 100.0);
    printf("  On-CPU μs expected:  ~%.0f μs\n", total_cpu_s * 1000000.0);
    printf("  Off-CPU μs expected: ~%.0f μs\n", total_sleep_s * 1000000.0);
    printf("  Stack traces: cpu_work_[c] and usleep→clock_nanosleep_[o]\n");
    
    printf("\n💡 PROFILER COMMAND:\n");
    printf("  sudo ./profiler -a wallclock -p %d -t 10\n", getpid());
    printf("============================================================\n\n");
}

int main() {
    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Record program start time
    clock_gettime(CLOCK_MONOTONIC, &program_start);
    
    printf("🚀 WALLCLOCK PROFILER TEST PROGRAM\n");
    printf("=================================\n");
    printf("PID: %d\n", getpid());
    printf("This program alternates between CPU work and blocking operations\n");
    printf("Press Ctrl+C to stop and see profiling expectations\n");
    printf("=================================\n\n");
    
    // Work parameters (can be adjusted for different test scenarios)
    int cpu_intensity = 8;  // 1-10 scale, affects computation time
    int sleep_ms = 200;     // milliseconds to sleep each iteration
    
    printf("Configuration:\n");
    printf("  CPU intensity: %d/10 (expect ~%dms per iteration)\n", cpu_intensity, cpu_intensity * 10);
    printf("  Sleep time:    %dms per iteration\n", sleep_ms);

    // Show statistics every 10 iterations
    int stats_interval = 10;
    
    while (running) {
        do_work_iteration(cpu_intensity, sleep_ms);
        
        // Show periodic statistics
        if (total_iterations % stats_interval == 0) {
            show_statistics();
        }
        
        // Slight variation to make it more realistic
        if (total_iterations % 20 == 0) {
            cpu_intensity = (cpu_intensity % 10) + 1; // Cycle intensity 1-10
        }
    }
    
    // Final statistics
    printf("\n🏁 FINAL STATISTICS:\n");
    show_statistics();
    
    return 0;
} 