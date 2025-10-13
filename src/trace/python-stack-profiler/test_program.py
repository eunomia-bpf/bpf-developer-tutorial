#!/usr/bin/env python3
"""
Simple Python test program to demonstrate stack profiling
This simulates a typical workload with multiple function calls
"""

import time
import sys

def expensive_computation(n):
    """Simulate CPU-intensive work"""
    result = 0
    for i in range(n):
        result += i ** 2
    return result

def process_data(iterations):
    """Process data with nested function calls"""
    results = []
    for i in range(iterations):
        value = expensive_computation(10000)
        results.append(value)
    return results

def load_model():
    """Simulate model loading"""
    time.sleep(0.1)
    data = process_data(50)
    return sum(data)

def main():
    """Main function that orchestrates the workload"""
    print("Python test program starting...")
    print(f"PID: {__import__('os').getpid()}")
    print("Running CPU-intensive workload...")

    # Run for a while to allow profiling
    for iteration in range(100):
        result = load_model()
        if iteration % 10 == 0:
            print(f"Iteration {iteration}: result = {result}")

    print("Test program completed.")

if __name__ == "__main__":
    main()
