#!/usr/bin/env python3
"""
Debug script to check RAPL energy readings
"""

import os
import time

def check_rapl():
    rapl_base = "/sys/class/powercap/intel-rapl"
    
    print("Checking Intel RAPL availability...")
    print("=" * 50)
    
    if not os.path.exists(rapl_base):
        print(f"ERROR: {rapl_base} does not exist!")
        print("Intel RAPL may not be available on this system.")
        return
    
    # Check permissions
    print("\nChecking permissions...")
    for item in os.listdir(rapl_base):
        if item.startswith("intel-rapl:"):
            energy_file = os.path.join(rapl_base, item, "energy_uj")
            if os.path.exists(energy_file):
                readable = os.access(energy_file, os.R_OK)
                print(f"{energy_file}: {'readable' if readable else 'NOT readable'}")
    
    print("\n" + "=" * 50)
    print("Reading energy values over 5 seconds...")
    print("=" * 50)
    
    # Discover domains
    domains = {}
    for item in os.listdir(rapl_base):
        path = os.path.join(rapl_base, item)
        if os.path.isdir(path) and item.startswith("intel-rapl:"):
            try:
                with open(os.path.join(path, "name"), "r") as f:
                    name = f.read().strip()
                energy_file = os.path.join(path, "energy_uj")
                if os.path.exists(energy_file):
                    domains[name] = energy_file
            except:
                pass
    
    if not domains:
        print("ERROR: No RAPL domains found!")
        return
    
    print(f"Found domains: {', '.join(domains.keys())}\n")
    
    # Read energy values multiple times
    readings = {domain: [] for domain in domains}
    
    for i in range(10):
        for domain, energy_file in domains.items():
            try:
                with open(energy_file, "r") as f:
                    energy = int(f.read().strip())
                    readings[domain].append(energy)
            except Exception as e:
                print(f"Error reading {domain}: {e}")
        
        time.sleep(0.5)
    
    # Analyze readings
    print("\nAnalysis:")
    print("-" * 50)
    
    for domain, values in readings.items():
        if len(values) < 2:
            continue
            
        print(f"\n{domain}:")
        print(f"  First reading: {values[0]} µJ")
        print(f"  Last reading:  {values[-1]} µJ")
        print(f"  Difference:    {values[-1] - values[0]} µJ")
        
        # Check if values are changing
        unique_values = len(set(values))
        print(f"  Unique values: {unique_values}")
        
        if unique_values == 1:
            print("  ⚠️  WARNING: Energy values are not changing!")
        else:
            # Calculate average power
            energy_diff = values[-1] - values[0]
            time_diff = 0.5 * (len(values) - 1)
            if energy_diff > 0:
                power = (energy_diff / 1e6) / time_diff
                print(f"  Average power: {power:.2f} W")
    
    print("\n" + "=" * 50)
    print("\nPossible issues if readings are zero:")
    print("1. The system is idle with very low power consumption")
    print("2. RAPL updates may be infrequent (try longer sampling intervals)")
    print("3. Permission issues (try running with sudo)")
    print("4. RAPL may not be fully supported on this CPU")

if __name__ == "__main__":
    check_rapl()