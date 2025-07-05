#!/usr/bin/env python3
"""
Test script to demonstrate energy monitor visualization features
"""

import subprocess
import sys
import os

def test_visualization():
    print("Energy Monitor Visualization Test")
    print("=" * 50)
    
    # Check if we can import matplotlib
    try:
        import matplotlib
        print("✓ matplotlib is installed")
    except ImportError:
        print("✗ matplotlib is not installed")
        print("Please install with: pip install matplotlib")
        return
    
    # Test 1: Real-time monitoring with visualization
    print("\nTest 1: Real-time monitoring with visualization (10 seconds)")
    print("This will show a live updating plot of power consumption")
    cmd1 = [sys.executable, "energy_monitor.py", "-d", "10", "-v"]
    print(f"Running: {' '.join(cmd1)}")
    input("Press Enter to start...")
    subprocess.run(cmd1)
    
    # Test 2: Logging with plot generation
    print("\n\nTest 2: Logging data and generating plot (15 seconds)")
    cmd2 = [sys.executable, "energy_monitor.py", "-l", "-d", "15", "-i", "0.5", "-v", "-o", "test_energy"]
    print(f"Running: {' '.join(cmd2)}")
    input("Press Enter to start...")
    subprocess.run(cmd2)
    
    # Test 3: Plot from saved data
    print("\n\nTest 3: Plotting from saved CSV file")
    if os.path.exists("test_energy.csv"):
        cmd3 = [sys.executable, "energy_monitor.py", "-p", "test_energy.csv"]
        print(f"Running: {' '.join(cmd3)}")
        input("Press Enter to start...")
        subprocess.run(cmd3)
    else:
        print("No saved data file found from Test 2")
    
    print("\n" + "=" * 50)
    print("Visualization tests complete!")
    print("\nUsage examples:")
    print("  Real-time monitoring with plot:     python energy_monitor.py -v")
    print("  Log data and generate plot:         python energy_monitor.py -l -v")
    print("  Plot from existing data:            python energy_monitor.py -p data.csv")

if __name__ == "__main__":
    test_visualization()