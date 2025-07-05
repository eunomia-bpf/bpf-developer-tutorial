# System Energy Monitoring with Intel RAPL

This project provides tools to monitor system energy consumption using Intel's Running Average Power Limit (RAPL) interface.

## Features

- Real-time power consumption monitoring
- Live terminal-based display of power usage across different domains (CPU, DRAM, etc.)
- Data logging to CSV or JSON formats
- Support for multiple Intel RAPL domains
- No external dependencies - uses only Python standard library

## Requirements

- Intel CPU with RAPL support
- Python 3.6+
- Root access or appropriate permissions for `/sys/class/powercap/intel-rapl`

## Installation

No additional Python packages required - uses only Python standard library.

## Usage

### Real-time Monitoring

```bash
sudo python3 energy_monitor.py
```

This displays real-time power consumption in the terminal:
- Power consumption for each domain (Package, DRAM, etc.)
- Total system power consumption
- Updates every 0.5 seconds

### Logging Energy Data

```bash
sudo python3 energy_monitor.py -l -d 300 -i 0.5 -f csv -o my_energy_log
```

Options:
- `-d, --duration`: Monitoring duration in seconds (default: 60)
- `-i, --interval`: Sampling interval in seconds (default: 1.0)
- `-f, --format`: Output format - csv or json (default: csv)
- `-o, --output`: Output filename without extension

## Permissions

If you don't want to run with sudo, adjust permissions:

```bash
sudo chmod -R a+r /sys/class/powercap/intel-rapl
```

Note: This allows all users to read RAPL data but not modify power limits.

## RAPL Domains

Common domains include:
- `package-0`: Entire CPU package power
- `core`: CPU cores power
- `uncore`: CPU uncore components (cache, memory controller)
- `dram`: Memory power consumption

## Example Output

The logger provides a summary like:
```
Total samples: 300
Average power: 45.23 W
Total energy: 0.0377 Wh
```