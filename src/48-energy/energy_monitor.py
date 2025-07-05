#!/usr/bin/env python3

import os
import time
import json
import csv
from datetime import datetime
from collections import deque
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.figure import Figure

class RAPLEnergyMonitor:
    def __init__(self):
        self.rapl_base = "/sys/class/powercap/intel-rapl"
        self.energy_data = {}
        self.timestamps = deque(maxlen=100)
        self.power_data = {}
        self.domains = self._discover_domains()
        
    def _discover_domains(self):
        domains = {}
        if not os.path.exists(self.rapl_base):
            raise RuntimeError("Intel RAPL not available. Are you running on Intel CPU with appropriate permissions?")
        
        for item in os.listdir(self.rapl_base):
            path = os.path.join(self.rapl_base, item)
            if os.path.isdir(path) and item.startswith("intel-rapl:"):
                try:
                    with open(os.path.join(path, "name"), "r") as f:
                        name = f.read().strip()
                    domains[name] = {
                        "path": path,
                        "energy_file": os.path.join(path, "energy_uj"),
                        "max_energy": self._read_max_energy(path),
                        "last_energy": None,
                        "last_time": None
                    }
                except:
                    continue
                    
                # Check for subdomains
                for subitem in os.listdir(path):
                    subpath = os.path.join(path, subitem)
                    if os.path.isdir(subpath) and subitem.startswith("intel-rapl:"):
                        try:
                            with open(os.path.join(subpath, "name"), "r") as f:
                                subname = f.read().strip()
                            domains[f"{name}:{subname}"] = {
                                "path": subpath,
                                "energy_file": os.path.join(subpath, "energy_uj"),
                                "max_energy": self._read_max_energy(subpath),
                                "last_energy": None,
                                "last_time": None
                            }
                        except:
                            continue
                            
        for domain in domains:
            self.power_data[domain] = deque(maxlen=100)
            
        return domains
    
    def _read_max_energy(self, path):
        try:
            with open(os.path.join(path, "max_energy_range_uj"), "r") as f:
                return int(f.read().strip())
        except:
            return 2**32
    
    def _read_energy(self, domain):
        try:
            with open(self.domains[domain]["energy_file"], "r") as f:
                return int(f.read().strip())
        except:
            return None
    
    def update_power(self):
        current_time = time.time()
        
        for domain in self.domains:
            energy = self._read_energy(domain)
            if energy is None:
                continue
                
            domain_info = self.domains[domain]
            
            if domain_info["last_energy"] is not None:
                # Handle wraparound
                if energy < domain_info["last_energy"]:
                    energy_diff = (domain_info["max_energy"] - domain_info["last_energy"]) + energy
                else:
                    energy_diff = energy - domain_info["last_energy"]
                    
                time_diff = current_time - domain_info["last_time"]
                
                if time_diff > 0 and energy_diff > 0:
                    # Convert from microjoules to watts
                    power = (energy_diff / 1e6) / time_diff
                    self.power_data[domain].append(power)
                elif time_diff > 0:
                    # No energy change, append last known power or 0
                    if len(self.power_data[domain]) > 0:
                        self.power_data[domain].append(self.power_data[domain][-1])
                    else:
                        self.power_data[domain].append(0.0)
            
            domain_info["last_energy"] = energy
            domain_info["last_time"] = current_time
        
        self.timestamps.append(current_time)
    
    def get_current_power(self):
        result = {}
        for domain in self.domains:
            if len(self.power_data[domain]) > 0:
                result[domain] = self.power_data[domain][-1]
            else:
                result[domain] = 0
        return result
    
    def get_power_history(self):
        return {domain: list(self.power_data[domain]) for domain in self.domains}
    
    def plot_power_history(self, save_path=None, show=True):
        """Plot power consumption history for all domains"""
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Get timestamps relative to start
        if len(self.timestamps) < 2:
            print("Not enough data to plot")
            return
        
        start_time = self.timestamps[0]
        time_points = [(t - start_time) for t in self.timestamps]
        
        # Plot each domain
        for domain in self.domains:
            if len(self.power_data[domain]) > 0:
                # Ensure we have matching lengths
                data_len = min(len(time_points), len(self.power_data[domain]))
                ax.plot(time_points[:data_len], 
                       list(self.power_data[domain])[:data_len], 
                       label=domain, linewidth=2)
        
        ax.set_xlabel('Time (seconds)', fontsize=12)
        ax.set_ylabel('Power (Watts)', fontsize=12)
        ax.set_title('System Power Consumption Over Time', fontsize=14)
        ax.grid(True, alpha=0.3)
        ax.legend()
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        
        if show:
            plt.show()
        
        return fig

class EnergyLogger:
    def __init__(self, output_format="csv"):
        self.monitor = RAPLEnergyMonitor()
        self.output_format = output_format
        self.start_time = time.time()
        self.log_data = []
        
    def log_sample(self):
        self.monitor.update_power()
        current_power = self.monitor.get_current_power()
        
        sample = {
            "timestamp": datetime.now().isoformat(),
            "elapsed_seconds": time.time() - self.start_time,
            "total_power": sum(current_power.values())
        }
        
        for domain, power in current_power.items():
            sample[f"power_{domain}"] = power
            
        self.log_data.append(sample)
        return sample
    
    def save_csv(self, filename):
        if not self.log_data:
            return
            
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.log_data[0].keys())
            writer.writeheader()
            writer.writerows(self.log_data)
    
    def save_json(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.log_data, f, indent=2)
    
    def save(self, filename=None):
        if filename is None:
            filename = f"energy_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
        if self.output_format == "csv":
            self.save_csv(f"{filename}.csv")
        else:
            self.save_json(f"{filename}.json")
            
        return filename
    
    def plot_log_data(self, save_path=None, show=True):
        """Plot logged energy data"""
        if not self.log_data:
            print("No data to plot")
            return
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
        
        # Extract data
        timestamps = [sample['elapsed_seconds'] for sample in self.log_data]
        total_power = [sample['total_power'] for sample in self.log_data]
        
        # Plot total power
        ax1.plot(timestamps, total_power, 'b-', linewidth=2, label='Total Power')
        ax1.set_xlabel('Time (seconds)', fontsize=12)
        ax1.set_ylabel('Power (Watts)', fontsize=12)
        ax1.set_title('Total System Power Consumption', fontsize=14)
        ax1.grid(True, alpha=0.3)
        ax1.legend()
        
        # Plot individual domains
        domain_names = [key for key in self.log_data[0].keys() 
                       if key.startswith('power_') and key != 'power_']
        
        for domain_key in domain_names:
            domain_power = [sample.get(domain_key, 0) for sample in self.log_data]
            domain_name = domain_key.replace('power_', '')
            ax2.plot(timestamps, domain_power, linewidth=2, label=domain_name)
        
        ax2.set_xlabel('Time (seconds)', fontsize=12)
        ax2.set_ylabel('Power (Watts)', fontsize=12)
        ax2.set_title('Power Consumption by Domain', fontsize=14)
        ax2.grid(True, alpha=0.3)
        ax2.legend()
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        
        if show:
            plt.show()
        
        return fig

def monitor_realtime(duration=60, visualize=False):
    """Real-time monitoring with optional visualization"""
    if visualize:
        return monitor_realtime_visual(duration)
    
    print("Real-time Energy Monitor")
    print("=" * 50)
    
    try:
        monitor = RAPLEnergyMonitor()
        print(f"Monitoring domains: {', '.join(monitor.domains.keys())}")
        print(f"Duration: {duration} seconds")
        print("=" * 50)
        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            monitor.update_power()
            power = monitor.get_current_power()
            
            # Clear line and print current values
            print("\r", end="")
            print(f"[{int(time.time() - start_time):3d}s] ", end="")
            
            for domain, watts in power.items():
                print(f"{domain}: {watts:6.2f}W  ", end="")
            
            print(f"Total: {sum(power.values()):6.2f}W", end="", flush=True)
            
            time.sleep(0.1)
        
        print("\n" + "=" * 50)
        print("Monitoring complete!")
        
    except RuntimeError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped by user.")

def monitor_realtime_visual(duration=60):
    """Real-time monitoring with live plotting"""
    plt.ion()
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
    
    try:
        monitor = RAPLEnergyMonitor()
        domains = list(monitor.domains.keys())
        
        # Initialize plot lines
        lines1 = {}
        lines2 = []
        
        # Setup total power plot
        ax1.set_xlabel('Time (seconds)')
        ax1.set_ylabel('Power (Watts)')
        ax1.set_title('Total System Power Consumption')
        ax1.grid(True, alpha=0.3)
        lines1['total'], = ax1.plot([], [], 'b-', linewidth=2, label='Total Power')
        ax1.legend()
        
        # Setup domain power plot
        ax2.set_xlabel('Time (seconds)')
        ax2.set_ylabel('Power (Watts)')
        ax2.set_title('Power Consumption by Domain')
        ax2.grid(True, alpha=0.3)
        
        for i, domain in enumerate(domains):
            line, = ax2.plot([], [], linewidth=2, label=domain)
            lines2.append(line)
        ax2.legend()
        
        # Data storage
        times = []
        total_powers = []
        domain_powers = {domain: [] for domain in domains}
        
        start_time = time.time()
        
        print(f"Monitoring for {duration} seconds... Press Ctrl+C to stop early.")
        
        while time.time() - start_time < duration:
            monitor.update_power()
            power = monitor.get_current_power()
            
            # Update data
            current_time = time.time() - start_time
            times.append(current_time)
            total_powers.append(sum(power.values()))
            
            for domain in domains:
                domain_powers[domain].append(power.get(domain, 0))
            
            # Update plots
            lines1['total'].set_data(times, total_powers)
            ax1.relim()
            ax1.autoscale_view()
            
            for i, domain in enumerate(domains):
                lines2[i].set_data(times, domain_powers[domain])
            ax2.relim()
            ax2.autoscale_view()
            
            plt.draw()
            plt.pause(0.05)
        
        plt.ioff()
        
        # Save final plot
        save_path = f"energy_plot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"\nPlot saved to: {save_path}")
        
        # Show final plot
        plt.show()
        
    except RuntimeError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped by user.")
        plt.ioff()
        plt.close()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Monitor system energy consumption")
    parser.add_argument("-d", "--duration", type=int, default=60,
                        help="Duration to monitor in seconds (default: 60)")
    parser.add_argument("-l", "--log", action="store_true",
                        help="Log data to file instead of real-time display")
    parser.add_argument("-i", "--interval", type=float, default=1.0,
                        help="Sampling interval for logging (default: 1.0)")
    parser.add_argument("-f", "--format", choices=["csv", "json"], default="csv",
                        help="Output format for logging (default: csv)")
    parser.add_argument("-o", "--output", type=str,
                        help="Output filename for logging")
    parser.add_argument("-v", "--visualize", action="store_true",
                        help="Enable real-time visualization")
    parser.add_argument("-p", "--plot", type=str,
                        help="Plot saved data from CSV/JSON file")
    
    args = parser.parse_args()
    
    # Handle plotting existing data
    if args.plot:
        print(f"Loading data from: {args.plot}")
        
        if args.plot.endswith('.csv'):
            # Load CSV data
            import pandas as pd
            df = pd.read_csv(args.plot)
            log_data = df.to_dict('records')
        elif args.plot.endswith('.json'):
            # Load JSON data
            with open(args.plot, 'r') as f:
                log_data = json.load(f)
        else:
            print("Error: Plot file must be .csv or .json")
            return
        
        # Create a temporary logger to use its plotting method
        logger = EnergyLogger()
        logger.log_data = log_data
        
        plot_path = args.plot.rsplit('.', 1)[0] + '_plot.png'
        logger.plot_log_data(save_path=plot_path)
        print(f"Plot saved to: {plot_path}")
        return
    
    if args.log:
        # Logging mode
        print(f"Starting energy logging for {args.duration} seconds...")
        print(f"Sampling interval: {args.interval} seconds")
        print(f"Output format: {args.format}")
        
        try:
            logger = EnergyLogger(output_format=args.format)
            
            start_time = time.time()
            sample_count = 0
            
            while time.time() - start_time < args.duration:
                sample = logger.log_sample()
                sample_count += 1
                
                print(f"\rSamples: {sample_count} | Total Power: {sample['total_power']:.2f} W", 
                      end='', flush=True)
                
                time.sleep(args.interval)
            
            print("\n\nSaving data...")
            filename = logger.save(args.output)
            print(f"Data saved to: {filename}.{args.format}")
            
            # Print summary
            avg_power = sum(s['total_power'] for s in logger.log_data) / len(logger.log_data)
            print(f"\nSummary:")
            print(f"  Total samples: {len(logger.log_data)}")
            print(f"  Average power: {avg_power:.2f} W")
            print(f"  Total energy: {avg_power * args.duration / 3600:.4f} Wh")
            
            # Generate plot if visualization is enabled
            if args.visualize:
                plot_filename = (args.output or filename) + "_plot.png"
                logger.plot_log_data(save_path=plot_filename)
                print(f"  Plot saved to: {plot_filename}")
            
        except RuntimeError as e:
            print(f"Error: {e}")
        except KeyboardInterrupt:
            print("\n\nLogging interrupted. Saving partial data...")
            if 'logger' in locals():
                filename = logger.save(args.output)
                print(f"Partial data saved to: {filename}.{args.format}")
    else:
        # Real-time monitoring mode
        monitor_realtime(args.duration, visualize=args.visualize)

if __name__ == "__main__":
    main()