
#!/usr/bin/env python3
"""
CUPTI Trace Parser Module
Parses CUPTI trace data and converts to Chrome Trace Format
"""

import re
import json
from typing import List, Dict, Any


class CuptiTraceParser:
    """Parser for CUPTI trace data"""
    
    def __init__(self):
        # Regular expressions for different trace line formats
        self.runtime_pattern = r'RUNTIME \[ (\d+), (\d+) \] duration (\d+), "([^"]+)", cbid (\d+), processId (\d+), threadId (\d+), correlationId (\d+)'
        self.driver_pattern = r'DRIVER \[ (\d+), (\d+) \] duration (\d+), "([^"]+)", cbid (\d+), processId (\d+), threadId (\d+), correlationId (\d+)'
        self.kernel_pattern = r'CONCURRENT_KERNEL \[ (\d+), (\d+) \] duration (\d+), "([^"]+)", correlationId (\d+)'
        self.overhead_pattern = r'OVERHEAD ([A-Z_]+) \[ (\d+), (\d+) \] duration (\d+), (\w+), id (\d+), correlation id (\d+)'
        self.memory_pattern = r'MEMORY2 \[ (\d+) \] memoryOperationType (\w+), memoryKind (\w+), size (\d+), address (\d+)'
        self.memcpy_pattern = r'MEMCPY "([^"]+)" \[ (\d+), (\d+) \] duration (\d+), size (\d+), copyCount (\d+), srcKind (\w+), dstKind (\w+), correlationId (\d+)'
        self.grid_pattern = r'\s+grid \[ (\d+), (\d+), (\d+) \], block \[ (\d+), (\d+), (\d+) \]'
        self.device_pattern = r'\s+deviceId (\d+), contextId (\d+), streamId (\d+)'
        
    def parse_file(self, filename: str) -> List[Dict[str, Any]]:
        """Parse CUPTI trace file and return list of events"""
        with open(filename, 'r') as f:
            lines = f.readlines()
        
        return self.parse_lines(lines)
    
    def parse_lines(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse CUPTI trace lines and return list of events"""
        events = []
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            
            # Skip empty lines or non-trace lines
            if not line or self._should_skip_line(line):
                i += 1
                continue
            
            # Try parsing different event types
            event = None
            lines_consumed = 1
            
            # Parse RUNTIME events
            match = re.search(self.runtime_pattern, line)
            if match:
                event = self._parse_runtime_event(match)
            else:
                # Parse DRIVER events
                match = re.search(self.driver_pattern, line)
                if match:
                    event = self._parse_driver_event(match)
                else:
                    # Parse CONCURRENT_KERNEL events
                    match = re.search(self.kernel_pattern, line)
                    if match:
                        event, lines_consumed = self._parse_kernel_event(match, lines, i)
                    else:
                        # Parse OVERHEAD events
                        match = re.search(self.overhead_pattern, line)
                        if match:
                            event = self._parse_overhead_event(match)
                        else:
                            # Parse MEMCPY events
                            match = re.search(self.memcpy_pattern, line)
                            if match:
                                event, lines_consumed = self._parse_memcpy_event(match, lines, i)
                            else:
                                # Parse MEMORY2 events
                                match = re.search(self.memory_pattern, line)
                                if match:
                                    event = self._parse_memory_event(match)
            
            if event:
                events.append(event)
            
            i += lines_consumed
        
        return events
    
    def _should_skip_line(self, line: str) -> bool:
        """Check if line should be skipped"""
        skip_prefixes = [
            'Calling CUPTI', 'Enabling', 'Disabling', 'Found',
            'Configuring', 'It took', 'Activity buffer', 'CUPTI trace output',
            'Running command', 'Trace output:', 'Started target', 
            'Starting CPU', 'Stopping CPU', 'CPU profile'
        ]
        return any(line.startswith(prefix) for prefix in skip_prefixes)
    
    def _parse_runtime_event(self, match) -> Dict[str, Any]:
        """Parse RUNTIME event"""
        start_time = int(match.group(1))
        duration = int(match.group(3))
        name = match.group(4)
        cbid = match.group(5)
        process_id = int(match.group(6))
        thread_id = int(match.group(7))
        correlation_id = int(match.group(8))
        
        return {
            "name": f"Runtime: {name}",
            "ph": "X",  # Complete event
            "ts": start_time / 1000,  # Convert ns to µs
            "dur": duration / 1000,
            "tid": thread_id,
            "pid": process_id,
            "cat": "CUDA_Runtime",
            "args": {
                "cbid": cbid,
                "correlationId": correlation_id
            }
        }
    
    def _parse_driver_event(self, match) -> Dict[str, Any]:
        """Parse DRIVER event"""
        start_time = int(match.group(1))
        duration = int(match.group(3))
        name = match.group(4)
        cbid = match.group(5)
        process_id = int(match.group(6))
        thread_id = int(match.group(7))
        correlation_id = int(match.group(8))
        
        return {
            "name": f"Driver: {name}",
            "ph": "X",
            "ts": start_time / 1000,
            "dur": duration / 1000,
            "tid": thread_id,
            "pid": process_id,
            "cat": "CUDA_Driver",
            "args": {
                "cbid": cbid,
                "correlationId": correlation_id
            }
        }
    
    def _parse_kernel_event(self, match, lines: List[str], current_index: int) -> tuple:
        """Parse CONCURRENT_KERNEL event with optional additional info"""
        start_time = int(match.group(1))
        duration = int(match.group(3))
        name = match.group(4)
        correlation_id = int(match.group(5))
        
        kernel_info = {
            "name": f"Kernel: {name}",
            "ph": "X",
            "ts": start_time / 1000,
            "dur": duration / 1000,
            "cat": "GPU_Kernel",
            "args": {
                "correlationId": correlation_id
            }
        }
        
        lines_consumed = 1
        
        # Check next lines for additional kernel info
        if current_index + 1 < len(lines):
            next_line = lines[current_index + 1].strip()
            grid_match = re.search(self.grid_pattern, next_line)
            if grid_match:
                kernel_info["args"]["grid"] = [
                    int(grid_match.group(1)),
                    int(grid_match.group(2)),
                    int(grid_match.group(3))
                ]
                kernel_info["args"]["block"] = [
                    int(grid_match.group(4)),
                    int(grid_match.group(5)),
                    int(grid_match.group(6))
                ]
                lines_consumed += 1
                
        if current_index + lines_consumed < len(lines):
            next_line = lines[current_index + lines_consumed].strip()
            device_match = re.search(self.device_pattern, next_line)
            if device_match:
                device_id = int(device_match.group(1))
                context_id = int(device_match.group(2))
                stream_id = int(device_match.group(3))
                
                kernel_info["tid"] = f"GPU{device_id}_Stream{stream_id}"
                kernel_info["pid"] = f"Device_{device_id}"
                kernel_info["args"]["deviceId"] = device_id
                kernel_info["args"]["contextId"] = context_id
                kernel_info["args"]["streamId"] = stream_id
                lines_consumed += 1
        
        return kernel_info, lines_consumed
    
    def _parse_overhead_event(self, match) -> Dict[str, Any]:
        """Parse OVERHEAD event"""
        overhead_type = match.group(1)
        start_time = int(match.group(2))
        duration = int(match.group(4))
        overhead_target = match.group(5)
        overhead_id = int(match.group(6))
        correlation_id = int(match.group(7))
        
        return {
            "name": f"Overhead: {overhead_type}",
            "ph": "X",
            "ts": start_time / 1000,
            "dur": duration / 1000,
            "tid": overhead_id,
            "pid": "CUPTI_Overhead",
            "cat": "Overhead",
            "args": {
                "type": overhead_type,
                "target": overhead_target,
                "correlationId": correlation_id
            }
        }
    
    def _parse_memcpy_event(self, match, lines: List[str], current_index: int) -> tuple:
        """Parse MEMCPY event with optional device info"""
        copy_type = match.group(1)
        start_time = int(match.group(2))
        duration = int(match.group(4))
        size = int(match.group(5))
        copy_count = int(match.group(6))
        src_kind = match.group(7)
        dst_kind = match.group(8)
        correlation_id = int(match.group(9))
        
        memcpy_info = {
            "name": f"MemCopy: {copy_type}",
            "ph": "X",
            "ts": start_time / 1000,
            "dur": duration / 1000,
            "cat": "MemCopy",
            "args": {
                "type": copy_type,
                "size": size,
                "copyCount": copy_count,
                "srcKind": src_kind,
                "dstKind": dst_kind,
                "correlationId": correlation_id
            }
        }
        
        lines_consumed = 1
        
        # Check next line for device info
        if current_index + 1 < len(lines):
            next_line = lines[current_index + 1].strip()
            device_match = re.search(self.device_pattern, next_line)
            if device_match:
                device_id = int(device_match.group(1))
                context_id = int(device_match.group(2))
                stream_id = int(device_match.group(3))
                
                memcpy_info["tid"] = f"GPU{device_id}_Stream{stream_id}"
                memcpy_info["pid"] = f"Device_{device_id}"
                memcpy_info["args"]["deviceId"] = device_id
                memcpy_info["args"]["contextId"] = context_id
                memcpy_info["args"]["streamId"] = stream_id
                lines_consumed += 1
            else:
                memcpy_info["tid"] = "MemCopy_Operations"
                memcpy_info["pid"] = "MemCopy"
        
        return memcpy_info, lines_consumed
    
    def _parse_memory_event(self, match) -> Dict[str, Any]:
        """Parse MEMORY2 event"""
        timestamp = int(match.group(1))
        operation = match.group(2)
        memory_kind = match.group(3)
        size = int(match.group(4))
        address = int(match.group(5))
        
        return {
            "name": f"Memory: {operation} ({memory_kind})",
            "ph": "i",  # Instant event
            "ts": timestamp / 1000,
            "tid": "Memory_Operations",
            "pid": "Memory",
            "cat": "Memory",
            "s": "g",  # Global scope
            "args": {
                "operation": operation,
                "kind": memory_kind,
                "size": size,
                "address": hex(address)
            }
        }
    
    def to_chrome_trace(self, events: List[Dict[str, Any]], metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Convert events to Chrome Trace Format"""
        trace_data = {
            "traceEvents": events,
            "displayTimeUnit": "ms",
            "metadata": metadata or {
                "tool": "CUPTI Trace Parser",
                "format": "Chrome Trace Format"
            }
        }
        return trace_data
    
    def save_chrome_trace(self, events: List[Dict[str, Any]], output_file: str, metadata: Dict[str, Any] = None):
        """Save events as Chrome Trace Format JSON"""
        trace_data = self.to_chrome_trace(events, metadata)
        with open(output_file, 'w') as f:
            json.dump(trace_data, f, indent=2)