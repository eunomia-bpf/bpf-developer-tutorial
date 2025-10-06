# Intel NPU Driver Analysis Report

## Repository Analysis Steps

### 1. Clone and Initial Exploration
```bash
# Clone the repository
git clone https://github.com/intel/linux-npu-driver/

# Explore the directory structure
ls -la /home/yunwei37/linux-npu-driver
```

### 2. Driver Architecture Discovery

The Intel NPU driver consists of two main components:

1. **Kernel Module Driver** (`intel_vpu`)
   - Located in mainline kernel: `drivers/accel/ivpu/`
   - Creates device file: `/dev/accel/accel0`
   - Handles hardware communication and memory management

2. **User-Space Driver** (`libze_intel_vpu.so`)
   - Implements Level Zero API
   - Located in this repository under `umd/level_zero_driver/`
   - Communicates with kernel module via ioctls

### 3. Symbol Export Analysis

#### User-Space Library Symbols
Found export file: `/home/yunwei37/linux-npu-driver/umd/level_zero_driver/api/ze.exports`
```
{
  global:
      ze*;
  local:
      *;
};
```

This exports all symbols starting with "ze" including:
- Core API: `zeInit`, `zeDriverGet`, `zeDeviceGet`
- Memory: `zeMemAllocShared`, `zeMemAllocDevice`, `zeMemAllocHost`
- Execution: `zeCommandListCreate`, `zeCommandQueueCreate`
- NPU-specific: `zeGraphCreate`, `zeGraphDestroy` (graph extensions)

#### Kernel Module Symbols
```bash
# Check if module is loaded
lsmod | grep intel_vpu
# Output: intel_vpu             278528  0

# Get module information
modinfo intel_vpu

# Dump all kernel symbols to file
cat /proc/kallsyms | grep intel_vpu > intel_vpu_symbols.txt
# Result: 1312 symbols dumped
```

### 4. Key Findings

#### Module Information:
- **Name**: intel_vpu (Neural Processing Unit driver)
- **Version**: 1.0.0
- **License**: GPL and additional rights
- **Supported devices**: 
  - PCI ID 0x643E
  - PCI ID 0x7D1D  
  - PCI ID 0xAD1D
  - PCI ID 0xB03E
- **Firmware files**:
  - intel/vpu/vpu_37xx_v0.0.bin
  - intel/vpu/vpu_40xx_v0.0.bin
  - intel/vpu/vpu_50xx_v0.0.bin

#### Symbol Types in Kernel Module:
- `t` - local text (function) symbols
- `d` - data symbols
- `r` - read-only data symbols
- `b` - BSS (uninitialized data) symbols

The kernel module doesn't export symbols for direct linking. Instead, it provides functionality through:
1. Device file interface (`/dev/accel/accel0`)
2. DRM ioctls for operations
3. IPC communication with NPU firmware

### 5. API to Kernel Mapping

| Level Zero API | Kernel ioctl | Kernel Function |
|----------------|--------------|-----------------|
| zeInit | - | ivpu_open |
| zeDeviceGetProperties | DRM_IOCTL_IVPU_GET_PARAM | ivpu_get_param_ioctl |
| zeMemAllocHost/Device | DRM_IOCTL_IVPU_BO_CREATE | ivpu_bo_create_ioctl |
| zeCommandQueueExecuteCommandLists | DRM_IOCTL_IVPU_SUBMIT | ivpu_submit_ioctl |
| zeMemFree | DRM_IOCTL_GEM_CLOSE | ivpu_gem_bo_free |

### 6. Function Call Frequency Analysis

From the trace analysis of 8,198 function calls:
1. **Memory Management** (4,648 calls):
   - `ivpu_mmu_context_map_page`: 4,131
   - `ivpu_pgtable_free_page`: 517

2. **IPC Communication** (2,842 calls):
   - `ivpu_ipc_irq_handler`: 946
   - `ivpu_hw_ip_ipc_rx_count_get`: 951
   - `ivpu_ipc_receive`: 945

3. **Buffer Management** (74 calls):
   - `ivpu_bo_create_ioctl`: 24
   - `ivpu_gem_create_object`: 25
   - `ivpu_bo_pin`: 25

### 7. Typical Workflow
1. Device initialization (open, query parameters)
2. Memory allocation for compute buffers
3. Command list creation and submission
4. IPC communication with firmware during execution
5. Synchronization and cleanup

## Files Generated
- `intel_vpu_symbols.txt` - Contains all 1,312 kernel module symbols
- This analysis report - `/home/yunwei37/intel_npu_driver_analysis.md`