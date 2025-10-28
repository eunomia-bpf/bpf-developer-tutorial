use std::mem;

extern crate libc;

#[repr(C)]
pub union sample_un {
    pub sample_period: u64,
    pub sample_freq: u64,
}

#[repr(C)]
pub union wakeup_un {
    pub wakeup_events: u32,
    pub wakeup_atermark: u32,
}

#[repr(C)]
pub union bp_1_un {
    pub bp_addr: u64,
    pub kprobe_func: u64,
    pub uprobe_path: u64,
    pub config1: u64,
}

#[repr(C)]
pub union bp_2_un {
    pub bp_len: u64,
    pub kprobe_addr: u64,
    pub probe_offset: u64,
    pub config2: u64,
}

#[repr(C)]
pub struct perf_event_attr {
    pub _type: u32,
    pub size: u32,
    pub config: u64,
    pub sample: sample_un,
    pub sample_type: u64,
    pub read_format: u64,
    pub flags: u64,
    pub wakeup: wakeup_un,
    pub bp_type: u32,
    pub bp_1: bp_1_un,
    pub bp_2: bp_2_un,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_stack_user: u32,
    pub clockid: i32,
    pub sample_regs_intr: u64,
    pub aux_watermark: u32,
    pub sample_max_stack: u16,
    pub __reserved_2: u16,
    pub aux_sample_size: u32,
    pub __reserved_3: u32,
}

impl Default for perf_event_attr {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

pub const PERF_TYPE_HARDWARE: u32 = 0;
pub const PERF_TYPE_SOFTWARE: u32 = 1;
pub const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
pub const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;

extern "C" {
    fn syscall(number: libc::c_long, ...) -> libc::c_long;
}

pub fn perf_event_open(
    hw_event: &perf_event_attr,
    pid: libc::pid_t,
    cpu: libc::c_int,
    group_fd: libc::c_int,
    flags: libc::c_ulong,
) -> libc::c_long {
    unsafe {
        syscall(
            libc::SYS_perf_event_open,
            hw_event as *const perf_event_attr,
            pid,
            cpu,
            group_fd,
            flags,
        )
    }
}
