use std::io;
use std::mem;
use nix::unistd::close;
use libbpf_rs::ErrorExt as _;

use crate::syscall;

pub fn init_perf_monitor(freq: u64, sw_event: bool, pid_filter: Option<i32>) -> Result<Vec<i32>, libbpf_rs::Error> {
    let nprocs = libbpf_rs::num_possible_cpus().unwrap();
    let pid = pid_filter.unwrap_or(-1);
    let attr = syscall::perf_event_attr {
        _type: if sw_event {
            syscall::PERF_TYPE_SOFTWARE
        } else {
            syscall::PERF_TYPE_HARDWARE
        },
        size: mem::size_of::<syscall::perf_event_attr>() as u32,
        config: if sw_event {
            syscall::PERF_COUNT_SW_CPU_CLOCK
        } else {
            syscall::PERF_COUNT_HW_CPU_CYCLES
        },
        sample: syscall::sample_un { sample_freq: freq },
        flags: 1 << 10, // freq = 1
        ..Default::default()
    };
    (0..nprocs)
        .map(|cpu| {
            let fd = syscall::perf_event_open(&attr, pid, cpu as i32, -1, 0) as i32;
            if fd == -1 {
                let mut error_context = "Failed to open perf event.";
                let os_error = io::Error::last_os_error();
                if !sw_event && os_error.kind() == io::ErrorKind::NotFound {
                    error_context = "Failed to open perf event.\n\
                                    Try running the profile example with the `--sw-event` option.";
                }
                Err(libbpf_rs::Error::from(os_error)).context(error_context)
            } else {
                Ok(fd)
            }
        })
        .collect()
}

pub fn attach_perf_event(
    pefds: &[i32],
    prog: &libbpf_rs::ProgramMut,
) -> Vec<Result<libbpf_rs::Link, libbpf_rs::Error>> {
    pefds
        .iter()
        .map(|pefd| prog.attach_perf_event(*pefd))
        .collect()
}

pub fn close_perf_events(pefds: Vec<i32>) -> Result<(), libbpf_rs::Error> {
    for pefd in pefds {
        close(pefd)
            .map_err(io::Error::from)
            .map_err(libbpf_rs::Error::from)
            .context("failed to close perf event")?;
    }
    Ok(())
}