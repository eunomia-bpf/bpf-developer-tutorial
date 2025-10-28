use std::mem::MaybeUninit;
use std::time::Duration;

use clap::ArgAction;
use clap::Parser;

use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::UprobeOpts;

use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::FmtSubscriber;

mod profile {
    include!(concat!(env!("OUT_DIR"), "/profile.skel.rs"));
}
mod syscall;
mod event;
mod perf;

use profile::*;

#[derive(Parser, Debug)]
struct Args {
    /// Sampling frequency (only used in perf mode)
    #[arg(short, default_value_t = 50)]
    freq: u64,
    /// Increase verbosity (can be supplied multiple times).
    #[arg(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
    verbosity: u8,
    /// Use software event for triggering stack trace capture.
    ///
    /// This can be useful for compatibility reasons if hardware event is not available
    /// (which could happen in a virtual machine, for example).
    #[arg(long = "sw-event")]
    sw_event: bool,
    /// Filter by PID (optional)
    #[arg(short = 'p', long = "pid")]
    pid: Option<i32>,
    /// Output in extended folded format (timestamp_ns comm pid tid cpu stack1;stack2;...)
    #[arg(short = 'E', long = "fold-extend")]
    fold_extend: bool,
    /// Attach to kprobe (format: "symbol" e.g. "tcp_v4_connect")
    /// Can be specified multiple times
    #[arg(long = "kprobe")]
    kprobes: Vec<String>,
    /// Attach to kretprobe (format: "symbol")
    #[arg(long = "kretprobe")]
    kretprobes: Vec<String>,
    /// Attach to uprobe (format: "binary:symbol" e.g. "/lib/libc.so.6:malloc")
    #[arg(long = "uprobe")]
    uprobes: Vec<String>,
    /// Attach to uretprobe (format: "binary:symbol")
    #[arg(long = "uretprobe")]
    uretprobes: Vec<String>,
}

fn main() -> Result<(), libbpf_rs::Error> {
    let args = Args::parse();
    let level = match args.verbosity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_span_events(FmtSpan::FULL)
        .with_timer(SystemTime)
        .finish();
    let () = set_global_subscriber(subscriber).expect("failed to set tracing subscriber");

    let skel_builder = ProfileSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object).unwrap();
    let skel = open_skel.load().unwrap();

    let _perf_links;
    let mut pefds = Vec::new();
    let mut _probe_links = Vec::new();
    let mut probe_id: u32 = 1;

    let has_probes = !args.kprobes.is_empty() || !args.kretprobes.is_empty()
        || !args.uprobes.is_empty() || !args.uretprobes.is_empty();

    if has_probes {
        // Attach kprobes
        for symbol in &args.kprobes {
            let link = skel.progs.kprobe_handler.attach_kprobe(false, symbol)?;
            eprintln!("Attached kprobe (id={}): {}", probe_id, symbol);
            _probe_links.push(link);
            probe_id += 1;
        }

        // Attach kretprobes
        for symbol in &args.kretprobes {
            let link = skel.progs.kretprobe_handler.attach_kprobe(true, symbol)?;
            eprintln!("Attached kretprobe (id={}): {}", probe_id, symbol);
            _probe_links.push(link);
            probe_id += 1;
        }

        // Attach uprobes
        for spec in &args.uprobes {
            let parts: Vec<&str> = spec.split(':').collect();
            if parts.len() != 2 {
                eprintln!("Error: uprobe format should be 'binary:symbol'");
                std::process::exit(1);
            }
            let opts = UprobeOpts {
                func_name: parts[1].to_string(),
                cookie: probe_id as u64,
                retprobe: false,
                ..Default::default()
            };
            let link = skel.progs.uprobe_handler.attach_uprobe_with_opts(-1, parts[0], 0, opts)?;
            eprintln!("Attached uprobe (id={}): {} in {}", probe_id, parts[1], parts[0]);
            _probe_links.push(link);
            probe_id += 1;
        }

        // Attach uretprobes
        for spec in &args.uretprobes {
            let parts: Vec<&str> = spec.split(':').collect();
            if parts.len() != 2 {
                eprintln!("Error: uretprobe format should be 'binary:symbol'");
                std::process::exit(1);
            }
            let opts = UprobeOpts {
                func_name: parts[1].to_string(),
                cookie: probe_id as u64,
                retprobe: true,
                ..Default::default()
            };
            let link = skel.progs.uretprobe_handler.attach_uprobe_with_opts(-1, parts[0], 0, opts)?;
            eprintln!("Attached uretprobe (id={}): {} in {}", probe_id, parts[1], parts[0]);
            _probe_links.push(link);
            probe_id += 1;
        }
    } else {
        // Perf mode
        let freq = if args.freq < 1 { 1 } else { args.freq };
        pefds = perf::init_perf_monitor(freq, args.sw_event, args.pid)?;
        _perf_links = perf::attach_perf_event(&pefds, &skel.progs.profile);
        eprintln!("Perf mode: sampling at {} Hz", freq);
    }

    let output_format = if args.fold_extend {
        event::OutputFormat::FoldedExtended
    } else {
        event::OutputFormat::Standard
    };

    let event_handler = event::EventHandler::new(output_format);

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(&skel.maps.events, move |data| {
            event_handler.handle(data)
        })
        .unwrap();

    let ringbuf = builder.build().unwrap();
    while ringbuf.poll(Duration::MAX).is_ok() {}

    // Clean up perf events if in perf mode
    if !pefds.is_empty() {
        perf::close_perf_events(pefds)?;
    }

    Ok(())
}
