use std::mem::MaybeUninit;
use std::time::Duration;

use clap::ArgAction;
use clap::Parser;

use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;

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
    /// Sampling frequency
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

    let freq = if args.freq < 1 { 1 } else { args.freq };

    let skel_builder = ProfileSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object).unwrap();
    let skel = open_skel.load().unwrap();

    let pefds = perf::init_perf_monitor(freq, args.sw_event, args.pid)?;
    let _links = perf::attach_perf_event(&pefds, &skel.progs.profile);

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    
    let output_format = if args.fold_extend {
        event::OutputFormat::FoldedExtended
    } else {
        event::OutputFormat::Standard
    };
    
    let event_handler = event::EventHandler::new(output_format);
    
    builder
        .add(&skel.maps.events, move |data| {
            event_handler.handle(data)
        })
        .unwrap();
    
    let ringbuf = builder.build().unwrap();
    while ringbuf.poll(Duration::MAX).is_ok() {}

    perf::close_perf_events(pefds)?;

    Ok(())
}
