use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/profile.bpf.c";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("profile.skel.rs");

    let _arch = env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_else(|_| "x86_64".to_string());
    
    // Map Rust target arch to kernel arch naming
    let kernel_arch = match _arch.as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        "arm" => "arm",
        "powerpc64" => "powerpc",
        "mips" | "mips64" => "mips",
        "riscv64" => "riscv",
        "loongarch64" => "loongarch",
        _ => "x86", // default to x86
    };

    // Path to the vmlinux directory containing arch-specific headers
    let vmlinux_path = format!("../third_party/vmlinux/{}", kernel_arch);

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            Path::new(&vmlinux_path).as_os_str(),
            OsStr::new("-I"),
            Path::new(".output").as_os_str(),
        ])
        .build_and_generate(out)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", SRC);
}
