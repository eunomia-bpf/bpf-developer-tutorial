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

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    // Ensure we're building for a supported architecture
    println!("cargo:warning=Building for architecture: {}", arch);

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            Path::new("../vmlinux").as_os_str()
        ])
        .build_and_generate(out)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", SRC);
}
