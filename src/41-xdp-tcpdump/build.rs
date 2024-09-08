use std::env;
use std::path::Path;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/xdppass.bpf.c";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("xdppass.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(format!(
            "-I{}",
            Path::new("../third_party/vmlinux")
                .join(match arch.as_ref() {
                    "aarch64" => "arm64",
                    "loongarch64" => "loongarch",
                    "powerpc64" => "powerpc",
                    "riscv64" => "riscv",
                    "x86_64" => "x86",
                    _ => &arch,
                })
                .display()
        ))
        .build_and_generate(out)
        .unwrap();
    println!("cargo:rerun-if-changed={}", SRC);
}
