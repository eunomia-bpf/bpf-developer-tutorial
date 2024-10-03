use std::env;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::ops::Deref as _;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;

use anyhow::bail;
use anyhow::Context as _;
use anyhow::Result;

/// Format a command with the given list of arguments as a string.
fn format_command<C, A, S>(command: C, args: A) -> String
where
    C: AsRef<OsStr>,
    A: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter().fold(
        command.as_ref().to_string_lossy().into_owned(),
        |mut cmd, arg| {
            cmd += " ";
            cmd += arg.as_ref().to_string_lossy().deref();
            cmd
        },
    )
}

/// Run a command with the provided arguments.
fn run<C, A, S>(command: C, args: A) -> Result<()>
where
    C: AsRef<OsStr>,
    A: IntoIterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    let instance = Command::new(command.as_ref())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .args(args.clone())
        .output()
        .with_context(|| {
            format!(
                "failed to run `{}`",
                format_command(command.as_ref(), args.clone())
            )
        })?;

    if !instance.status.success() {
        let code = if let Some(code) = instance.status.code() {
            format!(" ({code})")
        } else {
            " (terminated by signal)".to_string()
        };

        let stderr = String::from_utf8_lossy(&instance.stderr);
        let stderr = stderr.trim_end();
        let stderr = if !stderr.is_empty() {
            format!(": {stderr}")
        } else {
            String::new()
        };

        bail!(
            "`{}` reported non-zero exit-status{code}{stderr}",
            format_command(command, args),
        );
    }

    Ok(())
}

/// Compile `src` into `dst` using `cc`.
fn cc(src: &Path, dst: &str, options: &[&str]) {
    let dst = src.with_file_name(dst);
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", dst.display());

    // Ideally we'd use the `cc` crate here, but it seemingly can't be convinced
    // to create binaries.
    run(
        "cc",
        options
            .iter()
            .map(OsStr::new)
            .chain([src.as_os_str(), "-o".as_ref(), dst.as_os_str()]),
    )
    .expect("failed to run `cc`")
}

/// Convert debug information contained in `src` into GSYM in `dst` using
/// `llvm-gsymutil`.
fn gsym(src: &Path, dst: &str) {
    let dst = src.with_file_name(dst);
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", dst.display());

    let gsymutil = env::var_os("LLVM_GSYMUTIL").unwrap_or_else(|| OsString::from("llvm-gsymutil"));

    run(
        gsymutil,
        ["--convert".as_ref(), src, "--out-file".as_ref(), &dst],
    )
    .expect("failed to run `llvm-gsymutil`")
}

/// Build the various test binaries.
fn build_test_bins(crate_root: &Path) {
    let src = crate_root.join("data").join("test.c");
    cc(&src, "test-no-debug.bin", &["-g0"]);
    cc(&src, "test-dwarf-v4.bin", &["-gdwarf-4"]);

    let src = crate_root.join("data").join("test-gsym.c");
    let ld_script = crate_root.join("data").join("test-gsym.ld");
    let ld_script = ld_script.to_str().unwrap();
    println!("cargo:rerun-if-changed={ld_script}");
    cc(
        &src,
        "test-gsym.bin",
        &[
            "-gdwarf-4",
            "-T",
            ld_script,
            "-Wl,--build-id=none",
            "-O0",
            "-nostdlib",
        ],
    );

    let src = crate_root.join("data").join("test-gsym.bin");
    gsym(&src, "test.gsym");
}

fn main() {
    let crate_dir = env!("CARGO_MANIFEST_DIR");

    if !cfg!(feature = "dont-generate-test-files") {
        build_test_bins(crate_dir.as_ref());
    }

    #[cfg(feature = "cheader")]
    {
        let build_type = env::var("PROFILE").unwrap();
        let target_path = Path::new(&crate_dir).join("target").join(build_type);

        cbindgen::Builder::new()
            .with_crate(crate_dir)
            .with_config(cbindgen::Config::from_root_or_default(crate_dir))
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(target_path.join("blazesym.h"));
    }
}
