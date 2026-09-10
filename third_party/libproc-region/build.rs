// SPDX-License-Identifier: MIT
// Derived from libproc 0.14.11; see README.md and LICENSE for attribution.

#[cfg(target_os = "macos")]
fn main() {
    use bindgen::{RustEdition, RustTarget};
    use std::env;
    use std::path::Path;

    let sdk = env::var_os("SDKROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let output = std::process::Command::new("xcrun")
                .args(["--sdk", "macosx", "--show-sdk-path"])
                .output()
                .expect("cannot locate the macOS SDK");
            assert!(
                output.status.success(),
                "xcrun could not locate the macOS SDK"
            );
            std::path::PathBuf::from(
                String::from_utf8(output.stdout)
                    .expect("SDK path is not UTF-8")
                    .trim(),
            )
        });
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SDKROOT");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    println!(
        "cargo:rerun-if-changed={}",
        sdk.join("SDKSettings.json").display()
    );
    let rust_target = RustTarget::stable(90, 0).expect("unsupported bindgen Rust target");
    let bindings = bindgen::builder()
        .header("wrapper.h")
        .rust_target(rust_target)
        .rust_edition(RustEdition::Edition2024)
        .allowlist_type("proc_regionwithpathinfo")
        .allowlist_function("proc_pidinfo")
        .allowlist_function("_NSGetMachExecuteHeader")
        .allowlist_var("PROC_PIDREGIONPATHINFO")
        .layout_tests(true)
        // CargoCallbacks::new() enables top-level wrapper.h tracking in 0.72.1,
        // as well as every transitive SDK header (including in-place upgrades).
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .clang_arg("-isysroot")
        .clang_arg(sdk.to_str().expect("SDK path is not UTF-8"))
        .generate()
        .expect("Failed to build libproc bindings");
    let output_path = Path::new(&env::var("OUT_DIR").expect("OUT_DIR env var was not defined"))
        .join("osx_libproc_bindings.rs");
    bindings
        .write_to_file(output_path)
        .expect("Failed to write libproc bindings");
}

#[cfg(not(target_os = "macos"))]
fn main() {
    assert_ne!(
        std::env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("macos"),
        "libproc-region requires a native macOS build host with the Apple SDK"
    );
}
