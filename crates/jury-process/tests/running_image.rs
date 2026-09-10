//! Real subprocess identity regressions, with a barrier before capture.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use jury_process::RunningImage;
use wait_timeout::ChildExt as _;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn normal_image_matches_the_executable() -> TestResult {
    let image = RunningImage::capture()?;
    let metadata = fs::metadata(std::env::current_exe()?)?;
    assert_eq!(image.device(), metadata.dev());
    assert_eq!(image.inode(), metadata.ino());
    assert_eq!(image.mode(), metadata.mode());
    assert_eq!(image.length(), metadata.len());
    #[cfg(target_os = "linux")]
    assert_eq!(image.path(), fs::canonicalize("/proc/self/exe")?);
    Ok(())
}

#[test]
#[ignore = "subprocess entry point with a parent-owned barrier"]
fn image_probe() -> TestResult {
    if std::env::var("EXAMPLE_IMAGE_CHANGE")? == "fail-before-barrier" {
        eprintln!("Example child failure diagnostic");
        return Err("Example child failure".into());
    }
    let ready = std::env::var_os("EXAMPLE_IMAGE_READY").ok_or("missing barrier")?;
    fs::write(ready, b"ready")?;
    std::io::stdin().read_exact(&mut [0])?;
    let image = RunningImage::capture();
    if matches!(
        std::env::var("EXAMPLE_IMAGE_CHANGE")?.as_str(),
        "delete" | "rename-over"
    ) {
        assert!(image.is_err(), "unlinked image identity was accepted");
    } else {
        let image = image?;
        let original = std::env::var_os("EXAMPLE_IMAGE_ORIGINAL").ok_or("missing image")?;
        let metadata = fs::metadata(&original)?;
        if std::env::var("EXAMPLE_IMAGE_CHANGE")? == "symlink" {
            assert_eq!(image.path(), fs::canonicalize(original)?);
        }
        assert_eq!(image.device(), metadata.dev());
        assert_eq!(image.inode(), metadata.ino());
        assert_eq!(image.mode(), metadata.mode());
        assert_eq!(image.length(), metadata.len());
    }
    Ok(())
}

#[test]
fn replacement_before_capture_cannot_supply_image_identity() -> TestResult {
    run_image_probe("replace")
}

#[test]
fn deleted_image_is_refused() -> TestResult {
    run_image_probe("delete")
}

#[test]
fn atomic_upgrade_over_running_image_is_refused() -> TestResult {
    run_image_probe("rename-over")
}

#[test]
fn a_hard_link_does_not_change_image_identity() -> TestResult {
    run_image_probe("hardlink")
}

#[cfg(target_os = "macos")]
#[test]
fn hardened_runtime_image_can_be_captured_without_entitlements() -> TestResult {
    run_image_probe("hardened")
}

fn run_image_probe(change: &str) -> TestResult {
    // Parallel fork/exec can inherit another thread's briefly writable copied
    // image until exec closes CLOEXEC descriptors, causing Linux ETXTBSY.
    // Serialize this test binary's copy-and-spawn fixtures, not capture itself.
    static PROBE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = PROBE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let temporary = tempfile::tempdir()?;
    let root = fs::canonicalize(temporary.path())?;
    let executable = root.join("ExampleImage");
    let original = root.join("ExampleOriginal");
    let ready = root.join("ExampleReady");
    if change == "symlink" {
        fs::copy(std::env::current_exe()?, &original)?;
        std::os::unix::fs::symlink(&original, &executable)?;
    } else {
        fs::copy(std::env::current_exe()?, &executable)?;
    }
    #[cfg(target_os = "macos")]
    if change == "hardened" {
        let signed = Command::new("/usr/bin/codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--options",
                "runtime",
                "--timestamp=none",
            ])
            .arg(&executable)
            .output()?;
        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
        let signature = Command::new("/usr/bin/codesign")
            .args(["--display", "--verbose=2"])
            .arg(&executable)
            .output()?;
        assert!(signature.status.success());
        assert!(String::from_utf8_lossy(&signature.stderr).contains("runtime"));
    }
    let mut child = Command::new(&executable)
        .args(["--ignored", "--exact", "image_probe"])
        .env("EXAMPLE_IMAGE_READY", &ready)
        .env("EXAMPLE_IMAGE_CHANGE", change)
        .env(
            "EXAMPLE_IMAGE_ORIGINAL",
            if change == "hardened" {
                &executable
            } else {
                &original
            },
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let result = (|| -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            if Instant::now() >= deadline || child.try_wait()?.is_some() {
                return Err("image probe did not reach barrier".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if change == "hardlink" {
            fs::hard_link(&executable, &original)?;
        } else if change == "rename-over" {
            fs::copy(&executable, &original)?;
            assert_ne!(
                fs::metadata(&original)?.ino(),
                fs::metadata(&executable)?.ino()
            );
            fs::rename(&original, &executable)?;
        } else if !matches!(change, "symlink" | "hardened") {
            fs::rename(&executable, &original)?;
            fs::copy(&original, &executable)?;
            if fs::metadata(&original)?.ino() == fs::metadata(&executable)?.ino() {
                return Err("replacement reused the original inode".into());
            }
            if change == "delete" {
                fs::remove_file(&original)?;
            }
        }
        child.stdin.take().ok_or("missing stdin")?.write_all(b"x")?;
        if child.wait_timeout(Duration::from_secs(10))?.is_none() {
            return Err("image probe timed out".into());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let output = child.wait_with_output()?;
    if let Err(cause) = result {
        return Err(format!(
            "{cause}; child stdout: {}; child stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    assert!(
        output.status.success(),
        "image probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn early_probe_failure_preserves_child_diagnostics() -> TestResult {
    let error = run_image_probe("fail-before-barrier")
        .err()
        .ok_or("probe unexpectedly succeeded")?
        .to_string();
    assert!(
        error.contains("image probe did not reach barrier"),
        "{error}"
    );
    assert!(error.contains("Example child failure diagnostic"));
    Ok(())
}

#[test]
fn symlink_invocation_records_the_resolved_image() -> TestResult {
    run_image_probe("symlink")
}
