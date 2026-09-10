use super::*;

use std::net::TcpListener;
use std::time::{Duration, Instant};

#[test]
fn unsupported_children_fail_before_input_network_outputs_or_spawn() -> TestResult {
    let native = NativeHome::new()?;
    native.initialize()?;
    create_field(&native)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let request = native.cwd.join("request.json");
    let receipt = native.cwd.join("receipt.json");
    let marker = native.cwd.join("child-marker");
    let credential = native.cwd.join("absent-credential");
    let endpoint = format!(
        "{},http://{},{credential}",
        "11".repeat(32),
        listener.local_addr()?,
        credential = text(&credential)?
    );
    for operation in ["exec", "run"] {
        for direct in [false, true] {
            for existing in [false, true] {
                if existing {
                    fs::write(&request, b"Example existing request")?;
                    fs::write(&receipt, b"Example existing receipt")?;
                }
                let before = snapshot(&native.root)?;
                let mut command = native.command();
                command.args([
                    "--json",
                    "--passphrase-stdin",
                    operation,
                    "--file",
                    "EXAMPLE=ExampleItem/ExampleField",
                ]);
                if direct {
                    command.arg("--direct");
                } else {
                    command
                        .arg("--checkpoint")
                        .arg(native.cwd.join("absent-checkpoint"))
                        .arg("--request-out")
                        .arg(&request)
                        .arg("--receipt")
                        .arg(&receipt)
                        .args(["--witness", &endpoint, "--allow-insecure-loopback"]);
                }
                command
                    .args([
                        "--",
                        "/bin/sh",
                        "-c",
                        "printf ExampleMarker > \"$1\"",
                        "example-child",
                    ])
                    .arg(&marker);
                let mut child = command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;
                // Keep stdin open and empty: any passphrase read would block.
                let deadline = Instant::now() + Duration::from_secs(5);
                while child.try_wait()?.is_none() {
                    if Instant::now() >= deadline {
                        child.kill()?;
                        child.wait()?;
                        return Err("unsupported execution waited for private input".into());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let output = child.wait_with_output()?;
                assert_refusal(&native, &listener, &marker, &before, output)?;
                if existing {
                    fs::remove_file(&request)?;
                    fs::remove_file(&receipt)?;
                }
            }
        }
    }
    let before = snapshot(&native.root)?;
    let output = native
        .command()
        .args([
            "--json",
            "internal-exec",
            "--executable-fd",
            "3",
            "--working-directory-fd",
            "4",
            "--",
            "/bin/true",
        ])
        .output()?;
    assert_refusal(&native, &listener, &marker, &before, output)
}

fn assert_refusal(
    native: &NativeHome,
    listener: &TcpListener,
    marker: &Path,
    before: &[(PathBuf, Vec<u8>)],
    output: Output,
) -> TestResult {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["code"], "child-execution-unsupported");
    assert_eq!(snapshot(&native.root)?, before);
    assert!(!marker.exists());
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}

fn snapshot(root: &Path) -> TestResult<Vec<(PathBuf, Vec<u8>)>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            result.push((path.clone(), Vec::new()));
            result.extend(snapshot(&path)?);
        } else {
            result.push((path.clone(), fs::read(path)?));
        }
    }
    result.sort();
    Ok(result)
}
