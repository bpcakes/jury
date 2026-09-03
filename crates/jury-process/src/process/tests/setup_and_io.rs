#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Read;
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::PathBuf;
use std::process::Command;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Stdio;
use std::time::Duration;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::Instant;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use tempfile::tempdir;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use jury_protected::{ProtectedMemory, ProtectionPolicy};

use super::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
const TEST_MODE_ENV: &str = "JURY_PROCESS_TEST_MODE";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const TEST_MARKER_ENV: &str = "JURY_PROCESS_TEST_MARKER";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const TEST_GATE_ENV: &str = "JURY_PROCESS_TEST_GATE";

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct IgnoreProcessActivity;

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl OwnedProcessObserver for IgnoreProcessActivity {}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn shell_quote(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let path = path
        .to_str()
        .ok_or("test helper path was not valid UTF-8")?;
    Ok(format!("'{}'", path.replace('\'', "'\"'\"'")))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn wait_for_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    if path.exists() {
        Ok(())
    } else {
        Err(format!(
            "test synchronization file {} was not published",
            path.display()
        )
        .into())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn marker_path_to_gate(marker: &Path) -> PathBuf {
    marker.with_extension("release")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_descendant_did_not_survive(marker: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(marker_path_to_gate(marker), b"release")?;
    std::thread::sleep(Duration::from_millis(500));
    if marker.exists() {
        Err("a descendant survived process-tree cleanup".into())
    } else {
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn descendant_command(marker: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let executable = shell_quote(&std::env::current_exe()?)?;
    let gate = shell_quote(&marker_path_to_gate(marker))?;
    let marker = shell_quote(marker)?;
    Ok(format!(
        "{TEST_MODE_ENV}=delayed-marker {TEST_MARKER_ENV}={marker} {TEST_GATE_ENV}={gate} {executable} --exact process::tests::process_test_helper --nocapture >/dev/null 2>&1"
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn descendant_script(
    marker: &Path,
    keep_leader_alive: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let tail = if keep_leader_alive {
        "while :; do sleep 1; done"
    } else {
        "exit 0"
    };
    Ok(format!("{} & {tail}", descendant_command(marker)?))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn process_test_helper() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mode) = std::env::var_os(TEST_MODE_ENV) else {
        return Ok(());
    };
    let marker = std::env::var_os(TEST_MARKER_ENV).map(PathBuf::from);
    let gate = std::env::var_os(TEST_GATE_ENV).map(PathBuf::from);
    match mode.to_str().ok_or("test mode was not valid UTF-8")? {
        "delayed-marker" => {
            wait_for_file(&gate.ok_or("missing delayed marker gate path")?)?;
            std::fs::write(marker.ok_or("missing delayed marker path")?, b"survived")?;
        }
        "partial-setup" => {
            wait_for_file(&gate.ok_or("missing partial-setup gate path")?)?;
            std::fs::write(
                marker.ok_or("missing partial-setup marker path")?,
                b"survived",
            )?;
            std::thread::sleep(Duration::from_secs(5));
        }
        "escape-owner-spawn" => {
            use std::os::unix::process::CommandExt;

            let marker = marker.ok_or("missing escaped-owner marker path")?;
            let mut child = Command::new(std::env::current_exe()?);
            child
                .args([
                    "--exact",
                    "process::tests::process_test_helper",
                    "--nocapture",
                ])
                .env(TEST_MODE_ENV, "escaped-owner")
                .env(TEST_MARKER_ENV, &marker)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .process_group(0);
            drop(child.spawn()?);
            wait_for_file(&marker)?;
        }
        "escaped-owner" => {
            std::fs::write(
                marker.ok_or("missing escaped-owner marker path")?,
                b"started",
            )?;
            std::thread::sleep(Duration::from_millis(600));
        }
        other => return Err(format!("unknown process helper mode {other}").into()),
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn successful_leader_exit_still_cleans_descendants() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let marker = temp.path().join("successful-leader-descendant");
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", &descendant_script(&marker, false)?])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output =
        run_owned_process_tree_with_output(&mut command, Duration::from_secs(2), || false)?;
    assert!(output.status.success());
    assert_descendant_did_not_survive(&marker)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn output_only_supervision_closes_unused_piped_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "cat >/dev/null; printf done"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output =
        run_owned_process_tree_with_output(&mut command, Duration::from_millis(500), || false)?;
    assert!(output.status.success());
    assert_eq!(
        output.stdout.ok_or("stdout was not captured")?.bytes,
        b"done"
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn protected_stdin_is_delivered_while_output_is_drained() -> Result<(), Box<dyn std::error::Error>>
{
    let bytes = b"Example binary input\0with a suffix";
    let input = ProtectedMemory::initialize(
        bytes.len(),
        ProtectionPolicy::EmergencyAllowDegraded,
        |destination| {
            destination.copy_from_slice(bytes);
            Ok::<usize, ()>(bytes.len())
        },
    )?;
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "cat; printf stderr-ready >&2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut observer = IgnoreProcessActivity;
    let mut options = OwnedProcessTreeOptions::bounded(Duration::from_secs(2));
    options.stdin = Some(input);

    let output = run_owned_process_tree_with_options(&mut command, options, &mut observer)?;
    assert_eq!(output.stdout.ok_or("stdout was not captured")?.bytes, bytes);
    assert_eq!(
        output.stderr.ok_or("stderr was not captured")?.bytes,
        b"stderr-ready"
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn partial_stdin_consumer_is_a_delivery_failure() -> Result<(), Box<dyn std::error::Error>> {
    let input = ProtectedMemory::initialize(
        1024 * 1024,
        ProtectionPolicy::EmergencyAllowDegraded,
        |destination| {
            destination.fill(0xa5);
            Ok::<usize, ()>(destination.len())
        },
    )?;
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "dd bs=1 count=7 of=/dev/null 2>/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut observer = IgnoreProcessActivity;
    let mut options = OwnedProcessTreeOptions::bounded(Duration::from_secs(2));
    options.stdin = Some(input);

    let error = run_owned_process_tree_with_options(&mut command, options, &mut observer)
        .err()
        .ok_or("partial child stdin consumption unexpectedly succeeded")?;
    assert!(matches!(error, OwnedProcessTreeError::Stdin));
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn refused_protected_stdin_terminates_the_owned_tree() -> Result<(), Box<dyn std::error::Error>> {
    let input = ProtectedMemory::initialize(
        1024 * 1024,
        ProtectionPolicy::EmergencyAllowDegraded,
        |destination| {
            destination.fill(0xa5);
            Ok::<usize, ()>(destination.len())
        },
    )?;
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "exec 0<&-; sleep 1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut observer = IgnoreProcessActivity;
    let mut options = OwnedProcessTreeOptions::bounded(Duration::from_secs(2));
    options.stdin = Some(input);

    let error = run_owned_process_tree_with_options(&mut command, options, &mut observer)
        .err()
        .ok_or("closed child stdin unexpectedly succeeded")?;
    assert!(matches!(error, OwnedProcessTreeError::Stdin));
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn unbounded_streaming_retains_nothing_but_observes_every_byte()
-> Result<(), Box<dyn std::error::Error>> {
    #[derive(Default)]
    struct StreamObserver(Vec<u8>);
    impl OwnedProcessObserver for StreamObserver {
        fn output(
            &mut self,
            stream: OwnedProcessOutputStream,
            bytes: &[u8],
        ) -> std::io::Result<()> {
            if stream == OwnedProcessOutputStream::Stdout {
                self.0.extend_from_slice(bytes);
            }
            Ok(())
        }
    }

    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "printf 'streamed-output'"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut observer = StreamObserver::default();
    let mut options = OwnedProcessTreeOptions::unbounded();
    options.limits = ProcessOutputLimits {
        stdout: 0,
        stderr: 0,
    };

    let output = run_owned_process_tree_with_options(&mut command, options, &mut observer)?;
    assert_eq!(observer.0, b"streamed-output");
    let retained = output.stdout.ok_or("stdout was not captured")?;
    assert!(retained.bytes.is_empty());
    assert!(retained.truncated);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn observer_output_failure_is_terminal() -> Result<(), Box<dyn std::error::Error>> {
    struct FailingObserver;
    impl OwnedProcessObserver for FailingObserver {
        fn output(
            &mut self,
            _stream: OwnedProcessOutputStream,
            _bytes: &[u8],
        ) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "example downstream closure",
            ))
        }
    }

    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "printf output; sleep 1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let error = run_owned_process_tree_with_output_limits_and_observer(
        &mut command,
        Duration::from_secs(2),
        ProcessOutputLimits::default(),
        &mut FailingObserver,
    )
    .err()
    .ok_or("observer output failure unexpectedly succeeded")?;
    assert!(matches!(error, OwnedProcessTreeError::Output));
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn supervision_preserves_command_environment_for_reuse() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "printf %s \"$EXAMPLE_REUSABLE_VALUE\""])
        .env("EXAMPLE_REUSABLE_VALUE", "present")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for _ in 0..2 {
        let output =
            run_owned_process_tree_with_output(&mut command, Duration::from_secs(2), || false)?;
        assert_eq!(
            output.stdout.ok_or("stdout was not captured")?.bytes,
            b"present"
        );
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn timeout_cleans_the_complete_process_tree() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let marker = temp.path().join("timeout-descendant");
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", &descendant_script(&marker, true)?])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let error =
        run_owned_process_tree_with_output(&mut command, Duration::from_millis(100), || false)
            .err()
            .ok_or("timeout unexpectedly succeeded")?;
    assert!(matches!(error, OwnedProcessTreeError::TimedOut));
    assert_descendant_did_not_survive(&marker)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cancellation_cleans_the_complete_process_tree() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let marker = temp.path().join("cancelled-descendant");
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", &descendant_script(&marker, true)?])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut polls = 0_u8;

    let error = run_owned_process_tree_with_output(&mut command, Duration::from_secs(2), || {
        polls = polls.saturating_add(1);
        polls >= 3
    })
    .err()
    .ok_or("cancellation unexpectedly succeeded")?;
    assert!(matches!(error, OwnedProcessTreeError::Cancelled));
    assert_descendant_did_not_survive(&marker)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn forwarded_signal_reaches_the_group_and_preserves_status()
-> Result<(), Box<dyn std::error::Error>> {
    struct ForwardOnReady {
        ready: bool,
        forwarded: bool,
    }

    impl OwnedProcessObserver for ForwardOnReady {
        fn output(
            &mut self,
            stream: OwnedProcessOutputStream,
            bytes: &[u8],
        ) -> std::io::Result<()> {
            if stream == OwnedProcessOutputStream::Stdout && !bytes.is_empty() {
                self.ready = true;
            }
            Ok(())
        }

        fn signal(&mut self) -> Option<ProcessSignal> {
            if self.ready && !self.forwarded {
                self.forwarded = true;
                Some(ProcessSignal::Terminate)
            } else {
                None
            }
        }
    }

    let temp = tempdir()?;
    let marker = temp.path().join("signalled-descendant");
    let script = format!(
        "{} & printf ready; while :; do sleep 1; done",
        descendant_command(&marker)?
    );
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut observer = ForwardOnReady {
        ready: false,
        forwarded: false,
    };

    let output = run_owned_process_tree_with_output_limits_and_observer(
        &mut command,
        Duration::from_secs(2),
        ProcessOutputLimits::default(),
        &mut observer,
    )?;
    assert!(observer.forwarded);
    assert_eq!(
        output.portable_status().signal,
        Some(rustix::process::Signal::TERM.as_raw())
    );
    assert_descendant_did_not_survive(&marker)?;
    Ok(())
}
