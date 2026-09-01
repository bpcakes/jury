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
        fn output(&mut self, stream: OwnedProcessOutputStream, bytes: &[u8]) {
            if stream == OwnedProcessOutputStream::Stdout {
                self.0.extend_from_slice(bytes);
            }
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
        fn output(&mut self, stream: OwnedProcessOutputStream, bytes: &[u8]) {
            if stream == OwnedProcessOutputStream::Stdout && !bytes.is_empty() {
                self.ready = true;
            }
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn bounded_capture_is_binary_safe_and_reports_truncation() -> Result<(), Box<dyn std::error::Error>>
{
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "i=0; while [ \"$i\" -lt 500 ]; do printf '0123456789abcdef' >&2; i=$((i + 1)); done; printf '\\377diagnostic\\n'",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = run_owned_process_tree_with_output_limits(
        &mut command,
        Duration::from_secs(2),
        ProcessOutputLimits {
            stdout: 128,
            stderr: 1024,
        },
        || false,
    )?;
    let stdout = output.stdout.ok_or("stdout was not captured")?;
    let stderr = output.stderr.ok_or("stderr was not captured")?;
    assert!(stdout.complete);
    assert!(stdout.to_string_lossy().contains("diagnostic"));
    assert!(stderr.complete);
    assert!(stderr.truncated);
    assert_eq!(stderr.bytes.len(), 1024);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn fatal_output_overflow_terminates_descendants_immediately()
-> Result<(), Box<dyn std::error::Error>> {
    struct Ignore;
    impl OwnedProcessObserver for Ignore {}

    let temp = tempdir()?;
    let marker = temp.path().join("overflow-descendant");
    let script = format!(
        "{} & i=0; while [ \"$i\" -lt 1000 ]; do printf '0123456789abcdef'; i=$((i + 1)); done; wait",
        descendant_command(&marker)?
    );
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();

    let error = run_owned_process_tree_with_output_policy_and_observer(
        &mut command,
        Duration::from_secs(3),
        ProcessOutputLimits {
            stdout: 512,
            stderr: 512,
        },
        ProcessOutputOverflowPolicy::Error,
        &mut Ignore,
    )
    .err()
    .ok_or("fatal overflow unexpectedly succeeded")?;
    assert!(matches!(
        error,
        OwnedProcessTreeError::OutputLimitExceeded(OwnedProcessOutputStream::Stdout)
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_descendant_did_not_survive(&marker)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn fatal_output_policy_rejects_overflow_found_during_final_drain()
-> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("/bin/sh").args(["-c", "exit 0"]).status()?;
    let capture = || BoundedProcessOutput {
        bytes: vec![b'x'; 8],
        truncated: true,
        complete: true,
    };

    let error = finalize_owned_process_output(
        Ok(status),
        Some(capture()),
        None,
        ProcessOutputOverflowPolicy::Error,
    )
    .err()
    .ok_or("fatal final-drain overflow unexpectedly succeeded")?;
    assert!(matches!(
        error,
        OwnedProcessTreeError::OutputLimitExceeded(OwnedProcessOutputStream::Stdout)
    ));

    let output = finalize_owned_process_output(
        Ok(status),
        Some(capture()),
        None,
        ProcessOutputOverflowPolicy::Truncate,
    )?;
    assert!(output.stdout.is_some_and(|stdout| stdout.truncated));
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn streaming_redaction_precedes_capture_and_observation() -> Result<(), Box<dyn std::error::Error>>
{
    #[derive(Default)]
    struct CaptureObserver(Vec<u8>);
    impl OwnedProcessObserver for CaptureObserver {
        fn output(&mut self, _stream: OwnedProcessOutputStream, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }

    let redactor = StreamingRedactor::from_patterns([b"ExampleSecret".to_vec()])?;
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "printf Example; sleep 0.03; printf Secret; printf Example >&2; sleep 0.03; printf Secret >&2",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut observer = CaptureObserver::default();

    let output = run_owned_process_tree_with_redacted_output(
        &mut command,
        Duration::from_secs(2),
        ProcessOutputLimits::default(),
        ProcessOutputOverflowPolicy::Truncate,
        Some(ProcessOutputRedaction::new(redactor)),
        &mut observer,
    )?;
    let stdout = output.stdout.ok_or("stdout was not captured")?;
    let stderr = output.stderr.ok_or("stderr was not captured")?;
    assert_eq!(stdout.bytes, b"[REDACTED]");
    assert_eq!(stderr.bytes, b"[REDACTED]");
    assert!(!observer.0.windows(13).any(|w| w == b"ExampleSecret"));
    assert_eq!(
        observer
            .0
            .windows(b"[REDACTED]".len())
            .filter(|window| *window == b"[REDACTED]")
            .count(),
        2
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn redaction_state_never_crosses_between_output_streams() -> Result<(), Box<dyn std::error::Error>>
{
    struct Ignore;
    impl OwnedProcessObserver for Ignore {}

    let redactor = StreamingRedactor::from_patterns([b"ExampleSecret".to_vec()])?;
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "printf Example; printf Secret >&2"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = run_owned_process_tree_with_redacted_output(
        &mut command,
        Duration::from_secs(2),
        ProcessOutputLimits::default(),
        ProcessOutputOverflowPolicy::Truncate,
        Some(ProcessOutputRedaction::new(redactor)),
        &mut Ignore,
    )?;
    assert_eq!(
        output.stdout.ok_or("stdout was not captured")?.bytes,
        b"Example"
    );
    assert_eq!(
        output.stderr.ok_or("stderr was not captured")?.bytes,
        b"Secret"
    );
    Ok(())
}

#[test]
fn cancellation_before_spawn_and_spawn_failure_are_distinct() {
    let mut cancelled = Command::new("jury-process-fixture-that-does-not-exist");
    assert!(matches!(
        run_owned_process_tree_with_output(&mut cancelled, Duration::from_secs(1), || true),
        Err(OwnedProcessTreeError::CancelledBeforeStart)
    ));

    let mut missing = Command::new("jury-process-fixture-that-does-not-exist");
    let error =
        run_owned_process_tree_with_output(&mut missing, Duration::from_secs(1), || false).err();
    assert!(matches!(error, Some(OwnedProcessTreeError::Start(_))));
}

#[test]
fn an_unrepresentable_timeout_fails_before_spawn() {
    let mut missing = Command::new("jury-process-fixture-that-does-not-exist");
    assert!(matches!(
        run_owned_process_tree_with_output(&mut missing, Duration::MAX, || false),
        Err(OwnedProcessTreeError::InvalidTimeout)
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn partial_pipe_setup_failure_cleans_the_spawned_child() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let marker = temp.path().join("partial-setup-child");
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "process::tests::process_test_helper",
            "--nocapture",
        ])
        .env(TEST_MODE_ENV, "partial-setup")
        .env(TEST_MARKER_ENV, &marker)
        .env(TEST_GATE_ENV, marker_path_to_gate(&marker))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let error = interaction::run_owned_process_tree_with_cooperative_interaction::<(), _>(
        &mut command,
        Duration::from_secs(1),
        |_stdin, _stdout, _deadline| Ok(()),
    )
    .err()
    .ok_or("partial setup unexpectedly succeeded")?;
    assert!(matches!(
        error,
        interaction::OwnedProcessTreeInteractionError::Interaction(
            interaction::ProcessInteractionFailure::MissingStdin
        )
    ));
    assert_descendant_did_not_survive(&marker)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn interaction_failure_is_typed_and_cleans_the_process_tree()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let marker = temp.path().join("interaction-failure-descendant");
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", &descendant_script(&marker, true)?])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let error = interaction::run_owned_process_tree_with_cooperative_interaction::<(), _>(
        &mut command,
        Duration::from_secs(2),
        |_stdin, _stdout, _deadline| Err(interaction::ProcessInteractionFailure::Callback),
    )
    .err()
    .ok_or("rejected interaction unexpectedly succeeded")?;
    assert!(matches!(
        error,
        interaction::OwnedProcessTreeInteractionError::Interaction(
            interaction::ProcessInteractionFailure::Callback
        )
    ));
    assert_descendant_did_not_survive(&marker)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn escaped_pipe_owner_does_not_make_capture_unbounded() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let marker = temp.path().join("escaped-output-owner");
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "process::tests::process_test_helper",
            "--nocapture",
        ])
        .env(TEST_MODE_ENV, "escape-owner-spawn")
        .env(TEST_MARKER_ENV, &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();

    let output =
        run_owned_process_tree_with_output(&mut command, Duration::from_secs(2), || false)?;
    assert!(started.elapsed() < Duration::from_millis(500));
    let stdout = output.stdout.ok_or("stdout was not captured")?;
    let stderr = output.stderr.ok_or("stderr was not captured")?;
    assert!(!stdout.complete || !stderr.complete);
    std::thread::sleep(Duration::from_millis(700));
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cooperative_interaction_deadline_survives_an_escaped_pipe_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let marker = temp.path().join("escaped-interaction-owner");
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "process::tests::process_test_helper",
            "--nocapture",
        ])
        .env(TEST_MODE_ENV, "escape-owner-spawn")
        .env(TEST_MARKER_ENV, &marker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let started = Instant::now();

    let error = interaction::run_owned_process_tree_with_cooperative_interaction::<(), _>(
        &mut command,
        Duration::from_millis(100),
        |_stdin, mut stdout, deadline| {
            let mut buffer = [0_u8; 256];
            loop {
                match stdout.read(&mut buffer) {
                    Ok(0) => return Ok(()),
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err(interaction::ProcessInteractionFailure::Callback);
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => return Err(interaction::ProcessInteractionFailure::Callback),
                }
            }
        },
    )
    .err()
    .ok_or("escaped interaction unexpectedly succeeded")?;

    assert!(matches!(
        error,
        interaction::OwnedProcessTreeInteractionError::Interaction(
            interaction::ProcessInteractionFailure::Callback
        )
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(marker.exists());
    std::thread::sleep(Duration::from_millis(700));
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn injected_wait_failure_still_cleans_descendants() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let marker = temp.path().join("wait-failure-descendant");
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", &descendant_script(&marker, true)?])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut process = spawn_owned_process(&mut command)?;

    let error = finish_owned_process_wait(
        &mut process,
        Err(std::io::Error::other("injected wait failure")),
    )
    .err()
    .ok_or("injected wait failure unexpectedly succeeded")?;
    assert!(matches!(error, OwnedProcessTreeError::Await));
    assert_descendant_did_not_survive(&marker)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn tree_cleanup_failure_reaps_the_leader_and_retains_the_primary_error()
-> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "while :; do :; done"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut process = spawn_owned_process(&mut command)?;

    let first = process
        .terminate_and_reap_with(|_, _| Err(std::io::Error::other("injected process-tree failure")))
        .err()
        .ok_or("injected process-tree failure unexpectedly succeeded")?
        .to_string();
    assert!(first.contains("injected process-tree failure"));
    assert!(process.cleanup_finalized);
    assert!(!process.cleanup_complete);
    assert!(process.reaped_status.is_some());
    assert!(process.process_group.is_none());
    let retained = process
        .terminate_and_reap()
        .err()
        .ok_or("failed cleanup was not retained")?
        .to_string();
    assert_eq!(retained, first);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cleanup_retries_signals_between_quiescence_proofs() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::VecDeque;

    assert_eq!(
        REQUIRED_CONSECUTIVE_PROCESS_GROUP_PROOFS, 2,
        "the containment contract requires two independent quiescence snapshots"
    );

    #[derive(Default)]
    struct Injected {
        signals: usize,
        proofs: VecDeque<bool>,
    }

    let now = Instant::now();
    let mut state = Injected {
        proofs: VecDeque::from([false, true, true]),
        ..Injected::default()
    };
    confirm_process_group_quiescent_with(
        &mut state,
        ProcessGroupQuiescence {
            process_group: 73,
            deadline: now + Duration::from_secs(1),
            required_consecutive_proofs: REQUIRED_CONSECUTIVE_PROCESS_GROUP_PROOFS,
            timeout_phase: "injected confirmation",
        },
        |state, _, _| {
            state.signals += 1;
            Ok(ProcessGroupSignalResult::Delivered)
        },
        |state, _, _| {
            state
                .proofs
                .pop_front()
                .ok_or_else(|| std::io::Error::other("proof sequence exhausted"))
        },
        || now,
        |_| {},
    )?;
    assert_eq!(state.signals, 3);
    assert!(state.proofs.is_empty());
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_failed_leader_observation_prevents_group_signalling() -> Result<(), Box<dyn std::error::Error>>
{
    #[derive(Default)]
    struct Injected {
        observations: usize,
        signals: usize,
    }

    let mut state = Injected::default();
    let error = observe_owned_process_before_group_signal_with(
        &mut state,
        |state| {
            state.observations += 1;
            Err(std::io::Error::from(rustix::io::Errno::CHILD))
        },
        |state, _| {
            state.signals += 1;
            Ok(ProcessGroupSignalResult::Delivered)
        },
    )
    .err()
    .ok_or("the injected observation failure unexpectedly succeeded")?;

    assert_eq!(
        error.raw_os_error(),
        Some(rustix::io::Errno::CHILD.raw_os_error())
    );
    assert_eq!(state.observations, 1);
    assert_eq!(state.signals, 0);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_terminal_signal_error_prevents_membership_proof() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Default)]
    struct Injected {
        signals: usize,
        proofs: usize,
    }

    let now = Instant::now();
    let mut state = Injected::default();
    let error = confirm_process_group_quiescent_with(
        &mut state,
        ProcessGroupQuiescence {
            process_group: 73,
            deadline: now + Duration::from_secs(1),
            required_consecutive_proofs: REQUIRED_CONSECUTIVE_PROCESS_GROUP_PROOFS,
            timeout_phase: "injected terminal error",
        },
        |state, _, _| {
            state.signals += 1;
            Err(std::io::Error::from(rustix::io::Errno::CHILD))
        },
        |state, _, _| {
            state.proofs += 1;
            Ok(true)
        },
        || now,
        |_| {},
    )
    .err()
    .ok_or("the injected signal failure unexpectedly succeeded")?;

    assert_eq!(
        error.raw_os_error(),
        Some(rustix::io::Errno::CHILD.raw_os_error())
    );
    assert_eq!(state.signals, 1);
    assert_eq!(state.proofs, 0);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cleanup_rechecks_the_absolute_deadline_after_signalling()
-> Result<(), Box<dyn std::error::Error>> {
    #[derive(Default)]
    struct Injected {
        signals: usize,
        proofs: usize,
    }

    let start = Instant::now();
    let deadline = start + Duration::from_millis(20);
    let observed_now = std::cell::Cell::new(start);
    let sleeps = std::cell::Cell::new(0_usize);
    let mut state = Injected::default();
    let error = confirm_process_group_quiescent_with(
        &mut state,
        ProcessGroupQuiescence {
            process_group: 73,
            deadline,
            required_consecutive_proofs: REQUIRED_CONSECUTIVE_PROCESS_GROUP_PROOFS,
            timeout_phase: "injected deadline",
        },
        |state, _, _| {
            state.signals += 1;
            observed_now.set(deadline);
            Ok(ProcessGroupSignalResult::Delivered)
        },
        |state, _, _| {
            state.proofs += 1;
            Ok(true)
        },
        || observed_now.get(),
        |_| sleeps.set(sleeps.get() + 1),
    )
    .err()
    .ok_or("cleanup accepted a proof after its absolute deadline")?;

    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(state.signals, 1);
    assert_eq!(state.proofs, 0);
    assert_eq!(sleeps.get(), 0);
    Ok(())
}

#[test]
fn workspace_dependency_lock_contains_no_jig_package() -> Result<(), Box<dyn std::error::Error>> {
    let lock =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock"))?;
    assert!(!lock.contains("name = \"jig"));
    assert!(!lock.contains("jig-owned-process"));
    Ok(())
}

#[test]
fn platform_support_is_explicit() {
    #[cfg(target_os = "linux")]
    assert_eq!(
        process_tree_platform_support(),
        ProcessTreePlatformSupport::LinuxProcessGroups
    );
    #[cfg(target_os = "macos")]
    assert_eq!(
        process_tree_platform_support(),
        ProcessTreePlatformSupport::DeferredMacosBackend
    );
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    assert_eq!(
        process_tree_platform_support(),
        ProcessTreePlatformSupport::Unsupported
    );
}
