
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
        fn output(
            &mut self,
            _stream: OwnedProcessOutputStream,
            bytes: &[u8],
        ) -> std::io::Result<()> {
            self.0.extend_from_slice(bytes);
            Ok(())
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
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result =
            run_owned_process_tree_with_output(&mut command, Duration::from_secs(2), || false);
        let _ = sender.send(result);
    });

    wait_for_file(&marker)?;
    let result = receiver.recv_timeout(Duration::from_millis(500));
    worker
        .join()
        .map_err(|_| "escaped-owner capture worker panicked")?;
    let output = result.map_err(|_| "capture remained blocked by the escaped pipe owner")??;
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
