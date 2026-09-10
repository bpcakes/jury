use std::os::unix::process::ExitStatusExt;

use super::*;

fn cleanup_with_injected_confirmation_error(
    process: &mut OwnedProcess,
) -> std::io::Result<ExitStatus> {
    let mut injected = false;
    let result = process.terminate_and_reap_with(|process, deadline| {
        // Run real group cleanup first so even assertion failures cannot leave
        // descendants behind. Only the reported confirmation error is injected.
        terminate_owned_process_tree(process, deadline)?;
        injected = true;
        Err(std::io::Error::other(
            "Example cleanup confirmation failure",
        ))
    });
    assert!(
        injected,
        "native cleanup failed before reaching fault injection"
    );
    assert!(result.is_err());
    assert!(process.cleanup_finalized);
    assert!(!process.cleanup_complete);
    assert_eq!(
        process.reaped_status.and_then(|status| status.signal()),
        Some(9)
    );
    assert!(process.process_group.is_none());
    result
}

#[test]
fn setup_failures_preserve_the_primary_cause_with_or_without_cleanup_failure()
-> Result<(), Box<dyn std::error::Error>> {
    use std::cell::Cell;
    use std::error::Error as _;

    for input_fails in [true, false] {
        for cleanup_fails in [false, true] {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "while :; do :; done"])
                .stdin(if input_fails {
                    Stdio::null()
                } else {
                    Stdio::piped()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            let mut options = OwnedProcessTreeOptions::bounded(Duration::from_secs(5));
            options.stdin = Some(ProtectedMemory::initialize(
                12,
                ProtectionPolicy::Strict,
                |destination| {
                    destination.copy_from_slice(b"ExampleInput");
                    Ok::<usize, ()>(destination.len())
                },
            )?);
            let output_starts = Cell::new(0);
            let cleanups = Cell::new(0);
            let error = run_owned_process_tree_with_io_and_cleanup(
                &mut command,
                options,
                &mut IgnoreProcessActivity,
                |child, limits, redaction| {
                    output_starts.set(output_starts.get() + 1);
                    assert!(child.stdin.is_none(), "protected stdin was not prepared");
                    assert!(child.stdout.is_some());
                    let drains = OwnedProcessOutputDrains::start(child, limits, redaction)?;
                    assert!(
                        child.stdout.is_none(),
                        "native output pipe was not acquired"
                    );
                    drop(drains);
                    // Deliberate failure after real pipe acquisition, without
                    // invalid descriptors, unsafe calls or a global test hook.
                    Err(std::io::Error::other("Example output setup failure"))
                },
                |process| {
                    cleanups.set(cleanups.get() + 1);
                    if cleanup_fails {
                        cleanup_with_injected_confirmation_error(process)
                    } else {
                        let status = process.terminate_and_reap()?;
                        assert_eq!(status.signal(), Some(9));
                        assert!(process.cleanup_complete);
                        Ok(status)
                    }
                },
            )
            .err()
            .ok_or("setup failure unexpectedly succeeded")?;
            assert_eq!(output_starts.get(), usize::from(!input_fails));
            assert_eq!(
                cleanups.get(),
                1,
                "setup failure did not explicitly clean up"
            );
            let primary = if cleanup_fails {
                assert!(matches!(
                    error,
                    OwnedProcessTreeError::CleanupAfterFailure(_)
                ));
                error
                    .source()
                    .and_then(|cause| cause.downcast_ref::<OwnedProcessTreeError>())
                    .ok_or("compound error lost its typed primary cause")?
            } else {
                &error
            };
            assert!(matches!(
                (input_fails, primary),
                (true, OwnedProcessTreeError::Stdin) | (false, OwnedProcessTreeError::Output)
            ));
            assert!(!error.is_cancellation());
        }
    }
    Ok(())
}

#[test]
fn final_drain_failure_preserves_primary_and_cleanup_failures()
-> Result<(), Box<dyn std::error::Error>> {
    struct CancelAfterOutputReady {
        gate: PathBuf,
        ready: PathBuf,
        cancelled: bool,
        handshake_error: Option<Box<dyn std::error::Error>>,
        output_calls: usize,
    }
    impl OwnedProcessObserver for CancelAfterOutputReady {
        fn poll(&mut self, _: Duration) {
            // The supervisor has just polled empty stdout. Arrange output
            // before cancellation so only its final drain can observe it.
            self.handshake_error = std::fs::write(&self.gate, b"release")
                .map_err(Into::into)
                .and_then(|()| wait_for_file(&self.ready))
                .err();
            self.cancelled = true;
        }
        fn cancelled(&mut self) -> bool {
            self.cancelled
        }
        fn output(&mut self, _: OwnedProcessOutputStream, bytes: &[u8]) -> std::io::Result<()> {
            assert_eq!(bytes, b"ExampleOutput");
            self.output_calls += 1;
            Err(std::io::Error::other("Example observer failure"))
        }
    }
    for cleanup_fails in [false, true] {
        let temporary = tempdir()?;
        let gate = temporary.path().join("ExampleRelease");
        let ready = temporary.path().join("ExampleReady");
        let mut command = Command::new("/bin/sh");
        command
        .args(["-c", "while [ ! -e \"$1\" ]; do sleep 0.01; done; printf ExampleOutput; : > \"$2\"; while :; do sleep 1; done", "ExampleChild"])
        .arg(&gate)
        .arg(&ready)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
        let mut observer = CancelAfterOutputReady {
            gate,
            ready,
            cancelled: false,
            handshake_error: None,
            output_calls: 0,
        };
        let result = run_owned_process_tree_with_io_and_cleanup(
            &mut command,
            OwnedProcessTreeOptions::bounded(Duration::from_secs(5)),
            &mut observer,
            OwnedProcessOutputDrains::start,
            |process| {
                if cleanup_fails {
                    cleanup_with_injected_confirmation_error(process)
                } else {
                    process.terminate_and_reap()
                }
            },
        );
        if let Some(error) = observer.handshake_error {
            return Err(error);
        }
        assert_eq!(observer.output_calls, 1, "final drain was not attempted");
        let error = result.err().ok_or("cancellation unexpectedly succeeded")?;
        if cleanup_fails {
            assert!(
                matches!(error, OwnedProcessTreeError::CleanupAfterFailure(ref cause)
            if matches!(**cause, OwnedProcessTreeError::Cancelled))
            );
            assert!(!error.is_cancellation());
        } else {
            assert!(matches!(error, OwnedProcessTreeError::Cancelled));
        }
    }
    Ok(())
}
