#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_wait_observation_keeps_the_exited_leader_pinned() -> Result<(), Box<dyn std::error::Error>>
{
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "exit 23"]).stdin(Stdio::null());
    let mut process = spawn_owned_process(&mut command)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while observe_owned_process(&mut process)? == UnreapedChildObservation::Running {
        if Instant::now() >= deadline {
            return Err("leader did not exit".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    for _ in 0..3 {
        assert_eq!(
            observe_owned_process(&mut process)?,
            UnreapedChildObservation::Exited
        );
        assert!(process.process_group.is_some());
        #[cfg(target_os = "macos")]
        assert!(macos_process_group_contains_only_pinned_leader(
            i32::try_from(process.child.id())?
        )?);
    }
    assert_eq!(process.terminate_and_reap()?.code(), Some(23));
    assert!(process.process_group.is_none());
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn consumed_native_wait_status_revokes_all_numeric_signalling()
-> Result<(), Box<dyn std::error::Error>> {
    for fallback_first in [false, true] {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]).stdin(Stdio::null());
        let mut process = spawn_owned_process(&mut command)?;
        assert!(
            process
                .child
                .wait_timeout(Duration::from_secs(5))?
                .is_some()
        );
        let result = if fallback_first {
            terminate_owned_process_fallback(&mut process)
        } else {
            forward_owned_process_signal(&mut process, ProcessSignal::Terminate)
        };
        let error = result
            .err()
            .ok_or("consumed status still permitted signaling")?;
        assert!(error_has_errno(&error, rustix::io::Errno::CHILD));
        assert!(process.process_group.is_none());
        assert!(terminate_owned_process_fallback(&mut process).is_err());
        assert!(forward_owned_process_signal(&mut process, ProcessSignal::Terminate).is_err());
        assert!(process.terminate_and_reap().is_err());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cleanup_failure_preserves_timeout_and_cancellation_causes()
-> Result<(), Box<dyn std::error::Error>> {
    use std::error::Error as _;
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "while :; do :; done"])
        .stdin(Stdio::null());
    let mut process = spawn_owned_process(&mut command)?;
    assert!(
        process
            .terminate_and_reap_with(|_, _| Err(std::io::Error::other("Example cleanup failure")))
            .is_err()
    );
    assert!(process.reaped_status.is_some());
    let timeout = finish_owned_process_wait(&mut process, Ok(OwnedProcessWait::TimedOut), OwnedProcess::terminate_and_reap)
        .err()
        .ok_or("expected operation failure")?;
    assert!(matches!(
        timeout,
        OwnedProcessTreeError::CleanupAfterFailure(_)
    ));
    assert!(matches!(
        timeout
            .source()
            .and_then(|cause| cause.downcast_ref::<OwnedProcessTreeError>()),
        Some(OwnedProcessTreeError::TimedOut)
    ));
    let cancelled = finish_owned_process_wait(&mut process, Ok(OwnedProcessWait::Cancelled), OwnedProcess::terminate_and_reap)
        .err()
        .ok_or("expected operation failure")?;
    assert!(
        !cancelled.is_cancellation(),
        "cleanup failure must not look like normal cancellation"
    );
    assert!(matches!(
        cancelled
            .source()
            .and_then(|cause| cause.downcast_ref::<OwnedProcessTreeError>()),
        Some(OwnedProcessTreeError::Cancelled)
    ));
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn macos_eperm_is_inconclusive_only_with_an_exited_pinned_leader()
-> Result<(), Box<dyn std::error::Error>> {
    let permission = || std::io::Error::from(rustix::io::Errno::PERM);
    assert_eq!(
        resolve_macos_process_group_signal_eperm(
            permission(),
            Ok(UnreapedChildObservation::Exited)
        )?,
        ProcessGroupSignalResult::Inconclusive
    );
    assert!(error_has_errno(
        &resolve_macos_process_group_signal_eperm(
            permission(),
            Ok(UnreapedChildObservation::Running)
        )
        .err()
        .ok_or("expected operation failure")?,
        rustix::io::Errno::PERM
    ));
    assert!(
        resolve_macos_process_group_signal_eperm(
            permission(),
            Err(std::io::Error::from(rustix::io::Errno::CHILD))
        )
        .is_err()
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_late_membership_query_cannot_complete_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let deadline = start + Duration::from_millis(20);
    let now = std::cell::Cell::new(start);
    let error = confirm_process_group_quiescent_with(
        &mut (),
        ProcessGroupQuiescence {
            process_group: 73,
            deadline,
            required_consecutive_proofs: 1,
            timeout_phase: "Example provider delay",
        },
        |_, _, _| Ok(ProcessGroupSignalResult::Delivered),
        |_, _, supplied_deadline| {
            assert_eq!(supplied_deadline, deadline);
            now.set(deadline);
            Ok(true)
        },
        || now.get(),
        |_| panic!("a late proof must not reset the deadline"),
    )
    .err()
    .ok_or("expected operation failure")?;
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn non_consuming_wait_errors_keep_direct_child_fallback_available()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::process::ExitStatusExt;
    for errno in [rustix::io::Errno::INVAL, rustix::io::Errno::NOSYS] {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "while :; do :; done"])
            .stdin(Stdio::null());
        let mut process = spawn_owned_process(&mut command)?;
        assert_eq!(
            observe_owned_process(&mut process)?,
            UnreapedChildObservation::Running
        );
        terminate_owned_process_fallback_with(&mut process, |_| Err(std::io::Error::from(errno)))?;
        assert!(process.process_group.is_some());
        let deadline = Instant::now() + Duration::from_secs(5);
        while observe_owned_process(&mut process)? == UnreapedChildObservation::Running {
            if Instant::now() >= deadline {
                return Err("direct fallback did not kill its live child".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(process.terminate_and_reap()?.signal(), Some(9));
        assert!(process.process_group.is_none());
    }
    Ok(())
}
