
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
