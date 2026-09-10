use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) fn fixture_command(mode: &str, marker: &Path) -> std::io::Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "process::tests::native_churn::helper",
            "--nocapture",
        ])
        .env("EXAMPLE_CONTAINMENT_MODE", mode)
        .env("EXAMPLE_CONTAINMENT_MARKER", marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    Ok(command)
}

pub(super) struct FixtureChild(pub(super) Option<std::process::Child>);

impl FixtureChild {
    pub(super) fn wait(&mut self) -> TestResult {
        let child = self.0.as_mut().ok_or("missing fixture child")?;
        let status = child
            .wait_timeout(Duration::from_secs(5))?
            .ok_or("fixture child did not exit")?;
        if !status.success() {
            return Err("fixture child failed".into());
        }
        self.0.take();
        Ok(())
    }
}

impl Drop for FixtureChild {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            if let Err(error) = child.kill() {
                eprintln!("Example fixture kill failed: {error}");
            }
            match child.wait_timeout(Duration::from_secs(2)) {
                Ok(Some(_)) => {}
                result => eprintln!("Example fixture cleanup failed: {result:?}"),
            }
        }
    }
}

#[test]
fn helper() -> TestResult {
    let Some(mode) = std::env::var_os("EXAMPLE_CONTAINMENT_MODE") else {
        return Ok(());
    };
    let marker =
        PathBuf::from(std::env::var_os("EXAMPLE_CONTAINMENT_MARKER").ok_or("missing marker")?);
    let gate = marker_path_to_gate(&marker);
    if mode == "member" || mode == "joining-member" {
        std::fs::write(marker.with_extension("ready"), b"ready")?;
        if mode == "joining-member" {
            // These members start before the controlled cleanup test. Allow
            // its setup and five-second coordination budget to finish, while
            // still bounding the helper if its controller disappears.
            wait_for_file_until(
                &marker.with_extension("join"),
                Instant::now() + Duration::from_secs(15),
            )?;
            let raw_group: i32 = std::env::var("EXAMPLE_TARGET_GROUP")?.parse()?;
            let group = rustix::process::Pid::from_raw(raw_group).ok_or("invalid target group")?;
            rustix::process::setpgid(None, Some(group))?;
            std::fs::write(marker.with_extension("joined"), b"joined")?;
        }
        if let Err(error) = wait_for_file(&gate) {
            std::fs::write(marker.with_extension("member-expired"), b"expired")?;
            return Err(error);
        }
        std::fs::write(&marker, b"survived")?;
        return Ok(());
    }
    let mut member = FixtureChild(Some(fixture_command("member", &marker)?.spawn()?));
    wait_for_file(&marker.with_extension("ready"))?;
    if mode == "leader-exit" {
        // The supervising test owns this complete group. Its leader exits
        // deliberately while an acknowledged descendant waits for release.
        member.0.take();
        return Ok(());
    }
    if mode == "leader-escape" {
        let raw_group: i32 = std::env::var("EXAMPLE_PARENT_GROUP")?.parse()?;
        let group = rustix::process::Pid::from_raw(raw_group).ok_or("invalid parent group")?;
        rustix::process::setpgid(None, Some(group))?;
        // The supervisor still owns the original group and the unreaped
        // leader, but the only member of that group is now the descendant.
        member.0.take();
        return Ok(());
    }
    if mode == "leader-hold" {
        let second_marker = marker.with_file_name("ExampleSecondMember");
        let mut second = FixtureChild(Some(fixture_command("member", &second_marker)?.spawn()?));
        wait_for_file(&second_marker.with_extension("ready"))?;
        std::fs::write(marker.with_extension("group-ready"), b"ready")?;
        member.wait()?;
        std::fs::write(marker.with_extension("member-reaped"), b"ready")?;
        second.wait()?;
        std::fs::write(marker.with_extension("members-reaped"), b"ready")?;
        wait_for_file(&marker.with_extension("leader-release"))?;
        return Ok(());
    }
    if mode == "leader-churn" {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut completed = 0;
        while Instant::now() < deadline {
            let mut child = FixtureChild(Some(
                Command::new("/bin/sh").args(["-c", "exit 0"]).spawn()?,
            ));
            child.wait()?;
            completed += 1;
            if completed == 4 {
                std::fs::write(marker.with_extension("churning"), b"ready")?;
            }
        }
        std::fs::write(marker.with_extension("churn-ended"), b"expired")?;
        return Err("supervisor did not cancel during bounded churn".into());
    }
    Err("unknown native fixture mode".into())
}

#[test]
fn descendant_release_positive_control_and_successful_leader_cleanup() -> TestResult {
    let temporary = tempdir()?;
    let positive = temporary.path().join("ExamplePositive");
    {
        let mut child = spawn_owned_process(&mut fixture_command("member", &positive)?)?;
        wait_for_file(&positive.with_extension("ready"))?;
        std::fs::write(marker_path_to_gate(&positive), b"release")?;
        wait_for_file(&positive)?;
        child.terminate_and_reap()?;
    }
    let negative = temporary.path().join("ExampleContained");
    let output = run_owned_process_tree_with_output(
        &mut fixture_command("leader-exit", &negative)?,
        Duration::from_secs(5),
        || false,
    )?;
    assert!(output.status.success());
    assert!(
        negative.with_extension("ready").exists(),
        "descendant never acknowledged startup"
    );
    assert_native_descendant_was_contained(&negative)?;
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn native_membership_handles_three_two_and_one_members() -> TestResult {
    let temporary = tempdir()?;
    let marker = temporary.path().join("ExampleMembership");
    let mut process = spawn_owned_process(&mut fixture_command("leader-hold", &marker)?)?;
    wait_for_file(&marker.with_extension("group-ready"))?;
    // Three live members genuinely truncate the two-slot native response.
    for _ in 0..3 {
        assert!(!macos_process_group_contains_only_pinned_leader(
            i32::try_from(process.child.id())?
        )?);
    }
    std::fs::write(marker_path_to_gate(&marker), b"release")?;
    wait_for_file(&marker.with_extension("member-reaped"))?;
    assert!(!macos_process_group_contains_only_pinned_leader(
        i32::try_from(process.child.id())?
    )?);
    std::fs::write(
        marker_path_to_gate(&marker.with_file_name("ExampleSecondMember")),
        b"release",
    )?;
    wait_for_file(&marker.with_extension("members-reaped"))?;
    assert!(macos_process_group_contains_only_pinned_leader(
        i32::try_from(process.child.id())?
    )?);
    assert_eq!(
        observe_owned_process(&mut process)?,
        UnreapedChildObservation::Running
    );
    std::fs::write(marker.with_extension("leader-release"), b"release")?;
    process.terminate_and_reap()?;
    Ok(())
}

#[test]
fn cleanup_during_native_membership_churn_leaves_no_in_group_writer() -> TestResult {
    let temporary = tempdir()?;
    // Fixed denominator: eight fresh process groups, each acknowledges a
    // stable descendant and four completed member spawn/reap cycles before
    // cancellation. A surviving descendant produces a failure marker.
    for iteration in 0..8 {
        let marker = temporary.path().join(format!("ExampleChurn{iteration}"));
        let result = run_owned_process_tree_with_output(
            &mut fixture_command("leader-churn", &marker)?,
            Duration::from_secs(5),
            || marker.with_extension("churning").exists(),
        );
        assert!(matches!(result, Err(OwnedProcessTreeError::Cancelled)));
        assert!(marker.with_extension("churning").exists());
        assert!(marker.with_extension("ready").exists());
        assert!(
            !marker.with_extension("churn-ended").exists(),
            "churn ended before supervised cleanup"
        );
        assert_native_descendant_was_contained(&marker)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn native_nonleader_singleton_keeps_membership_non_quiescent() -> TestResult {
    let temporary = tempdir()?;
    let marker = temporary.path().join("ExampleRemainingMember");
    let mut command = fixture_command("leader-escape", &marker)?;
    command.env(
        "EXAMPLE_PARENT_GROUP",
        rustix::process::getpgrp().as_raw_pid().to_string(),
    );
    let mut process = spawn_owned_process(&mut command)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while observe_owned_process(&mut process)? == UnreapedChildObservation::Running {
        if Instant::now() >= deadline {
            return Err("escaped leader did not exit".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(marker.with_extension("ready").exists());
    for _ in 0..3 {
        assert!(!macos_process_group_contains_only_pinned_leader(
            i32::try_from(process.child.id())?
        )?);
    }
    // The departed leader cannot supply the required sole-leader positive
    // proof, so this remains a cleanup failure after killing the descendant.
    assert!(process.terminate_and_reap().is_err());
    assert!(process.reaped_status.is_some());
    assert_native_descendant_was_contained(&marker)?;
    Ok(())
}

fn assert_native_descendant_was_contained(marker: &Path) -> TestResult {
    assert_descendant_did_not_survive(marker)?;
    if marker.with_extension("member-expired").exists() {
        return Err("descendant expired before the containment check".into());
    }
    Ok(())
}

#[test]
fn expired_member_fixture_cannot_count_as_successful_containment() -> TestResult {
    let temporary = tempdir()?;
    let marker = temporary.path().join("ExampleExpiredMember");
    let mut command = fixture_command("member", &marker)?;
    command.stderr(Stdio::piped());
    // Allow the fixture's own five-second deadline to expire without release.
    // Its natural exit must not masquerade as successful supervisor cleanup.
    let output =
        run_owned_process_tree_with_output(&mut command, Duration::from_secs(8), || false)?;
    assert!(!output.status.success());
    assert!(marker.with_extension("ready").exists());
    assert!(marker.with_extension("member-expired").exists());
    assert!(!marker.exists());
    assert!(assert_native_descendant_was_contained(&marker).is_err());
    Ok(())
}
