use std::os::unix::process::{CommandExt, ExitStatusExt};

use super::native_churn::{FixtureChild, fixture_command};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct JoiningMember {
    child: FixtureChild,
    marker: PathBuf,
    joined: bool,
}

impl JoiningMember {
    fn spawn(marker: PathBuf, group: i32) -> TestResult<Self> {
        let mut command = fixture_command("joining-member", &marker)?;
        command
            .env("EXAMPLE_TARGET_GROUP", group.to_string())
            .process_group(0);
        let member = Self {
            child: FixtureChild(Some(command.spawn()?)),
            marker,
            joined: false,
        };
        wait_for_file(&member.marker.with_extension("ready"))?;
        Ok(member)
    }

    fn join(&mut self, group: i32, deadline: Instant) -> std::io::Result<()> {
        std::fs::write(self.marker.with_extension("join"), b"join")?;
        while !self.marker.with_extension("joined").exists() {
            ensure_owned_process_cleanup_budget(deadline, "awaiting native member join")?;
            std::thread::sleep(Duration::from_millis(1));
        }
        let child = self.child.0.as_ref().ok_or_else(missing_member)?;
        let pid = rustix::process::Pid::from_child(child);
        assert_eq!(rustix::process::getpgid(Some(pid))?.as_raw_pid(), group);
        self.joined = true;
        Ok(())
    }

    fn reap_killed(&mut self, deadline: Instant) -> std::io::Result<()> {
        if !self.joined || self.child.0.is_none() {
            return Ok(());
        }
        // If a repeated signal is omitted, release makes the live helper
        // publish its survival marker and exit normally. Neither natural
        // fixture expiry nor the RAII fallback can count as successful cleanup.
        std::fs::write(marker_path_to_gate(&self.marker), b"release")?;
        let remaining = owned_process_cleanup_remaining_at(
            deadline,
            Instant::now(),
            "reaping the signalled native member",
        )?;
        let status = self
            .child
            .0
            .as_mut()
            .ok_or_else(missing_member)?
            .wait_timeout(remaining)?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "member survived"))?;
        self.child.0.take();
        assert_eq!(status.signal(), Some(Signal::KILL.as_raw()));
        assert!(
            !self.marker.exists(),
            "native group member survived SIGKILL"
        );
        Ok(())
    }
}

fn missing_member() -> std::io::Error {
    std::io::Error::other("missing native member")
}

#[test]
fn native_growth_between_proofs_resets_quiescence_and_is_killed() -> TestResult {
    let temporary = tempdir()?;
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "exit 0"]);
    let mut leader = spawn_owned_process(&mut command)?;
    let group = i32::try_from(leader.child.id())?;
    let startup_deadline = Instant::now() + Duration::from_secs(5);
    while observe_owned_process(&mut leader)? != UnreapedChildObservation::Exited {
        ensure_owned_process_cleanup_budget(startup_deadline, "awaiting fixture leader exit")?;
        std::thread::sleep(Duration::from_millis(1));
    }

    // The test process stays outside the group and retains every member's
    // Child handle. Unlike an in-group spawner, it survives the first SIGKILL.
    let mut positive = JoiningMember::spawn(temporary.path().join("ExamplePositiveJoin"), group)?;
    positive.join(group, Instant::now() + Duration::from_secs(5))?;
    assert!(!prove_macos_process_group_quiescent(
        &mut leader,
        group,
        Instant::now() + Duration::from_secs(5),
    )?);
    std::fs::write(marker_path_to_gate(&positive.marker), b"release")?;
    positive.child.wait()?;
    assert!(
        positive.marker.exists(),
        "positive control never wrote its marker"
    );

    struct State<'a> {
        leader: &'a mut OwnedProcess,
        members: Vec<JoiningMember>,
        proofs: Vec<bool>,
    }
    let mut state = State {
        leader: &mut leader,
        members: (0..4)
            .map(|index| {
                JoiningMember::spawn(
                    temporary.path().join(format!("ExampleJoining{index}")),
                    group,
                )
            })
            .collect::<TestResult<_>>()?,
        proofs: Vec::new(),
    };
    // Bound fixture coordination independently of the production 500 ms
    // budget: this loop also waits for external test helpers and reaps them.
    // The late-membership-query regression covers production deadline rejection.
    let deadline = Instant::now() + Duration::from_secs(5);
    confirm_process_group_quiescent_with(
        &mut state,
        ProcessGroupQuiescence {
            process_group: group,
            deadline,
            required_consecutive_proofs: REQUIRED_CONSECUTIVE_PROCESS_GROUP_PROOFS,
            timeout_phase: "confirming native membership during controlled churn",
        },
        |state, group, deadline| {
            let result = signal_pinned_process_group(state.leader, group, deadline)?;
            for member in &mut state.members {
                member.reap_killed(deadline)?;
            }
            // Publish actual native growth AFTER the signal and BEFORE the
            // next proof. Each batch makes a three-member group, saturating
            // the provider's two PID slots. The first batch interrupts a
            // successful proof; the second requires another real SIGKILL.
            let batch = match state.proofs.len() {
                1 => Some(0..2),
                2 => Some(2..4),
                _ => None,
            };
            if let Some(batch) = batch {
                for member in &mut state.members[batch] {
                    member.join(group, deadline)?;
                }
            }
            Ok(result)
        },
        |state, group, deadline| {
            let proof = prove_macos_process_group_quiescent(state.leader, group, deadline)?;
            state.proofs.push(proof);
            Ok(proof)
        },
        Instant::now,
        std::thread::sleep,
    )?;
    assert_eq!(state.proofs, [true, false, false, true, true]);
    assert!(
        state
            .members
            .iter()
            .all(|member| member.joined && member.child.0.is_none())
    );
    assert_eq!(
        observe_owned_process(state.leader)?,
        UnreapedChildObservation::Exited
    );
    state.leader.terminate_and_reap()?;
    Ok(())
}
