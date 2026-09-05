#[derive(Clone, Copy, Debug)]
enum ModelCommand {
    Reserve,
    ApproveFirst,
    ApproveSecond,
    DenyFirst,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelReplayState {
    Empty,
    Reserved(u8),
    Stable(WitnessDecisionKindV1, WitnessReasonV1),
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelObservation {
    Error(WitnessReasonV1),
    Reserved,
    Pending,
    Stable(WitnessDecisionKindV1, WitnessReasonV1),
    Cancelled,
    TooLate,
}

impl ModelReplayState {
    fn apply(&mut self, command: ModelCommand) -> (ModelObservation, bool) {
        match command {
            ModelCommand::Reserve => match *self {
                Self::Empty => {
                    *self = Self::Reserved(0);
                    (ModelObservation::Reserved, true)
                }
                Self::Reserved(_) => (ModelObservation::Reserved, false),
                Self::Stable(decision, reason) => {
                    (ModelObservation::Stable(decision, reason), false)
                }
                Self::Cancelled => (
                    ModelObservation::Stable(
                        WitnessDecisionKindV1::Deny,
                        WitnessReasonV1::Cancelled,
                    ),
                    false,
                ),
            },
            ModelCommand::ApproveFirst => self.apply_approval(1),
            ModelCommand::ApproveSecond => self.apply_approval(2),
            ModelCommand::DenyFirst => match *self {
                Self::Empty => (ModelObservation::Error(WitnessReasonV1::Invalid), false),
                Self::Reserved(approvals) => {
                    let reason = if approvals & 1 != 0 {
                        WitnessReasonV1::ApprovalConflict
                    } else {
                        WitnessReasonV1::ApprovalDenied
                    };
                    *self = Self::Stable(WitnessDecisionKindV1::Deny, reason);
                    (
                        ModelObservation::Stable(WitnessDecisionKindV1::Deny, reason),
                        true,
                    )
                }
                Self::Stable(decision, reason) => {
                    (ModelObservation::Stable(decision, reason), false)
                }
                Self::Cancelled => (
                    ModelObservation::Stable(
                        WitnessDecisionKindV1::Deny,
                        WitnessReasonV1::Cancelled,
                    ),
                    false,
                ),
            },
            ModelCommand::Cancel => match *self {
                Self::Empty | Self::Reserved(_) => {
                    *self = Self::Cancelled;
                    (ModelObservation::Cancelled, true)
                }
                Self::Cancelled => (ModelObservation::Cancelled, false),
                Self::Stable(_, _) => (ModelObservation::TooLate, false),
            },
        }
    }

    fn apply_approval(&mut self, bit: u8) -> (ModelObservation, bool) {
        match *self {
            Self::Empty => (ModelObservation::Error(WitnessReasonV1::Invalid), false),
            Self::Reserved(approvals) if approvals & bit != 0 => {
                (ModelObservation::Pending, false)
            }
            Self::Reserved(approvals) if (approvals | bit) == 3 => {
                *self = Self::Stable(WitnessDecisionKindV1::Approve, WitnessReasonV1::None);
                (
                    ModelObservation::Stable(
                        WitnessDecisionKindV1::Approve,
                        WitnessReasonV1::None,
                    ),
                    true,
                )
            }
            Self::Reserved(approvals) => {
                *self = Self::Reserved(approvals | bit);
                (ModelObservation::Pending, true)
            }
            Self::Stable(decision, reason) => {
                (ModelObservation::Stable(decision, reason), false)
            }
            Self::Cancelled => (
                ModelObservation::Stable(
                    WitnessDecisionKindV1::Deny,
                    WitnessReasonV1::Cancelled,
                ),
                false,
            ),
        }
    }
}

fn observe_progress(
    result: Result<WitnessProgress, WitnessEngineError>,
) -> ModelObservation {
    match result {
        Ok(WitnessProgress::Reserved) => ModelObservation::Reserved,
        Ok(WitnessProgress::Pending) => ModelObservation::Pending,
        Ok(WitnessProgress::Stable(response)) => {
            ModelObservation::Stable(response.decision.decision, response.decision.reason)
        }
        Err(error) => ModelObservation::Error(error.reason()),
    }
}

fn observe_cancellation(
    result: Result<CancellationProgress, WitnessEngineError>,
) -> ModelObservation {
    match result {
        Ok(CancellationProgress::Cancelled(_)) => ModelObservation::Cancelled,
        Ok(CancellationProgress::TooLate(_)) => ModelObservation::TooLate,
        Err(error) => ModelObservation::Error(error.reason()),
    }
}

fn assert_replay_model_sequence(
    fixture: &Fixture,
    denial: &ApprovalDecisionV1,
    cancellation: &RequestCancellationV1,
    commands: &[ModelCommand],
    seed: u64,
) -> TestResult {
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: seed,
    };
    let mut store = empty_store(fixture);
    let mut anchor = MemoryAnchor::default();
    let mut random = TestRandom::new(seed);
    register_fixture(fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let mut model = ModelReplayState::Empty;

    for command in commands {
        let generation_before = store.state.logical.state_generation;
        let (expected, mutates) = model.apply(*command);
        let observed = {
            let mut engine = WitnessEngine::new(
                &fixture.actors.witnesses[0],
                &mut store,
                &mut anchor,
                &clock,
                &mut random,
            );
            match command {
                ModelCommand::Reserve => observe_progress(engine.reserve(
                    &fixture.policy,
                    fixture.request.clone(),
                    &fixture.manifest,
                )),
                ModelCommand::ApproveFirst => observe_progress(engine.decide(
                    &fixture.policy,
                    &fixture.request,
                    &fixture.manifest,
                    &fixture.approvals[..1],
                )),
                ModelCommand::ApproveSecond => observe_progress(engine.decide(
                    &fixture.policy,
                    &fixture.request,
                    &fixture.manifest,
                    &fixture.approvals[1..],
                )),
                ModelCommand::DenyFirst => observe_progress(engine.decide(
                    &fixture.policy,
                    &fixture.request,
                    &fixture.manifest,
                    std::slice::from_ref(denial),
                )),
                ModelCommand::Cancel => observe_cancellation(engine.cancel(
                    &fixture.policy,
                    &fixture.request,
                    cancellation,
                )),
            }
        };
        assert_eq!(observed, expected, "command sequence: {commands:?}");
        assert_eq!(
            store.state.logical.state_generation,
            generation_before + u64::from(mutates),
            "generation mismatch for command sequence: {commands:?}"
        );
        assert!(store.state.pending_anchor.is_none());
        assert_eq!(
            store
                .state
                .published_anchor
                .as_ref()
                .map(|value| value.state_generation),
            Some(store.state.logical.state_generation)
        );
        assert_eq!(
            anchor.value.as_ref().map(|value| value.state_generation),
            Some(store.state.logical.state_generation)
        );

        let key = (fixture.request.vault_id, fixture.request.request_id);
        let actual = store.state.logical.replay.get(&key);
        match model {
            ModelReplayState::Empty => assert!(actual.is_none()),
            ModelReplayState::Reserved(mask) => {
                let actual = actual.ok_or("model expected a replay reservation")?;
                assert_eq!(actual.state, ReplayStateV1::Reserved);
                assert_eq!(actual.approvals.len(), mask.count_ones() as usize);
                assert!(actual.response.is_none());
            }
            ModelReplayState::Stable(decision, _) => {
                let actual = actual.ok_or("model expected a stable replay result")?;
                assert_eq!(
                    actual.state,
                    if decision == WitnessDecisionKindV1::Approve {
                        ReplayStateV1::Approved
                    } else {
                        ReplayStateV1::Denied
                    }
                );
                assert!(actual.response.is_some());
            }
            ModelReplayState::Cancelled => {
                let actual = actual.ok_or("model expected a cancelled replay result")?;
                assert_eq!(actual.state, ReplayStateV1::Cancelled);
                assert!(actual.cancellation.is_some());
                assert!(actual.response.is_some());
            }
        }
    }
    Ok(())
}

#[test]
fn replay_state_machine_matches_an_independent_model() -> TestResult {
    let fixture = fixture()?;
    let denial = denying_approval(&fixture, 0)?;
    let cancellation = cancellation(&fixture)?;
    let commands = [
        ModelCommand::Reserve,
        ModelCommand::ApproveFirst,
        ModelCommand::ApproveSecond,
        ModelCommand::DenyFirst,
        ModelCommand::Cancel,
    ];
    let mut seed = 1_u64;
    for first in commands {
        for second in commands {
            for third in commands {
                assert_replay_model_sequence(
                    &fixture,
                    &denial,
                    &cancellation,
                    &[first, second, third],
                    seed,
                )?;
                seed += 1;
            }
        }
    }
    for sequence in [
        [
            ModelCommand::Reserve,
            ModelCommand::ApproveFirst,
            ModelCommand::ApproveSecond,
            ModelCommand::Cancel,
            ModelCommand::Reserve,
        ],
        [
            ModelCommand::Cancel,
            ModelCommand::Cancel,
            ModelCommand::Reserve,
            ModelCommand::ApproveFirst,
            ModelCommand::DenyFirst,
        ],
    ] {
        assert_replay_model_sequence(&fixture, &denial, &cancellation, &sequence, seed)?;
        seed += 1;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum RecoveryLocal {
    Empty,
    StableOne,
    PendingTwo,
    StableTwo,
}

#[derive(Clone, Copy, Debug)]
enum RecoveryExternal {
    None,
    StableOne,
    CandidateTwo,
}

#[test]
fn anchor_recovery_state_machine_matches_the_split_write_model() -> TestResult {
    let fixture = fixture()?;
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 500,
    };
    let mut initial_store = empty_store(&fixture);
    let empty = initial_store.state.clone();
    let mut initial_anchor = MemoryAnchor::default();
    let mut random = TestRandom::new(500);
    register_fixture(
        &fixture,
        &mut initial_store,
        &mut initial_anchor,
        &clock,
        &mut random,
    )?;
    let stable_one = initial_store.state.clone();
    let anchor_one = initial_anchor.value.clone().ok_or("missing generation-one anchor")?;

    initial_store.fail_after_commit_once = true;
    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut initial_store,
        &mut initial_anchor,
        &clock,
        &mut random,
    );
    assert_eq!(
        engine
            .reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)
            .map_err(WitnessEngineError::kind),
        Err(WitnessEngineErrorKind::StoreUnavailable)
    );
    let pending_two = initial_store.state.clone();
    let candidate_two = pending_two
        .pending_anchor
        .clone()
        .ok_or("missing generation-two candidate")?;

    let mut reconciled_store = MemoryStore {
        state: pending_two.clone(),
        fail_before_commit_once: false,
        fail_after_commit_once: false,
        fail_mark_once: false,
    };
    let mut reconciled_anchor = MemoryAnchor {
        value: Some(anchor_one.clone()),
        ..MemoryAnchor::default()
    };
    WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut reconciled_store,
        &mut reconciled_anchor,
        &clock,
        &mut random,
    )
    .check_ready()?;
    let stable_two = reconciled_store.state.clone();

    let cases = [
        (RecoveryLocal::Empty, RecoveryExternal::None, true, 0),
        (
            RecoveryLocal::StableOne,
            RecoveryExternal::StableOne,
            true,
            1,
        ),
        (
            RecoveryLocal::PendingTwo,
            RecoveryExternal::StableOne,
            true,
            2,
        ),
        (
            RecoveryLocal::PendingTwo,
            RecoveryExternal::CandidateTwo,
            true,
            2,
        ),
        (
            RecoveryLocal::StableTwo,
            RecoveryExternal::CandidateTwo,
            true,
            2,
        ),
        (
            RecoveryLocal::StableOne,
            RecoveryExternal::None,
            false,
            1,
        ),
        (
            RecoveryLocal::StableOne,
            RecoveryExternal::CandidateTwo,
            false,
            1,
        ),
        (
            RecoveryLocal::StableTwo,
            RecoveryExternal::StableOne,
            false,
            2,
        ),
        (
            RecoveryLocal::PendingTwo,
            RecoveryExternal::None,
            false,
            2,
        ),
    ];

    for (local, external, expected_ready, expected_generation) in cases {
        let state = match local {
            RecoveryLocal::Empty => empty.clone(),
            RecoveryLocal::StableOne => stable_one.clone(),
            RecoveryLocal::PendingTwo => pending_two.clone(),
            RecoveryLocal::StableTwo => stable_two.clone(),
        };
        let external_value = match external {
            RecoveryExternal::None => None,
            RecoveryExternal::StableOne => Some(anchor_one.clone()),
            RecoveryExternal::CandidateTwo => Some(candidate_two.clone()),
        };
        let mut store = MemoryStore {
            state,
            fail_before_commit_once: false,
            fail_after_commit_once: false,
            fail_mark_once: false,
        };
        let mut anchor = MemoryAnchor {
            value: external_value,
            ..MemoryAnchor::default()
        };
        let result = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        )
        .check_ready();
        assert_eq!(result.is_ok(), expected_ready, "case: {local:?}/{external:?}");
        if let Err(error) = result {
            assert_eq!(error.reason(), WitnessReasonV1::AnchorConflict);
        }
        assert_eq!(store.state.logical.state_generation, expected_generation);
        if expected_ready {
            assert!(store.state.pending_anchor.is_none());
            assert_eq!(store.state.published_anchor, anchor.value);
        }
    }
    Ok(())
}
