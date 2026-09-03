#[test]
fn committed_pending_anchor_reconciles_without_repeating_the_mutation() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 10,
    };
    let mut random = TestRandom::new(0x1111_2222_3333_4444);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    store.fail_after_commit_once = true;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine
                .reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)
                .map_err(WitnessEngineError::kind),
            Err(WitnessEngineErrorKind::StoreUnavailable)
        );
    }
    assert_eq!(store.state.logical.state_generation, 2);
    assert!(store.state.pending_anchor.is_some());
    assert_eq!(
        anchor.value.as_ref().map(|value| value.state_generation),
        Some(1)
    );
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?,
            WitnessProgress::Reserved
        );
    }
    assert_eq!(store.state.logical.state_generation, 2);
    assert!(store.state.pending_anchor.is_none());
    assert_eq!(
        anchor.value.as_ref().map(|value| value.state_generation),
        Some(2)
    );
    Ok(())
}

#[test]
fn failed_database_commit_leaves_no_reservation_and_retry_commits_once() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 25,
    };
    let mut random = TestRandom::new(0xff00_1122_3344_5566);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let generation = store.state.logical.state_generation;
    let publish_count = anchor.publishes;
    store.fail_before_commit_once = true;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine
                .reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)
                .map_err(WitnessEngineError::kind),
            Err(WitnessEngineErrorKind::StoreUnavailable)
        );
    }
    assert_eq!(store.state.logical.state_generation, generation);
    assert!(store.state.logical.replay.is_empty());
    assert_eq!(anchor.publishes, publish_count);
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?,
            WitnessProgress::Reserved
        );
    }
    assert_eq!(store.state.logical.state_generation, generation + 1);
    assert_eq!(anchor.publishes, publish_count + 1);
    Ok(())
}

#[test]
fn failed_local_anchor_mark_reconciles_without_republishing() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 26,
    };
    let mut random = TestRandom::new(0x0011_2233_4455_6677);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    store.fail_mark_once = true;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine
                .reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)
                .map_err(WitnessEngineError::kind),
            Err(WitnessEngineErrorKind::StoreUnavailable)
        );
    }
    assert!(store.state.pending_anchor.is_some());
    let publish_count = anchor.publishes;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?,
            WitnessProgress::Reserved
        );
    }
    assert!(store.state.pending_anchor.is_none());
    assert_eq!(anchor.publishes, publish_count);
    Ok(())
}

#[test]
fn response_waits_for_failed_readback_and_retry_returns_the_same_bytes() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 11,
    };
    let mut random = TestRandom::new(0x2222_3333_4444_5555);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?,
            WitnessProgress::Reserved
        );
    }
    anchor.fail_readback_once = true;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine
                .decide(
                    &fixture.policy,
                    &fixture.request,
                    &fixture.manifest,
                    &fixture.approvals,
                )
                .map_err(WitnessEngineError::kind),
            Err(WitnessEngineErrorKind::AnchorUnavailable)
        );
    }
    let stored = store
        .state
        .logical
        .replay
        .values()
        .next()
        .and_then(|entry| entry.response.as_ref())
        .ok_or("missing durable response")?
        .canonical_bytes()?;
    assert!(store.state.pending_anchor.is_some());
    let publish_count = anchor.publishes;
    let retry = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?
    };
    let WitnessProgress::Stable(retry) = retry else {
        return Err("expected reconciled stable response".into());
    };
    assert_eq!(retry.canonical_bytes()?, stored);
    assert_eq!(anchor.publishes, publish_count);
    assert!(store.state.pending_anchor.is_none());
    Ok(())
}

#[test]
fn denial_and_cancellation_never_create_contributions() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 12,
    };
    let mut random = TestRandom::new(0x3333_4444_5555_6666);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let denial = denying_approval(&fixture, 0)?;
    let denied = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
        engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &[denial],
        )?
    };
    let WitnessProgress::Stable(denied) = denied else {
        return Err("expected denial".into());
    };
    assert_eq!(denied.decision.decision, WitnessDecisionKindV1::Deny);
    assert_eq!(denied.decision.reason, WitnessReasonV1::ApprovalDenied);
    assert!(denied.contribution.is_none());

    let second = self::fixture()?;
    let mut second_store = empty_store(&second);
    let mut second_anchor = MemoryAnchor::default();
    let mut second_random = TestRandom::new(0x4444_5555_6666_7777);
    register_fixture(
        &second,
        &mut second_store,
        &mut second_anchor,
        &clock,
        &mut second_random,
    )?;
    let cancellation = cancellation(&second)?;
    let cancelled = {
        let mut engine = WitnessEngine::new(
            &second.actors.witnesses[0],
            &mut second_store,
            &mut second_anchor,
            &clock,
            &mut second_random,
        );
        engine.cancel(&second.policy, &second.request, &cancellation)?
    };
    let CancellationProgress::Cancelled(cancelled) = cancelled else {
        return Err("expected cancellation".into());
    };
    assert_eq!(cancelled.decision.reason, WitnessReasonV1::Cancelled);
    assert!(cancelled.contribution.is_none());
    Ok(())
}

#[test]
fn cancellation_after_a_durable_approval_is_too_late_and_returns_the_same_response() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 47,
    };
    let mut random = TestRandom::new(0x3456_789a_bcde_f012);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let approved = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
        let progress = engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?;
        let WitnessProgress::Stable(response) = progress else {
            return Err("expected stable approval".into());
        };
        response
    };
    let generation = store.state.logical.state_generation;
    let publish_count = anchor.publishes;
    let late = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.cancel(&fixture.policy, &fixture.request, &cancellation(&fixture)?)?
    };
    let CancellationProgress::TooLate(late) = late else {
        return Err("expected cancellation-too-late outcome".into());
    };
    assert_eq!(late.canonical_bytes()?, approved.canonical_bytes()?);
    assert_eq!(store.state.logical.state_generation, generation);
    assert_eq!(anchor.publishes, publish_count);
    Ok(())
}

#[test]
fn invalid_approval_and_unsafe_clock_leave_replay_unchanged() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 13,
    };
    let mut random = TestRandom::new(0x5555_6666_7777_8888);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
    }
    let generation = store.state.logical.state_generation;
    let mut forged = fixture.approvals[0].clone();
    let mut signature = *forged.signature.as_bytes();
    signature[0] ^= 1;
    forged.signature = Signature64::new(signature);
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine
                .decide(
                    &fixture.policy,
                    &fixture.request,
                    &fixture.manifest,
                    &[forged],
                )
                .map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::InvalidSignature)
        );
    }
    assert_eq!(store.state.logical.state_generation, generation);
    assert!(
        store
            .state
            .logical
            .replay
            .values()
            .next()
            .is_some_and(|entry| {
                entry.state == ReplayStateV1::Reserved && entry.approvals.is_empty()
            })
    );

    let rollback_clock = FixedClock {
        wall_ms: NOW_MS - ACCEPTED_CLOCK_SKEW_MS - 1,
        monotonic_ms: 14,
    };
    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut store,
        &mut anchor,
        &rollback_clock,
        &mut random,
    );
    assert_eq!(
        engine
            .reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::UnsafeClock)
    );
    assert_eq!(store.state.logical.state_generation, generation);
    Ok(())
}

#[test]
fn validly_signed_wrong_scope_and_time_approvals_are_refused_without_mutation() -> TestResult {
    let fixture = fixture()?;
    let mut cases = Vec::new();

    let mut wrong_request = fixture.approvals[0].clone();
    wrong_request.request_id = RequestId::from_bytes([0xb1; 32])?;
    resign_approval(&fixture, 0, &mut wrong_request)?;
    cases.push((wrong_request, WitnessReasonV1::Invalid));

    let mut wrong_manifest = fixture.approvals[0].clone();
    wrong_manifest.action_manifest_digest = Digest32::new([0xb2; 32]);
    resign_approval(&fixture, 0, &mut wrong_manifest)?;
    cases.push((wrong_manifest, WitnessReasonV1::Invalid));

    let mut wrong_presentation = fixture.approvals[0].clone();
    wrong_presentation.presentation_digest = Digest32::new([0xb3; 32]);
    resign_approval(&fixture, 0, &mut wrong_presentation)?;
    cases.push((wrong_presentation, WitnessReasonV1::Invalid));

    let mut wrong_policy = fixture.approvals[0].clone();
    wrong_policy.witness_policy_digest = Digest32::new([0xb4; 32]);
    resign_approval(&fixture, 0, &mut wrong_policy)?;
    cases.push((wrong_policy, WitnessReasonV1::Invalid));

    let mut wrong_witness_set = fixture.approvals[0].clone();
    wrong_witness_set.intended_witness_set_digest = Digest32::new([0xb5; 32]);
    resign_approval(&fixture, 0, &mut wrong_witness_set)?;
    cases.push((wrong_witness_set, WitnessReasonV1::Invalid));

    let mut wrong_mode = fixture.approvals[0].clone();
    wrong_mode.approval_mode = ApprovalModeV1::Automatic;
    resign_approval(&fixture, 0, &mut wrong_mode)?;
    cases.push((wrong_mode, WitnessReasonV1::Invalid));

    let mut expired = fixture.approvals[0].clone();
    expired.issued_at_ms = NOW_MS - 100;
    expired.expires_at_ms = NOW_MS;
    resign_approval(&fixture, 0, &mut expired)?;
    cases.push((expired, WitnessReasonV1::Invalid));

    let mut future = fixture.approvals[0].clone();
    future.issued_at_ms = NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 1;
    resign_approval(&fixture, 0, &mut future)?;
    cases.push((future, WitnessReasonV1::Invalid));

    let mut unauthorized = fixture.approvals[0].clone();
    unauthorized.approver_id = fixture.actors.witnesses[1].principal_id();
    cases.push((unauthorized, WitnessReasonV1::PolicyDenied));

    for (index, (approval, expected)) in cases.into_iter().enumerate() {
        assert_approval_refused_without_state_change(
            &fixture,
            approval,
            expected,
            0x500 + index as u64,
        )?;
    }
    Ok(())
}

#[test]
fn replay_compaction_waits_until_after_the_retention_horizon() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 15,
    };
    let mut random = TestRandom::new(0x6666_7777_8888_9999);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let cancellation = cancellation(&fixture)?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.cancel(&fixture.policy, &fixture.request, &cancellation)?;
    }
    let horizon = fixture.request.expires_at_ms + REPLAY_RETENTION_MS;
    let exact_clock = FixedClock {
        wall_ms: horizon,
        monotonic_ms: 16,
    };
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &exact_clock,
            &mut random,
        );
        assert_eq!(engine.compact_replay()?, 0);
    }
    let after_clock = FixedClock {
        wall_ms: horizon + 1,
        monotonic_ms: 17,
    };
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &after_clock,
            &mut random,
        );
        assert_eq!(engine.compact_replay()?, 1);
    }
    assert!(store.state.logical.replay.is_empty());
    assert_eq!(
        anchor.value.as_ref().map(|value| value.state_generation),
        Some(store.state.logical.state_generation)
    );
    Ok(())
}

#[test]
fn missing_or_divergent_external_anchor_stops_service() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 18,
    };
    let mut random = TestRandom::new(0x7777_8888_9999_aaaa);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    anchor.value = None;
    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut store,
        &mut anchor,
        &clock,
        &mut random,
    );
    assert_eq!(
        engine
            .reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::AnchorConflict)
    );
    assert!(store.state.logical.replay.is_empty());
    Ok(())
}

#[test]
fn anchor_behind_and_database_behind_restores_both_stop_service() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 23,
    };
    let mut random = TestRandom::new(0xddee_ff00_1122_3344);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let registered_state = store.state.clone();
    let registered_anchor = anchor.value.clone().ok_or("missing registration anchor")?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
    }
    let reserved_state = store.state.clone();
    let reserved_anchor = anchor.value.clone().ok_or("missing reservation anchor")?;

    anchor.value = Some(registered_anchor.clone());
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.compact_replay().map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::AnchorConflict)
        );
    }

    store.state = registered_state;
    anchor.value = Some(reserved_anchor);
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.compact_replay().map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::AnchorConflict)
        );
    }

    assert_ne!(reserved_state.published_anchor, Some(registered_anchor));
    Ok(())
}

#[test]
fn restored_state_cannot_move_to_another_witness_identity() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 24,
    };
    let mut random = TestRandom::new(0xeeff_0011_2233_4455);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[1],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.compact_replay().map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::RestoredStateUnsafe)
        );
    }

    let mut replacement_store = MemoryStore {
        state: PersistedWitnessState::empty(fixture.actors.witnesses[1].principal_id()),
        fail_before_commit_once: false,
        fail_after_commit_once: false,
        fail_mark_once: false,
    };
    let mut replacement_anchor = MemoryAnchor::default();
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[1],
            &mut replacement_store,
            &mut replacement_anchor,
            &clock,
            &mut random,
        );
        engine.register_vault(
            &fixture.policy,
            RegistrationBytes::new(vec![10, 11, 12])?,
            fixture.checkpoint.clone(),
            PolicyMaterialBytes::new(vec![13, 14, 15])?,
        )?;
    }
    assert_eq!(replacement_store.state.logical.state_generation, 1);
    assert_eq!(replacement_anchor.publishes, 1);
    Ok(())
}
