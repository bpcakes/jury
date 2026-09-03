
#[test]
fn response_is_stable_and_escapes_only_after_anchor_publication() -> TestResult {
    let fixture = fixture()?;
    let witness_id = fixture.actors.witnesses[0].principal_id();
    let mut store = MemoryStore {
        state: PersistedWitnessState::empty(witness_id),
        fail_before_commit_once: false,
        fail_after_commit_once: false,
        fail_mark_once: false,
    };
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 42,
    };
    let mut random = TestRandom::new(0xdead_beef_0123_4567);
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.register_vault(
            &fixture.policy,
            RegistrationBytes::new(vec![1, 2, 3])?,
            fixture.checkpoint.clone(),
            PolicyMaterialBytes::new(vec![4, 5, 6])?,
        )?;
        assert_eq!(
            engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?,
            WitnessProgress::Reserved
        );
        assert_eq!(
            engine.decide(
                &fixture.policy,
                &fixture.request,
                &fixture.manifest,
                &fixture.approvals[..1],
            )?,
            WitnessProgress::Pending
        );
        let stable = engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?;
        let WitnessProgress::Stable(response) = stable else {
            return Err("expected stable response".into());
        };
        assert_eq!(response.decision.decision, WitnessDecisionKindV1::Approve);
        assert!(response.contribution.is_some());
        validate_witness_response(
            &fixture.policy,
            &fixture.checkpoint,
            &fixture.request,
            &fixture.manifest,
            &response,
        )?;
        let mut corrupted = (*response).clone();
        let contribution = corrupted
            .contribution
            .as_mut()
            .ok_or("missing contribution")?;
        let mut ciphertext = *contribution.ciphertext.as_bytes();
        ciphertext[0] ^= 1;
        contribution.ciphertext = ShareCiphertext49::from_slice(&ciphertext)?;
        assert_eq!(
            validate_witness_response(
                &fixture.policy,
                &fixture.checkpoint,
                &fixture.request,
                &fixture.manifest,
                &corrupted,
            )
            .map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::InvalidContribution)
        );
        let stable_bytes = response.canonical_bytes()?;
        let retry = engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?;
        let WitnessProgress::Stable(retry) = retry else {
            return Err("expected stable retry".into());
        };
        assert_eq!(retry.canonical_bytes()?, stable_bytes);
    }
    assert_eq!(store.state.logical.state_generation, 4);
    assert_eq!(
        store
            .state
            .logical
            .replay
            .values()
            .next()
            .ok_or("missing replay entry")?
            .approvals
            .len(),
        2
    );
    assert!(store.state.pending_anchor.is_none());
    assert_eq!(anchor.publishes, 4);
    assert_eq!(
        anchor.value.as_ref().map(|value| value.state_generation),
        Some(4)
    );
    Ok(())
}

#[test]
fn receipt_material_is_bound_to_the_request_policy_and_counted_members() -> TestResult {
    let fixture = fixture()?;
    let mut counted_approver_ids = fixture
        .approvals
        .iter()
        .map(|approval| approval.approver_id)
        .collect::<Vec<_>>();
    counted_approver_ids.sort_unstable();
    let witness_policy = fixture
        .policy
        .witness_policy(&fixture.request.witness_policy_digest)
        .ok_or("missing witness policy")?;
    let mut counted_witness_ids = witness_policy
        .witness_descriptors
        .iter()
        .map(|descriptor| descriptor.witness_id)
        .collect::<Vec<_>>();
    counted_witness_ids.sort_unstable();
    let material = WitnessReceiptMaterialV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0xd1; 32])?,
        request_digest: fixture.request.digest()?,
        action_manifest_digest: fixture.manifest.digest()?,
        presentation_digest: fixture.manifest.presentation_digest.clone(),
        policy_checkpoint_digest: fixture.checkpoint.digest()?,
        witness_policy_digest: fixture.request.witness_policy_digest.clone(),
        approval_threshold: 2,
        witness_threshold: 2,
        counted_approver_ids,
        counted_witness_ids,
        reason: WitnessReasonV1::None,
        issued_at_ms: NOW_MS,
        expires_at_ms: fixture.request.expires_at_ms,
    };
    validate_receipt_material(
        &fixture.policy,
        &fixture.checkpoint,
        &fixture.request,
        &fixture.manifest,
        &material,
    )?;

    let mut wrong_member = material.clone();
    *wrong_member
        .counted_witness_ids
        .last_mut()
        .ok_or("missing counted witness")? = PrincipalId::from_bytes([0x7f; 32])?;
    assert_eq!(
        validate_receipt_material(
            &fixture.policy,
            &fixture.checkpoint,
            &fixture.request,
            &fixture.manifest,
            &wrong_member,
        )
        .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::WrongScope)
    );

    let mut wrong_scope = material;
    wrong_scope.presentation_digest = Digest32::new([0xff; 32]);
    assert_eq!(
        validate_receipt_material(
            &fixture.policy,
            &fixture.checkpoint,
            &fixture.request,
            &fixture.manifest,
            &wrong_scope,
        )
        .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::WrongScope)
    );
    Ok(())
}

#[test]
fn distinct_second_approve_from_one_identity_is_an_approval_conflict() -> TestResult {
    let fixture = fixture()?;
    let mut repeated = fixture.approvals[0].clone();
    repeated.approval_id = ApprovalId::from_bytes([0xe1; 32])?;
    repeated.nonce = ApprovalId::from_bytes([0xe2; 32])?;
    repeated.signature =
        fixture.actors.approvers[0].sign_validated_approval(&repeated.signature_preimage()?)?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 43,
    };
    let mut random = TestRandom::new(0x0123_4567_89ab_cdef);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let progress = {
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
            &[
                fixture.approvals[0].clone(),
                repeated,
                fixture.approvals[1].clone(),
            ],
        )?
    };
    let WitnessProgress::Stable(response) = progress else {
        return Err("expected stable denial".into());
    };
    assert_eq!(response.decision.decision, WitnessDecisionKindV1::Deny);
    assert_eq!(response.decision.reason, WitnessReasonV1::ApprovalConflict);
    assert!(response.contribution.is_none());
    assert_eq!(
        store
            .state
            .logical
            .replay
            .values()
            .next()
            .ok_or("missing replay entry")?
            .approvals
            .len(),
        3
    );
    Ok(())
}

#[test]
fn an_expired_stored_approval_stops_counting_without_poisoning_the_request() -> TestResult {
    let fixture = fixture()?;
    let mut short = fixture.approvals[0].clone();
    short.expires_at_ms = NOW_MS + 1;
    short.signature =
        fixture.actors.approvers[0].sign_validated_approval(&short.signature_preimage()?)?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let initial_clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 44,
    };
    let mut random = TestRandom::new(0x1234_0000_5678_0000);
    register_fixture(
        &fixture,
        &mut store,
        &mut anchor,
        &initial_clock,
        &mut random,
    )?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &initial_clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
        assert_eq!(
            engine.decide(
                &fixture.policy,
                &fixture.request,
                &fixture.manifest,
                &[short],
            )?,
            WitnessProgress::Pending
        );
    }

    let later_clock = FixedClock {
        wall_ms: NOW_MS + 2,
        monotonic_ms: 45,
    };
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &later_clock,
            &mut random,
        );
        assert_eq!(
            engine.decide(
                &fixture.policy,
                &fixture.request,
                &fixture.manifest,
                &fixture.approvals[1..],
            )?,
            WitnessProgress::Pending
        );
    }
    let retained = &store
        .state
        .logical
        .replay
        .values()
        .next()
        .ok_or("missing replay entry")?
        .approvals;
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].approver_id, fixture.approvals[1].approver_id);

    let mut renewed = fixture.approvals[0].clone();
    renewed.approval_id = ApprovalId::from_bytes([0xe3; 32])?;
    renewed.nonce = ApprovalId::from_bytes([0xe4; 32])?;
    renewed.issued_at_ms = NOW_MS + 2;
    renewed.signature =
        fixture.actors.approvers[0].sign_validated_approval(&renewed.signature_preimage()?)?;
    let progress = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &later_clock,
            &mut random,
        );
        engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &[renewed],
        )?
    };
    let WitnessProgress::Stable(response) = progress else {
        return Err("expected stable approval".into());
    };
    assert_eq!(response.decision.decision, WitnessDecisionKindV1::Approve);
    Ok(())
}

#[test]
fn request_time_boundaries_apply_skew_not_before_and_strict_expiry() -> TestResult {
    let fixture = fixture()?;

    let (request, manifest) = signed_time_variant(
        &fixture,
        NOW_MS + ACCEPTED_CLOCK_SKEW_MS,
        None,
        NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 1,
    )?;
    assert_eq!(
        reserve_once(&fixture, request, &manifest, NOW_MS, 0x101)?,
        WitnessProgress::Reserved
    );

    let (request, manifest) = signed_time_variant(
        &fixture,
        NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 1,
        None,
        NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 2,
    )?;
    assert_eq!(
        reserve_once(&fixture, request, &manifest, NOW_MS, 0x102)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::NotYetValid)
    );

    let (request, manifest) = signed_time_variant(
        &fixture,
        NOW_MS - 1_000,
        Some(NOW_MS + ACCEPTED_CLOCK_SKEW_MS),
        NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 1,
    )?;
    assert_eq!(
        reserve_once(&fixture, request, &manifest, NOW_MS, 0x103)?,
        WitnessProgress::Reserved
    );

    let (request, manifest) = signed_time_variant(
        &fixture,
        NOW_MS - 1_000,
        Some(NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 1),
        NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 2,
    )?;
    assert_eq!(
        reserve_once(&fixture, request, &manifest, NOW_MS, 0x104)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::NotYetValid)
    );

    let (request, manifest) = signed_time_variant(&fixture, NOW_MS - 1_000, None, NOW_MS + 1)?;
    assert_eq!(
        reserve_once(&fixture, request, &manifest, NOW_MS, 0x105)?,
        WitnessProgress::Reserved
    );

    let (request, manifest) = signed_time_variant(&fixture, NOW_MS - 1_000, None, NOW_MS)?;
    assert_eq!(
        reserve_once(&fixture, request, &manifest, NOW_MS, 0x106)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::Expired)
    );
    Ok(())
}

#[test]
fn forward_clock_jump_turns_a_reserved_request_into_a_stable_expiry_denial() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let initial_clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 48,
    };
    let mut random = TestRandom::new(0x4567_89ab_cdef_0123);
    register_fixture(
        &fixture,
        &mut store,
        &mut anchor,
        &initial_clock,
        &mut random,
    )?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &initial_clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
    }
    let expiry_clock = FixedClock {
        wall_ms: fixture.request.expires_at_ms,
        monotonic_ms: 49,
    };
    let denied = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &expiry_clock,
            &mut random,
        );
        engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?
    };
    let WitnessProgress::Stable(denied) = denied else {
        return Err("expected expiry denial".into());
    };
    assert_eq!(denied.decision.reason, WitnessReasonV1::Expired);
    assert!(denied.contribution.is_none());
    let retry = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &expiry_clock,
            &mut random,
        );
        engine.decide(&fixture.policy, &fixture.request, &fixture.manifest, &[])?
    };
    let WitnessProgress::Stable(retry) = retry else {
        return Err("expected stable expiry retry".into());
    };
    assert_eq!(retry.canonical_bytes()?, denied.canonical_bytes()?);
    Ok(())
}

#[test]
fn conflicting_request_id_terminalizes_only_the_original_reservation() -> TestResult {
    let fixture = fixture()?;
    let mut conflicting = fixture.request.clone();
    conflicting.request_session_public_key = fixture.actors.witnesses[1]
        .public_descriptor()?
        .recipient_public_key;
    conflicting.request_session_key_fingerprint =
        recipient_public_key_fingerprint(&conflicting.request_session_public_key);
    conflicting.client_signature = fixture
        .actors
        .owner
        .sign_validated_statement(&conflicting.signature_preimage()?)?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 46,
    };
    let mut random = TestRandom::new(0x2345_6789_abcd_ef01);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let conflict_response = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
        let progress = engine.reserve(&fixture.policy, conflicting.clone(), &fixture.manifest)?;
        let WitnessProgress::Stable(response) = progress else {
            return Err("expected replay-conflict denial".into());
        };
        response
    };
    assert_eq!(
        conflict_response.decision.reason,
        WitnessReasonV1::ReplayConflict
    );
    assert_eq!(
        conflict_response.decision.request_digest,
        fixture.request.digest()?
    );
    assert!(conflict_response.contribution.is_none());

    let original_retry = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?
    };
    let WitnessProgress::Stable(original_retry) = original_retry else {
        return Err("expected stable original denial".into());
    };
    assert_eq!(
        original_retry.canonical_bytes()?,
        conflict_response.canonical_bytes()?
    );

    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut store,
        &mut anchor,
        &clock,
        &mut random,
    );
    assert_eq!(
        engine
            .reserve(&fixture.policy, conflicting, &fixture.manifest)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::ReplayConflict)
    );
    Ok(())
}

#[test]
fn common_scope_check_rejects_each_changed_duplicate() -> TestResult {
    let fixture = fixture()?;
    assert_request_scope_mismatches(&fixture)?;
    assert_manifest_scope_mismatches(&fixture)?;
    let mut request = fixture.request.clone();
    request.protocol_version = 2;
    assert_eq!(
        validate_request_manifest(&request, &fixture.manifest).map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::UnsupportedVersion)
    );
    Ok(())
}

fn assert_wrong_scope(
    fixture: &Fixture,
    name: &str,
    change: impl FnOnce(&mut ActionManifestV1) -> TestResult,
) -> TestResult {
    let mut changed = fixture.manifest.clone();
    change(&mut changed)?;
    assert!(changed.validate_shape().is_ok(), "{name} fixture");
    assert_eq!(
        validate_request_manifest(&fixture.request, &changed).map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::WrongScope),
        "{name}"
    );
    Ok(())
}

fn assert_request_scope_mismatches(fixture: &Fixture) -> TestResult {
    assert_wrong_scope(fixture, "request ID", |manifest| {
        manifest.request_id = RequestId::from_bytes([0xd0; 32])?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "vault", |manifest| {
        manifest.vault_id = VaultId::from_bytes([0xd1; 32])?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "genesis", |manifest| {
        manifest.genesis_fingerprint = Digest32::new([0xd2; 32]);
        Ok(())
    })?;
    assert_wrong_scope(fixture, "item", |manifest| {
        let item_id = ItemId::from_bytes([0xd3; 32])?;
        manifest.item_id = item_id;
        manifest.approval_target.entries[0].item_id = item_id;
        manifest.approval_target_digest = manifest.approval_target.digest()?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "key epoch", |manifest| {
        manifest.key_epoch = 2;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "access mode", |manifest| {
        manifest.item_access_mode = ItemAccessMode::Mixed;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "slot", |manifest| {
        manifest.slot_id = SlotId::from_bytes([0xd4; 32])?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "content role", |manifest| {
        manifest.content_role = ContentRole::Descriptor;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "revision", |manifest| {
        manifest.revision = 2;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "revision seal", |manifest| {
        manifest.revision_seal_id = RevisionSealId::from_bytes([0xd5; 32])?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "policy sequence", |manifest| {
        manifest.vault_policy_sequence = 2;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "policy hash", |manifest| {
        manifest.vault_policy_hash = Digest32::new([0xd6; 32]);
        Ok(())
    })?;
    assert_wrong_scope(fixture, "witness policy ID", |manifest| {
        manifest.witness_policy_id = WitnessPolicyId::from_bytes([0xd7; 32])?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "witness policy revision", |manifest| {
        manifest.witness_policy_revision = 2;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "witness policy digest", |manifest| {
        manifest.witness_policy_digest = Digest32::new([0xd8; 32]);
        Ok(())
    })?;
    assert_wrong_scope(fixture, "requester", |manifest| {
        manifest.requester_principal_id = PrincipalId::from_bytes([0xd9; 32])?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "requested role", |manifest| {
        manifest.requested_access_role = AccessRole::Reader;
        Ok(())
    })?;
    Ok(())
}

fn assert_manifest_scope_mismatches(fixture: &Fixture) -> TestResult {
    assert_wrong_scope(fixture, "operation", |manifest| {
        manifest.operation = WitnessOperationV1::WritePrivateFile;
        manifest.operation_context = OperationContextV1::WritePrivateFile;
        manifest.output_sink = OutputSinkV1::PrivateFile;
        manifest.output_sink_commitment = Some(Digest32::new([0xda; 32]));
        Ok(())
    })?;
    assert_wrong_scope(fixture, "approval target", |manifest| {
        manifest.approval_target.entries[0].presentation_commitment = Digest32::new([0xdb; 32]);
        manifest.approval_target_digest = manifest.approval_target.digest()?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "issued time", |manifest| {
        manifest.issued_at_ms -= 1;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "not before", |manifest| {
        manifest.not_before_ms = Some(NOW_MS);
        Ok(())
    })?;
    assert_wrong_scope(fixture, "expiry", |manifest| {
        manifest.expires_at_ms -= 1;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "workload", |manifest| {
        manifest.output_limit_bytes -= 1;
        Ok(())
    })?;
    Ok(())
}
