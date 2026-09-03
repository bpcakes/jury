#[test]
fn strict_descendant_checkpoint_invalidates_old_reservations() -> TestResult {
    let fixture = fixture()?;
    let (next_policy, next_checkpoint) = descendant_policy_and_checkpoint(&fixture)?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 19,
    };
    let mut random = TestRandom::new(0x9999_aaaa_bbbb_cccc);
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
        engine.advance_checkpoint(
            &next_policy,
            next_checkpoint.clone(),
            PolicyMaterialBytes::new(vec![7, 8, 9])?,
        )?;
    }
    let entry = store
        .state
        .logical
        .replay
        .values()
        .next()
        .ok_or("missing stale replay record")?;
    assert_eq!(entry.state, ReplayStateV1::Denied);
    let response = entry.response.as_ref().ok_or("missing stale response")?;
    assert_eq!(response.decision.reason, WitnessReasonV1::StalePolicy);
    assert!(response.contribution.is_none());
    assert_eq!(
        store
            .state
            .logical
            .vaults
            .values()
            .next()
            .map(|vault| &vault.current_checkpoint),
        Some(&next_checkpoint)
    );
    assert_eq!(store.state.logical.state_generation, 3);
    assert_eq!(
        anchor.value.as_ref().map(|value| value.state_generation),
        Some(3)
    );
    Ok(())
}

#[test]
fn checkpoint_rotation_is_accepted_then_the_replaced_witness_stops_serving() -> TestResult {
    let fixture = fixture()?;
    let mut identity_random = TestRandom::new(0xbbbb_cccc_dddd_eeee);
    let replacement = make_identity(0x31, PrincipalKind::Witness, &mut identity_random)?;
    let UnlockedIdentity::Witness(replacement) = replacement else {
        return Err("replacement role mismatch".into());
    };
    let (next_policy, next_checkpoint) =
        descendant_policy_and_checkpoint_with_replacement(&fixture, Some(&replacement))?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 21,
    };
    let mut random = TestRandom::new(0xbbcc_ddee_ff00_1122);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.advance_checkpoint(
            &next_policy,
            next_checkpoint.clone(),
            PolicyMaterialBytes::new(vec![7, 8, 9])?,
        )?;
    }
    assert_eq!(
        store
            .state
            .logical
            .vaults
            .values()
            .next()
            .map(|vault| &vault.current_checkpoint),
        Some(&next_checkpoint)
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
            .reserve(&next_policy, fixture.request.clone(), &fixture.manifest)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::PolicyDenied)
    );
    Ok(())
}

#[test]
fn signed_rotation_binds_both_fresh_item_seals_and_the_new_key_period() -> TestResult {
    let fixture = fixture()?;
    let mut identity_random = TestRandom::new(0xbbbb_cccc_dddd_eeef);
    let UnlockedIdentity::Witness(replacement) =
        make_identity(0x31, PrincipalKind::Witness, &mut identity_random)?
    else {
        return Err("replacement role mismatch".into());
    };
    let (mut next, next_checkpoint) =
        descendant_policy_and_checkpoint_with_replacement(&fixture, Some(&replacement))?;
    let mut prior = fixture.policy.clone();

    let prior_item = prior
        .items
        .get_mut(&fixture.request.item_id)
        .ok_or("prior item absent")?;
    let prior_state = prior_item
        .witnessed_state
        .as_mut()
        .ok_or("prior witnessed state absent")?;
    let mut prior_descriptor_slot = prior_state
        .slots
        .first()
        .cloned()
        .ok_or("prior body slot absent")?;
    prior_descriptor_slot.slot_id = SlotId::from_bytes([0x44; 32])?;
    prior_descriptor_slot.content_role = ContentRole::Descriptor;
    prior_descriptor_slot.revision = prior_item.descriptor.revision;
    prior_descriptor_slot.revision_seal_id = prior_item.descriptor.revision_seal_id;
    prior_state.slots.insert(0, prior_descriptor_slot);
    prior_state.digest = witnessed_slot_set_digest(&prior_state.slots)?;

    let next_item = next
        .items
        .get_mut(&fixture.request.item_id)
        .ok_or("next item absent")?;
    next_item.descriptor.key_epoch = 2;
    next_item.descriptor.revision = 2;
    next_item.descriptor.revision_seal_id = RevisionSealId::from_bytes([0x46; 32])?;
    let next_state = next_item
        .witnessed_state
        .as_mut()
        .ok_or("next witnessed state absent")?;
    let mut next_descriptor_slot = next_state
        .slots
        .first()
        .cloned()
        .ok_or("next body slot absent")?;
    next_descriptor_slot.slot_id = SlotId::from_bytes([0x45; 32])?;
    next_descriptor_slot.content_role = ContentRole::Descriptor;
    next_descriptor_slot.revision = next_item.descriptor.revision;
    next_descriptor_slot.revision_seal_id = next_item.descriptor.revision_seal_id;
    next_state.slots.insert(0, next_descriptor_slot.clone());
    next_state.digest = witnessed_slot_set_digest(&next_state.slots)?;
    let next_body_slot = next_state
        .slots
        .iter()
        .find(|slot| slot.content_role == ContentRole::Body)
        .cloned()
        .ok_or("next body slot absent")?;

    let prior_policy = prior
        .witness_policy(&fixture.request.witness_policy_digest)
        .ok_or("prior witness policy absent")?;
    let next_policy_digest = next_descriptor_slot.witness_policy_digest.clone();
    let next_witness_policy = next
        .witness_policy(&next_policy_digest)
        .ok_or("next witness policy absent")?;
    let owner = fixture.actors.owner.public_descriptor()?;
    let mut rotation = WitnessPolicyRotationV1 {
        schema: 1,
        rotation_id: RotationId::from_bytes([0xd5; 32])?,
        vault_id: prior.vault_id(),
        genesis_fingerprint: prior.genesis_fingerprint().clone(),
        prior_vault_policy_sequence: prior.sequence(),
        prior_vault_policy_hash: prior.terminal_revision_hash().clone(),
        next_vault_policy_sequence: next.sequence(),
        next_vault_policy_hash: next.terminal_revision_hash().clone(),
        prior_witness_policy_id: prior_policy.witness_policy_id,
        prior_witness_policy_revision: prior_policy.revision,
        prior_witness_policy_digest: fixture.request.witness_policy_digest.clone(),
        next_witness_policy_id: next_witness_policy.witness_policy_id,
        next_witness_policy_revision: next_witness_policy.revision,
        next_witness_policy_digest: next_policy_digest,
        reason: WitnessRotationReasonV1::ContributionKey,
        affected_items: vec![WitnessRotationItemV1 {
            item_id: fixture.request.item_id,
            prior_key_epoch: 1,
            next_key_epoch: 2,
            next_descriptor_revision: next_descriptor_slot.revision,
            next_descriptor_revision_seal_id: next_descriptor_slot.revision_seal_id,
            next_descriptor_capsule_set_digest: next_descriptor_slot.capsule_set_digest.clone(),
            next_body_revision: next_body_slot.revision,
            next_body_revision_seal_id: next_body_slot.revision_seal_id,
            next_body_capsule_set_digest: next_body_slot.capsule_set_digest.clone(),
        }],
        issued_at_ms: NOW_MS,
        owner_id: owner.principal_id,
        owner_key_fingerprint: signing_key_fingerprint(
            1,
            &owner.principal_id,
            1,
            &owner.verification_public_key,
        ),
        owner_key_epoch: 1,
        signature: Signature64::new([0; 64]),
    };
    rotation.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&rotation.signature_preimage()?)?;
    assert_eq!(
        verify_witness_policy_rotation(&prior, &next, &rotation)?,
        rotation.digest()?
    );

    let registration = RegistrationBytes::new(vec![0x91, 0x92])?;
    let mut recovery = WitnessRecoveryV1 {
        schema: 1,
        recovery_id: RecoveryId::from_bytes([0xfc; 32])?,
        vault_id: next.vault_id(),
        genesis_fingerprint: next.genesis_fingerprint().clone(),
        unavailable_prior_witness_id: None,
        new_witness_descriptor: WitnessDescriptorBytes::new(
            next_witness_policy.witness_descriptors[0].canonical_bytes(),
        )?,
        new_registration_digest: witness_registration_digest(&registration)?,
        prior_checkpoint_digest: fixture.checkpoint.digest()?,
        next_checkpoint_digest: next_checkpoint.digest()?,
        rotation_record_digest: rotation.digest()?,
        statement: 1,
        issued_at_ms: NOW_MS,
        owner_id: owner.principal_id,
        owner_key_fingerprint: rotation.owner_key_fingerprint.clone(),
        owner_key_epoch: 1,
        signature: Signature64::new([0; 64]),
    };
    recovery.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&recovery.signature_preimage()?)?;
    let mut lower_threshold = next.clone();
    lower_threshold
        .witness_policies
        .get_mut(&rotation.next_witness_policy_digest)
        .ok_or("next witness policy absent")?
        .witness_threshold = 1;
    let unsafe_recovery = verify_witness_recovery(
        &prior,
        &lower_threshold,
        &fixture.checkpoint,
        &next_checkpoint,
        &rotation,
        &registration,
        &recovery,
    )
    .err()
    .ok_or("recovery lowered the witness threshold")?;
    assert_eq!(
        unsafe_recovery.kind(),
        RotationVerificationErrorKind::UnsafeRecovery
    );

    let mut forked_next = next.clone();
    forked_next.revision_hashes[0] = Digest32::new([0xfe; 32]);
    let fork_error = verify_witness_policy_rotation(&prior, &forked_next, &rotation)
        .err()
        .ok_or("an unrelated terminal policy snapshot verified as a descendant")?;
    assert_eq!(
        fork_error.kind(),
        RotationVerificationErrorKind::InvalidPolicyTransition
    );

    let mut added_governed_item = next.clone();
    let added_item_id = ItemId::from_bytes([0xfd; 32])?;
    let mut added_item = added_governed_item
        .item(&fixture.request.item_id)
        .cloned()
        .ok_or("next governed item absent")?;
    if let Some(state) = &mut added_item.witnessed_state {
        for slot in &mut state.slots {
            slot.item_id = added_item_id;
        }
    }
    added_governed_item.items.insert(added_item_id, added_item);
    let added_item_error = verify_witness_policy_rotation(&prior, &added_governed_item, &rotation)
        .err()
        .ok_or("a newly governed item omitted from rotation evidence verified")?;
    assert_eq!(
        added_item_error.kind(),
        RotationVerificationErrorKind::IncompleteItemRotation
    );

    let mut incomplete = rotation.clone();
    incomplete.affected_items[0].next_descriptor_capsule_set_digest = Digest32::new([0xff; 32]);
    incomplete.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&incomplete.signature_preimage()?)?;
    let incomplete_error = match verify_witness_policy_rotation(&prior, &next, &incomplete) {
        Err(error) => error,
        Ok(_) => return Err("an incomplete descriptor reseal verified".into()),
    };
    assert_eq!(
        incomplete_error.kind(),
        RotationVerificationErrorKind::IncompleteItemRotation
    );

    let mut wrong_reason = rotation;
    wrong_reason.reason = WitnessRotationReasonV1::WitnessSigningKey;
    wrong_reason.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&wrong_reason.signature_preimage()?)?;
    let reason_error = match verify_witness_policy_rotation(&prior, &next, &wrong_reason) {
        Err(error) => error,
        Ok(_) => return Err("a non-canonical rotation reason verified".into()),
    };
    assert_eq!(
        reason_error.kind(),
        RotationVerificationErrorKind::InvalidPolicyTransition
    );
    Ok(())
}

#[test]
fn checkpoint_gap_fork_and_downgrade_have_distinct_safe_outcomes() -> TestResult {
    let fixture = fixture()?;
    let (next_policy, next_checkpoint) = descendant_policy_and_checkpoint(&fixture)?;
    let (gap_policy, gap_checkpoint) =
        descendant_policy_and_checkpoint_at_sequence(&fixture, None, 3)?;
    let mut fork_checkpoint = next_checkpoint.clone();
    fork_checkpoint.predecessor_checkpoint_digest = Digest32::new([0xfa; 32]);
    fork_checkpoint.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&fork_checkpoint.signature_preimage()?)?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 22,
    };
    let mut random = TestRandom::new(0xccdd_eeff_0011_2233);
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
            engine
                .advance_checkpoint(
                    &next_policy,
                    fork_checkpoint,
                    PolicyMaterialBytes::new(vec![7])?,
                )
                .map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::CheckpointFork)
        );
        assert_eq!(
            engine
                .advance_checkpoint(
                    &gap_policy,
                    gap_checkpoint,
                    PolicyMaterialBytes::new(vec![8])?,
                )
                .map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::WitnessBehind)
        );
        engine.advance_checkpoint(
            &next_policy,
            next_checkpoint,
            PolicyMaterialBytes::new(vec![9])?,
        )?;
        assert_eq!(
            engine
                .advance_checkpoint(
                    &fixture.policy,
                    fixture.checkpoint.clone(),
                    PolicyMaterialBytes::new(vec![4, 5, 6])?,
                )
                .map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::StalePolicy)
        );
    }
    assert_eq!(store.state.logical.state_generation, 2);
    Ok(())
}

#[test]
fn rotation_reason_matches_active_descriptors_by_identity() -> TestResult {
    let fixture = fixture()?;
    let mut identity_random = TestRandom::new(0xabcd_1234_5678_90ef);
    let UnlockedIdentity::Witness(replacement) =
        make_identity(0x31, PrincipalKind::Witness, &mut identity_random)?
    else {
        return Err("replacement role mismatch".into());
    };
    let (next, _) =
        descendant_policy_and_checkpoint_with_replacement(&fixture, Some(&replacement))?;
    let mut prior_policy = fixture
        .policy
        .witness_policy(&fixture.request.witness_policy_digest)
        .cloned()
        .ok_or("prior witness policy absent")?;
    let next_item = next
        .item(&fixture.request.item_id)
        .and_then(|item| item.witnessed_state.as_ref())
        .and_then(|state| state.slots.first())
        .ok_or("next witnessed slot absent")?;
    let next_policy = next
        .witness_policy(&next_item.witness_policy_digest)
        .ok_or("next witness policy absent")?;

    let mut retired = prior_policy.witness_descriptors[0].clone();
    retired.status = DescriptorStatus::Revoked;
    retired.witness_id = PrincipalId::from_bytes([0x01; 32])?;
    retired.share_index = 32;
    prior_policy.witness_descriptors.insert(0, retired);

    assert_eq!(
        rotation_reason(&prior_policy, next_policy),
        WitnessRotationReasonV1::ContributionKey
    );
    Ok(())
}

#[test]
fn a_policy_ahead_of_the_registered_checkpoint_is_witness_behind_not_a_fork() -> TestResult {
    let fixture = fixture()?;
    let (next_policy, _) = descendant_policy_and_checkpoint(&fixture)?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 20,
    };
    let mut random = TestRandom::new(0xaaaa_bbbb_cccc_dddd);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut store,
        &mut anchor,
        &clock,
        &mut random,
    );
    assert_eq!(
        engine
            .reserve(&next_policy, fixture.request.clone(), &fixture.manifest)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::WitnessBehind)
    );
    Ok(())
}

#[test]
fn store_capacity_is_preserved_as_a_protocol_refusal() {
    let error = map_store_error(WitnessStoreError::capacity_exhausted());
    assert_eq!(
        error.kind(),
        WitnessEngineErrorKind::Refused(WitnessReasonV1::CapacityExhausted)
    );
}

#[test]
fn unpublishable_anchor_is_refused_before_local_state_commit() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor {
        reject_candidate_capacity: true,
        ..MemoryAnchor::default()
    };
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 50,
    };
    let mut random = TestRandom::new(0x1234_5678_9abc_def0);
    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut store,
        &mut anchor,
        &clock,
        &mut random,
    );

    assert_eq!(
        engine
            .register_vault(
                &fixture.policy,
                RegistrationBytes::new(vec![1, 2, 3])?,
                fixture.checkpoint.clone(),
                PolicyMaterialBytes::new(vec![4, 5, 6])?,
            )
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::CapacityExhausted)
    );
    assert_eq!(store.state.logical.state_generation, 0);
    assert!(store.state.logical.vaults.is_empty());
    assert!(store.state.pending_anchor.is_none());
    assert!(anchor.value.is_none());
    Ok(())
}

#[test]
fn independent_witness_acknowledgements_progress_without_a_global_freshness_claim() -> TestResult {
    let fixture = fixture()?;
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 60,
    };
    let mut first_store = empty_store(&fixture);
    let mut first_anchor = MemoryAnchor::default();
    let mut first_random = TestRandom::new(0x1111_2222_3333_4444);
    let first_acknowledgement = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut first_store,
        &mut first_anchor,
        &clock,
        &mut first_random,
    )
    .register_vault(
        &fixture.policy,
        RegistrationBytes::new(vec![1])?,
        fixture.checkpoint.clone(),
        PolicyMaterialBytes::new(vec![2])?,
    )?;
    let first_status = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut first_store,
        &mut first_anchor,
        &clock,
        &mut first_random,
    )
    .operational_status()?;
    let published = first_status
        .published_anchor
        .as_ref()
        .ok_or("registered witness status omitted its signed anchor")?;
    assert_eq!(published.vault_high_watermarks.len(), 1);
    assert_eq!(published, &first_acknowledgement.exact_anchor);

    let proposed = verify_checkpoint_propagation(&fixture.policy, &fixture.checkpoint, &[])?;
    assert_eq!(proposed.phase, CheckpointPropagationPhase::Proposed);
    assert!(!proposed.global_freshness_claimed);
    let partial = verify_checkpoint_propagation(
        &fixture.policy,
        &fixture.checkpoint,
        std::slice::from_ref(&first_acknowledgement),
    )?;
    assert_eq!(
        partial.phase,
        CheckpointPropagationPhase::PartiallyPropagated
    );
    assert_eq!(partial.acknowledged_witness_count, 1);
    assert!(!partial.global_freshness_claimed);

    let mut second_store = MemoryStore {
        state: PersistedWitnessState::empty(fixture.actors.witnesses[1].principal_id()),
        fail_before_commit_once: false,
        fail_after_commit_once: false,
        fail_mark_once: false,
    };
    let mut second_anchor = MemoryAnchor::default();
    let mut second_random = TestRandom::new(0x5555_6666_7777_8888);
    let second_acknowledgement = WitnessEngine::new(
        &fixture.actors.witnesses[1],
        &mut second_store,
        &mut second_anchor,
        &clock,
        &mut second_random,
    )
    .register_vault(
        &fixture.policy,
        RegistrationBytes::new(vec![3])?,
        fixture.checkpoint.clone(),
        PolicyMaterialBytes::new(vec![4])?,
    )?;
    let durable = verify_checkpoint_propagation(
        &fixture.policy,
        &fixture.checkpoint,
        &[first_acknowledgement.clone(), second_acknowledgement],
    )?;
    assert_eq!(durable.phase, CheckpointPropagationPhase::DurablyAccepted);
    assert_eq!(durable.acknowledged_witness_count, 2);
    assert!(!durable.global_freshness_claimed);

    let mut forged = first_acknowledgement;
    let mut signature = *forged.exact_anchor.signature.as_bytes();
    signature[0] ^= 1;
    forged.exact_anchor.signature = Signature64::new(signature);
    forged.anchor_digest = forged.exact_anchor.digest()?;
    assert!(
        verify_checkpoint_propagation(&fixture.policy, &fixture.checkpoint, &[forged]).is_err()
    );
    Ok(())
}
