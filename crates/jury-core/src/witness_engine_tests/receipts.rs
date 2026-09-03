
fn complete_receipt(fixture: &Fixture) -> TestResult<WitnessReceiptV1> {
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 70,
    };
    let mut decisions = Vec::new();
    for (index, identity) in fixture.actors.witnesses.iter().enumerate() {
        let mut store = MemoryStore {
            state: PersistedWitnessState::empty(identity.principal_id()),
            fail_before_commit_once: false,
            fail_after_commit_once: false,
            fail_mark_once: false,
        };
        let mut anchor = MemoryAnchor::default();
        let mut random = TestRandom::new(0x9000_u64.saturating_add(index as u64));
        let mut engine = WitnessEngine::new(identity, &mut store, &mut anchor, &clock, &mut random);
        engine.register_vault(
            &fixture.policy,
            RegistrationBytes::new(vec![u8::try_from(index + 1)?])?,
            fixture.checkpoint.clone(),
            PolicyMaterialBytes::new(vec![0xa0_u8.saturating_add(u8::try_from(index)?)])?,
        )?;
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
        let WitnessProgress::Stable(response) = engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?
        else {
            return Err("complete approvals did not create a stable witness response".into());
        };
        decisions.push(response.decision);
    }
    decisions.sort_unstable_by_key(|decision| decision.witness_id);
    let mut counted_approver_ids = fixture
        .approvals
        .iter()
        .map(|decision| decision.approver_id)
        .collect::<Vec<_>>();
    counted_approver_ids.sort_unstable();
    let counted_witness_ids = decisions
        .iter()
        .map(|decision| decision.witness_id)
        .collect();
    Ok(WitnessReceiptV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0xe1; 32])?,
        request_signature_preimage: RequestBytes::new(fixture.request.signature_preimage()?)?,
        client_signature: fixture.request.client_signature.clone(),
        request_digest: fixture.request.digest()?,
        action_manifest_digest: fixture.manifest.digest()?,
        presentation_digest: fixture.manifest.presentation_digest.clone(),
        public_scope: PublicReceiptScopeV1::from_request(&fixture.request),
        approval_decisions: fixture.approvals.to_vec(),
        witness_decisions: decisions,
        policy_checkpoint: fixture.checkpoint.clone(),
        witness_policy_material: PolicyMaterialBytes::new(vec![1])?,
        approval_threshold: 2,
        witness_threshold: 2,
        counted_approver_ids,
        counted_witness_ids,
        outcome: ReceiptOutcomeV1::Approved,
        reason: WitnessReasonV1::None,
        issued_at_ms: NOW_MS,
        expires_at_ms: fixture.request.expires_at_ms,
        endpoint_acknowledgement: None,
        endpoint_completion: None,
    })
}

#[test]
fn complete_receipt_verification_rejects_bit_and_field_substitution_mutations() -> TestResult {
    let fixture = fixture()?;
    let receipt = complete_receipt(&fixture)?;
    let verified =
        verify_witness_receipt_with_policy(&receipt, &fixture.policy, Some(&fixture.checkpoint))?;
    assert_eq!(verified.counted_approver_ids.len(), 2);
    assert_eq!(verified.counted_witness_ids.len(), 2);
    assert!(
        verified
            .witness_generations
            .iter()
            .all(|generation| generation.state_generation >= 3)
    );
    assert!(!verified.endpoint_acknowledged);
    assert!(!verified.endpoint_completion_recorded);
    assert!(!verified.receipt_core_endpoint_authenticated);
    assert!(verified.retained_checkpoint_matched);

    let mut mutations = Vec::new();
    let mut changed_request_digest = receipt.clone();
    changed_request_digest.request_digest = Digest32::new([0xf1; 32]);
    mutations.push(changed_request_digest);
    let mut substituted_manifest = receipt.clone();
    substituted_manifest.action_manifest_digest = Digest32::new([0xf2; 32]);
    mutations.push(substituted_manifest);
    let mut substituted_scope = receipt.clone();
    substituted_scope.public_scope.item_id = ItemId::from_bytes([0xf3; 32])?;
    mutations.push(substituted_scope);
    let mut substituted_identity = receipt.clone();
    *substituted_identity
        .counted_witness_ids
        .last_mut()
        .ok_or("counted witness absent")? = PrincipalId::from_bytes([0x7f; 32])?;
    mutations.push(substituted_identity);
    let mut changed_approval_bit = receipt.clone();
    let mut approval_signature = *changed_approval_bit.approval_decisions[0]
        .signature
        .as_bytes();
    approval_signature[0] ^= 1;
    changed_approval_bit.approval_decisions[0].signature = Signature64::new(approval_signature);
    mutations.push(changed_approval_bit);
    let mut changed_generation = receipt.clone();
    changed_generation.witness_decisions[0].state_generation += 1;
    mutations.push(changed_generation);
    let mut changed_checkpoint = receipt.clone();
    let mut checkpoint_signature = *changed_checkpoint.policy_checkpoint.signature.as_bytes();
    checkpoint_signature[0] ^= 1;
    changed_checkpoint.policy_checkpoint.signature = Signature64::new(checkpoint_signature);
    mutations.push(changed_checkpoint);
    let mut false_denial = receipt.clone();
    false_denial.outcome = ReceiptOutcomeV1::Denied;
    false_denial.reason = WitnessReasonV1::PolicyDenied;
    mutations.push(false_denial);

    for mutation in mutations {
        assert!(
            verify_witness_receipt_with_policy(&mutation, &fixture.policy, None).is_err(),
            "a receipt evidence mutation verified"
        );
    }

    let owner = fixture.actors.owner.public_descriptor()?;
    let mut endpoint_records = receipt.clone();
    let mut acknowledgement = ReceiptAcknowledgementV1 {
        schema: 1,
        receipt_id: endpoint_records.receipt_id,
        receipt_core_digest: endpoint_records.core_digest()?,
        request_digest: endpoint_records.request_digest.clone(),
        endpoint_principal_id: owner.principal_id,
        endpoint_key_fingerprint: signing_key_fingerprint(
            1,
            &owner.principal_id,
            1,
            &owner.verification_public_key,
        ),
        endpoint_key_epoch: 1,
        started_at_ms: NOW_MS + 1,
        signature: Signature64::new([0; 64]),
    };
    acknowledgement.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&acknowledgement.signature_preimage()?)?;
    let mut completion = ReceiptCompletionV1 {
        schema: 1,
        receipt_id: endpoint_records.receipt_id,
        receipt_core_digest: endpoint_records.core_digest()?,
        acknowledgement_digest: Some(acknowledgement.digest()?),
        endpoint_principal_id: owner.principal_id,
        endpoint_key_fingerprint: acknowledgement.endpoint_key_fingerprint.clone(),
        endpoint_key_epoch: 1,
        outcome: ReceiptOutcomeV1::Approved,
        reason: WitnessReasonV1::None,
        completed_at_ms: NOW_MS + 2,
        signature: Signature64::new([0; 64]),
    };
    completion.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&completion.signature_preimage()?)?;
    endpoint_records.endpoint_acknowledgement = Some(acknowledgement);
    endpoint_records.endpoint_completion = Some(completion);
    let verified_records =
        verify_witness_receipt_with_policy(&endpoint_records, &fixture.policy, None)?;
    assert!(verified_records.endpoint_acknowledged);
    assert!(verified_records.endpoint_completion_recorded);
    assert!(verified_records.receipt_core_endpoint_authenticated);

    let mut identity_random = TestRandom::new(0xaaaa_9999_8888_7777);
    let UnlockedIdentity::Witness(replacement) =
        make_identity(0x31, PrincipalKind::Witness, &mut identity_random)?
    else {
        return Err("replacement witness role differs".into());
    };
    let (_next_policy, _next_checkpoint) =
        descendant_policy_and_checkpoint_with_replacement(&fixture, Some(&replacement))?;
    assert!(verify_witness_receipt_with_policy(&receipt, &fixture.policy, None).is_ok());
    Ok(())
}

#[test]
fn shared_request_policy_validation_rejects_role_and_lifetime_drift() -> TestResult {
    let fixture = fixture()?;

    let mut wrong_role = fixture.request.clone();
    wrong_role.requested_access_role = AccessRole::Reader;
    wrong_role.client_signature = fixture
        .actors
        .owner
        .sign_validated_statement(&wrong_role.signature_preimage()?)?;
    assert!(matches!(
        validate_request_policy(&fixture.policy, &wrong_role),
        Err(RequestPolicyError::PolicyDenied)
    ));

    let mut overlong = fixture.request.clone();
    overlong.expires_at_ms = overlong.expires_at_ms.saturating_add(1);
    overlong.client_signature = fixture
        .actors
        .owner
        .sign_validated_statement(&overlong.signature_preimage()?)?;
    assert!(matches!(
        validate_request_policy(&fixture.policy, &overlong),
        Err(RequestPolicyError::StalePolicy)
    ));
    Ok(())
}

#[test]
fn receipt_accepts_engine_compatible_skew_and_shorter_decision_expiry() -> TestResult {
    let fixture = fixture()?;
    let mut receipt = complete_receipt(&fixture)?;
    let earlier = fixture.request.issued_at_ms.saturating_sub(30_000);

    receipt.approval_decisions[0].issued_at_ms = earlier;
    receipt.approval_decisions[0].expires_at_ms = fixture.request.expires_at_ms - 1;
    receipt.approval_decisions[0].signature = fixture.actors.approvers[0]
        .sign_validated_approval(&receipt.approval_decisions[0].signature_preimage()?)?;
    receipt.witness_decisions[0].issued_at_ms = earlier;
    receipt.witness_decisions[0].expires_at_ms = fixture.request.expires_at_ms - 1;
    receipt.witness_decisions[0].signature = fixture.actors.witnesses[0]
        .sign_validated_decision(&receipt.witness_decisions[0].signature_preimage()?)?;

    verify_witness_receipt_with_policy(&receipt, &fixture.policy, None)?;
    Ok(())
}

#[test]
fn expired_denial_reports_unauthenticated_collector_reason() -> TestResult {
    let fixture = fixture()?;
    let mut receipt = complete_receipt(&fixture)?;
    let mut denial = receipt.witness_decisions.remove(0);
    denial.decision = WitnessDecisionKindV1::Deny;
    denial.reason = WitnessReasonV1::Expired;
    denial.issued_at_ms = fixture.request.expires_at_ms.saturating_add(1);
    denial.contribution_digest = None;
    denial.share_index = None;
    denial.share_commitment = None;
    denial.signature =
        fixture.actors.witnesses[0].sign_validated_decision(&denial.signature_preimage()?)?;
    receipt.witness_decisions = vec![denial];
    receipt.counted_witness_ids.clear();
    receipt.outcome = ReceiptOutcomeV1::Denied;
    receipt.reason = WitnessReasonV1::Expired;
    receipt.issued_at_ms = fixture.request.expires_at_ms.saturating_add(2);

    let verified =
        verify_witness_receipt_with_policy(&receipt, &fixture.policy, Some(&fixture.checkpoint))?;
    assert_eq!(verified.outcome, ReceiptOutcomeV1::Denied);
    assert_eq!(verified.reported_reason, WitnessReasonV1::Expired);
    assert!(!verified.receipt_core_endpoint_authenticated);
    assert!(verified.retained_checkpoint_matched);

    receipt.reason = WitnessReasonV1::Unavailable;
    let relabelled = verify_witness_receipt_with_policy(&receipt, &fixture.policy, None)?;
    assert_eq!(relabelled.reported_reason, WitnessReasonV1::Unavailable);
    assert!(!relabelled.receipt_core_endpoint_authenticated);
    Ok(())
}
