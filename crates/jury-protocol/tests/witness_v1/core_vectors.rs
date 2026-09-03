#[test]
fn action_manifest_matches_the_frozen_vector() -> TestResult {
    let corpus = corpus()?;
    let manifest = action_manifest(&corpus)?;
    assert_eq!(
        manifest.canonical_body()?,
        vector_hex(&corpus, "action_manifest", "body_hex")?
    );
    assert_eq!(
        manifest.digest()?,
        digest_hex(&corpus, "action_manifest", "digest_hex")?
    );
    assert_eq!(
        manifest.workload_digest()?,
        digest_hex(&corpus, "workload", "digest_hex")?
    );
    Ok(())
}

#[test]
fn request_matches_the_frozen_vector_and_rejects_unknown_versions() -> TestResult {
    let corpus = corpus()?;
    let request = witness_request(&corpus)?;
    assert_eq!(
        request.signature_preimage()?,
        vector_hex(&corpus, "witness_request", "preimage_hex")?
    );
    assert_eq!(
        request.canonical_bytes()?,
        vector_hex(&corpus, "witness_request", "message_hex")?
    );
    assert_eq!(
        request.digest()?,
        digest_hex(&corpus, "witness_request", "digest_hex")?
    );
    assert_eq!(
        WitnessRequestV1::from_signature_preimage(
            &request.signature_preimage()?,
            request.client_signature.clone(),
        )?,
        request
    );

    let mut trailing = request.signature_preimage()?;
    trailing.push(0);
    assert!(
        WitnessRequestV1::from_signature_preimage(&trailing, request.client_signature.clone())
            .is_err()
    );

    let mut unknown_protocol = request.clone();
    unknown_protocol.protocol_version = 2;
    assert!(unknown_protocol.signature_preimage().is_err());
    let mut unknown_construction = request;
    unknown_construction.construction = 2;
    assert!(unknown_construction.signature_preimage().is_err());
    Ok(())
}

#[test]
fn approval_and_checkpoint_match_the_frozen_vectors() -> TestResult {
    let corpus = corpus()?;
    let approval = ApprovalDecisionV1 {
        schema: 1,
        approval_id: ApprovalId::from_bytes([0x80; 32])?,
        request_id: RequestId::from_bytes([0x07; 32])?,
        request_digest: digest_hex(&corpus, "witness_request", "digest_hex")?,
        action_manifest_digest: digest_hex(&corpus, "action_manifest", "digest_hex")?,
        presentation_digest: digest_hex(&corpus, "approval_presentation", "digest_hex")?,
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: digest_hex(&corpus, "witness_policy", "digest_hex")?,
        approver_id: PrincipalId::from_bytes([0x41; 32])?,
        approver_key_fingerprint: fixed_hex(hex::decode(
            "896a715e557e5fd595d5ba99aac1f19e66698087f15a0f465db6c67753b4624e",
        )?)?,
        approver_key_epoch: 1,
        approval_mode: ApprovalModeV1::Human,
        decision: ApprovalDecisionKindV1::Approve,
        reason: WitnessReasonV1::None,
        issued_at_ms: ISSUED_AT + 1_000,
        not_before_ms: None,
        expires_at_ms: EXPIRES_AT,
        nonce: ApprovalId::from_bytes([0x82; 32])?,
        intended_witness_set_digest: fixed_hex(hex::decode(
            "67aa234cb2c72a8d9301dd1a41ccb89980488a19ed903bccba6a2ba2ef46fe5a",
        )?)?,
        signature: fixed_hex(vector_hex(&corpus, "approval_decision_1", "signature_hex")?)?,
    };
    assert_eq!(
        approval.signature_preimage()?,
        vector_hex(&corpus, "approval_decision_1", "preimage_hex")?
    );
    assert_eq!(
        approval.canonical_bytes()?,
        vector_hex(&corpus, "approval_decision_1", "message_hex")?
    );
    assert_eq!(
        approval.digest()?,
        digest_hex(&corpus, "approval_decision_1", "digest_hex")?
    );

    let checkpoint = VaultPolicyCheckpointV1 {
        schema: 1,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: repeated_digest(0x02),
        vault_policy_sequence: 7,
        vault_policy_hash: repeated_digest(0x72),
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: digest_hex(&corpus, "witness_policy", "digest_hex")?,
        witness_set_digest: fixed_hex(hex::decode(
            "1ca3be89d2e1d2de0bf25cfcfe82569fd63228031feea946b1fff38ee30b200a",
        )?)?,
        approver_set_digest: fixed_hex(hex::decode(
            "95ac3364e23be58775128029e79a3bd9f447011cc96bf95a98bc2e193d8d6bb5",
        )?)?,
        review_label_set_digest: fixed_hex(hex::decode(
            "da3e0c4bc71493d609254bd71fc7f182947aa6f61bb63129cdcb3baea42082c5",
        )?)?,
        predecessor_checkpoint_digest: repeated_digest(0),
        issued_at_ms: ISSUED_AT - 500,
        issuer_owner_id: PrincipalId::from_bytes([0x09; 32])?,
        issuer_key_fingerprint: fixed_hex(hex::decode(
            "20367a13894f8ebbb319f692e58c68369ddd3d547ed886b08fcb05ef74f1932c",
        )?)?,
        issuer_key_epoch: 1,
        signature: fixed_hex(vector_hex(&corpus, "policy_checkpoint", "signature_hex")?)?,
    };
    assert_eq!(
        checkpoint.signature_preimage()?,
        vector_hex(&corpus, "policy_checkpoint", "preimage_hex")?
    );
    assert_eq!(
        checkpoint.canonical_bytes()?,
        vector_hex(&corpus, "policy_checkpoint", "message_hex")?
    );
    assert_eq!(
        checkpoint.digest()?,
        digest_hex(&corpus, "policy_checkpoint", "digest_hex")?
    );
    Ok(())
}
#[test]
fn decision_and_anchor_match_the_frozen_vectors() -> TestResult {
    let corpus = corpus()?;
    let witness_fingerprint = fixed_hex(hex::decode(
        "82ccd975752822c52ea537cb8aba52a957768b40d49748419e72c5b0dbd49fda",
    )?)?;
    let decision = WitnessDecisionV1 {
        schema: 1,
        response_id: ResponseId::from_bytes([0xb0; 32])?,
        request_id: RequestId::from_bytes([0x07; 32])?,
        request_digest: digest_hex(&corpus, "witness_request", "digest_hex")?,
        action_manifest_digest: digest_hex(&corpus, "action_manifest", "digest_hex")?,
        witness_id: PrincipalId::from_bytes([0x51; 32])?,
        witness_signing_key_fingerprint: witness_fingerprint.clone(),
        witness_signing_key_epoch: 1,
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: digest_hex(&corpus, "witness_policy", "digest_hex")?,
        policy_checkpoint_digest: digest_hex(&corpus, "policy_checkpoint", "digest_hex")?,
        state_generation: 2,
        decision: WitnessDecisionKindV1::Approve,
        reason: WitnessReasonV1::None,
        issued_at_ms: ISSUED_AT + 2_000,
        expires_at_ms: EXPIRES_AT,
        contribution_digest: Some(fixed_hex(hex::decode(
            "878e3f50c5199d22573d5320dd6ad264f0e3b427982536fbb82cf8dd72fb3511",
        )?)?),
        share_index: Some(1),
        share_commitment: Some(fixed_hex(hex::decode(
            "7ab077ffd8c344846de4250d24dc092f372087842217d884325b59f7f4cbbaa0",
        )?)?),
        signature: fixed_hex(vector_hex(&corpus, "witness_decision_1", "signature_hex")?)?,
    };
    assert_eq!(
        decision.signature_preimage()?,
        vector_hex(&corpus, "witness_decision_1", "preimage_hex")?
    );
    assert_eq!(
        decision.canonical_bytes()?,
        vector_hex(&corpus, "witness_decision_1", "message_hex")?
    );
    assert_eq!(
        decision.digest()?,
        digest_hex(&corpus, "witness_decision_1", "digest_hex")?
    );
    let contribution_vector = &corpus["construction_vector"]["contributions"][0];
    let capsule_vector = &corpus["construction_vector"]["capsules"][0];
    let contribution = WitnessContributionEnvelopeV1 {
        schema: 1,
        response_id: ResponseId::from_bytes([0xb0; 32])?,
        share_index: 1,
        share_commitment: fixed_hex(hex::decode(
            capsule_vector["share_commitment_hex"]
                .as_str()
                .ok_or_else(|| failure("missing share commitment"))?,
        )?)?,
        capsule_context_digest: fixed_hex(hex::decode(
            capsule_vector["context_digest_hex"]
                .as_str()
                .ok_or_else(|| failure("missing capsule context digest"))?,
        )?)?,
        capsule_set_digest: fixed_hex(hex::decode(
            corpus["construction_vector"]["capsule_set_digest_hex"]
                .as_str()
                .ok_or_else(|| failure("missing capsule set digest"))?,
        )?)?,
        request_session_key_fingerprint: recipient_public_key_fingerprint(&fixed_hex::<1216>(
            hex::decode(
                contribution_vector["request_session_public_key_hex"]
                    .as_str()
                    .ok_or_else(|| failure("missing request session public key"))?,
            )?,
        )?),
        encapsulation: fixed_hex::<1120>(hex::decode(
            contribution_vector["enc_hex"]
                .as_str()
                .ok_or_else(|| failure("missing contribution encapsulation"))?,
        )?)?,
        ciphertext: fixed_hex::<49>(hex::decode(
            contribution_vector["ciphertext_hex"]
                .as_str()
                .ok_or_else(|| failure("missing contribution ciphertext"))?,
        )?)?,
    };
    let response = WitnessResponseV1 {
        decision,
        contribution: Some(contribution),
    };
    assert_eq!(
        response.canonical_bytes()?,
        hex::decode(
            contribution_vector["response_hex"]
                .as_str()
                .ok_or_else(|| failure("missing response vector"))?,
        )?
    );
    let mut unknown_response = response;
    unknown_response.decision.schema = 2;
    assert!(unknown_response.canonical_bytes().is_err());

    let anchor = WitnessStateAnchorV1 {
        schema: 1,
        witness_id: PrincipalId::from_bytes([0x51; 32])?,
        witness_signing_key_fingerprint: witness_fingerprint,
        witness_signing_key_epoch: 1,
        state_generation: 4,
        database_state_digest: fixed_hex(hex::decode(
            "d09a95ebdbb009c5eb4f587410479e1df5974c30b182578c4ffe794ae02fa4fa",
        )?)?,
        vault_high_watermarks: vec![VaultHighWatermarkV1 {
            vault_id: VaultId::from_bytes([0x01; 32])?,
            genesis_fingerprint: repeated_digest(0x02),
            policy_sequence: 7,
            checkpoint_digest: digest_hex(&corpus, "policy_checkpoint", "digest_hex")?,
            highest_retained_request_expiry_ms: EXPIRES_AT,
        }],
        replay_retain_through_ms: EXPIRES_AT + 86_400_000,
        last_accepted_wall_time_ms: ISSUED_AT + 2_000,
        predecessor_anchor_digest: repeated_digest(0xd5),
        issued_at_ms: ISSUED_AT + 2_100,
        signature: fixed_hex(vector_hex(
            &corpus,
            "witness_state_anchor",
            "signature_hex",
        )?)?,
    };
    assert_eq!(
        anchor.signature_preimage()?,
        vector_hex(&corpus, "witness_state_anchor", "preimage_hex")?
    );
    assert_eq!(
        anchor.canonical_bytes()?,
        vector_hex(&corpus, "witness_state_anchor", "message_hex")?
    );
    assert_eq!(
        anchor.digest()?,
        digest_hex(&corpus, "witness_state_anchor", "digest_hex")?
    );
    Ok(())
}

#[test]
fn cancellation_matches_the_frozen_vector() -> TestResult {
    let corpus = corpus()?;
    let mut cancellation = RequestCancellationV1 {
        schema: 1,
        cancellation_id: CancellationId::from_bytes([0xd0; 32])?,
        request_signature_preimage: RequestBytes::new(vector_hex(
            &corpus,
            "witness_request",
            "preimage_hex",
        )?)?,
        client_signature: fixed_hex(vector_hex(&corpus, "witness_request", "signature_hex")?)?,
        request_id: RequestId::from_bytes([0x07; 32])?,
        request_digest: digest_hex(&corpus, "witness_request", "digest_hex")?,
        canceller_id: PrincipalId::from_bytes([0x08; 32])?,
        canceller_key_fingerprint: fixed_hex(hex::decode(
            "35f1855bea5300000e81997b4e41acfffa69fc25897afccd5f640fc8b37ca32a",
        )?)?,
        canceller_key_epoch: 1,
        canceller_role: CancellerRoleV1::OriginalRequester,
        issued_at_ms: ISSUED_AT + 3_000,
        reason: WitnessReasonV1::Cancelled,
        nonce: CancellationId::from_bytes([0xd1; 32])?,
        signature: FixedBytes::new([0; 64]),
    };
    cancellation.signature = fixed_hex(vector_hex(
        &corpus,
        "request_cancellation",
        "signature_hex",
    )?)?;
    assert_eq!(
        cancellation.signature_preimage()?,
        vector_hex(&corpus, "request_cancellation", "preimage_hex")?
    );
    assert_eq!(
        cancellation.canonical_bytes()?,
        vector_hex(&corpus, "request_cancellation", "message_hex")?
    );
    assert_eq!(
        cancellation.digest()?,
        digest_hex(&corpus, "request_cancellation", "digest_hex")?
    );
    Ok(())
}
