#[test]
fn complete_receipt_matches_the_frozen_vector_and_round_trips_json() -> TestResult {
    let corpus = corpus()?;
    let request = witness_request(&corpus)?;
    let mut policy_material = length_prefixed(&vector_hex(
        &corpus,
        "owner_policy_revision",
        "message_hex",
    )?)?;
    policy_material.extend_from_slice(&length_prefixed(&vector_hex(
        &corpus,
        "witness_policy",
        "body_hex",
    )?)?);
    let core_digest = digest_hex(&corpus, "receipt_core", "digest_hex")?;
    let endpoint_fingerprint = request.requester_signing_key_fingerprint.clone();
    let acknowledgement = ReceiptAcknowledgementV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0xe0; 32])?,
        receipt_core_digest: core_digest.clone(),
        request_digest: request.digest()?,
        endpoint_principal_id: request.requester_principal_id,
        endpoint_key_fingerprint: endpoint_fingerprint.clone(),
        endpoint_key_epoch: 1,
        started_at_ms: ISSUED_AT + 1_500,
        signature: fixed_hex(vector_hex(
            &corpus,
            "receipt_acknowledgement",
            "signature_hex",
        )?)?,
    };
    assert_eq!(
        acknowledgement.canonical_bytes()?,
        vector_hex(&corpus, "receipt_acknowledgement", "message_hex")?
    );
    let completion = ReceiptCompletionV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0xe0; 32])?,
        receipt_core_digest: core_digest,
        acknowledgement_digest: Some(acknowledgement.digest()?),
        endpoint_principal_id: request.requester_principal_id,
        endpoint_key_fingerprint: endpoint_fingerprint,
        endpoint_key_epoch: 1,
        outcome: ReceiptOutcomeV1::Approved,
        reason: WitnessReasonV1::None,
        completed_at_ms: ISSUED_AT + 3_000,
        signature: fixed_hex(vector_hex(&corpus, "receipt_completion", "signature_hex")?)?,
    };
    assert_eq!(
        completion.canonical_bytes()?,
        vector_hex(&corpus, "receipt_completion", "message_hex")?
    );
    let receipt = WitnessReceiptV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0xe0; 32])?,
        request_signature_preimage: RequestBytes::new(request.signature_preimage()?)?,
        client_signature: request.client_signature.clone(),
        request_digest: request.digest()?,
        action_manifest_digest: digest_hex(&corpus, "action_manifest", "digest_hex")?,
        presentation_digest: digest_hex(&corpus, "approval_presentation", "digest_hex")?,
        public_scope: PublicReceiptScopeV1::from_request(&request),
        approval_decisions: vec![
            approval_decision(&corpus, 0)?,
            approval_decision(&corpus, 1)?,
        ],
        witness_decisions: vec![witness_decision(&corpus, 0)?, witness_decision(&corpus, 1)?],
        policy_checkpoint: policy_checkpoint(&corpus)?,
        witness_policy_material: PolicyMaterialBytes::new(policy_material)?,
        approval_threshold: 2,
        witness_threshold: 2,
        counted_approver_ids: vec![
            PrincipalId::from_bytes([0x41; 32])?,
            PrincipalId::from_bytes([0x42; 32])?,
        ],
        counted_witness_ids: vec![
            PrincipalId::from_bytes([0x51; 32])?,
            PrincipalId::from_bytes([0x52; 32])?,
        ],
        outcome: ReceiptOutcomeV1::Approved,
        reason: WitnessReasonV1::None,
        issued_at_ms: ISSUED_AT + 3_000,
        expires_at_ms: EXPIRES_AT,
        endpoint_acknowledgement: Some(acknowledgement),
        endpoint_completion: Some(completion),
    };
    assert_eq!(
        receipt.core_bytes()?,
        vector_hex(&corpus, "receipt_core", "body_hex")?
    );
    assert_eq!(
        receipt.core_digest()?,
        digest_hex(&corpus, "receipt_core", "digest_hex")?
    );
    assert_eq!(
        receipt.canonical_bytes()?,
        vector_hex(&corpus, "witness_receipt", "body_hex")?
    );
    assert_eq!(
        receipt.digest()?,
        digest_hex(&corpus, "witness_receipt", "digest_hex")?
    );
    assert_eq!(
        receipt.validated_digests()?,
        (
            digest_hex(&corpus, "receipt_core", "digest_hex")?,
            digest_hex(&corpus, "witness_receipt", "digest_hex")?,
        )
    );
    let encoded = receipt.to_json_bytes()?;
    assert_eq!(WitnessReceiptV1::parse_json(&encoded)?, receipt);
    Ok(())
}

#[test]
fn receipt_material_is_canonical_and_rejects_unknown_schema() -> TestResult {
    let corpus = corpus()?;
    let material = WitnessReceiptMaterialV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0xe0; 32])?,
        request_digest: digest_hex(&corpus, "witness_request", "digest_hex")?,
        action_manifest_digest: digest_hex(&corpus, "action_manifest", "digest_hex")?,
        presentation_digest: digest_hex(&corpus, "approval_presentation", "digest_hex")?,
        policy_checkpoint_digest: digest_hex(&corpus, "policy_checkpoint", "digest_hex")?,
        witness_policy_digest: digest_hex(&corpus, "witness_policy", "digest_hex")?,
        approval_threshold: 2,
        witness_threshold: 2,
        counted_approver_ids: vec![
            PrincipalId::from_bytes([0x41; 32])?,
            PrincipalId::from_bytes([0x42; 32])?,
        ],
        counted_witness_ids: vec![
            PrincipalId::from_bytes([0x51; 32])?,
            PrincipalId::from_bytes([0x52; 32])?,
        ],
        reason: WitnessReasonV1::None,
        issued_at_ms: ISSUED_AT + 3_000,
        expires_at_ms: EXPIRES_AT,
    };
    let canonical = material.canonical_bytes()?;
    let mut changed = material.clone();
    changed.presentation_digest = repeated_digest(0xff);
    assert_ne!(changed.canonical_bytes()?, canonical);
    let mut unknown = material;
    unknown.schema = 2;
    assert!(unknown.canonical_bytes().is_err());
    Ok(())
}

#[test]
fn signed_messages_reject_one_bit_scope_changes() -> TestResult {
    let corpus = corpus()?;
    let mut manifest = action_manifest(&corpus)?;
    let expected = manifest.digest()?;
    manifest.output_limit_bytes ^= 1;
    assert_ne!(manifest.digest()?, expected);

    let mut checkpoint_bytes = vector_hex(&corpus, "policy_checkpoint", "message_hex")?;
    let last = checkpoint_bytes
        .last_mut()
        .ok_or_else(|| failure("empty checkpoint vector"))?;
    *last ^= 1;
    assert_ne!(
        checkpoint_bytes,
        vector_hex(&corpus, "policy_checkpoint", "message_hex")?
    );
    Ok(())
}
