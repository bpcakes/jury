#[test]
fn rotation_and_recovery_match_the_frozen_vectors() -> TestResult {
    let corpus = corpus()?;
    assert_eq!(
        witness_registration_digest(&RegistrationBytes::new(vector_hex(
            &corpus,
            "witness_registration",
            "body_hex",
        )?)?)?,
        digest_hex(&corpus, "witness_registration", "digest_hex")?
    );
    let owner_fingerprint = fixed_hex(hex::decode(
        "20367a13894f8ebbb319f692e58c68369ddd3d547ed886b08fcb05ef74f1932c",
    )?)?;
    let rotation = WitnessPolicyRotationV1 {
        schema: 1,
        rotation_id: RotationId::from_bytes([0xda; 32])?,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: repeated_digest(0x02),
        prior_vault_policy_sequence: 7,
        prior_vault_policy_hash: repeated_digest(0x72),
        next_vault_policy_sequence: 8,
        next_vault_policy_hash: repeated_digest(0xdb),
        prior_witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        prior_witness_policy_revision: 1,
        prior_witness_policy_digest: digest_hex(&corpus, "witness_policy", "digest_hex")?,
        next_witness_policy_id: WitnessPolicyId::from_bytes([0xdc; 32])?,
        next_witness_policy_revision: 2,
        next_witness_policy_digest: repeated_digest(0xdd),
        reason: WitnessRotationReasonV1::ApproverRuleOrLabel,
        affected_items: vec![WitnessRotationItemV1 {
            item_id: ItemId::from_bytes([0x03; 32])?,
            prior_key_epoch: 3,
            next_key_epoch: 4,
            next_descriptor_revision: 5,
            next_descriptor_revision_seal_id: RevisionSealId::from_bytes([0xd6; 32])?,
            next_descriptor_capsule_set_digest: repeated_digest(0xd7),
            next_body_revision: 5,
            next_body_revision_seal_id: RevisionSealId::from_bytes([0xd8; 32])?,
            next_body_capsule_set_digest: repeated_digest(0xd9),
        }],
        issued_at_ms: ISSUED_AT + 4_000,
        owner_id: PrincipalId::from_bytes([0x09; 32])?,
        owner_key_fingerprint: owner_fingerprint.clone(),
        owner_key_epoch: 1,
        signature: fixed_hex(vector_hex(
            &corpus,
            "witness_policy_rotation",
            "signature_hex",
        )?)?,
    };
    assert_eq!(
        rotation.signature_preimage()?,
        vector_hex(&corpus, "witness_policy_rotation", "preimage_hex")?
    );
    assert_eq!(
        rotation.canonical_bytes()?,
        vector_hex(&corpus, "witness_policy_rotation", "message_hex")?
    );
    assert_eq!(
        rotation.digest()?,
        digest_hex(&corpus, "witness_policy_rotation", "digest_hex")?
    );

    let recovery = WitnessRecoveryV1 {
        schema: 1,
        recovery_id: RecoveryId::from_bytes([0xde; 32])?,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: repeated_digest(0x02),
        unavailable_prior_witness_id: Some(PrincipalId::from_bytes([0x51; 32])?),
        new_witness_descriptor: WitnessDescriptorBytes::new(vector_hex(
            &corpus,
            "witness_descriptor_3",
            "message_hex",
        )?)?,
        new_registration_digest: digest_hex(&corpus, "witness_registration", "digest_hex")?,
        prior_checkpoint_digest: digest_hex(&corpus, "policy_checkpoint", "digest_hex")?,
        next_checkpoint_digest: repeated_digest(0xdf),
        rotation_record_digest: rotation.digest()?,
        statement: 1,
        issued_at_ms: ISSUED_AT + 5_000,
        owner_id: PrincipalId::from_bytes([0x09; 32])?,
        owner_key_fingerprint: owner_fingerprint,
        owner_key_epoch: 1,
        signature: fixed_hex(vector_hex(&corpus, "witness_recovery", "signature_hex")?)?,
    };
    assert_eq!(
        recovery.signature_preimage()?,
        vector_hex(&corpus, "witness_recovery", "preimage_hex")?
    );
    assert_eq!(
        recovery.canonical_bytes()?,
        vector_hex(&corpus, "witness_recovery", "message_hex")?
    );
    assert_eq!(
        recovery.digest()?,
        digest_hex(&corpus, "witness_recovery", "digest_hex")?
    );
    Ok(())
}
