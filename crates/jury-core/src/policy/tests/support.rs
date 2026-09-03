fn witnessed_policy(
    vault_id: VaultId,
    genesis_fingerprint: Digest32,
    sequence: u64,
    approvers: &[TestSigner; 2],
    witnesses: &[TestSigner; 3],
    share_indexes: [u8; 3],
    item_id: ItemId,
) -> AnyResult<WitnessPolicy> {
    let approver_descriptors = approvers
        .iter()
        .map(approver_policy_descriptor)
        .collect::<AnyResult<Vec<_>>>()?;
    let witness_descriptors = witnesses
        .iter()
        .zip(share_indexes)
        .map(|(signer, share_index)| witness_policy_descriptor(share_index, signer))
        .collect::<AnyResult<Vec<_>>>()?;
    Ok(WitnessPolicy {
        schema: 1,
        witness_policy_id: WitnessPolicyId::from_bytes([0x71; 32])?,
        revision: 1,
        predecessor_policy_digest: FixedBytes::new([0; 32]),
        vault_id,
        genesis_fingerprint,
        vault_policy_sequence: sequence,
        vault_policy_hash: FixedBytes::new([0x72; 32]),
        construction: 1,
        suite: 1,
        approver_descriptors,
        witness_descriptors,
        witness_threshold: 2,
        operation_rules: vec![OperationRule {
            operation: WitnessOperation::ReadStdout,
            eligible_approver_ids: approvers.iter().map(TestSigner::principal_id).collect(),
            approval_threshold: 2,
            allowed_request_lifetime_ms: 300_000,
            max_timeout_ms: 30_000,
            max_output_bytes: 4_096,
            max_target_count: 1,
            required_platform_assurance: PlatformAssurance::NormalizedPathOnly,
            automatic_read_targets: Vec::new(),
        }],
        review_label_set_digest: FixedBytes::new(*item_id.as_bytes()),
        direct_fallback: false,
    })
}

fn approver_policy_descriptor(signer: &TestSigner) -> AnyResult<ApproverPolicyDescriptor> {
    let mut descriptor = ApproverPolicyDescriptor {
        schema: 1,
        approver_id: signer.principal_id(),
        signing_public_key: signer.descriptor.verification_public_key.clone(),
        signing_key_fingerprint: signing_fingerprint(
            2,
            signer.principal_id(),
            &signer.descriptor.verification_public_key,
        ),
        signing_key_epoch: 1,
        status: DescriptorStatus::Active,
        approval_mode: ApprovalMode::Human,
        allowed_operations: vec![WitnessOperation::ReadStdout],
        created_at_ms: 1_700_000_000_000,
        self_signature: Signature64::new([0; 64]),
    };
    descriptor.self_signature = Signature64::new(
        signer
            .key
            .sign(&descriptor.self_signature_preimage()?)
            .to_bytes(),
    );
    Ok(descriptor)
}

fn witness_policy_descriptor(
    share_index: u8,
    signer: &TestSigner,
) -> AnyResult<WitnessPolicyDescriptor> {
    let signing_public_key = signer.descriptor.verification_public_key.clone();
    let mut descriptor = WitnessPolicyDescriptor {
        schema: 1,
        witness_id: signer.principal_id(),
        share_index,
        signing_public_key: signing_public_key.clone(),
        signing_key_fingerprint: signing_fingerprint(3, signer.principal_id(), &signing_public_key),
        signing_key_epoch: 1,
        contribution_public_key: signer.descriptor.recipient_public_key.clone(),
        contribution_key_fingerprint: recipient_public_key_fingerprint(
            &signer.descriptor.recipient_public_key,
        ),
        contribution_key_epoch: 1,
        status: DescriptorStatus::Active,
        created_at_ms: 1_700_000_000_000,
        self_signature: Signature64::new([0; 64]),
    };
    descriptor.self_signature = Signature64::new(
        signer
            .key
            .sign(&descriptor.self_signature_preimage()?)
            .to_bytes(),
    );
    Ok(descriptor)
}

fn signing_fingerprint(
    role: u8,
    principal_id: PrincipalId,
    public_key: &VerificationPublicKey32,
) -> Digest32 {
    let mut preimage = b"jury-witness-v1/signing-key/fingerprint\0\0\x01".to_vec();
    preimage.push(role);
    preimage.extend_from_slice(principal_id.as_bytes());
    preimage.extend_from_slice(&1_u64.to_be_bytes());
    preimage.extend_from_slice(public_key.as_bytes());
    FixedBytes::new(Sha256::digest(preimage).into())
}

#[allow(clippy::too_many_arguments)]
fn witnessed_state(
    vault_id: VaultId,
    genesis_fingerprint: Digest32,
    item_id: ItemId,
    sequence: u64,
    policy_id: WitnessPolicyId,
    policy_digest: Digest32,
    witnesses: &[TestSigner; 3],
    share_indexes: [u8; 3],
    mode: ItemAccessMode,
    marker_base: u8,
) -> AnyResult<WitnessedStateV1> {
    let mut slots = Vec::new();
    for (role_index, content_role) in [ContentRole::Descriptor, ContentRole::Body]
        .into_iter()
        .enumerate()
    {
        let marker = u8::try_from(role_index)?
            .saturating_mul(8)
            .saturating_add(marker_base);
        let slot_id = SlotId::from_bytes([marker; 32])?;
        let seal_id = RevisionSealId::from_bytes([marker.saturating_add(2); 32])?;
        let mut capsules = Vec::new();
        for (witness, share_index) in witnesses.iter().zip(share_indexes) {
            let mut capsule = WitnessShareCapsuleV1 {
                capsule_schema: 1,
                protocol: 1,
                construction: 1,
                vault_id,
                genesis_fingerprint: genesis_fingerprint.clone(),
                item_id,
                key_epoch: 1,
                item_access_mode: mode,
                slot_id,
                content_role,
                revision: 1,
                revision_seal_id: seal_id,
                vault_policy_sequence: sequence,
                witness_policy_id: policy_id,
                witness_policy_revision: 1,
                witness_policy_digest: policy_digest.clone(),
                threshold: 2,
                member_count: 3,
                witness_id: witness.principal_id(),
                contribution_key_fingerprint: recipient_public_key_fingerprint(
                    &witness.descriptor.recipient_public_key,
                ),
                share_index,
                context_digest: FixedBytes::new([0; 32]),
                share_commitment: FixedBytes::new([share_index; 32]),
                encapsulation: Encapsulation1120::new([marker.saturating_add(share_index); 1120]),
                ciphertext: ShareCiphertext49::new([marker.wrapping_add(share_index); 49]),
            };
            capsule.context_digest = capsule.recomputed_context_digest();
            capsules.push(capsule);
        }
        let mut slot = WitnessedSlotV1 {
            slot_schema: 1,
            slot_algorithm: 2,
            suite: 1,
            protocol: 1,
            construction: 1,
            vault_id,
            genesis_fingerprint: genesis_fingerprint.clone(),
            item_id,
            key_epoch: 1,
            item_access_mode: mode,
            slot_id,
            content_role,
            revision: 1,
            revision_seal_id: seal_id,
            vault_policy_sequence: sequence,
            witness_policy_id: policy_id,
            witness_policy_revision: 1,
            witness_policy_digest: policy_digest.clone(),
            threshold: 2,
            member_count: 3,
            capsules,
            capsule_set_digest: FixedBytes::new([0; 32]),
        };
        slot.capsule_set_digest = slot.recomputed_capsule_set_digest()?;
        slots.push(slot);
    }
    let mut state = WitnessedStateV1 {
        slots,
        digest: FixedBytes::new([0; 32]),
    };
    state.digest = state.recomputed_digest()?;
    Ok(state)
}

fn descriptor_metadata(epoch: u64, revision: u64, marker: u8) -> AnyResult<DescriptorMetadataV1> {
    Ok(DescriptorMetadataV1 {
        revision,
        revision_seal_id: RevisionSealId::from_bytes([marker; 32])?,
        nonce: Nonce12::new([marker.wrapping_add(1); 12]),
        ciphertext_length: 272,
        ciphertext_digest: Digest32::new([marker.wrapping_add(2); 32]),
        plaintext_schema: 1,
        key_epoch: epoch,
    })
}

#[allow(clippy::too_many_arguments)]
fn direct_slots(
    vault_id: jury_protocol::vault_v1::VaultId,
    item_id: ItemId,
    principal_id: PrincipalId,
    epoch: u64,
    sequence: u64,
    role: AccessRole,
    mode: ItemAccessMode,
    recipient_fingerprint: Digest32,
) -> AnyResult<Vec<DirectSlotV1>> {
    [ContentRole::Descriptor, ContentRole::Body]
        .into_iter()
        .enumerate()
        .map(|(index, content_role)| {
            let role_marker = u8::try_from(index)?.wrapping_add(0x70);
            let encapsulation_marker =
                principal_id.as_bytes()[0].wrapping_add(u8::try_from(index)?);
            Ok(DirectSlotV1 {
                slot_schema: 1,
                slot_algorithm: 1,
                suite: 1,
                kem: 0x647a,
                kdf: 1,
                aead: 3,
                vault_id,
                item_id,
                key_epoch: epoch,
                content_role,
                revision: 1,
                revision_seal_id: RevisionSealId::from_bytes([role_marker; 32])?,
                recipient_principal_id: principal_id,
                policy_sequence: sequence,
                recipient_public_key_fingerprint: recipient_fingerprint.clone(),
                access_role: role,
                item_access_mode: mode,
                encapsulation: Encapsulation1120::new([encapsulation_marker; 1120]),
                ciphertext: DirectCiphertext48::new([encapsulation_marker; 48]),
            })
        })
        .collect()
}

fn sort_direct_slots(slots: &mut [DirectSlotV1]) {
    slots.sort_by(|left, right| {
        (
            left.content_role,
            left.recipient_principal_id,
            left.canonical_bytes(),
        )
            .cmp(&(
                right.content_role,
                right.recipient_principal_id,
                right.canonical_bytes(),
            ))
    });
}
