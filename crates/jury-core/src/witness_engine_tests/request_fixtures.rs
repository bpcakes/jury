fn fixture_policy(
    fixture_principals: &FixturePrincipals,
    witness_policy: &WitnessPolicy,
    witness_policy_digest: &Digest32,
) -> TestResult<PolicyState> {
    let witnessed_state = fixture_witnessed_state(
        &fixture_principals.witness_policy_descriptors,
        witness_policy_digest,
    )?;
    let principals = std::iter::once(fixture_principals.owner_descriptor.clone())
        .chain(fixture_principals.approver_descriptors.iter().cloned())
        .chain(fixture_principals.witness_descriptors.iter().cloned())
        .map(|descriptor| {
            (
                descriptor.principal_id,
                PrincipalPolicyState {
                    descriptor,
                    display_label: "ExamplePrincipal".to_owned(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let principal_ids = principals.keys().copied().collect::<BTreeSet<_>>();
    let recipient_keys = principals
        .values()
        .map(|principal| principal.descriptor.recipient_public_key.clone())
        .collect::<BTreeSet<RecipientPublicKey1216>>();
    let verification_keys = principals
        .values()
        .map(|principal| principal.descriptor.verification_public_key.clone())
        .collect();
    let item_id = ItemId::from_bytes([0x03; 32])?;
    let items = [(
        item_id,
        ItemPolicyState {
            item_kind: ItemKind::Canonical,
            key_epoch: 1,
            descriptor: DescriptorMetadataV1 {
                revision: 1,
                revision_seal_id: RevisionSealId::from_bytes([0x40; 32])?,
                nonce: Nonce12::new([0x41; 12]),
                ciphertext_length: 1,
                ciphertext_digest: Digest32::new([0x42; 32]),
                plaintext_schema: 1,
                key_epoch: 1,
            },
            current_item_revision_hash: Digest32::new([0x43; 32]),
            grants: BTreeMap::new(),
            direct_slots: Vec::new(),
            witnessed_state: Some(witnessed_state),
        },
    )]
    .into_iter()
    .collect();
    Ok(PolicyState {
        suite: 1,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: Digest32::new([0x02; 32]),
        sequence: 1,
        terminal_revision_hash: Digest32::new([0x72; 32]),
        revision_hashes: vec![Digest32::new([0x02; 32]), Digest32::new([0x72; 32])],
        principals: principals.clone(),
        historical_principal_descriptors: principals
            .iter()
            .map(|(id, principal)| (*id, principal.descriptor.clone()))
            .collect(),
        historical_principal_ids: principal_ids,
        historical_recipient_keys: recipient_keys,
        historical_verification_keys: verification_keys,
        owners: [fixture_principals.owner_descriptor.principal_id]
            .into_iter()
            .collect(),
        items,
        historical_item_ids: [item_id].into_iter().collect(),
        tombstones: BTreeMap::new(),
        witness_policies: [(witness_policy_digest.clone(), witness_policy.clone())]
            .into_iter()
            .collect(),
    })
}

fn fixture_checkpoint(
    principals: &FixturePrincipals,
    witness_policy: &WitnessPolicy,
    witness_policy_digest: &Digest32,
) -> TestResult<VaultPolicyCheckpointV1> {
    let (approver_set_digest, witness_set_digest) =
        witness_policy.active_descriptor_set_digests()?;
    let mut checkpoint = VaultPolicyCheckpointV1 {
        schema: 1,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: Digest32::new([0x02; 32]),
        vault_policy_sequence: 1,
        vault_policy_hash: Digest32::new([0x02; 32]),
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: witness_policy_digest.clone(),
        witness_set_digest,
        approver_set_digest,
        review_label_set_digest: witness_policy.review_label_set_digest.clone(),
        predecessor_checkpoint_digest: Digest32::new([0; 32]),
        issued_at_ms: NOW_MS - 5_000,
        issuer_owner_id: principals.owner_descriptor.principal_id,
        issuer_key_fingerprint: signing_key_fingerprint(
            1,
            &principals.owner_descriptor.principal_id,
            1,
            &principals.owner_descriptor.verification_public_key,
        ),
        issuer_key_epoch: 1,
        signature: Signature64::new([0; 64]),
    };
    checkpoint.signature = principals
        .actors
        .owner
        .sign_validated_statement(&checkpoint.signature_preimage()?)?;
    Ok(checkpoint)
}

fn fixture_manifest(
    owner_descriptor: &PrincipalDescriptorV1,
    witness_policy_digest: &Digest32,
) -> TestResult<(ActionManifestV1, Digest32)> {
    let presentation_digest = Digest32::new([0x81; 32]);
    let approval_target = ApprovalTargetV1 {
        entries: vec![ApprovalTargetEntryV1 {
            item_id: ItemId::from_bytes([0x03; 32])?,
            field_id: None,
            presentation_commitment: Digest32::new([0x82; 32]),
        }],
        presentation_digest: presentation_digest.clone(),
    };
    let approval_target_digest = approval_target.digest()?;
    let manifest = ActionManifestV1 {
        schema: 1,
        request_id: RequestId::from_bytes([0x07; 32])?,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: Digest32::new([0x02; 32]),
        item_id: ItemId::from_bytes([0x03; 32])?,
        key_epoch: 1,
        item_access_mode: ItemAccessMode::WitnessedOnly,
        slot_id: SlotId::from_bytes([0x05; 32])?,
        content_role: ContentRole::Body,
        revision: 1,
        revision_seal_id: RevisionSealId::from_bytes([0x06; 32])?,
        vault_policy_sequence: 1,
        vault_policy_hash: Digest32::new([0x02; 32]),
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: witness_policy_digest.clone(),
        requester_principal_id: owner_descriptor.principal_id,
        requested_access_role: AccessRole::Owner,
        operation: WitnessOperationV1::ReadStdout,
        operation_context: OperationContextV1::ReadStdout,
        approval_target,
        approval_target_digest: approval_target_digest.clone(),
        executable_identity: None,
        arguments: Vec::new(),
        working_directory_commitment: None,
        environment_injections: Vec::new(),
        stdin_target: None,
        stdin_mode: StdinModeV1::None,
        output_sink: OutputSinkV1::Stdout,
        output_sink_commitment: None,
        platform_assurance: PlatformAssuranceV1::NormalizedPathOnly,
        timeout_ms: 30_000,
        output_limit_bytes: 4_096,
        issued_at_ms: NOW_MS - 1_000,
        not_before_ms: None,
        expires_at_ms: NOW_MS + 299_000,
        presentation_digest: presentation_digest.clone(),
    };
    Ok((manifest, presentation_digest))
}

fn fixture_request(
    principals: &FixturePrincipals,
    checkpoint: &VaultPolicyCheckpointV1,
    manifest: &ActionManifestV1,
    witness_policy_digest: Digest32,
) -> TestResult<jury_protocol::witness_v1::WitnessRequestV1> {
    let intended_witness_set = principals
        .witness_policy_descriptors
        .iter()
        .map(|descriptor| IntendedWitnessV1 {
            witness_id: descriptor.witness_id,
            share_index: descriptor.share_index,
            signing_key_fingerprint: descriptor.signing_key_fingerprint.clone(),
            contribution_key_fingerprint: descriptor.contribution_key_fingerprint.clone(),
        })
        .collect();
    let approval_target_digest = manifest.approval_target_digest.clone();
    let mut request = jury_protocol::witness_v1::WitnessRequestV1 {
        schema: 1,
        protocol_version: 1,
        construction: 1,
        request_id: RequestId::from_bytes([0x07; 32])?,
        client_nonce: RequestId::from_bytes([0x75; 32])?,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: Digest32::new([0x02; 32]),
        item_id: ItemId::from_bytes([0x03; 32])?,
        key_epoch: 1,
        item_access_mode: ItemAccessMode::WitnessedOnly,
        slot_id: SlotId::from_bytes([0x05; 32])?,
        content_role: ContentRole::Body,
        revision: 1,
        revision_seal_id: RevisionSealId::from_bytes([0x06; 32])?,
        vault_policy_sequence: 1,
        vault_policy_hash: Digest32::new([0x02; 32]),
        policy_checkpoint_digest: checkpoint.digest()?,
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest,
        requester_principal_id: principals.owner_descriptor.principal_id,
        requester_signing_key_fingerprint: signing_key_fingerprint(
            1,
            &principals.owner_descriptor.principal_id,
            1,
            &principals.owner_descriptor.verification_public_key,
        ),
        requester_signing_key_epoch: 1,
        requested_access_role: AccessRole::Owner,
        operation: WitnessOperationV1::ReadStdout,
        approval_target_digest,
        action_manifest_digest: manifest.digest()?,
        workload_digest: manifest.workload_digest()?,
        issued_at_ms: manifest.issued_at_ms,
        not_before_ms: None,
        expires_at_ms: manifest.expires_at_ms,
        request_session_public_key: principals.owner_descriptor.recipient_public_key.clone(),
        request_session_key_fingerprint: recipient_public_key_fingerprint(
            &principals.owner_descriptor.recipient_public_key,
        ),
        intended_witness_set,
        client_signature: Signature64::new([0; 64]),
    };
    request.client_signature = principals
        .actors
        .owner
        .sign_validated_statement(&request.signature_preimage()?)?;
    Ok(request)
}

fn fixture_approvals(
    principals: &FixturePrincipals,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    presentation_digest: &Digest32,
) -> TestResult<[ApprovalDecisionV1; 2]> {
    let request_digest = request.digest()?;
    let intended_witness_set_digest = request.intended_witness_set_digest()?;
    let mut approvals = Vec::new();
    for (index, descriptor) in principals.approver_policy_descriptors.iter().enumerate() {
        let mut approval = ApprovalDecisionV1 {
            schema: 1,
            approval_id: ApprovalId::from_bytes([0x90 + index as u8; 32])?,
            request_id: request.request_id,
            request_digest: request_digest.clone(),
            action_manifest_digest: manifest.digest()?,
            presentation_digest: presentation_digest.clone(),
            witness_policy_id: request.witness_policy_id,
            witness_policy_revision: request.witness_policy_revision,
            witness_policy_digest: request.witness_policy_digest.clone(),
            approver_id: descriptor.approver_id,
            approver_key_fingerprint: descriptor.signing_key_fingerprint.clone(),
            approver_key_epoch: 1,
            approval_mode: ApprovalModeV1::Human,
            decision: ApprovalDecisionKindV1::Approve,
            reason: WitnessReasonV1::None,
            issued_at_ms: NOW_MS,
            not_before_ms: None,
            expires_at_ms: request.expires_at_ms,
            nonce: ApprovalId::from_bytes([0xa0 + index as u8; 32])?,
            intended_witness_set_digest: intended_witness_set_digest.clone(),
            signature: Signature64::new([0; 64]),
        };
        approval.signature = principals.actors.approvers[index]
            .sign_validated_approval(&approval.signature_preimage()?)?;
        approvals.push(approval);
    }
    approvals
        .try_into()
        .map_err(|_| "approval fixture count changed".into())
}

fn fixture() -> TestResult<Fixture> {
    let principals = fixture_principals()?;
    let witness_policy = fixture_witness_policy(&principals)?;
    let witness_policy_digest = witness_policy.digest()?;
    let policy = fixture_policy(&principals, &witness_policy, &witness_policy_digest)?;
    let checkpoint = fixture_checkpoint(&principals, &witness_policy, &witness_policy_digest)?;
    let (manifest, presentation_digest) =
        fixture_manifest(&principals.owner_descriptor, &witness_policy_digest)?;
    let request = fixture_request(&principals, &checkpoint, &manifest, witness_policy_digest)?;
    let approvals = fixture_approvals(&principals, &request, &manifest, &presentation_digest)?;
    Ok(Fixture {
        actors: principals.actors,
        policy,
        checkpoint,
        request,
        manifest,
        approvals,
    })
}

fn empty_store(fixture: &Fixture) -> MemoryStore {
    MemoryStore {
        state: PersistedWitnessState::empty(fixture.actors.witnesses[0].principal_id()),
        fail_before_commit_once: false,
        fail_after_commit_once: false,
        fail_mark_once: false,
    }
}

fn register_fixture(
    fixture: &Fixture,
    store: &mut MemoryStore,
    anchor: &mut MemoryAnchor,
    clock: &FixedClock,
    random: &mut TestRandom,
) -> TestResult {
    let mut engine = WitnessEngine::new(&fixture.actors.witnesses[0], store, anchor, clock, random);
    engine.register_vault(
        &fixture.policy,
        RegistrationBytes::new(vec![1, 2, 3])?,
        fixture.checkpoint.clone(),
        PolicyMaterialBytes::new(vec![4, 5, 6])?,
    )?;
    Ok(())
}

fn cancellation(fixture: &Fixture) -> TestResult<RequestCancellationV1> {
    let mut cancellation = RequestCancellationV1 {
        schema: 1,
        cancellation_id: CancellationId::from_bytes([0xc1; 32])?,
        request_signature_preimage: RequestBytes::new(fixture.request.signature_preimage()?)?,
        client_signature: fixture.request.client_signature.clone(),
        request_id: fixture.request.request_id,
        request_digest: fixture.request.digest()?,
        canceller_id: fixture.request.requester_principal_id,
        canceller_key_fingerprint: fixture.request.requester_signing_key_fingerprint.clone(),
        canceller_key_epoch: 1,
        canceller_role: CancellerRoleV1::OriginalRequester,
        issued_at_ms: NOW_MS,
        reason: WitnessReasonV1::Cancelled,
        nonce: CancellationId::from_bytes([0xc2; 32])?,
        signature: Signature64::new([0; 64]),
    };
    cancellation.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&cancellation.signature_preimage()?)?;
    Ok(cancellation)
}

fn denying_approval(fixture: &Fixture, index: usize) -> TestResult<ApprovalDecisionV1> {
    let mut denial = fixture.approvals[index].clone();
    denial.decision = ApprovalDecisionKindV1::Deny;
    denial.reason = WitnessReasonV1::PolicyDenied;
    denial.signature =
        fixture.actors.approvers[index].sign_validated_approval(&denial.signature_preimage()?)?;
    Ok(denial)
}

fn resign_approval(
    fixture: &Fixture,
    index: usize,
    approval: &mut ApprovalDecisionV1,
) -> TestResult {
    approval.signature =
        fixture.actors.approvers[index].sign_validated_approval(&approval.signature_preimage()?)?;
    Ok(())
}

fn assert_approval_refused_without_state_change(
    fixture: &Fixture,
    approval: ApprovalDecisionV1,
    expected: WitnessReasonV1,
    seed: u64,
) -> TestResult {
    let mut store = empty_store(fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: seed,
    };
    let mut random = TestRandom::new(seed);
    register_fixture(fixture, &mut store, &mut anchor, &clock, &mut random)?;
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
            engine
                .decide(
                    &fixture.policy,
                    &fixture.request,
                    &fixture.manifest,
                    &[approval],
                )
                .map_err(WitnessEngineError::reason),
            Err(expected)
        );
    }
    assert_eq!(store.state.logical.state_generation, generation);
    assert_eq!(anchor.publishes, publish_count);
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
    Ok(())
}

fn signed_time_variant(
    fixture: &Fixture,
    issued_at_ms: u64,
    not_before_ms: Option<u64>,
    expires_at_ms: u64,
) -> TestResult<(
    jury_protocol::witness_v1::WitnessRequestV1,
    ActionManifestV1,
)> {
    let mut manifest = fixture.manifest.clone();
    manifest.issued_at_ms = issued_at_ms;
    manifest.not_before_ms = not_before_ms;
    manifest.expires_at_ms = expires_at_ms;
    let mut request = fixture.request.clone();
    request.issued_at_ms = issued_at_ms;
    request.not_before_ms = not_before_ms;
    request.expires_at_ms = expires_at_ms;
    request.action_manifest_digest = manifest.digest()?;
    request.workload_digest = manifest.workload_digest()?;
    request.client_signature = fixture
        .actors
        .owner
        .sign_validated_statement(&request.signature_preimage()?)?;
    Ok((request, manifest))
}

fn reserve_once(
    fixture: &Fixture,
    request: jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    wall_ms: u64,
    seed: u64,
) -> Result<WitnessProgress, WitnessEngineError> {
    let mut store = empty_store(fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms,
        monotonic_ms: seed,
    };
    let mut random = TestRandom::new(seed);
    register_fixture(fixture, &mut store, &mut anchor, &clock, &mut random)
        .map_err(|_| WitnessEngineError::store_unavailable())?;
    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut store,
        &mut anchor,
        &clock,
        &mut random,
    );
    engine.reserve(&fixture.policy, request, manifest)
}

fn descendant_policy_and_checkpoint(
    fixture: &Fixture,
) -> TestResult<(PolicyState, VaultPolicyCheckpointV1)> {
    descendant_policy_and_checkpoint_at_sequence(fixture, None, 2)
}

fn descendant_policy_and_checkpoint_with_replacement(
    fixture: &Fixture,
    replacement: Option<&WitnessIdentity>,
) -> TestResult<(PolicyState, VaultPolicyCheckpointV1)> {
    descendant_policy_and_checkpoint_at_sequence(fixture, replacement, 2)
}

fn descendant_policy_and_checkpoint_at_sequence(
    fixture: &Fixture,
    replacement: Option<&WitnessIdentity>,
    next_sequence: u64,
) -> TestResult<(PolicyState, VaultPolicyCheckpointV1)> {
    let prior_digest = fixture.request.witness_policy_digest.clone();
    let prior = fixture
        .policy
        .witness_policy(&prior_digest)
        .ok_or("missing prior witness policy")?;
    let mut next_witness_policy = prior.clone();
    next_witness_policy.revision = 2;
    next_witness_policy.predecessor_policy_digest = prior_digest;
    next_witness_policy.vault_policy_sequence = next_sequence;
    let predecessor_hash = if next_sequence == 2 { 0x72 } else { 0x74 };
    next_witness_policy.vault_policy_hash = Digest32::new([predecessor_hash; 32]);
    if let Some(replacement) = replacement {
        next_witness_policy.witness_descriptors[0] = witness_policy_descriptor(replacement, 1)?;
    }
    next_witness_policy.validate()?;
    let next_digest = next_witness_policy.digest()?;

    let mut capsule_random = TestRandom::new(0x8888_9999_aaaa_bbbb);
    let next_capsules = next_witness_policy
        .witness_descriptors
        .iter()
        .map(|descriptor| {
            witness_capsule(
                descriptor,
                CapsuleScope {
                    policy_digest: &next_digest,
                    vault_policy_sequence: next_sequence,
                    witness_policy_revision: 2,
                    key_epoch: 2,
                    revision: 2,
                    revision_seal_id: RevisionSealId::from_bytes([0x16; 32])?,
                },
                &mut capsule_random,
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    let mut next_slot = fixture
        .policy
        .item(&fixture.request.item_id)
        .and_then(|item| item.witnessed_state.as_ref())
        .and_then(|state| state.slots.first())
        .cloned()
        .ok_or("missing current witnessed slot")?;
    next_slot.key_epoch = 2;
    next_slot.revision = 2;
    next_slot.revision_seal_id = RevisionSealId::from_bytes([0x16; 32])?;
    next_slot.vault_policy_sequence = next_sequence;
    next_slot.witness_policy_revision = 2;
    next_slot.witness_policy_digest = next_digest.clone();
    next_slot.capsules = next_capsules;
    next_slot.capsule_set_digest = next_slot.recomputed_capsule_set_digest()?;
    let next_witnessed_state = WitnessedStateV1 {
        slots: vec![next_slot.clone()],
        digest: witnessed_slot_set_digest(std::slice::from_ref(&next_slot))?,
    };

    let mut next_policy = fixture.policy.clone();
    next_policy.sequence = next_sequence;
    next_policy.terminal_revision_hash = Digest32::new([0x74; 32]);
    next_policy
        .revision_hashes
        .push(next_policy.terminal_revision_hash.clone());
    if let Some(replacement) = replacement {
        let replacement = replacement.public_descriptor()?;
        let principal = next_policy
            .principals
            .get_mut(&replacement.principal_id)
            .ok_or("missing replaced witness principal")?;
        principal.descriptor = replacement.clone();
        next_policy
            .historical_recipient_keys
            .insert(replacement.recipient_public_key);
        next_policy
            .historical_verification_keys
            .insert(replacement.verification_public_key);
    }
    let item = next_policy
        .items
        .get_mut(&fixture.request.item_id)
        .ok_or("missing item")?;
    item.key_epoch = 2;
    item.witnessed_state = Some(next_witnessed_state);
    next_policy
        .witness_policies
        .insert(next_digest.clone(), next_witness_policy.clone());

    let (approver_set_digest, witness_set_digest) =
        next_witness_policy.active_descriptor_set_digests()?;
    let owner = fixture.actors.owner.public_descriptor()?;
    let mut checkpoint = VaultPolicyCheckpointV1 {
        schema: 1,
        vault_id: next_policy.vault_id(),
        genesis_fingerprint: next_policy.genesis_fingerprint().clone(),
        vault_policy_sequence: next_sequence,
        vault_policy_hash: Digest32::new([predecessor_hash; 32]),
        witness_policy_id: next_witness_policy.witness_policy_id,
        witness_policy_revision: 2,
        witness_policy_digest: next_digest,
        witness_set_digest,
        approver_set_digest,
        review_label_set_digest: next_witness_policy.review_label_set_digest,
        predecessor_checkpoint_digest: fixture.checkpoint.digest()?,
        issued_at_ms: NOW_MS,
        issuer_owner_id: owner.principal_id,
        issuer_key_fingerprint: signing_key_fingerprint(
            1,
            &owner.principal_id,
            1,
            &owner.verification_public_key,
        ),
        issuer_key_epoch: 1,
        signature: Signature64::new([0; 64]),
    };
    checkpoint.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&checkpoint.signature_preimage()?)?;
    Ok((next_policy, checkpoint))
}
