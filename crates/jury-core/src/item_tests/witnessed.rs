#[test]
fn witnessed_only_automatic_foreground_session_is_revision_scoped()
-> Result<(), Box<dyn std::error::Error>> {
    let protection = ProtectionPolicy::EmergencyAllowDegraded;
    let passphrase = ProtectedMemory::initialize(15, protection, |output| {
        output.copy_from_slice(b"ExamplePass1234");
        Ok::<usize, ()>(output.len())
    })?;
    let mut identities = IdentityCreator::new();
    let created = identities.create(
        PrincipalKind::Human,
        KdfProfile::PortableV1,
        1,
        &passphrase,
        |_| false,
    )?;
    let UnlockedIdentity::VaultPrincipal(owner) = unlock(&created.file, &passphrase)? else {
        return Err("owner identity role differs".into());
    };
    let mut policies = PolicyCreator::new();
    let mut created_policy = policies.create(&owner, 1, |_| false)?;
    let (mut witness_policy, _, _) = crate::policy::witness_tests::frozen_policy()?;
    let expected_item_id = ItemId::from_bytes([0x80; 32])?;
    witness_policy.operation_rules[0].approval_threshold = 0;
    witness_policy.operation_rules[0].automatic_read_targets = vec![AutomaticReadTarget {
        item_id: expected_item_id,
        field_id: None,
    }];
    witness_policy.review_label_set_digest = owner_review_label_set_digest(&[])?;

    let mut witness_private_keys = Vec::new();
    let mut additions = Vec::new();
    for (index, descriptor) in witness_policy.witness_descriptors.iter().enumerate() {
        let marker = 0x61_u8.saturating_add(u8::try_from(index)?);
        let (private, public) =
            crypto::generate_recipient_keypair(protection, &mut FillByte(marker))?;
        assert!(public == descriptor.contribution_public_key);
        witness_private_keys.push(private);
        additions.push(principal_add(
            descriptor.witness_id,
            PrincipalKind::Witness,
            public,
            0x31_u8.saturating_add(u8::try_from(index)?),
        )?);
    }
    for (index, descriptor) in witness_policy.approver_descriptors.iter().enumerate() {
        let (_, recipient) = crypto::generate_recipient_keypair(
            protection,
            &mut FillByte(0x71_u8.saturating_add(u8::try_from(index)?)),
        )?;
        additions.push(principal_add(
            descriptor.approver_id,
            PrincipalKind::Approver,
            recipient,
            0x21_u8.saturating_add(u8::try_from(index)?),
        )?);
    }
    additions.sort_by_key(|operation| match operation {
        PolicyOperationV1::PrincipalAdd { descriptor, .. } => descriptor.principal_id,
        _ => owner.principal_id(),
    });
    let added = created_policy
        .state
        .prepare_revision(&owner, 2, additions)?;
    created_policy.journal.revisions.push(added.revision);
    witness_policy.vault_id = created_policy.state.vault_id();
    witness_policy.genesis_fingerprint = created_policy.state.genesis_fingerprint().clone();
    witness_policy.vault_policy_sequence = 2;
    witness_policy.vault_policy_hash = added.state.terminal_revision_hash().clone();
    let witness_digest = witness_policy.digest()?;
    let policy = crate::policy::replay_policy_with_witness_policies(
        &created_policy.journal,
        std::slice::from_ref(&witness_policy),
    )?;

    let descriptor = ItemDescriptorV1::new("ExampleWitnessedItem".to_owned())?;
    let state = ItemStateV1 {
        plaintext_schema: 1,
        fields: Vec::new(),
    };
    let mut items = ItemCreator::from_source(IncrementingRandom(0x80), protection);
    let created_item = items.prepare_create(
        &policy,
        &owner,
        3,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: descriptor.clone(),
            state: state.clone(),
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: Vec::new(),
                witness_policy_digest: Some(witness_digest.clone()),
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    assert_eq!(created_item.envelope.item_id, expected_item_id);
    let witnessed = created_item
        .policy
        .revision
        .operations
        .iter()
        .find_map(|operation| match operation {
            PolicyOperationV1::ItemCreate {
                direct_slots,
                witnessed_state,
                ..
            } if direct_slots.is_empty() => witnessed_state.as_ref(),
            _ => None,
        })
        .ok_or("witnessed-only slots absent")?;
    assert!(witnessed.has_item_quorum_claim(0));
    let descriptor_secret =
        reconstruct_slot_secret(&witnessed.slots[0], &witness_private_keys, protection)?;
    let body_secret =
        reconstruct_slot_secret(&witnessed.slots[1], &witness_private_keys, protection)?;
    assert!(open_descriptor(&created_item.envelope, &descriptor_secret)? == descriptor);
    assert!(open_body(&created_item.envelope, &body_secret)? == state);
    assert!(matches!(
        open_body(&created_item.envelope, &descriptor_secret),
        Err(error) if error.kind() == ItemErrorKind::AuthenticationFailed
    ));

    let prior_authorization = assert_witnessed_provider_round_trip(WitnessedProviderFixture {
        owner: &owner,
        created_item: &created_item,
        expected_body: &state,
        witnessed,
        witness_private_keys: &witness_private_keys,
        witness_policy: &witness_policy,
        witness_digest: &witness_digest,
        request_random_start: 0xa0,
    })?;

    let partial_secret = reconstruct_slot_secret_with_count(
        &witnessed.slots[1],
        &witness_private_keys,
        protection,
        1,
    );
    assert!(partial_secret.is_err());

    let mixed = items.prepare_create(
        &policy,
        &owner,
        3,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: descriptor.clone(),
            state: state.clone(),
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![owner.principal_id()],
                witness_policy_digest: Some(witness_digest.clone()),
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    let (mixed_direct, mixed_witnessed) = mixed
        .policy
        .revision
        .operations
        .iter()
        .find_map(|operation| match operation {
            PolicyOperationV1::ItemCreate {
                direct_slots,
                witnessed_state: Some(witnessed_state),
                ..
            } => Some((direct_slots, witnessed_state)),
            _ => None,
        })
        .ok_or("mixed slots absent")?;
    assert!(!mixed_direct.is_empty());
    assert!(!mixed_witnessed.has_item_quorum_claim(mixed_direct.len()));

    let mut duplicate_operation = created_item.policy.revision.operations[0].clone();
    if let PolicyOperationV1::ItemCreate {
        witnessed_state: Some(state),
        ..
    } = &mut duplicate_operation
    {
        state.slots[0].capsules[1] = state.slots[0].capsules[0].clone();
        state.slots[0].capsule_set_digest = state.slots[0].recomputed_capsule_set_digest()?;
        state.digest = state.recomputed_digest()?;
    }
    assert!(
        jury_protocol::vault_v1::validate_policy_operation_context(
            &duplicate_operation,
            2,
            &policy.vault_id(),
            policy.genesis_fingerprint(),
        )
        .is_err()
    );

    let mut next_witness_policy = witness_policy.clone();
    next_witness_policy.revision = 2;
    next_witness_policy.predecessor_policy_digest = witness_digest;
    next_witness_policy.vault_policy_sequence = 3;
    next_witness_policy.vault_policy_hash =
        created_item.policy.state.terminal_revision_hash().clone();
    let next_witness_digest = next_witness_policy.digest()?;
    let mut journal = created_policy.journal.clone();
    journal.revisions.push(created_item.policy.revision.clone());
    let rekey_policy = crate::policy::replay_policy_with_witness_policies(
        &journal,
        &[witness_policy, next_witness_policy.clone()],
    )?;
    let mut inventory = ItemArtifactInventory::default();
    inventory
        .revision_seal_ids
        .insert(created_item.envelope.descriptor.revision_seal_id);
    inventory
        .revision_seal_ids
        .insert(created_item.envelope.current_revision.revision_seal_id);
    inventory
        .nonces
        .insert(created_item.envelope.descriptor.nonce.clone());
    inventory
        .nonces
        .insert(created_item.envelope.current_revision.nonce.clone());
    inventory
        .slot_ids
        .extend(witnessed.slots.iter().map(|slot| slot.slot_id));
    let rekeyed = items.prepare_rekey(
        &rekey_policy,
        &owner,
        4,
        &created_item.envelope,
        RekeyedItem {
            descriptor,
            state: state.clone(),
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: Vec::new(),
                witness_policy_digest: Some(next_witness_digest.clone()),
            },
            principal_replacement: None,
            principal_registration: None,
            owner_change: None,
        },
        &inventory,
    )?;
    let replacement = rekeyed
        .policy
        .revision
        .operations
        .iter()
        .find_map(|operation| match operation {
            PolicyOperationV1::ItemSlotsReplace {
                witnessed_state: Some(state),
                ..
            } => Some(state),
            _ => None,
        })
        .ok_or("witnessed replacement absent")?;
    let next_body_secret =
        reconstruct_slot_secret(&replacement.slots[1], &witness_private_keys, protection)?;
    assert!(matches!(
        open_body(&rekeyed.envelope, &body_secret),
        Err(error) if error.kind() == ItemErrorKind::AuthenticationFailed
    ));
    assert!(open_body(&rekeyed.envelope, &next_body_secret)? == state);

    assert_prior_witnessed_authorization_is_revision_scoped(
        &prior_authorization,
        &rekeyed.policy.state,
        &rekeyed.envelope,
        owner.principal_id(),
    )?;
    assert_fresh_witnessed_authorization(
        &prior_authorization,
        WitnessedProviderFixture {
            owner: &owner,
            created_item: &rekeyed,
            expected_body: &state,
            witnessed: replacement,
            witness_private_keys: &witness_private_keys,
            witness_policy: &next_witness_policy,
            witness_digest: &next_witness_digest,
            request_random_start: 0xb0,
        },
    )?;
    Ok(())
}

fn principal_add(
    principal_id: PrincipalId,
    kind: PrincipalKind,
    recipient_public_key: RecipientPublicKey1216,
    signing_seed: u8,
) -> Result<PolicyOperationV1, Box<dyn std::error::Error>> {
    let seed = [signing_seed; 32];
    let mut descriptor = jury_protocol::vault_v1::PrincipalDescriptorV1 {
        descriptor_version: 1,
        principal_id,
        principal_kind: kind,
        recipient_public_key,
        verification_public_key: crypto::verification_public_key_bytes(&seed)?,
        self_signature: Signature64::new([0; 64]),
    };
    descriptor.self_signature = crypto::sign_bytes(&seed, &descriptor.self_signature_preimage()?)?;
    Ok(PolicyOperationV1::PrincipalAdd {
        descriptor,
        display_label: format!("Example{signing_seed}"),
        registration_proof_digest: FixedBytes::new([signing_seed; 32]),
    })
}

struct WitnessedProviderFixture<'a> {
    owner: &'a VaultPrincipalIdentity,
    created_item: &'a PreparedItemMutation,
    expected_body: &'a ItemStateV1,
    witnessed: &'a WitnessedStateV1,
    witness_private_keys: &'a [ProtectedMemory],
    witness_policy: &'a WitnessPolicy,
    witness_digest: &'a Digest32,
    request_random_start: u8,
}

struct WitnessedRoundTrip {
    checkpoint: VaultPolicyCheckpointV1,
    prepared: PreparedWitnessRequest,
    responses: Vec<WitnessResponseV1>,
}

fn assert_fresh_witnessed_authorization(
    prior: &WitnessedRoundTrip,
    fixture: WitnessedProviderFixture<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let next = assert_witnessed_provider_round_trip(fixture)?;
    assert_ne!(
        prior.prepared.request.digest()?,
        next.prepared.request.digest()?
    );
    assert_ne!(
        prior.prepared.session.public_key(),
        next.prepared.session.public_key()
    );
    Ok(())
}

fn assert_prior_witnessed_authorization_is_revision_scoped(
    authorization: &WitnessedRoundTrip,
    policy: &PolicyState,
    envelope: &ItemEnvelopeV1,
    principal_id: PrincipalId,
) -> Result<(), Box<dyn std::error::Error>> {
    let target = RevisionAccessTarget::current(
        policy,
        envelope,
        principal_id,
        ContentRole::Body,
        Capability::Read,
    )?;
    let callback_called = Cell::new(false);
    let mut provider = WitnessedItemAccessProvider::new(
        &authorization.checkpoint,
        &authorization.prepared.request,
        &authorization.prepared.manifest,
        &authorization.responses,
        &authorization.prepared.session,
        1_800_000_000_003,
    );
    let result = provider.access_revision(
        RevisionAccessRequest {
            policy,
            envelope,
            target,
            capability: Capability::Read,
            cancellation: &NeverCancelled,
        },
        |_| {
            callback_called.set(true);
            Ok::<(), ()>(())
        },
    );
    assert!(matches!(
        result,
        Err(ItemAccessError::Provider(error))
            if matches!(
                error.kind(),
                AccessProviderErrorKind::InvalidRequest
                    | AccessProviderErrorKind::StalePolicy
                    | AccessProviderErrorKind::InvalidSlot
            )
    ));
    assert!(!callback_called.get());
    Ok(())
}

fn assert_witnessed_provider_round_trip(
    fixture: WitnessedProviderFixture<'_>,
) -> Result<WitnessedRoundTrip, Box<dyn std::error::Error>> {
    let (approver_set_digest, witness_set_digest) =
        fixture.witness_policy.active_descriptor_set_digests()?;
    let mut checkpoint = VaultPolicyCheckpointV1 {
        schema: 1,
        vault_id: fixture.created_item.policy.state.vault_id(),
        genesis_fingerprint: fixture
            .created_item
            .policy
            .state
            .genesis_fingerprint()
            .clone(),
        vault_policy_sequence: fixture.created_item.policy.state.sequence(),
        vault_policy_hash: fixture.witness_policy.vault_policy_hash.clone(),
        witness_policy_id: fixture.witness_policy.witness_policy_id,
        witness_policy_revision: fixture.witness_policy.revision,
        witness_policy_digest: fixture.witness_digest.clone(),
        witness_set_digest,
        approver_set_digest,
        review_label_set_digest: fixture.witness_policy.review_label_set_digest.clone(),
        predecessor_checkpoint_digest: Digest32::new([0; 32]),
        issued_at_ms: 1_800_000_000_000,
        issuer_owner_id: fixture.owner.principal_id(),
        issuer_key_fingerprint: signing_key_fingerprint(
            1,
            &fixture.owner.principal_id(),
            1,
            &fixture.owner.public_descriptor()?.verification_public_key,
        ),
        issuer_key_epoch: 1,
        signature: Signature64::new([0; 64]),
    };
    checkpoint.signature = fixture
        .owner
        .sign_validated_statement(&checkpoint.signature_preimage()?)?;
    let empty_presentation = ApprovalPresentationV1::default();
    let presentation_digest = empty_presentation.digest()?;
    let approval_target = ApprovalTargetV1 {
        entries: vec![ApprovalTargetEntryV1 {
            item_id: fixture.created_item.envelope.item_id,
            field_id: None,
            presentation_commitment: Digest32::new([0; 32]),
        }],
        presentation_digest: presentation_digest.clone(),
    };
    let body_slot = fixture
        .witnessed
        .slots
        .iter()
        .find(|slot| slot.content_role == ContentRole::Body)
        .ok_or("body witnessed slot absent")?;
    let manifest = ActionManifestV1 {
        schema: 1,
        request_id: RequestId::from_bytes([0x90; 32])?,
        vault_id: fixture.created_item.policy.state.vault_id(),
        genesis_fingerprint: fixture
            .created_item
            .policy
            .state
            .genesis_fingerprint()
            .clone(),
        item_id: fixture.created_item.envelope.item_id,
        key_epoch: body_slot.key_epoch,
        item_access_mode: ItemAccessMode::WitnessedOnly,
        slot_id: body_slot.slot_id,
        content_role: ContentRole::Body,
        revision: body_slot.revision,
        revision_seal_id: body_slot.revision_seal_id,
        vault_policy_sequence: fixture.created_item.policy.state.sequence(),
        vault_policy_hash: fixture.witness_policy.vault_policy_hash.clone(),
        witness_policy_id: fixture.witness_policy.witness_policy_id,
        witness_policy_revision: fixture.witness_policy.revision,
        witness_policy_digest: fixture.witness_digest.clone(),
        requester_principal_id: fixture.owner.principal_id(),
        requested_access_role: AccessRole::Owner,
        operation: WitnessOperationV1::ReadStdout,
        operation_context: OperationContextV1::ReadStdout,
        approval_target_digest: approval_target.digest()?,
        approval_target,
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
        issued_at_ms: 1_800_000_000_000,
        not_before_ms: None,
        expires_at_ms: 1_800_000_300_000,
        presentation_digest,
    };
    manifest
        .validate_shape()
        .map_err(|error| format!("manifest fixture invalid: {error:?}"))?;
    crate::witness_approval::validate_manifest_presentation(&manifest, &empty_presentation, false)
        .map_err(|error| format!("presentation fixture invalid: {:?}", error.kind()))?;
    crate::witness_engine::validate_checkpoint_public(
        &fixture.created_item.policy.state,
        &checkpoint,
    )
    .map_err(|error| format!("checkpoint fixture invalid: {:?}", error.reason()))?;
    let mut request_creator = WitnessRequestCreator::from_source(
        IncrementingRandom(fixture.request_random_start),
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    let prepared = request_creator.create(
        WitnessRequestContext {
            policy: &fixture.created_item.policy.state,
            checkpoint: &checkpoint,
            requester: fixture.owner,
            review_labels: Vec::new(),
            now_ms: 1_800_000_000_001,
        },
        manifest,
        empty_presentation,
    )?;
    let responses = witnessed_responses(
        &prepared,
        &checkpoint,
        body_slot,
        fixture.witness_private_keys,
        fixture.witness_policy,
        prepared.session.public_key(),
    )?;
    let target = RevisionAccessTarget::current(
        &fixture.created_item.policy.state,
        &fixture.created_item.envelope,
        fixture.owner.principal_id(),
        ContentRole::Body,
        Capability::Read,
    )?;
    let mut provider = WitnessedItemAccessProvider::new(
        &checkpoint,
        &prepared.request,
        &prepared.manifest,
        &responses,
        &prepared.session,
        1_800_000_000_002,
    );
    let opened = provider
        .access_revision(
            RevisionAccessRequest {
                policy: &fixture.created_item.policy.state,
                envelope: &fixture.created_item.envelope,
                target: target.clone(),
                capability: Capability::Read,
                cancellation: &NeverCancelled,
            },
            |access| access.open_body(),
        )
        .map_err(|_| "witnessed provider failed")?;
    assert!(matches!(
        opened,
        ItemAccessOutcome::Complete {
            authority: AccessCompletion::WitnessedApproved,
            value,
        } if value == *fixture.expected_body
    ));

    let (_, wrong_session_public_key) = crypto::generate_recipient_keypair(
        ProtectionPolicy::EmergencyAllowDegraded,
        &mut IncrementingRandom(0xe0),
    )?;
    let wrong_session_responses = witnessed_responses(
        &prepared,
        &checkpoint,
        body_slot,
        fixture.witness_private_keys,
        fixture.witness_policy,
        &wrong_session_public_key,
    )?;
    let callback_called = Cell::new(false);
    let mut wrong_session_provider = WitnessedItemAccessProvider::new(
        &checkpoint,
        &prepared.request,
        &prepared.manifest,
        &wrong_session_responses,
        &prepared.session,
        1_800_000_000_002,
    );
    let wrong_session = wrong_session_provider.access_revision(
        RevisionAccessRequest {
            policy: &fixture.created_item.policy.state,
            envelope: &fixture.created_item.envelope,
            target,
            capability: Capability::Read,
            cancellation: &NeverCancelled,
        },
        |_| {
            callback_called.set(true);
            Ok::<(), ()>(())
        },
    );
    assert!(matches!(
        wrong_session,
        Err(ItemAccessError::Provider(error))
            if error.kind() == AccessProviderErrorKind::ProviderFailure
    ));
    assert!(!callback_called.get());
    Ok(WitnessedRoundTrip {
        checkpoint,
        prepared,
        responses,
    })
}

fn witnessed_responses(
    prepared: &PreparedWitnessRequest,
    checkpoint: &VaultPolicyCheckpointV1,
    slot: &WitnessedSlotV1,
    witness_private_keys: &[ProtectedMemory],
    witness_policy: &WitnessPolicy,
    session_public_key: &RecipientPublicKey1216,
) -> Result<Vec<WitnessResponseV1>, Box<dyn std::error::Error>> {
    let request_digest = prepared.request.digest()?;
    let manifest_digest = prepared.manifest.digest()?;
    let checkpoint_digest = checkpoint.digest()?;
    let mut responses = Vec::new();
    for (index, (capsule, private_key)) in slot
        .capsules
        .iter()
        .zip(witness_private_keys)
        .take(usize::from(slot.threshold))
        .enumerate()
    {
        let share = crypto::open_hpke(
            private_key,
            &capsule.encapsulation,
            capsule.ciphertext.as_bytes(),
            &capsule.info_preimage(),
            &capsule.aad_preimage(),
            33,
        )?;
        let response_id =
            ResponseId::from_bytes([0xc0_u8.saturating_add(u8::try_from(index)?); 32])?;
        let mut info = crate::canonical::jce_v1("jury-witness-v1/contribution/info");
        info.extend_from_slice(request_digest.as_bytes());
        info.extend_from_slice(manifest_digest.as_bytes());
        info.extend_from_slice(response_id.as_bytes());
        info.extend_from_slice(capsule.witness_id.as_bytes());
        info.extend_from_slice(prepared.request.witness_policy_digest.as_bytes());
        info.extend_from_slice(checkpoint_digest.as_bytes());
        info.extend_from_slice(capsule.share_commitment.as_bytes());
        info.push(capsule.share_index);
        let mut aad = crate::canonical::jce_v1("jury-witness-v1/contribution/aad");
        aad.extend_from_slice(slot.capsule_set_digest.as_bytes());
        aad.extend_from_slice(capsule.context_digest.as_bytes());
        aad.extend_from_slice(prepared.request.request_session_key_fingerprint.as_bytes());
        aad.extend_from_slice(&prepared.request.expires_at_ms.to_be_bytes());
        let mut random = FillByte(0xd0_u8.saturating_add(u8::try_from(index)?));
        let (encapsulation, ciphertext) =
            crypto::seal_hpke(session_public_key, &share, &info, &aad, &mut random)?;
        let contribution = WitnessContributionEnvelopeV1 {
            schema: 1,
            response_id,
            share_index: capsule.share_index,
            share_commitment: capsule.share_commitment.clone(),
            capsule_context_digest: capsule.context_digest.clone(),
            capsule_set_digest: slot.capsule_set_digest.clone(),
            request_session_key_fingerprint: prepared
                .request
                .request_session_key_fingerprint
                .clone(),
            encapsulation,
            ciphertext: ShareCiphertext49::from_slice(&ciphertext)?,
        };
        let descriptor = witness_policy
            .witness_descriptors
            .iter()
            .find(|descriptor| descriptor.witness_id == capsule.witness_id)
            .ok_or("witness descriptor absent")?;
        let mut decision = WitnessDecisionV1 {
            schema: 1,
            response_id,
            request_id: prepared.request.request_id,
            request_digest: request_digest.clone(),
            action_manifest_digest: manifest_digest.clone(),
            witness_id: capsule.witness_id,
            witness_signing_key_fingerprint: descriptor.signing_key_fingerprint.clone(),
            witness_signing_key_epoch: descriptor.signing_key_epoch,
            witness_policy_id: prepared.request.witness_policy_id,
            witness_policy_revision: prepared.request.witness_policy_revision,
            witness_policy_digest: prepared.request.witness_policy_digest.clone(),
            policy_checkpoint_digest: checkpoint_digest.clone(),
            state_generation: u64::try_from(index)?.saturating_add(1),
            decision: WitnessDecisionKindV1::Approve,
            reason: WitnessReasonV1::None,
            issued_at_ms: 1_800_000_000_002,
            expires_at_ms: prepared.request.expires_at_ms,
            contribution_digest: Some(contribution.digest()?),
            share_index: Some(capsule.share_index),
            share_commitment: Some(capsule.share_commitment.clone()),
            signature: Signature64::new([0; 64]),
        };
        let signing_seed = [0x31_u8.saturating_add(u8::try_from(index)?); 32];
        decision.signature = crypto::sign_bytes(&signing_seed, &decision.signature_preimage()?)?;
        responses.push(WitnessResponseV1 {
            decision,
            contribution: Some(contribution),
        });
    }
    Ok(responses)
}

fn reconstruct_slot_secret(
    slot: &WitnessedSlotV1,
    private_keys: &[ProtectedMemory],
    protection: ProtectionPolicy,
) -> Result<ProtectedRevisionSecret, Box<dyn std::error::Error>> {
    reconstruct_slot_secret_with_count(slot, private_keys, protection, usize::from(slot.threshold))
}

fn reconstruct_slot_secret_with_count(
    slot: &WitnessedSlotV1,
    private_keys: &[ProtectedMemory],
    protection: ProtectionPolicy,
    count: usize,
) -> Result<ProtectedRevisionSecret, Box<dyn std::error::Error>> {
    let mut shares = Zeroizing::new(Vec::new());
    for (capsule, private) in slot.capsules.iter().zip(private_keys).take(count) {
        let share = crypto::open_hpke(
            private,
            &capsule.encapsulation,
            capsule.ciphertext.as_bytes(),
            &capsule.info_preimage(),
            &capsule.aad_preimage(),
            33,
        )?;
        let bytes = share.expose(<[u8]>::to_vec)?;
        shares.push(bytes);
    }
    let reconstructed = Zeroizing::new(
        Gf256::combine_bytes(shares.as_slice())
            .map_err(|error| format!("combine witnessed shares: {error:?}"))?,
    );
    Ok(ProtectedRevisionSecret {
        bytes: protect(&reconstructed, protection)?,
    })
}
