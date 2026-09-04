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

include!("witnessed_round_trip.rs");
