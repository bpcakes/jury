#[test]
fn witnessed_item_uses_only_the_bound_membership_quorums_and_workload_rule() -> AnyResult {
    let (owner, mut created) = created_policy()?;
    let approvers = [
        TestSigner::new(0x41, 0x21, PrincipalKind::Approver)?,
        TestSigner::new(0x42, 0x22, PrincipalKind::Approver)?,
    ];
    let witnesses = [
        TestSigner::new(0x51, 0x51, PrincipalKind::Witness)?,
        TestSigner::new(0x52, 0x52, PrincipalKind::Witness)?,
        TestSigner::new(0x53, 0x53, PrincipalKind::Witness)?,
    ];
    let add_operations = approvers
        .iter()
        .chain(&witnesses)
        .map(|signer| PolicyOperationV1::PrincipalAdd {
            descriptor: signer.descriptor.clone(),
            display_label: "ExampleAuthority".to_owned(),
            registration_proof_digest: FixedBytes::new([0x45; 32]),
        })
        .collect();
    let add = prepare_with_test_signer(&created.state, &owner, 1_700_000_000_001, add_operations)?;
    created.journal.revisions.push(add.revision);

    let item_id = ItemId::from_bytes([0x61; 32])?;
    let share_indexes = [2, 7, 31];
    let policy = witnessed_policy(
        add.state.vault_id(),
        add.state.genesis_fingerprint().clone(),
        2,
        &approvers,
        &witnesses,
        share_indexes,
        item_id,
    )?;
    policy
        .validate()
        .map_err(|error| std::io::Error::other(format!("policy fixture: {error:?}")))?;
    let policy_digest = policy.digest()?;
    let bound =
        replay_policy_with_witness_policies(&created.journal, std::slice::from_ref(&policy))
            .map_err(|error| std::io::Error::other(format!("catalog replay: {error:?}")))?;
    let witnessed_only_state = witnessed_state(
        bound.vault_id(),
        bound.genesis_fingerprint().clone(),
        item_id,
        2,
        policy.witness_policy_id,
        policy_digest.clone(),
        &witnesses,
        share_indexes,
        ItemAccessMode::WitnessedOnly,
        0x75,
    )?;
    let mixed_item_id = ItemId::from_bytes([0x64; 32])?;
    let mixed_state = witnessed_state(
        bound.vault_id(),
        bound.genesis_fingerprint().clone(),
        mixed_item_id,
        2,
        policy.witness_policy_id,
        policy_digest,
        &witnesses,
        share_indexes,
        ItemAccessMode::Mixed,
        0x95,
    )?;
    let mixed_direct = direct_slots(
        bound.vault_id(),
        mixed_item_id,
        owner.principal_id(),
        1,
        2,
        AccessRole::Owner,
        ItemAccessMode::Mixed,
        recipient_public_key_fingerprint(&owner.descriptor.recipient_public_key),
    )?;
    let item = prepare_with_test_signer(
        &bound,
        &owner,
        1_700_000_000_002,
        vec![
            PolicyOperationV1::ItemCreate {
                item_id,
                item_kind: ItemKind::Canonical,
                key_epoch: 1,
                descriptor: descriptor_metadata(1, 1, 0x62)?,
                current_item_revision_hash: FixedBytes::new([0x63; 32]),
                direct_slots: Vec::new(),
                witnessed_state: Some(witnessed_only_state),
            },
            PolicyOperationV1::ItemCreate {
                item_id: mixed_item_id,
                item_kind: ItemKind::Canonical,
                key_epoch: 1,
                descriptor: descriptor_metadata(1, 1, 0x65)?,
                current_item_revision_hash: FixedBytes::new([0x66; 32]),
                direct_slots: mixed_direct,
                witnessed_state: Some(mixed_state),
            },
        ],
    )
    .map_err(|error| std::io::Error::other(format!("witnessed item: {error:?}")))?;
    created.journal.revisions.push(item.revision);
    let replayed = replay_policy_with_witness_policies(&created.journal, &[policy])?;

    let access = replayed.access(&item_id, &owner.principal_id(), Capability::Read);
    assert!(access.allowed);
    assert_eq!(access.path, AccessPath::Witnessed);
    assert!(access.carries_quorum_claim);
    let rule = replayed.witness_access_rule(&item_id, WitnessOperation::ReadStdout)?;
    assert_eq!(rule.approval_threshold, 2);
    assert_eq!(rule.witness_threshold, 2);
    assert_eq!(rule.eligible_approver_ids.len(), 2);
    assert_eq!(rule.witness_ids.len(), 3);
    assert_eq!(rule.allowed_request_lifetime_ms, 300_000);
    assert_eq!(rule.max_timeout_ms, 30_000);
    assert_eq!(rule.max_output_bytes, 4_096);
    assert!(rule.carries_quorum_claim);

    let mixed = replayed.access(&mixed_item_id, &owner.principal_id(), Capability::Read);
    assert_eq!(mixed.path, AccessPath::Mixed);
    assert!(!mixed.carries_quorum_claim);
    assert!(
        !replayed
            .witness_access_rule(&mixed_item_id, WitnessOperation::ReadStdout)?
            .carries_quorum_claim
    );

    assert!(
        matches!(replay_policy(&created.journal), Err(error) if error.kind() == PolicyErrorKind::MissingWitnessPolicy)
    );
    Ok(())
}

#[test]
fn principal_replacement_requires_and_applies_one_complete_reader_rotation() -> AnyResult {
    let (owner, mut created) = created_policy()?;
    let reader = TestSigner::new(0x31, 0x41, PrincipalKind::Human)?;
    let replacement = TestSigner::new(0x32, 0x42, PrincipalKind::Human)?;
    let add = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_001,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor: reader.descriptor.clone(),
            display_label: "ExampleReader".to_owned(),
            registration_proof_digest: FixedBytes::new([0x43; 32]),
        }],
    )?;
    created.journal.revisions.push(add.revision);
    created.state = add.state;

    let item_id = ItemId::from_bytes([0x54; 32])?;
    let mut slots = direct_slots(
        created.state.vault_id(),
        item_id,
        owner.principal_id(),
        1,
        2,
        AccessRole::Owner,
        ItemAccessMode::DirectOnly,
        recipient_public_key_fingerprint(&owner.descriptor.recipient_public_key),
    )?;
    slots.extend(direct_slots(
        created.state.vault_id(),
        item_id,
        reader.principal_id(),
        1,
        2,
        AccessRole::Reader,
        ItemAccessMode::DirectOnly,
        recipient_public_key_fingerprint(&reader.descriptor.recipient_public_key),
    )?);
    sort_direct_slots(&mut slots);
    let create = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_002,
        vec![PolicyOperationV1::ItemCreate {
            item_id,
            item_kind: ItemKind::Canonical,
            key_epoch: 1,
            descriptor: descriptor_metadata(1, 1, 0x55)?,
            current_item_revision_hash: FixedBytes::new([0x56; 32]),
            direct_slots: slots,
            witnessed_state: None,
        }],
    )?;
    created.journal.revisions.push(create.revision);
    created.state = create.state;

    let replacement_operation = PolicyOperationV1::PrincipalReplace {
        prior_principal_id: reader.principal_id(),
        next_descriptor: replacement.descriptor.clone(),
        registration_proof_digest: FixedBytes::new([0x57; 32]),
    };
    let missing_rotation = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_003,
        vec![replacement_operation.clone()],
    );
    assert!(
        matches!(missing_rotation, Err(error) if error.kind() == PolicyErrorKind::IncompleteRotation)
    );

    let mut replacement_slots = direct_slots(
        created.state.vault_id(),
        item_id,
        owner.principal_id(),
        2,
        3,
        AccessRole::Owner,
        ItemAccessMode::DirectOnly,
        recipient_public_key_fingerprint(&owner.descriptor.recipient_public_key),
    )?;
    replacement_slots.extend(direct_slots(
        created.state.vault_id(),
        item_id,
        replacement.principal_id(),
        2,
        3,
        AccessRole::Reader,
        ItemAccessMode::DirectOnly,
        recipient_public_key_fingerprint(&replacement.descriptor.recipient_public_key),
    )?);
    sort_direct_slots(&mut replacement_slots);
    let replaced = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_003,
        vec![
            replacement_operation,
            PolicyOperationV1::ItemReaderSetChange {
                item_id,
                prior_epoch: 1,
                next_epoch: 2,
                prior_reader_ids: vec![owner.principal_id(), reader.principal_id()],
                next_reader_ids: vec![owner.principal_id(), replacement.principal_id()],
                replacement_descriptor: descriptor_metadata(2, 2, 0x58)?,
                replacement_current_item_revision_hash: FixedBytes::new([0x59; 32]),
            },
            PolicyOperationV1::ItemSlotsReplace {
                item_id,
                next_epoch: 2,
                direct_slots: replacement_slots,
                witnessed_state: None,
            },
        ],
    )?;

    assert!(replaced.state.principal(&reader.principal_id()).is_none());
    assert!(replaced.state.principal_id_was_used(&reader.principal_id()));
    assert!(
        replaced
            .state
            .access(&item_id, &replacement.principal_id(), Capability::Read)
            .allowed
    );
    created.journal.revisions.push(replaced.revision);
    assert_eq!(replay_policy(&created.journal)?, replaced.state);
    Ok(())
}

#[test]
fn deleted_item_identifier_stays_tombstoned_and_cannot_be_recreated() -> AnyResult {
    let (owner, mut created) = created_policy()?;
    let item_id = ItemId::from_bytes([0x67; 32])?;
    let descriptor = descriptor_metadata(1, 1, 0x68)?;
    let current_hash = FixedBytes::new([0x69; 32]);
    let create = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_001,
        vec![PolicyOperationV1::ItemCreate {
            item_id,
            item_kind: ItemKind::Canonical,
            key_epoch: 1,
            descriptor: descriptor.clone(),
            current_item_revision_hash: current_hash.clone(),
            direct_slots: direct_slots(
                created.state.vault_id(),
                item_id,
                owner.principal_id(),
                1,
                1,
                AccessRole::Owner,
                ItemAccessMode::DirectOnly,
                recipient_public_key_fingerprint(&owner.descriptor.recipient_public_key),
            )?,
            witnessed_state: None,
        }],
    )?;
    created.journal.revisions.push(create.revision);
    created.state = create.state;
    let delete = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_002,
        vec![PolicyOperationV1::ItemDelete {
            item_id,
            final_descriptor_digest: descriptor.ciphertext_digest,
            final_item_revision_hash: current_hash,
            deletion_policy_sequence: 2,
        }],
    )?;
    assert!(delete.state.tombstone(&item_id).is_some());

    let recreate = prepare_with_test_signer(
        &delete.state,
        &owner,
        1_700_000_000_003,
        vec![PolicyOperationV1::ItemCreate {
            item_id,
            item_kind: ItemKind::Canonical,
            key_epoch: 1,
            descriptor: descriptor_metadata(1, 1, 0x6a)?,
            current_item_revision_hash: FixedBytes::new([0x6b; 32]),
            direct_slots: direct_slots(
                delete.state.vault_id(),
                item_id,
                owner.principal_id(),
                1,
                3,
                AccessRole::Owner,
                ItemAccessMode::DirectOnly,
                recipient_public_key_fingerprint(&owner.descriptor.recipient_public_key),
            )?,
            witnessed_state: None,
        }],
    );
    assert!(matches!(recreate, Err(error) if error.kind() == PolicyErrorKind::IdentifierReused));
    Ok(())
}
