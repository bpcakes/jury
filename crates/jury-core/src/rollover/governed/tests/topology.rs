use super::*;
use crate::item::RekeyedItem;

// Construct the topology through actual signed item creation and per-item
// rekeying. Both revisions remain active because only one item is rotated.
fn two_active_policy_revisions(owner: &VaultPrincipalIdentity) -> TestResult<Fixture> {
    let mut fixture = fixture(owner)?;
    let inventory = ItemArtifactInventory::from_vault(&fixture.vault)?;
    let original_item = fixture.vault.items[0].item_id;
    let original = fixture
        .vault
        .policy
        .revisions
        .pop()
        .ok_or("missing creation")?;
    let policy = replay_policy_with_witness_policies(
        &fixture.vault.policy,
        &fixture.catalog.witness_policies,
    )?;
    let mut creator = ItemCreator::new(PROTECTION);
    let second = creator
        .prepare_create(
            &policy,
            owner,
            original.timestamp_ms,
            NewItem {
                kind: ItemKind::Canonical,
                descriptor: ItemDescriptorV1::new("ExampleSecondItem".into())?,
                state: fixture.state.clone(),
                bucket_id: 1,
                access: ItemAccessPlan {
                    grants: Vec::new(),
                    direct_recipient_ids: vec![owner.principal_id()],
                    witness_policy_digest: Some(fixture.catalog.witness_policies[0].digest()?),
                },
            },
            &inventory,
        )
        .map_err(|error| format!("second fixture item: {error}"))?;
    let mut operations = original.operations;
    operations.extend(second.policy.revision.operations);
    let combined = policy.prepare_revision(owner, original.timestamp_ms, operations)?;
    fixture.vault.policy.revisions.push(combined.revision);
    fixture.vault.items.push(second.envelope);
    fixture.vault.items.sort_by_key(|item| item.item_id);
    let rotated_index = fixture
        .vault
        .items
        .iter()
        .position(|item| item.item_id == original_item)
        .ok_or("missing original item")?;

    let mut next = fixture.catalog.witness_policies[0].clone();
    next.revision += 1;
    next.operation_rules[0].max_output_bytes -= 1;
    next.predecessor_policy_digest = fixture.catalog.witness_policies[0].digest()?;
    next.vault_policy_sequence = combined.state.sequence() + 1;
    next.vault_policy_hash = combined.state.terminal_revision_hash().clone();
    let label = OwnerReviewLabelCreator::new().create(
        OwnerReviewLabelInput {
            policy: &combined.state,
            owner,
            label_revision: 1,
            subject: ReviewLabelSubject::Field {
                item_id: original_item,
                field_id: fixture.state.fields[0].field_id,
            },
            public_label: jury_protocol::witness_v1::ReviewLabelBytes::new(
                b"ExampleField".to_vec(),
            )?,
            target_policy_sequence: next.vault_policy_sequence,
            issued_at_ms: 8,
            expires_at_ms: Some(100_020),
        },
        |_| false,
    )?;
    let labels = ReviewLabelSetV1::new(vec![label])?;
    next.review_label_set_digest = labels.digest.clone();
    fixture.catalog.review_label_sets.push(labels);
    fixture
        .catalog
        .review_label_sets
        .sort_by_key(|set| set.digest.clone());
    fixture.catalog.witness_policies.push(next.clone());
    let mut policies = std::mem::take(&mut fixture.catalog.witness_policies)
        .into_iter()
        .map(|policy| Ok((policy.digest()?, policy)))
        .collect::<TestResult<Vec<_>>>()?;
    policies.sort_by(|(left, _), (right, _)| left.cmp(right));
    fixture.catalog.witness_policies = policies.into_iter().map(|(_, policy)| policy).collect();
    let policy = replay_policy_with_witness_policies(
        &fixture.vault.policy,
        &fixture.catalog.witness_policies,
    )?;
    let rekeyed = creator
        .prepare_rekey(
            &policy,
            owner,
            8,
            &fixture.vault.items[rotated_index],
            RekeyedItem {
                descriptor: ItemDescriptorV1::new("ExampleWitnessedItem".into())?,
                // Removing a field need not remove its old public automatic
                // target or owner label. Rollover must keep that scope inert.
                state: ItemStateV1 {
                    plaintext_schema: 1,
                    fields: Vec::new(),
                },
                bucket_id: 1,
                access: ItemAccessPlan {
                    grants: Vec::new(),
                    direct_recipient_ids: vec![owner.principal_id()],
                    witness_policy_digest: Some(next.digest()?),
                },
                principal_replacement: None,
                principal_registration: None,
                owner_change: None,
            },
            &ItemArtifactInventory::from_vault(&fixture.vault)?,
        )
        .map_err(|error| format!("fixture per-item rotation: {error}"))?;
    fixture.vault.policy.revisions.push(rekeyed.policy.revision);
    fixture.vault.items[rotated_index] = rekeyed.envelope;
    fixture.vault.items.sort_by_key(|item| item.item_id);
    Ok(fixture)
}

#[test]
fn valid_source_can_keep_two_active_revisions_of_one_witness_policy() -> TestResult {
    let owner = crate::rollover::tests::owner()?;
    let fixture = two_active_policy_revisions(&owner)?;
    let source_bytes = fixture.vault.to_json_bytes()?;
    let source = RolloverSource::validate(&fixture.vault, &fixture.catalog.witness_policies)?;
    roles::validate_source_catalog(&source, &fixture.catalog)?;
    for policy in &fixture.catalog.witness_policies {
        let labels = fixture
            .catalog
            .review_label_sets
            .iter()
            .find(|set| set.digest == policy.review_label_set_digest)
            .ok_or("missing labels")?;
        for label in &labels.labels {
            crate::witness_approval::verify_owner_review_label(
                &source.policy,
                label,
                policy.vault_policy_sequence,
                10,
            )?;
        }
    }
    let portable = fixture.catalog.for_vault(&fixture.vault)?;
    crate::transfer::TransferCreator::new().create(&fixture.vault, portable, &owner, 9)?;
    let active = source
        .policy
        .items
        .values()
        .map(|item| {
            let slot = item
                .witnessed_state
                .as_ref()
                .ok_or("missing witnessed fixture")?
                .slots
                .first()
                .ok_or("missing fixture slot")?;
            Ok((slot.witness_policy_id, slot.witness_policy_digest.clone()))
        })
        .collect::<TestResult<BTreeSet<_>>>()?;
    assert_eq!(active.len(), 2);
    assert_eq!(
        active
            .iter()
            .map(|(id, _)| id)
            .collect::<BTreeSet<_>>()
            .len(),
        1
    );
    let prepared = complete(&source, &fixture, &owner, 10)?;
    assert_eq!(prepared.catalog().witness_policies.len(), 2);
    let limits = prepared
        .catalog()
        .witness_policies
        .iter()
        .map(|policy| policy.operation_rules[0].max_output_bytes)
        .collect::<BTreeSet<_>>();
    assert_eq!(limits.len(), 2);
    let ids = prepared
        .catalog()
        .witness_policies
        .iter()
        .map(|policy| policy.witness_policy_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), 2);
    for policy in &prepared.catalog().witness_policies {
        assert_eq!(policy.revision, 1);
    }
    assert_copied_fields(&prepared, &fixture)?;
    assert_eq!(fixture.vault.to_json_bytes()?, source_bytes);
    let original_id = ItemId::from_bytes([0x90; 32])?;
    let original = source
        .policy
        .item(&original_id)
        .ok_or("missing original item")?;
    let deletion = source.policy.prepare_revision(
        &owner,
        11,
        vec![PolicyOperationV1::ItemDelete {
            item_id: original_id,
            final_descriptor_digest: original.descriptor.ciphertext_digest.clone(),
            final_item_revision_hash: original.current_item_revision_hash.clone(),
            deletion_policy_sequence: source.policy.sequence() + 1,
        }],
    )?;
    let mut deleted = fixture.vault.clone();
    deleted.policy.revisions.push(deletion.revision);
    deleted.items.retain(|item| item.item_id != original_id);
    let source = RolloverSource::validate(&deleted, &fixture.catalog.witness_policies)?;
    let portable = fixture.catalog.for_vault(&deleted)?;
    crate::transfer::TransferCreator::new().create(&deleted, portable, &owner, 12)?;
    assert_eq!(source.policy.items.len(), 1);
    assert!(templates::initial_templates(&source, &source.policy).is_ok());
    // The surviving policy's explicit target and signed label remain inert.
    let prepared = complete(&source, &fixture, &owner, 13)?;
    assert_eq!(prepared.vault().items.len(), 1);
    assert_eq!(prepared.catalog().witness_policies.len(), 1);
    let target =
        &prepared.catalog().witness_policies[0].operation_rules[0].automatic_read_targets[0];
    assert_eq!(target.item_id, original_id);
    assert_eq!(target.field_id, Some(fixture.state.fields[0].field_id));
    assert_ne!(prepared.vault().items[0].item_id, target.item_id);
    let label = &prepared.catalog().review_label_sets[0].labels[0];
    assert_eq!(label.item_id, Some(original_id));
    assert_eq!(label.field_id, target.field_id);
    Ok(())
}

fn complete(
    source: &RolloverSource<'_>,
    fixture: &Fixture,
    owner: &VaultPrincipalIdentity,
    time: u64,
) -> TestResult<PreparedGovernedRollover> {
    let mut provider = AdministrativeProvider {
        direct: DirectItemAccessProvider::new(owner),
        roles: Vec::new(),
    };
    let draft = source.prepare_governed(
        &fixture.catalog,
        owner,
        &mut provider,
        GovernedRolloverOptions {
            created_at_ms: time,
            registration_lifetime_ms: 60_000,
            protection: PROTECTION,
        },
        &NeverCancelled,
    )?;
    assert_eq!(provider.roles.len(), source.policy.items.len() * 2);
    let initial = source.verify_registration_draft(draft.registration_journal())?;
    reject_swapped_policy_revisions(source, draft.registration_journal(), owner)?;
    let proofs = draft
        .challenges()
        .iter()
        .zip(draft.prior_roles())
        .map(|(challenge, role)| {
            let identity = fixture
                .identities
                .iter()
                .find(|identity| {
                    identity
                        .public_descriptor()
                        .is_ok_and(|descriptor| descriptor == challenge.candidate_descriptor)
                })
                .ok_or("missing fixture identity")?;
            Ok(answer_rollover_challenge(
                &initial,
                identity,
                challenge,
                role,
                time + 1,
            )?)
        })
        .collect::<TestResult<Vec<_>>>()?;
    let prepared = draft.complete(
        source,
        &fixture.catalog,
        owner,
        proofs,
        time + 2,
        &NeverCancelled,
    )?;
    source.verify_fresh_governed_destination(
        &fixture.catalog,
        prepared.vault(),
        prepared.catalog(),
    )?;
    crate::transfer::TransferCreator::new().create(
        prepared.vault(),
        prepared.catalog().clone(),
        owner,
        time + 3,
    )?;
    Ok(prepared)
}

fn assert_copied_fields(prepared: &PreparedGovernedRollover, fixture: &Fixture) -> TestResult {
    let destination =
        RolloverSource::validate(prepared.vault(), &prepared.catalog().witness_policies)?;
    for envelope in &prepared.vault().items {
        let item = destination
            .policy
            .item(&envelope.item_id)
            .ok_or("missing destination item")?;
        let slot = &item.witnessed_state.as_ref().ok_or("missing slots")?.slots[1];
        let secret =
            crate::item::reconstruct_slot_secret(slot, &fixture.recipient_keys, PROTECTION)?;
        let mut body = crate::item::open_body(envelope, &secret)?;
        let Some(SourceAttestationV1::Rollover { statement }) =
            &prepared.vault().policy.genesis.source_attestation
        else {
            return Err("missing bridge".into());
        };
        let mapping = statement
            .bootstrap_manifest
            .as_ref()
            .ok_or("missing manifest")?
            .items
            .iter()
            .find(|entry| entry.destination_item_id == envelope.item_id)
            .ok_or("missing mapping")?;
        if mapping.source_item_id == ItemId::from_bytes([0x90; 32])? {
            assert!(body.fields.is_empty());
            for policy in &prepared.catalog().witness_policies {
                let target = &policy.operation_rules[0].automatic_read_targets[0];
                assert_eq!(target.item_id, envelope.item_id);
                assert_ne!(target.field_id, Some(fixture.state.fields[0].field_id));
            }
        } else {
            assert_eq!(body.fields.len(), 1);
            assert!(body.fields[0].value == fixture.state.fields[0].value);
        }
        body.clear_sensitive();
    }
    Ok(())
}

fn reject_swapped_policy_revisions(
    source: &RolloverSource<'_>,
    journal: &jury_protocol::vault_v1::PolicyJournalV1,
    owner: &VaultPrincipalIdentity,
) -> TestResult {
    let mut changed = journal.clone();
    let Some(SourceAttestationV1::Rollover { statement }) = &mut changed.genesis.source_attestation
    else {
        return Err("missing bridge".into());
    };
    let manifest = statement
        .bootstrap_manifest
        .as_mut()
        .ok_or("missing manifest")?;
    if manifest.witness_policies.len() != 2 {
        return Ok(());
    }
    let first = &manifest.witness_policies[0];
    let second = &manifest.witness_policies[1];
    assert_eq!(first.source_policy_id, second.source_policy_id);
    assert_ne!(first.source_policy_revision, second.source_policy_revision);
    let (left, right) = (first.destination_policy_id, second.destination_policy_id);
    for item in &mut manifest.items {
        let witnessed = item.witnessed.as_mut().ok_or("missing witnessed mapping")?;
        witnessed.policy_id = if witnessed.policy_id == left {
            right
        } else {
            left
        };
    }
    statement.bootstrap_manifest_digest = manifest.digest()?;
    statement.signature = owner.sign_validated_statement(&statement.signature_preimage())?;
    changed.genesis.owner_signature =
        owner.sign_validated_statement(&changed.genesis.signature_preimage()?)?;
    replay_policy(&changed)?;
    source.verify_source_authorization(&changed.genesis)?;
    assert!(source.verify_registration_draft(&changed).is_err());
    Ok(())
}
