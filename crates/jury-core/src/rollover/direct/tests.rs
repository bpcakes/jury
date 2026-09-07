use super::*;
mod historical;
mod review;
use crate::access_provider::NeverCancelled;
use jury_protocol::vault_v1::{
    AccessRole, FieldId, ItemFieldKind, ItemFieldV1, ItemFieldValue, ItemKind,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PROTECTION: ProtectionPolicy = ProtectionPolicy::EmergencyAllowDegraded;

#[test]
fn direct_migration_reencrypts_every_item_and_rolls_over_under_suite_two() -> TestResult {
    use jury_protocol::hpke_context::VaultSuite;
    let owner = crate::rollover::tests::owner()?;
    let second = crate::rollover::tests::owner()?;
    let reader = crate::rollover::tests::owner()?;
    let source = source_with_items(&owner, &second, &reader)?;
    let before = source.to_json_bytes()?;
    let validated = RolloverSource::validate(&source, &[])?;
    assert!(
        validated
            .prepare_direct_migration(VaultSuite::Suite1, &owner, 10, PROTECTION, &NeverCancelled)
            .is_err()
    );
    let migrated = validated.prepare_direct_migration(
        VaultSuite::Suite2,
        &second,
        10,
        PROTECTION,
        &NeverCancelled,
    )?;
    let destination = migrated.vault();
    assert_eq!(destination.header.suite, 2);
    assert!(destination.suite_migration.is_some());
    validated.verify_fresh_direct_destination(destination)?;
    let policy = replay_policy(&destination.policy)?;
    for item in policy.items.values() {
        assert!(
            item.direct_slots
                .iter()
                .all(|slot| slot.suite == 2 && slot.aead == 2)
        );
    }
    for item in &destination.items {
        let copied = opened(&policy, item, &owner)?;
        assert!(
            copied.state.as_ref().ok_or("missing state")?.fields[0]
                .value
                .as_bytes()
                == b"ExampleSecret"
        );
        assert!(
            !source
                .items
                .iter()
                .any(|old| old.item_id == item.item_id
                    || old.body_ciphertext == item.body_ciphertext)
        );
    }
    let suite_two = RolloverSource::validate(destination, &[])?;
    assert!(
        suite_two
            .prepare_direct_migration(VaultSuite::Suite1, &second, 11, PROTECTION, &NeverCancelled)
            .is_err()
    );
    let rolled = suite_two.prepare_direct(&second, 11, PROTECTION, &NeverCancelled)?;
    assert_eq!(rolled.vault().header.suite, 2);
    assert!(rolled.vault().suite_migration.is_none());
    let rolled_policy = replay_policy(&rolled.vault().policy)?;
    for item in &rolled.vault().items {
        assert!(
            opened(&rolled_policy, item, &owner)?
                .state
                .as_ref()
                .ok_or("missing state")?
                .fields[0]
                .value
                .as_bytes()
                == b"ExampleSecret"
        );
    }
    let mut stripped = destination.clone();
    stripped.suite_migration = None;
    assert!(RolloverSource::validate(&stripped, &[]).is_err());
    let mut changed = destination.clone();
    changed
        .suite_migration
        .as_mut()
        .ok_or("missing migration")?
        .old_terminal_revision_hash = Digest32::new([0x55; 32]);
    assert!(RolloverSource::validate(&changed, &[]).is_err());
    migration_history_and_substitutions(&validated, destination, &owner, &second)?;
    assert_eq!(source.to_json_bytes()?, before);
    Ok(())
}

fn migration_history_and_substitutions(
    source: &RolloverSource<'_>,
    destination: &VaultFileV1,
    owner: &VaultPrincipalIdentity,
    genesis_owner: &VaultPrincipalIdentity,
) -> TestResult {
    let mut mixed = destination.clone();
    let slot = mixed
        .policy
        .revisions
        .iter_mut()
        .flat_map(|revision| &mut revision.operations)
        .find_map(|operation| match operation {
            PolicyOperationV1::ItemCreate { direct_slots, .. } => direct_slots.first_mut(),
            _ => None,
        })
        .ok_or("missing slot")?;
    slot.suite = 1;
    slot.aead = 3;
    assert!(mixed.to_json_bytes().is_err());
    assert!(replay_policy(&mixed.policy).is_err());
    let mut partial = destination.clone();
    partial.items.remove(0);
    assert!(source.verify_fresh_direct_destination(&partial).is_err());
    let mut forged = destination.clone();
    forged
        .suite_migration
        .as_mut()
        .ok_or("missing migration")?
        .signature = Signature64::new([0; 64]);
    assert!(RolloverSource::validate(&forged, &[]).is_err());

    let mut historical = destination.clone();
    let policy = replay_policy(&historical.policy)?;
    let deleted = policy.prepare_revision(
        owner,
        20,
        policy
            .items
            .iter()
            .map(|(id, item)| PolicyOperationV1::ItemDelete {
                item_id: *id,
                final_descriptor_digest: item.descriptor.ciphertext_digest.clone(),
                final_item_revision_hash: item.current_item_revision_hash.clone(),
                deletion_policy_sequence: 2,
            })
            .collect(),
    )?;
    historical.policy.revisions.push(deleted.revision);
    historical.items.clear();
    let removed = deleted.state.prepare_revision(
        owner,
        21,
        vec![
            PolicyOperationV1::OwnerRevoke {
                principal_id: genesis_owner.principal_id(),
            },
            PolicyOperationV1::PrincipalRemove {
                principal_id: genesis_owner.principal_id(),
                removal_reason: jury_protocol::vault_v1::RemovalReason::Retirement,
            },
        ],
    )?;
    historical.policy.revisions.push(removed.revision);
    assert!(!removed.state.is_owner(&genesis_owner.principal_id()));
    let catalog = crate::transfer::TransferPublicCatalogV1 {
        version: 1,
        registration_proofs: Vec::new(),
        witness_policies: Vec::new(),
        review_label_sets: Vec::new(),
    };
    source.verify_historical_direct_destination(&historical, &catalog)?;
    let transfer =
        crate::transfer::TransferCreator::new().create(&historical, catalog, owner, 22)?;
    crate::transfer::ValidatedTransfer::parse(&transfer.to_json_bytes()?)?;
    let migration = historical
        .suite_migration
        .as_mut()
        .ok_or("missing migration")?;
    migration.signature = owner.sign_validated_statement(&migration.signature_preimage())?;
    // A current owner cannot replace the retained genesis signer's attestation.
    assert!(RolloverSource::validate(&historical, &[]).is_err());
    Ok(())
}

fn source_with_items(
    owner: &VaultPrincipalIdentity,
    second: &VaultPrincipalIdentity,
    reader: &VaultPrincipalIdentity,
) -> TestResult<VaultFileV1> {
    let mut vault = crate::rollover::tests::source(owner)?;
    let state = replay_policy(&vault.policy)?;
    let prepared = state.prepare_revision(
        owner,
        3,
        vec![
            PolicyOperationV1::PrincipalAdd {
                descriptor: second.public_descriptor()?,
                display_label: "ExampleSecondOwner".into(),
                registration_proof_digest: Digest32::new([0x61; 32]),
            },
            PolicyOperationV1::OwnerGrant {
                principal_id: second.principal_id(),
            },
            PolicyOperationV1::PrincipalAdd {
                descriptor: reader.public_descriptor()?,
                display_label: "ExampleReader".into(),
                registration_proof_digest: Digest32::new([0x62; 32]),
            },
        ],
    )?;
    vault.policy.revisions.push(prepared.revision);
    for (index, kind) in [ItemKind::Canonical, ItemKind::Legacy]
        .into_iter()
        .enumerate()
    {
        let policy = replay_policy(&vault.policy)?;
        let mut recipients = vec![owner.principal_id(), second.principal_id()];
        let grants = if kind == ItemKind::Canonical {
            recipients.push(reader.principal_id());
            vec![ItemGrant {
                principal_id: reader.principal_id(),
                role: AccessRole::Reader,
            }]
        } else {
            Vec::new()
        };
        recipients.sort();
        let input = NewItem {
            kind,
            descriptor: ItemDescriptorV1::new(format!("ExampleItem{index}"))?,
            state: ItemStateV1 {
                plaintext_schema: 1,
                fields: vec![ItemFieldV1 {
                    name: "ExampleField".into(),
                    field_id: FieldId::from_bytes([0x71; 32])?,
                    value: ItemFieldValue::new(b"ExampleSecret".to_vec())?,
                    decoded_length: 13,
                    kind: ItemFieldKind::Concealed,
                    created_at_ms: 1,
                    updated_at_ms: 2,
                }],
            },
            bucket_id: 1,
            access: ItemAccessPlan {
                grants,
                direct_recipient_ids: recipients,
                witness_policy_digest: None,
            },
        };
        let prepared = ItemCreator::new(PROTECTION).prepare_create(
            &policy,
            owner,
            4 + index as u64,
            input,
            &ItemArtifactInventory::from_vault(&vault)?,
        )?;
        vault.policy.revisions.push(prepared.policy.revision);
        vault.items.push(prepared.envelope);
        vault.items.sort_by_key(|envelope| envelope.item_id);
    }
    vault.to_json_bytes()?;
    Ok(vault)
}

fn opened(
    policy: &PolicyState,
    envelope: &ItemEnvelopeV1,
    identity: &VaultPrincipalIdentity,
) -> TestResult<OpenedItem> {
    let mut provider = DirectItemAccessProvider::new(identity);
    let mut plaintext = OpenedItem::default();
    // Exercise the recipient's ordinary read API independently of the owner's
    // administrative source-copy helper used by the rollover constructor.
    for role in [ContentRole::Descriptor, ContentRole::Body] {
        let target = RevisionAccessTarget::current(
            policy,
            envelope,
            identity.principal_id(),
            role,
            Capability::Read,
        )?;
        let outcome = provider
            .access_revision(
                RevisionAccessRequest {
                    policy,
                    envelope,
                    target,
                    capability: Capability::Read,
                    cancellation: &NeverCancelled,
                },
                |access| {
                    match role {
                        ContentRole::Descriptor => {
                            plaintext.descriptor = Some(access.open_descriptor()?)
                        }
                        ContentRole::Body => plaintext.state = Some(access.open_body()?),
                    }
                    Ok::<(), crate::access_provider::AccessProviderError>(())
                },
            )
            .map_err(|error| error.to_string())?;
        assert!(matches!(outcome, ItemAccessOutcome::Complete { .. }));
    }
    Ok(plaintext)
}

#[test]
fn direct_rollover_preserves_logical_state_roles_and_source_bytes_with_fresh_material() -> TestResult
{
    let owner = crate::rollover::tests::owner()?;
    let second = crate::rollover::tests::owner()?;
    let reader = crate::rollover::tests::owner()?;
    let source = source_with_items(&owner, &second, &reader)?;
    let before = source.to_json_bytes()?;
    let validated = RolloverSource::validate(&source, &[])?;
    let prepared = validated.prepare_direct(&second, 10, PROTECTION, &NeverCancelled)?;
    let destination = prepared.vault();
    let parsed = VaultFileV1::parse(&destination.to_json_bytes()?)?;
    validated.verify_fresh_direct_destination(&parsed)?;
    assert_eq!(source.to_json_bytes()?, before);
    assert_ne!(source.header.vault_id, destination.header.vault_id);
    assert_eq!(destination.policy.revisions.len(), 1);
    let policy = replay_policy(&destination.policy)?;
    assert_eq!(policy.owner_count(), 2);
    assert_eq!(policy.principals.len(), 3);
    let Some(SourceAttestationV1::Rollover { statement }) =
        &destination.policy.genesis.source_attestation
    else {
        return Err("missing bridge".into());
    };
    let manifest = statement
        .bootstrap_manifest
        .as_ref()
        .ok_or("missing manifest")?;
    assert_eq!(manifest.items.len(), 2);
    for mapping in &manifest.items {
        let original = source
            .items
            .iter()
            .find(|envelope| envelope.item_id == mapping.source_item_id)
            .ok_or("missing source")?;
        let copied = destination
            .items
            .iter()
            .find(|envelope| envelope.item_id == mapping.destination_item_id)
            .ok_or("missing destination")?;
        let old = opened(&validated.policy, original, &owner)?;
        for recipient in [&owner, &second]
            .into_iter()
            .chain((mapping.item_kind == ItemKind::Canonical).then_some(&reader))
        {
            let new = opened(&policy, copied, recipient)?;
            assert_same_logical_item(&old, &new)?;
        }
        assert_ne!(
            original.descriptor.revision_seal_id,
            copied.descriptor.revision_seal_id
        );
        assert_ne!(
            original.current_revision.revision_seal_id,
            copied.current_revision.revision_seal_id
        );
        assert_ne!(original.body_ciphertext, copied.body_ciphertext);
        if mapping.item_kind == ItemKind::Legacy {
            assert!(opened(&policy, copied, &reader).is_err());
        }
    }
    check_tampering(&validated, destination, &second, &reader)?;
    // Reconstruct a real, signed v1 artifact using the retained v1 encoding.
    // Direct capsules and item signatures have no genesis dependency, so only
    // the bridge/genesis/bootstrap policy need signing for that older format.
    let mut v1 = destination.clone();
    let Some(SourceAttestationV1::Rollover { statement }) =
        &mut v1.policy.genesis.source_attestation
    else {
        return Err("missing bridge".into());
    };
    let manifest = statement
        .bootstrap_manifest
        .as_mut()
        .ok_or("missing manifest")?;
    manifest.version = 1;
    manifest.source_suite = None;
    resign_bootstrap(&mut v1, &second)?;
    validated.verify_fresh_direct_destination(&v1)?;
    validated.verify_historical_direct_destination(
        &v1,
        &crate::transfer::TransferPublicCatalogV1::empty(),
    )?;
    let transfer = crate::transfer::TransferCreator::new().create(
        &v1,
        crate::transfer::TransferPublicCatalogV1::empty(),
        &second,
        11,
    )?;
    let parsed = crate::transfer::ValidatedTransfer::parse(&transfer.to_json_bytes()?)?;
    let policy = replay_policy(&parsed.vault().policy)?;
    for envelope in &parsed.vault().items {
        let prior = destination
            .items
            .iter()
            .find(|item| item.item_id == envelope.item_id)
            .ok_or("missing item")?;
        let old = opened(&policy, prior, &second)?;
        let new = opened(&policy, envelope, &second)?;
        assert!(old.descriptor == new.descriptor);
        assert!(old.state == new.state);
    }
    Ok(())
}

fn assert_same_logical_item(old: &OpenedItem, new: &OpenedItem) -> TestResult {
    assert!(old.descriptor == new.descriptor);
    let old_state = old.state.as_ref().ok_or("missing plaintext")?;
    let new_state = new.state.as_ref().ok_or("missing plaintext")?;
    assert_eq!(old_state.fields.len(), new_state.fields.len());
    for (old_field, new_field) in old_state.fields.iter().zip(&new_state.fields) {
        assert!(old_field.name == new_field.name && old_field.value == new_field.value);
        assert_eq!(old_field.kind, new_field.kind);
        assert_eq!(old_field.created_at_ms, new_field.created_at_ms);
        assert_eq!(old_field.updated_at_ms, new_field.updated_at_ms);
        assert_ne!(old_field.field_id, new_field.field_id);
    }
    Ok(())
}

fn check_tampering(
    validated: &RolloverSource<'_>,
    destination: &VaultFileV1,
    second: &VaultPrincipalIdentity,
    reader: &VaultPrincipalIdentity,
) -> TestResult {
    // Re-sign a genuinely valid destination that omits an active source item.
    // Its own signatures and the source bridge are not a completeness proof.
    let mut omitted = destination.clone();
    let Some(SourceAttestationV1::Rollover { statement }) =
        &mut omitted.policy.genesis.source_attestation
    else {
        return Err("missing bridge".into());
    };
    let removed = statement
        .bootstrap_manifest
        .as_mut()
        .ok_or("missing manifest")?
        .items
        .pop()
        .ok_or("missing item")?
        .destination_item_id;
    omitted.items.retain(|envelope| envelope.item_id != removed);
    omitted.policy.revisions[0].operations.retain(|operation| !matches!(operation, PolicyOperationV1::ItemCreate { item_id, .. } if *item_id == removed));
    resign_bootstrap(&mut omitted, second)?;
    RolloverSource::validate(&omitted, &[])?;
    validated.verify_source_authorization(&omitted.policy.genesis)?;
    assert!(validated.verify_fresh_direct_destination(&omitted).is_err());

    let mut relabeled = destination.clone();
    let Some(SourceAttestationV1::Rollover { statement }) =
        &mut relabeled.policy.genesis.source_attestation
    else {
        return Err("missing bridge".into());
    };
    let principal = statement
        .bootstrap_manifest
        .as_mut()
        .ok_or("missing manifest")?
        .principals
        .iter_mut()
        .find(|entry| entry.principal_id == reader.principal_id())
        .ok_or("missing principal")?;
    principal.display_label = "ExampleSubstituted".into();
    for operation in &mut relabeled.policy.revisions[0].operations {
        if let PolicyOperationV1::PrincipalAdd {
            descriptor,
            display_label,
            ..
        } = operation
            && descriptor.principal_id == reader.principal_id()
        {
            *display_label = "ExampleSubstituted".into();
        }
    }
    resign_bootstrap(&mut relabeled, second)?;
    RolloverSource::validate(&relabeled, &[])?;
    validated.verify_source_authorization(&relabeled.policy.genesis)?;
    assert!(
        validated
            .verify_fresh_direct_destination(&relabeled)
            .is_err()
    );

    let mut missing = destination.clone();
    let Some(SourceAttestationV1::Rollover { statement }) =
        &mut missing.policy.genesis.source_attestation
    else {
        return Err("missing bridge".into());
    };
    statement.bootstrap_manifest = None;
    // The optional JSON field is opened by its digest, not independently signed.
    validated.verify_source_authorization(&missing.policy.genesis)?;
    assert!(validated.verify_fresh_direct_destination(&missing).is_err());
    Ok(())
}

fn resign_bootstrap(vault: &mut VaultFileV1, owner: &VaultPrincipalIdentity) -> TestResult {
    let genesis = &mut vault.policy.genesis;
    let Some(SourceAttestationV1::Rollover { statement }) = &mut genesis.source_attestation else {
        return Err("missing bridge".into());
    };
    statement.bootstrap_manifest_digest = statement
        .bootstrap_manifest
        .as_ref()
        .ok_or("missing manifest")?
        .digest()?;
    statement.signature = owner.sign_validated_statement(&statement.signature_preimage())?;
    let bridge_digest = Digest32::new(Sha256::digest(statement.signature_preimage()).into());
    for operation in &mut vault.policy.revisions[0].operations {
        if let PolicyOperationV1::PrincipalAdd {
            registration_proof_digest,
            ..
        } = operation
        {
            *registration_proof_digest = bridge_digest.clone();
        }
    }
    genesis.owner_signature = owner.sign_validated_statement(&genesis.signature_preimage()?)?;
    vault.header.genesis_fingerprint = genesis.recomputed_fingerprint()?;
    let initial = replay_policy(&PolicyJournalV1 {
        genesis: genesis.clone(),
        revisions: Vec::new(),
    })?;
    vault.policy.revisions[0] = initial
        .prepare_revision(
            owner,
            genesis.created_at_ms,
            vault.policy.revisions[0].operations.clone(),
        )?
        .revision;
    Ok(())
}

#[test]
fn full_source_policy_history_rolls_over_without_appending_or_pruning() -> TestResult {
    let owner = crate::rollover::tests::owner()?;
    let mut source = crate::rollover::tests::source(&owner)?;
    let mut policy = replay_policy(&source.policy)?;
    for sequence in 2..=jury_protocol::vault_v1::MAX_POLICY_REVISIONS {
        let principal = policy
            .principal(&owner.principal_id())
            .ok_or("missing owner")?;
        let next_label = if principal.display_label == "ExamplePrincipal" {
            "ExampleOwner"
        } else {
            "ExamplePrincipal"
        };
        let prepared = policy.prepare_revision(
            &owner,
            sequence as u64 + 1,
            vec![PolicyOperationV1::PrincipalLabelChange {
                principal_id: owner.principal_id(),
                prior_label: principal.display_label.clone(),
                next_label: next_label.into(),
            }],
        )?;
        policy = prepared.state;
        source.policy.revisions.push(prepared.revision);
    }
    assert_eq!(
        source.policy.revisions.len(),
        jury_protocol::vault_v1::MAX_POLICY_REVISIONS
    );
    let before = source.to_json_bytes()?;
    let validated = RolloverSource::validate(&source, &[])?;
    let prepared = validated.prepare_direct(&owner, 10_000, PROTECTION, &NeverCancelled)?;
    assert_eq!(prepared.vault().policy.revisions.len(), 1);
    validated.verify_fresh_direct_destination(prepared.vault())?;
    assert_eq!(source.to_json_bytes()?, before);
    Ok(())
}

#[test]
fn empty_bootstrap_is_signed_and_only_the_exact_rollover_case_allows_no_operations() -> TestResult {
    let owner = crate::rollover::tests::owner()?;
    let created = PolicyCreator::new().create(&owner, 1, |_| false)?;
    let source = VaultFileV1 {
        header: VaultHeaderV1 {
            magic: "jury-vault".into(),
            version: 1,
            vault_id: created.state.vault_id(),
            created_at_ms: 1,
            suite: 1,
            policy_schema: 1,
            item_schema: 1,
            identity_schema: 1,
            genesis_fingerprint: created.state.genesis_fingerprint().clone(),
        },
        policy: created.journal,
        items: Vec::new(),
        suite_migration: None,
    };
    let validated = RolloverSource::validate(&source, &[])?;
    let prepared = validated.prepare_direct(&owner, 2, PROTECTION, &NeverCancelled)?;
    assert!(prepared.vault().policy.revisions[0].operations.is_empty());
    validated.verify_fresh_direct_destination(prepared.vault())?;
    let mut changed = prepared.vault().clone();
    changed.policy.genesis.source_attestation = None;
    changed.policy.genesis.owner_signature =
        owner.sign_validated_statement(&changed.policy.genesis.signature_preimage()?)?;
    changed.header.genesis_fingerprint = changed.policy.genesis.recomputed_fingerprint()?;
    changed.policy.revisions[0].previous_revision_hash = changed.header.genesis_fingerprint.clone();
    changed.policy.revisions[0].signature =
        owner.sign_validated_statement(&changed.policy.revisions[0].signature_preimage()?)?;
    assert!(replay_policy(&changed.policy).is_err());
    assert!(changed.validate().is_err());
    let mut changed = prepared.vault().clone();
    let first = &changed.policy.revisions[0];
    let mut second = first.clone();
    second.sequence = 2;
    second.previous_revision_hash = first.recomputed_hash()?;
    second.signature = owner.sign_validated_statement(&second.signature_preimage()?)?;
    changed.policy.revisions.push(second);
    assert!(replay_policy(&changed.policy).is_err());
    assert!(changed.validate().is_err());
    Ok(())
}

#[test]
fn constructor_refuses_nonowner_stale_time_and_cancellation_without_source_mutation() -> TestResult
{
    let owner = crate::rollover::tests::owner()?;
    let stranger = crate::rollover::tests::owner()?;
    let source = crate::rollover::tests::source(&owner)?;
    let before = source.to_json_bytes()?;
    let validated = RolloverSource::validate(&source, &[])?;
    assert!(
        matches!(validated.prepare_direct(&stranger, 3, PROTECTION, &NeverCancelled), Err(error) if error.kind() == RolloverErrorKind::Unauthorized)
    );
    assert!(
        validated
            .prepare_direct(&owner, 1, PROTECTION, &NeverCancelled)
            .is_err()
    );
    struct Cancelled;
    impl CancellationCheck for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }
    assert!(
        validated
            .prepare_direct(&owner, 3, PROTECTION, &Cancelled)
            .is_err()
    );
    assert_eq!(source.to_json_bytes()?, before);
    Ok(())
}
