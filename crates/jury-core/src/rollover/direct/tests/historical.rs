use super::*;

#[test]
fn historical_direct_bootstrap_survives_deletion_and_current_label_change() -> TestResult {
    let owner = crate::rollover::tests::owner()?;
    let second = crate::rollover::tests::owner()?;
    let reader = crate::rollover::tests::owner()?;
    let source_vault = source_with_items(&owner, &second, &reader)?;
    let source = RolloverSource::validate(&source_vault, &[])?;
    let prepared = source.prepare_direct(&owner, 10, PROTECTION, &NeverCancelled)?;
    let original = prepared.vault().to_json_bytes()?;
    let mut no_manifest = prepared.vault().clone();
    let Some(SourceAttestationV1::Rollover { statement }) =
        &mut no_manifest.policy.genesis.source_attestation
    else {
        return Err("missing fixture attestation".into());
    };
    statement.bootstrap_manifest = None;
    // Reserved wire parsing stays compatible, but runtime transfer needs the
    // manifest even when the bridge and first revision remain authentic.
    no_manifest.to_json_bytes()?;
    source.verify_source_authorization(&no_manifest.policy.genesis)?;
    assert!(
        crate::transfer::TransferCreator::new()
            .create(
                &no_manifest,
                crate::transfer::TransferPublicCatalogV1::empty(),
                &owner,
                21
            )
            .is_err()
    );
    let mut vault = prepared.vault().clone();
    let policy = replay_policy(&vault.policy)?;
    let prior = &vault.items[0];
    let item = policy.item(&prior.item_id).ok_or("missing initial item")?;
    let mut plaintext = opened(&policy, prior, &owner)?;
    let mut body = plaintext.state.take().ok_or("missing opened body")?;
    body.fields[0].value = ItemFieldValue::new(b"ExampleChanged".to_vec())?;
    body.fields[0].decoded_length = 14;
    body.fields[0].updated_at_ms = 15;
    let rekeyed = ItemCreator::new(PROTECTION).prepare_rekey(
        &policy,
        &owner,
        15,
        prior,
        crate::item::RekeyedItem {
            descriptor: plaintext.descriptor.take().ok_or("missing descriptor")?,
            state: body,
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: item
                    .grants
                    .iter()
                    .map(|(id, role)| ItemGrant {
                        principal_id: *id,
                        role: *role,
                    })
                    .collect(),
                direct_recipient_ids: direct_recipients(&item.direct_slots),
                witness_policy_digest: None,
            },
            principal_replacement: None,
            principal_registration: None,
            owner_change: None,
        },
        &ItemArtifactInventory::from_vault(&vault)?,
    )?;
    vault.policy.revisions.push(rekeyed.policy.revision);
    vault.items[0] = rekeyed.envelope;
    source.verify_historical_direct_destination(
        &vault,
        &crate::transfer::TransferPublicCatalogV1::empty(),
    )?;
    // An authentic bootstrap is not enough: current artifacts and every later
    // policy revision must still authenticate after validation is consolidated.
    let catalog = crate::transfer::TransferPublicCatalogV1::empty();
    let mut tampered = vault.clone();
    tampered.items[0].current_revision.signature = Signature64::new([0; 64]);
    assert!(
        source
            .verify_historical_direct_destination(&tampered, &catalog)
            .is_err()
    );
    let mut tampered = vault.clone();
    tampered
        .policy
        .revisions
        .last_mut()
        .ok_or("missing descendant")?
        .signature = Signature64::new([0; 64]);
    assert!(
        source
            .verify_historical_direct_destination(&tampered, &catalog)
            .is_err()
    );
    let current = opened(&rekeyed.policy.state, &vault.items[0], &owner)?;
    assert!(
        current.state.as_ref().ok_or("missing current body")?.fields[0].value
            == ItemFieldValue::new(b"ExampleChanged".to_vec())?
    );
    let policy = replay_policy(&vault.policy)?;
    let mut operations = policy
        .items
        .iter()
        .map(|(id, item)| PolicyOperationV1::ItemDelete {
            item_id: *id,
            final_descriptor_digest: item.descriptor.ciphertext_digest.clone(),
            final_item_revision_hash: item.current_item_revision_hash.clone(),
            deletion_policy_sequence: policy.sequence() + 1,
        })
        .collect::<Vec<_>>();
    let prior_label = policy
        .principal(&owner.principal_id())
        .ok_or("missing owner")?
        .display_label
        .clone();
    operations.push(PolicyOperationV1::PrincipalLabelChange {
        principal_id: owner.principal_id(),
        prior_label,
        next_label: "ExampleLaterOwner".into(),
    });
    vault
        .policy
        .revisions
        .push(policy.prepare_revision(&owner, 20, operations)?.revision);
    vault.items.clear();
    let catalog = crate::transfer::TransferPublicCatalogV1::empty();
    source.verify_historical_direct_destination(&vault, &catalog)?;
    assert!(source.verify_fresh_direct_destination(&vault).is_err());
    let transfer =
        crate::transfer::TransferCreator::new().create(&vault, catalog.clone(), &owner, 21)?;
    let parsed = crate::transfer::ValidatedTransfer::parse(&transfer.to_json_bytes()?)?;
    source.verify_historical_direct_destination(parsed.vault(), parsed.catalog())?;
    assert_eq!(prepared.vault().to_json_bytes()?, original);

    // A new owner-signed first revision is structurally authentic, but cannot
    // omit initial items while preserving the original manifest commitment.
    let mut omitted = prepared.vault().clone();
    let operations = omitted.policy.revisions[0]
        .operations
        .iter()
        .filter(|operation| !matches!(operation, PolicyOperationV1::ItemCreate { .. }))
        .cloned()
        .collect();
    omitted.policy.revisions.clear();
    omitted.items.clear();
    let initial = replay_policy(&omitted.policy)?;
    omitted
        .policy
        .revisions
        .push(initial.prepare_revision(&owner, 10, operations)?.revision);
    RolloverSource::validate(&omitted, &[])?;
    assert!(
        source
            .verify_historical_direct_destination(&omitted, &catalog)
            .is_err()
    );
    assert!(
        crate::transfer::TransferCreator::new()
            .create(&omitted, catalog, &owner, 21)
            .is_err()
    );
    Ok(())
}
