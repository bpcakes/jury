use super::*;
use jury_protocol::vault_v1::RemovalReason;

pub(super) fn verify_after_removal(
    source: &RolloverSource<'_>,
    fixture: &Fixture,
    owner: &VaultPrincipalIdentity,
    prepared: &PreparedGovernedRollover,
) -> TestResult {
    let mut vault = prepared.vault().clone();
    let catalog = prepared.catalog();
    let policy = replay_policy_with_witness_policies(&vault.policy, &catalog.witness_policies)?;
    let delete = policy.prepare_revision(
        owner,
        100_003,
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
    vault.policy.revisions.push(delete.revision);
    vault.items.clear();
    let removed = catalog.registration_proofs[0].candidate_principal_id;
    vault.policy.revisions.push(
        delete
            .state
            .prepare_revision(
                owner,
                100_004,
                vec![PolicyOperationV1::PrincipalRemove {
                    principal_id: removed,
                    removal_reason: RemovalReason::Retirement,
                }],
            )?
            .revision,
    );
    source.verify_historical_governed_destination(&fixture.catalog, &vault, catalog)?;
    assert!(
        source
            .verify_fresh_governed_destination(&fixture.catalog, &vault, catalog)
            .is_err()
    );
    let portable = catalog.for_vault(&vault)?;
    assert_eq!(portable.registration_proofs, catalog.registration_proofs);
    let transfer =
        crate::transfer::TransferCreator::new().create(&vault, portable, owner, 100_005)?;
    let parsed = crate::transfer::ValidatedTransfer::parse(&transfer.to_json_bytes()?)?;
    source.verify_historical_governed_destination(
        &fixture.catalog,
        parsed.vault(),
        parsed.catalog(),
    )?;

    for kind in 0..3 {
        let mut missing = catalog.clone();
        match kind {
            0 => {
                missing.registration_proofs.remove(0);
            }
            1 => missing.witness_policies.clear(),
            _ => missing.review_label_sets.clear(),
        }
        assert!(
            missing.for_vault(&vault).is_err(),
            "missing retained input {kind}"
        );
        assert!(
            crate::transfer::TransferCreator::new()
                .create(&vault, missing, owner, 100_005)
                .is_err()
        );
    }

    // Ordinary suite-1 lineages keep their prior active-only transfer contract.
    let mut ordinary = fixture.vault.clone();
    let policy =
        replay_policy_with_witness_policies(&ordinary.policy, &fixture.catalog.witness_policies)?;
    let deletion = policy.prepare_revision(
        owner,
        100_003,
        policy
            .items
            .iter()
            .map(|(id, item)| PolicyOperationV1::ItemDelete {
                item_id: *id,
                final_descriptor_digest: item.descriptor.ciphertext_digest.clone(),
                final_item_revision_hash: item.current_item_revision_hash.clone(),
                deletion_policy_sequence: policy.sequence() + 1,
            })
            .collect(),
    )?;
    ordinary.policy.revisions.push(deletion.revision);
    ordinary.items.clear();
    ordinary.policy.revisions.push(
        deletion
            .state
            .prepare_revision(
                owner,
                100_004,
                vec![PolicyOperationV1::PrincipalRemove {
                    principal_id: removed,
                    removal_reason: RemovalReason::Retirement,
                }],
            )?
            .revision,
    );
    let selected = fixture.catalog.for_vault(&ordinary)?;
    assert_eq!(selected.registration_proofs.len(), 1);
    assert_ne!(
        selected.registration_proofs[0].candidate_principal_id,
        removed
    );
    crate::transfer::TransferCreator::new().create(&ordinary, selected, owner, 100_005)?;

    // A subsequent rollover re-admits only the remaining active witness, even
    // though the source catalog must retain both original bootstrap proofs.
    let next_source = RolloverSource::validate(&vault, &catalog.witness_policies)?;
    assert!(
        next_source
            .source_registration_role(catalog, removed)
            .is_err()
    );
    let mut provider = AdministrativeProvider {
        direct: DirectItemAccessProvider::new(owner),
        roles: Vec::new(),
    };
    let draft = next_source.prepare_governed(
        catalog,
        owner,
        &mut provider,
        GovernedRolloverOptions {
            created_at_ms: 100_006,
            registration_lifetime_ms: 60_000,
            protection: PROTECTION,
        },
        &NeverCancelled,
    )?;
    assert!(provider.roles.is_empty());
    assert_eq!(draft.challenges().len(), 1);
    assert_ne!(
        draft.challenges()[0].candidate_descriptor.principal_id,
        removed
    );
    let initial = next_source.verify_registration_draft(draft.registration_journal())?;
    let identity = fixture
        .identities
        .iter()
        .find(|identity| {
            identity
                .public_descriptor()
                .is_ok_and(|descriptor| descriptor == draft.challenges()[0].candidate_descriptor)
        })
        .ok_or("missing active fixture identity")?;
    let proof = answer_rollover_challenge(
        &initial,
        identity,
        &draft.challenges()[0],
        &draft.prior_roles()[0],
        100_007,
    )?;
    let next = draft.complete(
        &next_source,
        catalog,
        owner,
        vec![proof],
        100_008,
        &NeverCancelled,
    )?;
    next_source.verify_fresh_governed_destination(catalog, next.vault(), next.catalog())?;
    assert_eq!(next.catalog().registration_proofs.len(), 1);
    assert_eq!(next.vault().header.suite, vault.header.suite);
    assert!(next.vault().suite_migration.is_none());
    assert_ne!(
        next.catalog().registration_proofs[0].candidate_principal_id,
        removed
    );
    Ok(())
}
