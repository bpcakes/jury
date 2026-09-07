use super::*;
use crate::{
    registration::verify_proof_signatures,
    rollover::direct::{
        direct_digest, direct_recipients, grants, principal_operations, principals,
    },
    transfer::TransferPublicCatalogV1,
    witness_approval::verify_owner_review_label,
};
use jury_protocol::vault_v1::{Digest32, PolicyOperationV1};
use std::collections::BTreeSet;

/// Check the manifest against retained signed bootstrap inputs without an
/// external source vault. Source trust, source completeness and equality of
/// copied plaintext remain separate checks performed by the rollover use case.
pub(crate) fn validate_retained_bootstrap(
    vault: &VaultFileV1,
    catalog: &TransferPublicCatalogV1,
) -> Result<Option<PolicyState>, RolloverError> {
    crate::rollover::migration::verify(vault)?;
    let Some(SourceAttestationV1::Rollover { statement }) =
        &vault.policy.genesis.source_attestation
    else {
        return Ok(None);
    };
    let Some(manifest) = &statement.bootstrap_manifest else {
        // The protocol parser retains the original reserved preimage corpus,
        // but an installation or portable artifact needs complete provenance.
        return Err(invalid());
    };
    crypto::verify_bytes(
        &vault.policy.genesis.owner.verification_public_key,
        &statement.signature_preimage(),
        &statement.signature,
    )
    .map_err(|_| invalid())?;
    let bootstrap = bootstrap_state(vault, &catalog.witness_policies)?;
    let first = vault.policy.revisions.first().ok_or_else(invalid)?;
    let initial = replay_policy(&PolicyJournalV1 {
        genesis: vault.policy.genesis.clone(),
        revisions: Vec::new(),
    })
    .map_err(|_| invalid())?;
    if manifest.digest().map_err(|_| invalid())? != statement.bootstrap_manifest_digest
        || manifest.principals != principals(&bootstrap)?
        || manifest.items.len() != bootstrap.items.len()
        || !bootstrap.tombstones.is_empty()
        || first.author_principal_id != statement.acting_owner_principal_id
        || first.timestamp_ms < manifest.created_at_ms
    {
        return Err(invalid());
    }
    let mut expected = principal_operations(&bootstrap, statement)?;
    for operation in &mut expected {
        if let PolicyOperationV1::PrincipalAdd {
            descriptor,
            registration_proof_digest,
            ..
        } = operation
            && matches!(
                descriptor.principal_kind,
                jury_protocol::vault_v1::PrincipalKind::Approver
                    | jury_protocol::vault_v1::PrincipalKind::Witness
            )
        {
            let proof = catalog
                .registration_proofs
                .iter()
                .find(|proof| proof.candidate_principal_id == descriptor.principal_id)
                .ok_or_else(invalid)?;
            if proof.challenge.issued_at_ms < manifest.created_at_ms
                || proof.challenge.owner_principal_id != statement.acting_owner_principal_id
            {
                return Err(invalid());
            }
            *registration_proof_digest =
                verify_proof_signatures(&initial, &proof.challenge, proof, first.timestamp_ms)
                    .map_err(|_| invalid())?;
        }
    }
    let mut used_policies = BTreeSet::new();
    for entry in &manifest.items {
        let item = bootstrap
            .item(&entry.destination_item_id)
            .ok_or_else(invalid)?;
        if item.key_epoch != 1
            || entry.item_kind != item.item_kind
            || entry.descriptor != item.descriptor
            || entry.initial_item_revision_hash != item.current_item_revision_hash
            || entry.direct_slot_set_digest != direct_digest(&item.direct_slots)?
            || entry.grants != grants(&bootstrap, entry.destination_item_id)?
        {
            return Err(invalid());
        }
        match (&entry.witnessed, &item.witnessed_state) {
            (None, None) => {}
            (Some(binding), Some(state)) => {
                let policy_entry = manifest
                    .witness_policies
                    .iter()
                    .find(|entry| entry.destination_policy_id == binding.policy_id)
                    .ok_or_else(invalid)?;
                if state.slots.len() != 2
                    || state.slots[0].slot_id != binding.descriptor_slot_id
                    || state.slots[1].slot_id != binding.body_slot_id
                    || state.slots.iter().any(|slot| {
                        slot.witness_policy_id != binding.policy_id
                            || slot.witness_policy_revision != 1
                            || slot.vault_policy_sequence != 1
                    })
                {
                    return Err(invalid());
                }
                let policy = bootstrap
                    .witness_policy(&state.slots[0].witness_policy_digest)
                    .ok_or_else(invalid)?;
                let labels = catalog
                    .review_label_sets
                    .iter()
                    .find(|set| set.digest == policy.review_label_set_digest)
                    .map(|set| set.labels.as_slice())
                    .unwrap_or(&[]);
                if jury_protocol::witness_v1::owner_review_label_set_digest(labels)
                    .map_err(|_| invalid())?
                    != policy.review_label_set_digest
                    || policy.revision != 1
                    || policy.vault_policy_sequence != 1
                    || policy.predecessor_policy_digest != Digest32::new([0; 32])
                    || policy.vault_policy_hash != *initial.genesis_fingerprint()
                    || policy.genesis_fingerprint != *initial.genesis_fingerprint()
                    || super::super::witness_intent_digest(policy, labels)?
                        != policy_entry.intent_digest
                {
                    return Err(invalid());
                }
                for label in labels {
                    verify_owner_review_label(&initial, label, 1, first.timestamp_ms)
                        .map_err(|_| invalid())?;
                    if label.label_revision != 1
                        || label.issued_at_ms != manifest.created_at_ms
                        || label.issuer_owner_id != statement.acting_owner_principal_id
                    {
                        return Err(invalid());
                    }
                }
                used_policies.insert(binding.policy_id);
            }
            _ => return Err(invalid()),
        }
        expected.push(PolicyOperationV1::ItemCreate {
            item_id: entry.destination_item_id,
            item_kind: item.item_kind,
            key_epoch: 1,
            descriptor: item.descriptor.clone(),
            current_item_revision_hash: item.current_item_revision_hash.clone(),
            direct_slots: item.direct_slots.clone(),
            witnessed_state: item.witnessed_state.clone(),
        });
        let direct = direct_recipients(&item.direct_slots);
        for (principal_id, role) in &item.grants {
            if !direct.contains(principal_id) {
                expected.push(PolicyOperationV1::ItemRoleChange {
                    item_id: entry.destination_item_id,
                    principal_id: *principal_id,
                    prior_role: None,
                    next_role: Some(*role),
                });
            }
        }
    }
    if expected != first.operations
        || used_policies
            != manifest
                .witness_policies
                .iter()
                .map(|entry| entry.destination_policy_id)
                .collect()
    {
        return Err(invalid());
    }
    Ok(Some(bootstrap))
}
