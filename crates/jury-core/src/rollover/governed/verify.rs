use super::*;

mod scopes;

impl RolloverSource<'_> {
    /// Authenticate a complete first governed bootstrap against the exact
    /// source. This verifies public provenance and copied authority structure;
    /// plaintext equivalence is established by the constructor's actual opens,
    /// not by a claim that public ciphertext inspection proves equal values.
    pub fn verify_fresh_governed_destination(
        &self,
        source_catalog: &TransferPublicCatalogV1,
        vault: &VaultFileV1,
        catalog: &TransferPublicCatalogV1,
    ) -> Result<(), RolloverError> {
        if vault.policy.revisions.len() != 1 {
            return Err(invalid());
        }
        self.verify_governed_destination(source_catalog, vault, catalog, true)
    }

    /// Authenticate the initial governed authority after later mutations,
    /// including item deletion and role removal. Requires retained bootstrap
    /// proofs, policies and labels; does not assert current endpoint readiness.
    pub fn verify_historical_governed_destination(
        &self,
        source_catalog: &TransferPublicCatalogV1,
        vault: &VaultFileV1,
        catalog: &TransferPublicCatalogV1,
    ) -> Result<(), RolloverError> {
        self.verify_governed_destination(source_catalog, vault, catalog, false)
    }

    fn verify_governed_destination(
        &self,
        source_catalog: &TransferPublicCatalogV1,
        vault: &VaultFileV1,
        catalog: &TransferPublicCatalogV1,
        fresh: bool,
    ) -> Result<(), RolloverError> {
        roles::validate_source_catalog(self, source_catalog)?;
        self.verify_source_authorization(&vault.policy.genesis)?;
        let destination = RolloverSource::validate(vault, &catalog.witness_policies)?;
        catalog.to_json_bytes().map_err(|_| invalid())?;
        catalog
            .validate_for_policy(vault, &destination.policy)
            .map_err(|_| invalid())?;
        let bootstrap = super::super::bootstrap_state(vault, &catalog.witness_policies)?;
        let selected = bootstrap_catalog(catalog, &bootstrap)?;
        if fresh && &selected != catalog {
            return Err(invalid());
        }
        let catalog = &selected;
        let prior_proofs = roles::active_proofs(source_catalog, &self.policy);
        let Some(SourceAttestationV1::Rollover { statement }) =
            &vault.policy.genesis.source_attestation
        else {
            return Err(invalid());
        };
        let manifest = statement.bootstrap_manifest.as_ref().ok_or_else(invalid)?;
        if manifest.digest().map_err(|_| invalid())? != statement.bootstrap_manifest_digest
            || manifest.principals != principals(&self.policy)?
            || bootstrap.principals != self.policy.principals
            || bootstrap.owners != self.policy.owners
            || !bootstrap.tombstones.is_empty()
            || manifest.items.len() != self.policy.items.len()
            || manifest.items.len() != bootstrap.items.len()
            || catalog.registration_proofs.len() != prior_proofs.len()
            || catalog.witness_policies.len() != manifest.witness_policies.len()
        {
            return Err(invalid());
        }
        let revision = &vault.policy.revisions[0];
        if revision.author_principal_id != statement.acting_owner_principal_id
            || revision.timestamp_ms < manifest.created_at_ms
        {
            return Err(invalid());
        }
        let initial = replay_policy(&PolicyJournalV1 {
            genesis: vault.policy.genesis.clone(),
            revisions: Vec::new(),
        })
        .map_err(|_| invalid())?;
        let challenges = catalog
            .registration_proofs
            .iter()
            .map(|proof| proof.challenge.clone())
            .collect::<Vec<_>>();
        let prior_roles = prior_proofs
            .iter()
            .map(|proof| proof.role_descriptor.clone())
            .collect::<Vec<_>>();
        for (prior, proof) in prior_proofs.iter().zip(&catalog.registration_proofs) {
            if proof.challenge.issued_at_ms < manifest.created_at_ms
                || proof.challenge.candidate_descriptor != prior.challenge.candidate_descriptor
                || proof.challenge.owner_principal_id != statement.acting_owner_principal_id
                || proof.challenge.challenge_id == prior.challenge.challenge_id
            {
                return Err(invalid());
            }
        }
        roles::verify_fresh_roles(
            &initial,
            &challenges,
            &prior_roles,
            &catalog.registration_proofs,
            revision.timestamp_ms,
        )?;
        let mut operations =
            roles::principal_operations(&self.policy, statement, &catalog.registration_proofs)?;
        for entry in &manifest.items {
            let source = self
                .policy
                .item(&entry.source_item_id)
                .ok_or_else(invalid)?;
            let item = bootstrap
                .item(&entry.destination_item_id)
                .ok_or_else(invalid)?;
            if self.policy.item_id_was_used(&entry.destination_item_id)
                || item.item_kind != source.item_kind
                || entry.item_kind != item.item_kind
                || item.key_epoch != 1
                || item.grants != source.grants
                || entry.descriptor != item.descriptor
                || entry.initial_item_revision_hash != item.current_item_revision_hash
                || entry.direct_slot_set_digest != direct_digest(&item.direct_slots)?
                || entry.grants != grants(&self.policy, entry.source_item_id)?
                || entry.grants != grants(&bootstrap, entry.destination_item_id)?
            {
                return Err(invalid());
            }
            if fresh {
                super::super::verify_fresh_envelope(
                    vault,
                    entry,
                    statement,
                    manifest.created_at_ms,
                )?;
            }
            match (
                &source.witnessed_state,
                &item.witnessed_state,
                &entry.witnessed,
            ) {
                (None, None, None) => {}
                (Some(prior), Some(next), Some(binding)) => {
                    let source_slot = prior.slots.first().ok_or_else(invalid)?;
                    let policy = manifest
                        .witness_policies
                        .iter()
                        .find(|policy| {
                            policy.source_policy_id == source_slot.witness_policy_id
                                && policy.source_policy_revision.is_none_or(|revision| {
                                    revision == source_slot.witness_policy_revision
                                })
                                && policy.destination_policy_id == binding.policy_id
                        })
                        .ok_or_else(invalid)?;
                    if next.slots.len() != 2
                        || next.slots[0].slot_id != binding.descriptor_slot_id
                        || next.slots[1].slot_id != binding.body_slot_id
                        || next.slots.iter().any(|slot| {
                            slot.witness_policy_id != policy.destination_policy_id
                                || slot.witness_policy_revision != 1
                                || slot.vault_policy_sequence != 1
                        })
                    {
                        return Err(invalid());
                    }
                }
                _ => return Err(invalid()),
            }
            operations.push(PolicyOperationV1::ItemCreate {
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
                    operations.push(PolicyOperationV1::ItemRoleChange {
                        item_id: entry.destination_item_id,
                        principal_id: *principal_id,
                        prior_role: None,
                        next_role: Some(*role),
                    });
                }
            }
        }
        if revision.operations != operations
            || (fresh
                && !ItemArtifactInventory::from_vault(self.vault)
                    .map_err(|_| invalid())?
                    .is_disjoint(&ItemArtifactInventory::from_vault(vault).map_err(|_| invalid())?))
        {
            return Err(invalid());
        }
        scopes::verify(
            self,
            source_catalog,
            &initial,
            manifest,
            catalog,
            revision.timestamp_ms,
        )?;
        Ok(())
    }
}

fn bootstrap_catalog(
    catalog: &TransferPublicCatalogV1,
    bootstrap: &PolicyState,
) -> Result<TransferPublicCatalogV1, RolloverError> {
    let digests = bootstrap
        .items
        .values()
        .filter_map(|item| item.witnessed_state.as_ref())
        .flat_map(|state| {
            state
                .slots
                .iter()
                .map(|slot| slot.witness_policy_digest.clone())
        })
        .collect::<BTreeSet<_>>();
    let mut selected = catalog.clone();
    selected
        .registration_proofs
        .retain(|proof| bootstrap.principal(&proof.candidate_principal_id).is_some());
    selected.witness_policies.retain(|policy| {
        policy
            .digest()
            .is_ok_and(|digest| digests.contains(&digest))
    });
    let labels = selected
        .witness_policies
        .iter()
        .map(|policy| policy.review_label_set_digest.clone())
        .collect::<BTreeSet<_>>();
    selected
        .review_label_sets
        .retain(|set| labels.contains(&set.digest));
    selected.to_json_bytes().map_err(|_| invalid())?;
    Ok(selected)
}
