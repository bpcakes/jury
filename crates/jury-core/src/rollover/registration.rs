use super::*;
use jury_protocol::vault_v1::{PolicyJournalV1, VaultHeaderV1};

impl RolloverSource<'_> {
    /// Active roles that need fresh registration in the next lineage, in
    /// canonical principal order. The catalog is fully authenticated, including
    /// retained bootstrap evidence for roles that are no longer active.
    pub fn required_registration_roles<'a>(
        &self,
        catalog: &'a crate::transfer::TransferPublicCatalogV1,
    ) -> Result<Vec<&'a crate::registration::RegistrationRoleDescriptorV1>, RolloverError> {
        super::governed::roles::validate_source_catalog(self, catalog)?;
        Ok(super::governed::roles::active_proofs(catalog, &self.policy)
            .into_iter()
            .map(|proof| &proof.role_descriptor)
            .collect())
    }

    /// Return the role admitted by the authenticated source journal, rather
    /// than accepting an unrelated signed descriptor from a supplied catalog.
    pub fn source_registration_role<'a>(
        &self,
        catalog: &'a crate::transfer::TransferPublicCatalogV1,
        principal_id: jury_protocol::vault_v1::PrincipalId,
    ) -> Result<&'a crate::registration::RegistrationRoleDescriptorV1, RolloverError> {
        let invalid = || RolloverError::new(RolloverErrorKind::InvalidSource);
        self.required_registration_roles(catalog)?
            .into_iter()
            .find(|role| role.principal_id() == Some(principal_id))
            .ok_or_else(invalid)
    }

    /// Authenticate an unpublished registration context against this exact
    /// source. Its manifest must describe all active source identities, items
    /// and access grants. The returned state is sequence zero, not a completed
    /// bootstrap, and establishes neither destination readiness nor trust.
    pub fn verify_registration_draft(
        &self,
        journal: &PolicyJournalV1,
    ) -> Result<PolicyState, RolloverError> {
        let invalid = || RolloverError::new(RolloverErrorKind::InvalidDestination);
        if !journal.revisions.is_empty() {
            return Err(invalid());
        }
        self.verify_source_authorization(&journal.genesis)?;
        let initial = replay_policy(journal).map_err(|_| invalid())?;
        // Apply the normal bounded protocol/genesis validator, including the
        // optional manifest's actual bytes and destination scope. No item
        // inventory has been published at this sequence-zero stage.
        VaultFileV1 {
            header: VaultHeaderV1 {
                magic: "jury-vault".into(),
                version: 1,
                vault_id: initial.vault_id(),
                created_at_ms: journal.genesis.created_at_ms,
                suite: initial.suite(),
                policy_schema: 1,
                item_schema: 1,
                identity_schema: 1,
                genesis_fingerprint: initial.genesis_fingerprint().clone(),
            },
            policy: journal.clone(),
            items: Vec::new(),
            suite_migration: None,
        }
        .to_json_bytes()
        .map_err(|_| invalid())?;
        let Some(SourceAttestationV1::Rollover { statement }) = &journal.genesis.source_attestation
        else {
            return Err(invalid());
        };
        let manifest = statement.bootstrap_manifest.as_ref().ok_or_else(invalid)?;
        if manifest.principals != super::direct::principals(&self.policy)?
            || manifest.items.len() != self.policy.items.len()
        {
            return Err(invalid());
        }
        for entry in &manifest.items {
            let source = self
                .policy
                .item(&entry.source_item_id)
                .ok_or_else(invalid)?;
            if entry.item_kind != source.item_kind
                || entry.grants != super::direct::grants(&self.policy, entry.source_item_id)?
                || self.policy.item_id_was_used(&entry.destination_item_id)
            {
                return Err(invalid());
            }
            match (&source.witnessed_state, &entry.witnessed) {
                (None, None) => {}
                (Some(state), Some(witnessed)) => {
                    let slot = state.slots.first().ok_or_else(invalid)?;
                    if !manifest.witness_policies.iter().any(|policy| {
                        policy.source_policy_id == slot.witness_policy_id
                            && policy
                                .source_policy_revision
                                .is_none_or(|revision| revision == slot.witness_policy_revision)
                            && policy.destination_policy_id == witnessed.policy_id
                    }) {
                        return Err(invalid());
                    }
                }
                _ => return Err(invalid()),
            }
        }
        if manifest.witness_policies.iter().any(|entry| {
            self.policy
                .witness_policies
                .values()
                .any(|policy| policy.witness_policy_id == entry.destination_policy_id)
        }) {
            return Err(invalid());
        }
        Ok(initial)
    }
}
