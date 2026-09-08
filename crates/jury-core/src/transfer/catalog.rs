use super::*;
use jury_protocol::vault_v1::{PolicyOperationV1, PrincipalDescriptorV1, SourceAttestationV1};

impl TransferPublicCatalogV1 {
    /// Select portable role evidence for this authenticated vault. Ordinary
    /// lineages carry active roles; rollover lineages additionally retain roles
    /// admitted by their first revision, even after removal or replacement.
    pub fn for_vault(&self, vault: &VaultFileV1) -> Result<Self, TransferError> {
        self.for_vault_with_policy(vault)
            .map(|(catalog, _)| catalog)
    }

    /// Return the selected catalog and its authenticated policy together, so
    /// callers need not replay the same full journal again after validation.
    pub fn for_vault_with_policy(
        &self,
        vault: &VaultFileV1,
    ) -> Result<(Self, PolicyState), TransferError> {
        self.validate()?;
        let policy = validate_vault(vault, &self.witness_policies)?;
        let required = required_roles(vault, &policy);
        if required.keys().any(|id| {
            !self
                .registration_proofs
                .iter()
                .any(|proof| &proof.candidate_principal_id == id)
        }) {
            return Err(TransferError::new(
                TransferErrorKind::MissingRegistrationProof,
            ));
        }
        let mut catalog = self.clone();
        catalog
            .registration_proofs
            .retain(|proof| required.contains_key(&proof.candidate_principal_id));
        catalog.validate_for_policy(vault, &policy)?;
        Ok((catalog, policy))
    }

    pub(crate) fn validate_for_policy(
        &self,
        vault: &VaultFileV1,
        policy: &PolicyState,
    ) -> Result<Option<PolicyState>, TransferError> {
        let invalid = || TransferError::new(TransferErrorKind::InvalidCatalog);
        let expected = required_roles(vault, policy);
        let mut supplied = BTreeSet::new();
        for proof in &self.registration_proofs {
            let id = proof.candidate_principal_id;
            let (descriptor, digest) = expected.get(&id).ok_or_else(invalid)?;
            if &proof.challenge.candidate_descriptor != *descriptor
                || proof.digest().map_err(|_| invalid())? != **digest
                || !supplied.insert(id)
            {
                return Err(invalid());
            }
        }
        if supplied != expected.keys().copied().collect() {
            return Err(invalid());
        }
        crate::rollover::validate_retained_bootstrap(vault, self).map_err(|_| invalid())
    }
}

fn required_roles<'a>(
    vault: &'a VaultFileV1,
    policy: &PolicyState,
) -> BTreeMap<PrincipalId, (&'a PrincipalDescriptorV1, &'a Digest32)> {
    let rollover = matches!(
        &vault.policy.genesis.source_attestation,
        Some(SourceAttestationV1::Rollover { statement })
            if statement.bootstrap_manifest.is_some()
    );
    let mut required = BTreeMap::new();
    for revision in &vault.policy.revisions {
        for operation in &revision.operations {
            let (descriptor, digest) = match operation {
                PolicyOperationV1::PrincipalAdd {
                    descriptor,
                    registration_proof_digest,
                    ..
                } => (descriptor, registration_proof_digest),
                PolicyOperationV1::PrincipalReplace {
                    next_descriptor,
                    registration_proof_digest,
                    ..
                } => (next_descriptor, registration_proof_digest),
                _ => continue,
            };
            if matches!(
                descriptor.principal_kind,
                PrincipalKind::Approver | PrincipalKind::Witness
            ) && (policy.principal(&descriptor.principal_id).is_some()
                || (rollover && revision.sequence == 1))
            {
                required.insert(descriptor.principal_id, (descriptor, digest));
            }
        }
    }
    required
}
