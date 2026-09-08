use super::*;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::cli) struct PolicyCatalogV1 {
    version: u16,
    pub(in crate::cli) role_descriptors: Vec<RegistrationRoleDescriptorV1>,
    pub(super) registration_proofs: Vec<RegistrationProofV1>,
    pub(in crate::cli) witness_policies: Vec<WitnessPolicy>,
    pub(in crate::cli) review_label_sets: Vec<jury_core::transfer::ReviewLabelSetV1>,
}

impl PolicyCatalogV1 {
    pub(in crate::cli) const fn empty() -> Self {
        Self {
            version: 1,
            role_descriptors: Vec::new(),
            registration_proofs: Vec::new(),
            witness_policies: Vec::new(),
            review_label_sets: Vec::new(),
        }
    }

    pub(in crate::cli) fn parse_local(bytes: &[u8]) -> Result<Self, CliError> {
        let mut catalog: Self =
            serde_json::from_slice(bytes).map_err(|_| invalid_policy_catalog())?;
        if serde_json::to_vec(&catalog).ok().as_deref() != Some(bytes) {
            return Err(invalid_policy_catalog());
        }
        catalog.validate()?;
        catalog
            .role_descriptors
            .sort_by_key(RegistrationRoleDescriptorV1::principal_id);
        catalog
            .registration_proofs
            .sort_by_key(|proof| proof.candidate_principal_id);
        catalog.witness_policies.sort_by_key(|policy| {
            policy
                .digest()
                .map(|digest| *digest.as_bytes())
                .unwrap_or([0; 32])
        });
        catalog
            .review_label_sets
            .sort_by_key(|set| set.digest.clone());
        Ok(catalog)
    }

    pub(super) fn validate(&self) -> Result<(), CliError> {
        if self.version != 1 {
            return Err(invalid_policy_catalog());
        }
        let mut role_ids = BTreeSet::new();
        for role in &self.role_descriptors {
            match role {
                RegistrationRoleDescriptorV1::VaultPrincipal => {
                    return Err(invalid_policy_catalog());
                }
                RegistrationRoleDescriptorV1::Approver { descriptor } => descriptor
                    .validate()
                    .map_err(|_| invalid_policy_catalog())?,
                RegistrationRoleDescriptorV1::Witness { descriptor } => descriptor
                    .validate()
                    .map_err(|_| invalid_policy_catalog())?,
            }
            let id = role.principal_id().ok_or_else(invalid_policy_catalog)?;
            if !role_ids.insert(id) {
                return Err(invalid_policy_catalog());
            }
        }
        let mut proof_ids = BTreeSet::new();
        for proof in &self.registration_proofs {
            let bytes = proof
                .to_json_bytes()
                .map_err(|_| invalid_policy_catalog())?;
            RegistrationProofV1::parse(&bytes).map_err(|_| invalid_policy_catalog())?;
            let id = proof
                .role_descriptor
                .principal_id()
                .filter(|id| *id == proof.candidate_principal_id)
                .ok_or_else(invalid_policy_catalog)?;
            if !proof_ids.insert(id)
                || !self
                    .role_descriptors
                    .iter()
                    .any(|role| role.principal_id() == Some(id) && role == &proof.role_descriptor)
            {
                return Err(invalid_policy_catalog());
            }
        }
        let mut policy_digests = BTreeSet::new();
        for policy in &self.witness_policies {
            policy.validate().map_err(|_| invalid_policy_catalog())?;
            if !policy_digests.insert(policy.digest().map_err(|_| invalid_policy_catalog())?) {
                return Err(invalid_policy_catalog());
            }
        }
        let mut label_digests = BTreeSet::new();
        for set in &self.review_label_sets {
            set.validate().map_err(|_| invalid_policy_catalog())?;
            if !label_digests.insert(set.digest.clone()) {
                return Err(invalid_policy_catalog());
            }
        }
        Ok(())
    }

    pub(in crate::cli) fn replay_for_vault(
        &self,
        vault: &VaultFileV1,
    ) -> Result<PolicyState, CliError> {
        if matches!(
            &vault.policy.genesis.source_attestation,
            Some(jury_protocol::vault_v1::SourceAttestationV1::Rollover { .. })
        ) {
            self.portable_catalog()?
                .for_vault_with_policy(vault)
                .map(|(_, policy)| policy)
                .map_err(|error| {
                    if error.kind() == jury_core::transfer::TransferErrorKind::InvalidVault {
                        invalid_vault()
                    } else {
                        map_portable_error(error)
                    }
                })
        } else {
            replay_policy_with_witness_policies(&vault.policy, &self.witness_policies)
                .map_err(|_| invalid_vault())
        }
    }

    pub(in crate::cli) fn transfer_catalog(
        &self,
        vault: &VaultFileV1,
    ) -> Result<TransferPublicCatalogV1, CliError> {
        self.portable_catalog()?
            .for_vault(vault)
            .map_err(map_portable_error)
    }

    fn portable_catalog(&self) -> Result<TransferPublicCatalogV1, CliError> {
        let mut proofs = self.registration_proofs.clone();
        proofs.sort_by_key(|proof| proof.candidate_principal_id);
        TransferPublicCatalogV1::with_review_label_sets(
            proofs,
            self.witness_policies.clone(),
            self.review_label_sets.clone(),
        )
        .map_err(map_portable_error)
    }

    pub(in crate::cli) fn merge_transfer(
        &mut self,
        transfer: &TransferPublicCatalogV1,
    ) -> Result<(), CliError> {
        for proof in &transfer.registration_proofs {
            add_catalog_registration_proof(self, proof)?;
        }
        for incoming in &transfer.witness_policies {
            let digest = incoming.digest().map_err(|_| invalid_policy_catalog())?;
            if let Some(existing) = self
                .witness_policies
                .iter()
                .find(|policy| policy.digest().ok().as_ref() == Some(&digest))
            {
                if existing != incoming {
                    return Err(invalid_policy_catalog());
                }
            } else {
                self.witness_policies.push(incoming.clone());
            }
        }
        for incoming in &transfer.review_label_sets {
            if let Some(existing) = self
                .review_label_sets
                .iter()
                .find(|set| set.digest == incoming.digest)
            {
                if existing != incoming {
                    return Err(invalid_policy_catalog());
                }
            } else {
                self.review_label_sets.push(incoming.clone());
            }
        }
        self.witness_policies.sort_by_key(|policy| {
            policy
                .digest()
                .map(|digest| *digest.as_bytes())
                .unwrap_or([0; 32])
        });
        self.review_label_sets.sort_by_key(|set| set.digest.clone());
        self.validate()
    }
}

fn map_portable_error(error: jury_core::transfer::TransferError) -> CliError {
    if error.kind() == jury_core::transfer::TransferErrorKind::MissingRegistrationProof {
        CliError::new(
            CliErrorKind::Conflict,
            "portable-registration-proof-missing",
            "a required active or rollover bootstrap role lacks portable registration proof evidence",
        )
    } else {
        invalid_policy_catalog()
    }
}
