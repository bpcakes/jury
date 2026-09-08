use std::collections::{BTreeMap, BTreeSet};

use jury_protected::ProtectionPolicy;
use jury_protocol::{
    rollover_v1::{
        BootstrapItemV1, BootstrapManifestV1, BootstrapWitnessPolicyV1, BootstrapWitnessedItemV1,
    },
    vault_v1::{
        ContentRole, Digest32, FieldId, ItemId, PolicyJournalV1, PolicyOperationV1, PrincipalKind,
        RolloverId, Signature64, SignedRolloverV1, SourceAttestationV1, VaultFileV1, VaultHeaderV1,
        WitnessPolicyId,
    },
};

use super::direct::{
    OpenedItem, direct_digest, direct_recipients, grants, open_part, principal_operations,
    principals,
};
use super::{RolloverError, RolloverErrorKind, RolloverSource};
use crate::{
    access_provider::{CancellationCheck, ItemAccessProvider},
    domain::NativeIdGenerator,
    identity::VaultPrincipalIdentity,
    item::{
        ItemAccessPlan, ItemArtifactInventory, ItemCreator, ItemGrant, NewItem, StagedItemCreation,
    },
    policy::{
        PolicyCreator, PolicyState, WitnessPolicy, replay_policy,
        replay_policy_with_witness_policies,
    },
    registration::{
        RegistrationChallengeV1, RegistrationCreator, RegistrationProofV1,
        RegistrationRoleDescriptorV1, verify_proof, verify_proof_signatures,
    },
    transfer::{ReviewLabelSetV1, TransferPublicCatalogV1},
};

mod prepare;
pub(super) mod roles;
mod templates;
#[cfg(test)]
mod tests;
mod verify;

fn invalid() -> RolloverError {
    RolloverError::new(RolloverErrorKind::InvalidDestination)
}
fn failed() -> RolloverError {
    RolloverError::new(RolloverErrorKind::PreparationFailed)
}
fn source_invalid() -> RolloverError {
    RolloverError::new(RolloverErrorKind::InvalidSource)
}

#[derive(Clone, Copy)]
pub struct GovernedRolloverOptions {
    pub created_at_ms: u64,
    pub registration_lifetime_ms: u64,
    pub protection: ProtectionPolicy,
}

/// An in-memory candidate with encrypted item content and protected capsule
/// secrets. Its genesis is final, so candidates can answer the exposed fresh
/// registration challenges. This is not a usable vault or a readiness claim.
/// Dropping the draft destroys its protected pending item secrets.
pub struct GovernedRolloverDraft {
    protection: ProtectionPolicy,
    journal: PolicyJournalV1,
    context: PolicyState,
    creator: ItemCreator,
    staged: Vec<(StagedItemCreation, ItemAccessPlan)>,
    policies: Vec<WitnessPolicy>,
    labels: Vec<ReviewLabelSetV1>,
    challenges: Vec<RegistrationChallengeV1>,
    prior_roles: Vec<RegistrationRoleDescriptorV1>,
}

/// Complete authenticated bootstrap and portable public catalog. Publishing,
/// external trust, backup, endpoint registration, replay-state durability and
/// an external anchor are separate requirements before witnessed readiness.
pub struct PreparedGovernedRollover {
    vault: VaultFileV1,
    catalog: TransferPublicCatalogV1,
}

impl PreparedGovernedRollover {
    #[must_use]
    pub const fn vault(&self) -> &VaultFileV1 {
        &self.vault
    }
    #[must_use]
    pub const fn catalog(&self) -> &TransferPublicCatalogV1 {
        &self.catalog
    }
}

impl GovernedRolloverDraft {
    #[must_use]
    pub const fn registration_journal(&self) -> &PolicyJournalV1 {
        &self.journal
    }
    #[must_use]
    pub fn challenges(&self) -> &[RegistrationChallengeV1] {
        &self.challenges
    }
    #[must_use]
    pub fn prior_roles(&self) -> &[RegistrationRoleDescriptorV1] {
        &self.prior_roles
    }

    /// Replace expired registration challenges while preserving genesis and
    /// all staged content. Source approvals may take longer than the initial
    /// challenge lifetime. Prior challenge responses cannot satisfy the renewed
    /// challenges, and an invalid renewal leaves the current set intact.
    pub fn renew_registration_challenges(
        &mut self,
        owner: &VaultPrincipalIdentity,
        issued_at_ms: u64,
        lifetime_ms: u64,
    ) -> Result<(), RolloverError> {
        templates::ensure_label_lifetime(
            self.labels.iter().flat_map(|set| &set.labels),
            issued_at_ms,
            lifetime_ms,
        )?;
        if issued_at_ms < self.journal.genesis.created_at_ms
            || self
                .challenges
                .iter()
                .any(|challenge| issued_at_ms < challenge.issued_at_ms)
            || self.challenges.len() != self.prior_roles.len()
        {
            return Err(invalid());
        }
        let initial = replay_policy(&self.journal).map_err(|_| invalid())?;
        let mut creator = RegistrationCreator::new(self.protection);
        let mut renewed = Vec::with_capacity(self.challenges.len());
        for (prior, role) in self.challenges.iter().zip(&self.prior_roles) {
            let share_index = match role {
                RegistrationRoleDescriptorV1::Witness { descriptor } => {
                    Some(descriptor.share_index)
                }
                RegistrationRoleDescriptorV1::Approver { .. } => None,
                RegistrationRoleDescriptorV1::VaultPrincipal => return Err(invalid()),
            };
            let challenge = creator
                .create_challenge(
                    &initial,
                    owner,
                    prior.candidate_descriptor.clone(),
                    issued_at_ms,
                    lifetime_ms,
                    share_index,
                )
                .map_err(|_| failed())?;
            if challenge.challenge_id == prior.challenge_id {
                return Err(failed());
            }
            renewed.push(challenge);
        }
        self.challenges = renewed;
        Ok(())
    }

    /// Check collected proofs while retaining the exact pending candidate.
    /// Adapters can replace a missing or invalid response and retry this check
    /// without regenerating genesis or losing the protected pending content.
    pub fn verify_registration_proofs(
        &self,
        owner: &VaultPrincipalIdentity,
        proofs: &[RegistrationProofV1],
        now_ms: u64,
    ) -> Result<(), RolloverError> {
        let initial = replay_policy(&self.journal).map_err(|_| invalid())?;
        roles::verify_fresh_roles(
            &initial,
            &self.challenges,
            &self.prior_roles,
            proofs,
            now_ms,
        )?;
        for (challenge, proof) in self.challenges.iter().zip(proofs) {
            verify_proof(&initial, owner, challenge, proof, now_ms).map_err(|_| invalid())?;
        }
        Ok(())
    }

    /// Validate one named candidate response for diagnostic polling. Completion
    /// still verifies the whole ordered set at its actual admission time.
    pub fn verify_registration_proof(
        &self,
        owner: &VaultPrincipalIdentity,
        candidate: jury_protocol::vault_v1::PrincipalId,
        proof: &RegistrationProofV1,
        now_ms: u64,
    ) -> Result<(), RolloverError> {
        let index = self
            .challenges
            .iter()
            .position(|challenge| challenge.candidate_descriptor.principal_id == candidate)
            .ok_or_else(invalid)?;
        let challenge = &self.challenges[index];
        let prior = self.prior_roles.get(index).ok_or_else(invalid)?;
        let initial = replay_policy(&self.journal).map_err(|_| invalid())?;
        roles::verify_fresh_roles(
            &initial,
            std::slice::from_ref(challenge),
            std::slice::from_ref(prior),
            std::slice::from_ref(proof),
            now_ms,
        )?;
        verify_proof(&initial, owner, challenge, proof, now_ms).map_err(|_| invalid())?;
        Ok(())
    }

    /// Consume this exact candidate once. Every active source role must provide
    /// a fresh proof for its exposed challenge. Actual owner-side decapsulation
    /// and response-MAC verification precede bootstrap signing.
    pub fn complete(
        mut self,
        source: &RolloverSource<'_>,
        source_catalog: &TransferPublicCatalogV1,
        owner: &VaultPrincipalIdentity,
        proofs: Vec<RegistrationProofV1>,
        now_ms: u64,
        cancellation: &dyn CancellationCheck,
    ) -> Result<PreparedGovernedRollover, RolloverError> {
        if cancellation.is_cancelled() {
            return Err(failed());
        }
        source.verify_source_authorization(&self.journal.genesis)?;
        self.verify_registration_proofs(owner, &proofs, now_ms)?;
        let Some(SourceAttestationV1::Rollover { statement }) =
            &self.journal.genesis.source_attestation
        else {
            return Err(invalid());
        };
        let mut operations = roles::principal_operations(&source.policy, statement, &proofs)?;
        let mut envelopes = Vec::with_capacity(self.staged.len());
        for (staged, access) in self.staged {
            if cancellation.is_cancelled() {
                return Err(failed());
            }
            let component = self
                .creator
                .finish_create(&self.context, staged, access)
                .map_err(|_| failed())?;
            operations.extend(component.operations);
            envelopes.push(component.envelope);
        }
        envelopes.sort_by_key(|envelope| envelope.item_id);
        let initial = replay_policy_with_witness_policies(&self.journal, &self.policies)
            .map_err(|_| invalid())?;
        let revision = initial
            .prepare_revision(owner, now_ms, operations)
            .map_err(|_| failed())?;
        self.journal.revisions.push(revision.revision);
        let mut vault = VaultFileV1 {
            header: VaultHeaderV1 {
                magic: "jury-vault".into(),
                version: 1,
                vault_id: initial.vault_id(),
                created_at_ms: self.journal.genesis.created_at_ms,
                suite: initial.suite(),
                policy_schema: 1,
                item_schema: 1,
                identity_schema: 1,
                genesis_fingerprint: initial.genesis_fingerprint().clone(),
            },
            policy: self.journal,
            items: envelopes,
            suite_migration: None,
        };
        super::migration::attach(&mut vault, owner)?;
        self.policies.sort_by_key(|policy| policy.digest().ok());
        let catalog =
            TransferPublicCatalogV1::with_review_label_sets(proofs, self.policies, self.labels)
                .map_err(|_| invalid())?;
        source.verify_fresh_governed_destination(source_catalog, &vault, &catalog)?;
        if cancellation.is_cancelled() {
            return Err(failed());
        }
        Ok(PreparedGovernedRollover { vault, catalog })
    }
}
