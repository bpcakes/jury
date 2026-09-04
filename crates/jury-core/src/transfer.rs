//! Authenticated vault-only transfer creation and public validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use jury_protected::{OsRandom, RandomSource};
use jury_protocol::transfer_v1::{
    ParsedTransferEnvelopeV1, TransferCatalogBytes, TransferEnvelopeV1, TransferVaultBytes,
};
use jury_protocol::vault_v1::{
    Digest32, FixedBytes, ItemEnvelopeV1, ItemId, PrincipalId, PrincipalKind, Signature64,
    VaultFileV1,
};
use jury_protocol::witness_v1::{OwnerReviewLabelV1, owner_review_label_set_digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::canonical;
use crate::identity::VaultPrincipalIdentity;
use crate::local_state::CheckpointCandidate;
use crate::policy::{PolicyState, WitnessPolicy, replay_policy_with_witness_policies};
use crate::registration::{RegistrationProofV1, RegistrationRoleDescriptorV1};
use crate::{crypto, identity::IdentityErrorKind};

const MAX_TRANSFER_ID_ATTEMPTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferErrorKind {
    InvalidFormat,
    InvalidCatalog,
    InvalidVault,
    UnauthorizedExporter,
    AuthenticationFailed,
    EntropyUnavailable,
    ProtectionUnavailable,
    CapacityExhausted,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TransferError {
    kind: TransferErrorKind,
}

impl TransferError {
    const fn new(kind: TransferErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> TransferErrorKind {
        self.kind
    }
}

impl fmt::Debug for TransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransferError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for TransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            TransferErrorKind::InvalidFormat => "transfer format is invalid",
            TransferErrorKind::InvalidCatalog => "transfer public policy catalog is invalid",
            TransferErrorKind::InvalidVault => "transfer vault state is invalid",
            TransferErrorKind::UnauthorizedExporter => "transfer exporter is not active",
            TransferErrorKind::AuthenticationFailed => "transfer signature is invalid",
            TransferErrorKind::EntropyUnavailable => "transfer identifier entropy is unavailable",
            TransferErrorKind::ProtectionUnavailable => {
                "transfer signing protection is unavailable"
            }
            TransferErrorKind::CapacityExhausted => "transfer exceeds a hard capacity",
        })
    }
}

impl std::error::Error for TransferError {}

/// Public policy material required to replay witnessed vault state on a fresh
/// installation. It deliberately excludes every identity-private and local
/// custody file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferPublicCatalogV1 {
    pub version: u16,
    pub registration_proofs: Vec<RegistrationProofV1>,
    pub witness_policies: Vec<WitnessPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_label_sets: Vec<ReviewLabelSetV1>,
}

/// One complete owner-signed review-label set addressed by its policy digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLabelSetV1 {
    pub digest: Digest32,
    pub labels: Vec<OwnerReviewLabelV1>,
}

impl ReviewLabelSetV1 {
    pub fn new(mut labels: Vec<OwnerReviewLabelV1>) -> Result<Self, TransferError> {
        labels.sort_by_key(|label| label.label_id);
        let digest = owner_review_label_set_digest(&labels)
            .map_err(|_| TransferError::new(TransferErrorKind::InvalidCatalog))?;
        let set = Self { digest, labels };
        set.validate()?;
        Ok(set)
    }

    fn validate(&self) -> Result<(), TransferError> {
        if self
            .labels
            .windows(2)
            .any(|pair| pair[0].label_id >= pair[1].label_id)
            || self
                .labels
                .iter()
                .any(|label| label.validate_shape().is_err())
            || owner_review_label_set_digest(&self.labels).ok().as_ref() != Some(&self.digest)
        {
            return Err(TransferError::new(TransferErrorKind::InvalidCatalog));
        }
        Ok(())
    }
}

impl TransferPublicCatalogV1 {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            version: 1,
            registration_proofs: Vec::new(),
            witness_policies: Vec::new(),
            review_label_sets: Vec::new(),
        }
    }

    pub fn new(
        registration_proofs: Vec<RegistrationProofV1>,
        witness_policies: Vec<WitnessPolicy>,
    ) -> Result<Self, TransferError> {
        let catalog = Self {
            version: 1,
            registration_proofs,
            witness_policies,
            review_label_sets: Vec::new(),
        };
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn with_review_label_sets(
        registration_proofs: Vec<RegistrationProofV1>,
        witness_policies: Vec<WitnessPolicy>,
        mut review_label_sets: Vec<ReviewLabelSetV1>,
    ) -> Result<Self, TransferError> {
        review_label_sets.sort_by_key(|set| set.digest.clone());
        let catalog = Self {
            version: 1,
            registration_proofs,
            witness_policies,
            review_label_sets,
        };
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, TransferError> {
        let catalog: Self = canonical::deserialize_json(bytes)
            .map_err(|_| TransferError::new(TransferErrorKind::InvalidCatalog))?;
        catalog.validate()?;
        if catalog.to_json_bytes()? != bytes {
            return Err(TransferError::new(TransferErrorKind::InvalidCatalog));
        }
        Ok(catalog)
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, TransferError> {
        self.validate()?;
        canonical::compact_json_bytes(self, None)
            .map_err(|_| TransferError::new(TransferErrorKind::InvalidCatalog))
    }

    fn validate(&self) -> Result<(), TransferError> {
        self.validate_entries()?;
        let mut prior_principal = None;
        for proof in &self.registration_proofs {
            let id = proof
                .role_descriptor
                .principal_id()
                .ok_or_else(|| TransferError::new(TransferErrorKind::InvalidCatalog))?;
            if id != proof.candidate_principal_id
                || prior_principal.is_some_and(|prior| prior >= id)
            {
                return Err(TransferError::new(TransferErrorKind::InvalidCatalog));
            }
            prior_principal = Some(id);
        }
        let mut prior_digest: Option<Digest32> = None;
        for policy in &self.witness_policies {
            let digest = policy
                .digest()
                .map_err(|_| TransferError::new(TransferErrorKind::InvalidCatalog))?;
            if prior_digest.as_ref().is_some_and(|prior| prior >= &digest) {
                return Err(TransferError::new(TransferErrorKind::InvalidCatalog));
            }
            prior_digest = Some(digest);
        }
        let mut prior_label_digest: Option<Digest32> = None;
        for set in &self.review_label_sets {
            set.validate()?;
            if prior_label_digest
                .as_ref()
                .is_some_and(|prior| prior >= &set.digest)
            {
                return Err(TransferError::new(TransferErrorKind::InvalidCatalog));
            }
            prior_label_digest = Some(set.digest.clone());
        }
        Ok(())
    }

    fn validate_entries(&self) -> Result<(), TransferError> {
        if self.version != 1 {
            return Err(TransferError::new(TransferErrorKind::InvalidCatalog));
        }
        let mut role_ids = BTreeSet::new();
        for proof in &self.registration_proofs {
            let bytes = proof
                .to_json_bytes()
                .map_err(|_| TransferError::new(TransferErrorKind::InvalidCatalog))?;
            if RegistrationProofV1::parse(&bytes).is_err() {
                return Err(TransferError::new(TransferErrorKind::InvalidCatalog));
            }
            match &proof.role_descriptor {
                RegistrationRoleDescriptorV1::VaultPrincipal => {
                    return Err(TransferError::new(TransferErrorKind::InvalidCatalog));
                }
                RegistrationRoleDescriptorV1::Approver { descriptor } => descriptor
                    .validate()
                    .map_err(|_| TransferError::new(TransferErrorKind::InvalidCatalog))?,
                RegistrationRoleDescriptorV1::Witness { descriptor } => descriptor
                    .validate()
                    .map_err(|_| TransferError::new(TransferErrorKind::InvalidCatalog))?,
            }
            let id = proof
                .role_descriptor
                .principal_id()
                .ok_or_else(|| TransferError::new(TransferErrorKind::InvalidCatalog))?;
            if !role_ids.insert(id) {
                return Err(TransferError::new(TransferErrorKind::InvalidCatalog));
            }
        }
        let mut policy_digests = BTreeSet::new();
        for policy in &self.witness_policies {
            policy
                .validate()
                .map_err(|_| TransferError::new(TransferErrorKind::InvalidCatalog))?;
            let digest = policy
                .digest()
                .map_err(|_| TransferError::new(TransferErrorKind::InvalidCatalog))?;
            if !policy_digests.insert(digest) {
                return Err(TransferError::new(TransferErrorKind::InvalidCatalog));
            }
        }
        Ok(())
    }

    fn validate_for_policy(
        &self,
        vault: &VaultFileV1,
        policy: &PolicyState,
    ) -> Result<(), TransferError> {
        let mut expected = BTreeMap::new();
        for revision in &vault.policy.revisions {
            for operation in &revision.operations {
                match operation {
                    jury_protocol::vault_v1::PolicyOperationV1::PrincipalAdd {
                        descriptor,
                        registration_proof_digest,
                        ..
                    } => {
                        expected.insert(descriptor.principal_id, registration_proof_digest.clone());
                    }
                    jury_protocol::vault_v1::PolicyOperationV1::PrincipalRemove {
                        principal_id,
                        ..
                    } => {
                        expected.remove(principal_id);
                    }
                    jury_protocol::vault_v1::PolicyOperationV1::PrincipalReplace {
                        prior_principal_id,
                        next_descriptor,
                        registration_proof_digest,
                    } => {
                        expected.remove(prior_principal_id);
                        expected.insert(
                            next_descriptor.principal_id,
                            registration_proof_digest.clone(),
                        );
                    }
                    _ => {}
                }
            }
        }

        let mut supplied = BTreeSet::new();
        for proof in &self.registration_proofs {
            let principal_id = proof.candidate_principal_id;
            let principal = policy
                .principal(&principal_id)
                .ok_or_else(|| TransferError::new(TransferErrorKind::InvalidCatalog))?;
            let expected_digest = expected
                .get(&principal_id)
                .ok_or_else(|| TransferError::new(TransferErrorKind::InvalidCatalog))?;
            if proof.challenge.candidate_descriptor != principal.descriptor
                || proof
                    .digest()
                    .map_err(|_| TransferError::new(TransferErrorKind::InvalidCatalog))?
                    != *expected_digest
                || !supplied.insert(principal_id)
            {
                return Err(TransferError::new(TransferErrorKind::InvalidCatalog));
            }
        }
        if policy.principals().any(|(principal_id, principal)| {
            matches!(
                principal.descriptor.principal_kind,
                PrincipalKind::Approver | PrincipalKind::Witness
            ) && !supplied.contains(principal_id)
        }) {
            return Err(TransferError::new(TransferErrorKind::InvalidCatalog));
        }
        Ok(())
    }
}

pub struct TransferCreator<R = OsRandom> {
    source: R,
}

impl TransferCreator<OsRandom> {
    #[must_use]
    pub const fn new() -> Self {
        Self { source: OsRandom }
    }
}

impl Default for TransferCreator<OsRandom> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: RandomSource> TransferCreator<R> {
    #[cfg(test)]
    pub(crate) const fn from_source(source: R) -> Self {
        Self { source }
    }

    pub fn create(
        &mut self,
        vault: &VaultFileV1,
        catalog: TransferPublicCatalogV1,
        exporter: &VaultPrincipalIdentity,
        created_at_ms: u64,
    ) -> Result<TransferEnvelopeV1, TransferError> {
        if created_at_ms == 0 {
            return Err(TransferError::new(TransferErrorKind::InvalidFormat));
        }
        let vault_bytes = vault
            .to_json_bytes()
            .map_err(|_| TransferError::new(TransferErrorKind::InvalidVault))?;
        let policy = validate_vault(vault, &catalog.witness_policies)?;
        catalog.validate_for_policy(vault, &policy)?;
        require_exporter(&policy, exporter.principal_id())?;
        let catalog_bytes = catalog.to_json_bytes()?;
        let transfer_id = self.draw_transfer_id()?;
        let vault_digest = sha256(&vault_bytes);
        let catalog_digest = sha256(&catalog_bytes);
        let mut envelope = TransferEnvelopeV1 {
            magic: "jury-transfer".to_owned(),
            version: 1,
            transfer_id,
            created_at_ms,
            source_vault_id: vault.header.vault_id,
            source_genesis_fingerprint: vault.header.genesis_fingerprint.clone(),
            source_public_revision_hash: policy.terminal_revision_hash().clone(),
            vault_digest,
            catalog_digest,
            exporting_principal_id: exporter.principal_id(),
            vault_json: TransferVaultBytes::new(vault_bytes)
                .map_err(|_| TransferError::new(TransferErrorKind::CapacityExhausted))?,
            public_catalog_json: TransferCatalogBytes::new(catalog_bytes)
                .map_err(|_| TransferError::new(TransferErrorKind::CapacityExhausted))?,
            exporter_signature: Signature64::new([0; 64]),
        };
        envelope.exporter_signature = exporter
            .sign_validated_statement(&envelope.signature_preimage())
            .map_err(map_identity_error)?;
        envelope
            .to_json_bytes()
            .map_err(|_| TransferError::new(TransferErrorKind::CapacityExhausted))?;
        Ok(envelope)
    }

    fn draw_transfer_id(&mut self) -> Result<Digest32, TransferError> {
        for _ in 0..MAX_TRANSFER_ID_ATTEMPTS {
            let mut bytes = [0_u8; 32];
            self.source
                .fill(&mut bytes)
                .map_err(|_| TransferError::new(TransferErrorKind::EntropyUnavailable))?;
            if bytes.iter().any(|byte| *byte != 0) {
                return Ok(Digest32::new(bytes));
            }
        }
        Err(TransferError::new(TransferErrorKind::EntropyUnavailable))
    }
}

pub struct ValidatedTransfer {
    envelope: TransferEnvelopeV1,
    catalog: TransferPublicCatalogV1,
    vault: VaultFileV1,
    policy: PolicyState,
}

impl ValidatedTransfer {
    pub fn parse(bytes: &[u8]) -> Result<Self, TransferError> {
        let (envelope, vault) = ParsedTransferEnvelopeV1::parse(bytes)
            .map_err(|_| TransferError::new(TransferErrorKind::InvalidFormat))?
            .into_parts();
        let catalog = TransferPublicCatalogV1::parse(envelope.public_catalog_json.as_bytes())?;
        let policy = validate_vault(&vault, &catalog.witness_policies)?;
        catalog.validate_for_policy(&vault, &policy)?;
        let exporter = policy
            .principal(&envelope.exporting_principal_id)
            .ok_or_else(|| TransferError::new(TransferErrorKind::UnauthorizedExporter))?;
        if !matches!(
            exporter.descriptor.principal_kind,
            PrincipalKind::Human | PrincipalKind::Machine
        ) {
            return Err(TransferError::new(TransferErrorKind::UnauthorizedExporter));
        }
        crypto::verify_bytes(
            &exporter.descriptor.verification_public_key,
            &envelope.signature_preimage(),
            &envelope.exporter_signature,
        )
        .map_err(|_| TransferError::new(TransferErrorKind::AuthenticationFailed))?;
        Ok(Self {
            envelope,
            catalog,
            vault,
            policy,
        })
    }

    #[must_use]
    pub const fn envelope(&self) -> &TransferEnvelopeV1 {
        &self.envelope
    }

    #[must_use]
    pub const fn catalog(&self) -> &TransferPublicCatalogV1 {
        &self.catalog
    }

    #[must_use]
    pub const fn vault(&self) -> &VaultFileV1 {
        &self.vault
    }

    #[must_use]
    pub const fn policy(&self) -> &PolicyState {
        &self.policy
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactRelation {
    Identical,
    IncomingStrictDescendant,
    LocalStrictDescendant,
    Divergent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferItemDelta {
    pub item_id: ItemId,
    pub local_revision: Option<u64>,
    pub incoming_revision: Option<u64>,
}

pub fn compare_artifacts(local: &VaultFileV1, incoming: &VaultFileV1) -> ArtifactRelation {
    if local == incoming {
        ArtifactRelation::Identical
    } else if is_strict_descendant(local, incoming) {
        ArtifactRelation::IncomingStrictDescendant
    } else if is_strict_descendant(incoming, local) {
        ArtifactRelation::LocalStrictDescendant
    } else {
        ArtifactRelation::Divergent
    }
}

#[must_use]
pub fn item_deltas(local: &VaultFileV1, incoming: &VaultFileV1) -> Vec<TransferItemDelta> {
    let local_items = local
        .items
        .iter()
        .map(|item| (item.item_id, item))
        .collect::<BTreeMap<_, _>>();
    let incoming_items = incoming
        .items
        .iter()
        .map(|item| (item.item_id, item))
        .collect::<BTreeMap<_, _>>();
    local_items
        .keys()
        .chain(incoming_items.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|item_id| {
            let local = local_items.get(&item_id).copied();
            let incoming = incoming_items.get(&item_id).copied();
            (local != incoming).then(|| TransferItemDelta {
                item_id,
                local_revision: local.map(|item| item.current_revision.item_revision),
                incoming_revision: incoming.map(|item| item.current_revision.item_revision),
            })
        })
        .collect()
}

fn is_strict_descendant(base: &VaultFileV1, candidate: &VaultFileV1) -> bool {
    if base.header.vault_id != candidate.header.vault_id
        || base.header.genesis_fingerprint != candidate.header.genesis_fingerprint
        || base.policy.genesis != candidate.policy.genesis
        || base.suite_migration != candidate.suite_migration
        || candidate.policy.revisions.len() <= base.policy.revisions.len()
        || !candidate
            .policy
            .revisions
            .starts_with(&base.policy.revisions)
    {
        return false;
    }
    let candidate_items = candidate
        .items
        .iter()
        .map(|item| (item.item_id, item))
        .collect::<BTreeMap<_, _>>();
    base.items.iter().all(|base_item| {
        candidate_items.get(&base_item.item_id).map_or_else(
            || policy_suffix_deletes(candidate, base.policy.revisions.len(), base_item.item_id),
            |candidate_item| item_history_is_prefix(base_item, candidate_item),
        )
    })
}

fn item_history_is_prefix(base: &ItemEnvelopeV1, candidate: &ItemEnvelopeV1) -> bool {
    let base_history = base
        .prior_revisions
        .iter()
        .chain(std::iter::once(&base.current_revision))
        .collect::<Vec<_>>();
    let candidate_history = candidate
        .prior_revisions
        .iter()
        .chain(std::iter::once(&candidate.current_revision))
        .collect::<Vec<_>>();
    if !candidate_history.starts_with(&base_history) {
        return false;
    }
    candidate_history.len() > base_history.len()
        || (candidate.current_revision == base.current_revision
            && candidate.body_ciphertext == base.body_ciphertext
            && candidate.descriptor.revision >= base.descriptor.revision
            && candidate.descriptor.key_epoch >= base.descriptor.key_epoch)
}

fn policy_suffix_deletes(vault: &VaultFileV1, start: usize, item_id: ItemId) -> bool {
    vault.policy.revisions[start..].iter().any(|revision| {
        revision.operations.iter().any(|operation| {
            matches!(
                operation,
                jury_protocol::vault_v1::PolicyOperationV1::ItemDelete {
                    item_id: deleted,
                    ..
                } if *deleted == item_id
            )
        })
    })
}

fn validate_vault(
    vault: &VaultFileV1,
    witness_policies: &[WitnessPolicy],
) -> Result<PolicyState, TransferError> {
    vault
        .validate()
        .map_err(|_| TransferError::new(TransferErrorKind::InvalidVault))?;
    let policy = replay_policy_with_witness_policies(&vault.policy, witness_policies)
        .map_err(|_| TransferError::new(TransferErrorKind::InvalidVault))?;
    CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)
        .map_err(|_| TransferError::new(TransferErrorKind::InvalidVault))?;
    Ok(policy)
}

fn require_exporter(policy: &PolicyState, principal_id: PrincipalId) -> Result<(), TransferError> {
    if policy.principal(&principal_id).is_some_and(|principal| {
        matches!(
            principal.descriptor.principal_kind,
            PrincipalKind::Human | PrincipalKind::Machine
        )
    }) {
        Ok(())
    } else {
        Err(TransferError::new(TransferErrorKind::UnauthorizedExporter))
    }
}

fn sha256(bytes: &[u8]) -> Digest32 {
    FixedBytes::new(Sha256::digest(bytes).into())
}

fn map_identity_error(error: crate::identity::IdentityError) -> TransferError {
    TransferError::new(match error.kind() {
        IdentityErrorKind::ProtectionUnavailable => TransferErrorKind::ProtectionUnavailable,
        _ => TransferErrorKind::AuthenticationFailed,
    })
}

#[cfg(test)]
#[path = "transfer_tests.rs"]
mod tests;
