//! Revision-scoped item encryption and atomic policy/envelope mutations.

mod inventory;
mod opening;
mod random;
mod sealing;

pub use inventory::ItemArtifactInventory;
pub(crate) use opening::{open_body, open_descriptor, verify_item_ancestry};
use random::{draw_nonce, draw_seal_id, draw_slot_id};
use sealing::{SealedContent, resolve_access};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chacha20::ChaCha20Rng;
use hpke::rand_core::SeedableRng as _;
use jury_protected::{OsRandom, ProtectedMemory, ProtectionPolicy, RandomSource};
use jury_protocol::vault_v1::{
    AccessRole, ContentRole, DescriptorCiphertext272, DescriptorMetadataV1, Digest32,
    DirectCiphertext48, DirectSlotV1, Encapsulation1120, FieldId, FixedBytes, ItemAccessMode,
    ItemDescriptorV1, ItemEnvelopeV1, ItemId, ItemKind, ItemStateV1, Nonce12, PolicyOperationV1,
    PrincipalDescriptorV1, PrincipalId, PrincipalKind, RecipientPublicKey1216, RevisionSealId,
    ShareCiphertext49, Signature64, SignedItemRevisionV1, WitnessShareCapsuleV1, WitnessedSlotV1,
    WitnessedStateV1, item_body_aad, item_descriptor_aad, recipient_public_key_fingerprint,
};
use sha2::{Digest as _, Sha256};
use vsss_rs::{Gf256, IdentifierGf256};
use zeroize::Zeroizing;

use crate::canonical::jce_v1 as jce;
use crate::crypto::{self, CryptoError};
use crate::domain::{IdentifierGenerationError, NativeIdGenerator};
use crate::identity::{ProtectedRevisionSecret, VaultPrincipalIdentity};
use crate::policy::{
    DescriptorStatus, PolicyErrorKind, PolicyState, PreparedPolicyRevision, WitnessPolicy,
};

const SUITE: u16 = 1;
const ZERO_DIGEST: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemErrorKind {
    InvalidInput,
    InvalidAncestry,
    Unauthorized,
    EntropyUnavailable,
    RetryExhausted,
    ProtectionUnavailable,
    ProviderFailure,
    AuthenticationFailed,
    CapacityExhausted,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ItemError {
    kind: ItemErrorKind,
}

impl ItemError {
    const fn new(kind: ItemErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> ItemErrorKind {
        self.kind
    }
}

impl fmt::Debug for ItemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ItemError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for ItemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ItemErrorKind::InvalidInput => "item input is invalid",
            ItemErrorKind::InvalidAncestry => "item ancestry is invalid",
            ItemErrorKind::Unauthorized => "item mutation is unauthorized",
            ItemErrorKind::EntropyUnavailable => "operating-system entropy was unavailable",
            ItemErrorKind::RetryExhausted => "item generation exhausted its retry bound",
            ItemErrorKind::ProtectionUnavailable => "protected memory is unavailable",
            ItemErrorKind::ProviderFailure => "item cryptographic provider failed",
            ItemErrorKind::AuthenticationFailed => "item authentication failed",
            ItemErrorKind::CapacityExhausted => "item capacity is exhausted",
        })
    }
}

impl std::error::Error for ItemError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ItemGrant {
    pub principal_id: PrincipalId,
    pub role: AccessRole,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemAccessPlan {
    pub grants: Vec<ItemGrant>,
    pub direct_recipient_ids: Vec<PrincipalId>,
    pub witness_policy_digest: Option<Digest32>,
}

pub struct NewItem {
    pub kind: ItemKind,
    pub descriptor: ItemDescriptorV1,
    pub state: ItemStateV1,
    pub bucket_id: u8,
    pub access: ItemAccessPlan,
}

pub struct RekeyedItem {
    pub descriptor: ItemDescriptorV1,
    pub state: ItemStateV1,
    pub bucket_id: u8,
    pub access: ItemAccessPlan,
    pub principal_replacement: Option<PrincipalReplacement>,
    /// One not-yet-registered recipient to add before this item's role and
    /// slot changes in the same signed policy revision.
    pub principal_registration: Option<PrincipalRegistration>,
    /// One owner-set change whose implicit reader-set transition is rotated
    /// atomically with this item.
    pub owner_change: Option<OwnerChange>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalReplacement {
    pub prior_principal_id: PrincipalId,
    pub next_descriptor: PrincipalDescriptorV1,
    pub registration_proof_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalRegistration {
    pub descriptor: PrincipalDescriptorV1,
    pub display_label: String,
    pub registration_proof_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerChange {
    Grant(PrincipalId),
    Revoke(PrincipalId),
}

pub struct PreparedItemMutation {
    pub policy: PreparedPolicyRevision,
    pub envelope: ItemEnvelopeV1,
}

/// One cryptographically complete item replacement awaiting validation as
/// part of a multi-item policy revision.
pub struct PreparedItemBatchComponent {
    pub(crate) operations: Vec<PolicyOperationV1>,
    pub(crate) envelope: ItemEnvelopeV1,
}

pub struct ItemCreator<R = OsRandom> {
    source: R,
    protection: ProtectionPolicy,
}

impl ItemCreator<OsRandom> {
    #[must_use]
    pub const fn new(protection: ProtectionPolicy) -> Self {
        Self {
            source: OsRandom,
            protection,
        }
    }
}

impl<R: RandomSource> ItemCreator<R> {
    #[cfg(test)]
    pub(crate) const fn from_source(source: R, protection: ProtectionPolicy) -> Self {
        Self { source, protection }
    }

    pub fn prepare_create(
        &mut self,
        policy: &PolicyState,
        author: &VaultPrincipalIdentity,
        timestamp_ms: u64,
        input: NewItem,
        inventory: &ItemArtifactInventory,
    ) -> Result<PreparedItemMutation, ItemError> {
        let item_id = {
            let mut generator = NativeIdGenerator::from_source(&mut self.source);
            let generated = generator
                .generate_item_id(|candidate| {
                    ItemId::from_bytes(*candidate.as_bytes())
                        .map_or(true, |wire| policy.item_id_was_used(&wire))
                })
                .map_err(map_identifier_error)?;
            ItemId::from_bytes(*generated.as_bytes())
                .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?
        };
        let sequence = next(policy.sequence())?;
        let resolved = resolve_access(policy, sequence, &input.access, None, None, None)?;
        let mut reserved = inventory.clone();
        let descriptor = self.seal_content(
            policy,
            item_id,
            1,
            ContentRole::Descriptor,
            1,
            input.bucket_id,
            &input.descriptor,
            &input.state,
            &mut reserved,
        )?;
        let body = self.seal_content(
            policy,
            item_id,
            1,
            ContentRole::Body,
            1,
            input.bucket_id,
            &input.descriptor,
            &input.state,
            &mut reserved,
        )?;
        let slots = self.build_slots(
            policy,
            item_id,
            1,
            sequence,
            &resolved,
            &descriptor,
            &body,
            &mut reserved,
        )?;
        let current_revision = sign_item_revision(
            author,
            policy,
            item_id,
            1,
            FixedBytes::new(ZERO_DIGEST),
            1,
            sequence,
            timestamp_ms,
            input.bucket_id,
            &body,
        )?;
        let current_hash = current_revision
            .recomputed_hash()
            .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?;
        let descriptor_metadata = descriptor_metadata(1, 1, &descriptor)?;
        let envelope = ItemEnvelopeV1 {
            item_id,
            descriptor: descriptor_metadata.clone(),
            descriptor_ciphertext: DescriptorCiphertext272::from_slice(&descriptor.ciphertext)
                .map_err(|_| ItemError::new(ItemErrorKind::ProviderFailure))?,
            prior_revisions: Vec::new(),
            current_revision,
            body_ciphertext: jury_protocol::vault_v1::ItemCiphertext::new(body.ciphertext.clone())
                .map_err(|_| ItemError::new(ItemErrorKind::CapacityExhausted))?,
        };
        let mut operations = vec![PolicyOperationV1::ItemCreate {
            item_id,
            item_kind: input.kind,
            key_epoch: 1,
            descriptor: descriptor_metadata,
            current_item_revision_hash: current_hash,
            direct_slots: slots.direct,
            witnessed_state: slots.witnessed,
        }];
        append_creation_grants(
            &mut operations,
            &input.access,
            &resolved.direct_roles,
            item_id,
        );
        let prepared = policy
            .prepare_revision(author, timestamp_ms, operations)
            .map_err(map_policy_error)?;
        Ok(PreparedItemMutation {
            policy: prepared,
            envelope,
        })
    }

    /// Generates a nonzero field identifier distinct from every identifier in
    /// the decrypted item body. The adapter never supplies caller-chosen field
    /// identifiers and cannot inject its own randomness source in production.
    pub fn generate_field_id(&mut self, existing: &[FieldId]) -> Result<FieldId, ItemError> {
        for _ in 0..crate::domain::IDENTIFIER_COLLISION_RETRY_ATTEMPTS {
            for _ in 0..crate::domain::IDENTIFIER_ZERO_RETRY_ATTEMPTS {
                let mut bytes = [0_u8; 32];
                self.source
                    .fill(&mut bytes)
                    .map_err(|_| ItemError::new(ItemErrorKind::EntropyUnavailable))?;
                let Ok(candidate) = FieldId::from_bytes(bytes) else {
                    continue;
                };
                if !existing.contains(&candidate) {
                    return Ok(candidate);
                }
            }
        }
        Err(ItemError::new(ItemErrorKind::RetryExhausted))
    }

    pub fn prepare_rekey(
        &mut self,
        policy: &PolicyState,
        author: &VaultPrincipalIdentity,
        timestamp_ms: u64,
        prior: &ItemEnvelopeV1,
        input: RekeyedItem,
        inventory: &ItemArtifactInventory,
    ) -> Result<PreparedItemMutation, ItemError> {
        let component = self.prepare_rekey_batch_component(
            policy,
            author,
            timestamp_ms,
            prior,
            input,
            inventory,
        )?;
        let prepared = policy
            .prepare_revision(author, timestamp_ms, component.operations)
            .map_err(map_policy_error)?;
        Ok(PreparedItemMutation {
            policy: prepared,
            envelope: component.envelope,
        })
    }

    /// Prepares one item for an atomic multi-item revision. The returned
    /// component is opaque outside `jury-core` and must be consumed by
    /// `VaultMutationPlan::prepare_item_component_batch`, which validates the
    /// complete combined transition before exposing commit bytes.
    pub fn prepare_rekey_batch_component(
        &mut self,
        policy: &PolicyState,
        author: &VaultPrincipalIdentity,
        timestamp_ms: u64,
        prior: &ItemEnvelopeV1,
        input: RekeyedItem,
        inventory: &ItemArtifactInventory,
    ) -> Result<PreparedItemBatchComponent, ItemError> {
        verify_item_ancestry(prior, |principal_id| policy.verification_key(&principal_id))?;
        let item = policy
            .item(&prior.item_id)
            .ok_or_else(|| ItemError::new(ItemErrorKind::InvalidAncestry))?;
        let prior_hash = prior
            .current_revision
            .recomputed_hash()
            .map_err(|_| ItemError::new(ItemErrorKind::InvalidAncestry))?;
        if item.current_item_revision_hash != prior_hash
            || item.descriptor != prior.descriptor
            || prior.current_revision.key_epoch != item.key_epoch
        {
            return Err(ItemError::new(ItemErrorKind::InvalidAncestry));
        }
        let sequence = next(policy.sequence())?;
        let epoch = next(item.key_epoch)?;
        let descriptor_revision = next(item.descriptor.revision)?;
        let body_revision = next(prior.current_revision.item_revision)?;
        let replacement = input.principal_replacement.as_ref();
        let registration = input.principal_registration.as_ref();
        let owner_change = input.owner_change;
        if usize::from(replacement.is_some())
            + usize::from(registration.is_some())
            + usize::from(owner_change.is_some())
            > 1
        {
            return Err(ItemError::new(ItemErrorKind::InvalidInput));
        }
        let resolved = resolve_access(
            policy,
            sequence,
            &input.access,
            replacement,
            registration,
            owner_change,
        )?;
        let mut reserved = inventory.clone();
        let descriptor = self.seal_content(
            policy,
            prior.item_id,
            epoch,
            ContentRole::Descriptor,
            descriptor_revision,
            input.bucket_id,
            &input.descriptor,
            &input.state,
            &mut reserved,
        )?;
        let body = self.seal_content(
            policy,
            prior.item_id,
            epoch,
            ContentRole::Body,
            body_revision,
            input.bucket_id,
            &input.descriptor,
            &input.state,
            &mut reserved,
        )?;
        let slots = self.build_slots(
            policy,
            prior.item_id,
            epoch,
            sequence,
            &resolved,
            &descriptor,
            &body,
            &mut reserved,
        )?;
        let current_revision = sign_item_revision(
            author,
            policy,
            prior.item_id,
            body_revision,
            prior_hash,
            epoch,
            sequence,
            timestamp_ms,
            input.bucket_id,
            &body,
        )?;
        let current_hash = current_revision
            .recomputed_hash()
            .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?;
        let descriptor_metadata = descriptor_metadata(descriptor_revision, epoch, &descriptor)?;
        let mut prior_revisions = prior.prior_revisions.clone();
        prior_revisions.push(prior.current_revision.clone());
        let envelope = ItemEnvelopeV1 {
            item_id: prior.item_id,
            descriptor: descriptor_metadata.clone(),
            descriptor_ciphertext: DescriptorCiphertext272::from_slice(&descriptor.ciphertext)
                .map_err(|_| ItemError::new(ItemErrorKind::ProviderFailure))?,
            prior_revisions,
            current_revision,
            body_ciphertext: jury_protocol::vault_v1::ItemCiphertext::new(body.ciphertext.clone())
                .map_err(|_| ItemError::new(ItemErrorKind::CapacityExhausted))?,
        };

        let mut operations = registration.map_or_else(Vec::new, |registration| {
            vec![PolicyOperationV1::PrincipalAdd {
                descriptor: registration.descriptor.clone(),
                display_label: registration.display_label.clone(),
                registration_proof_digest: registration.registration_proof_digest.clone(),
            }]
        });
        operations.extend(replacement.map_or_else(Vec::new, |replacement| {
            vec![PolicyOperationV1::PrincipalReplace {
                prior_principal_id: replacement.prior_principal_id,
                next_descriptor: replacement.next_descriptor.clone(),
                registration_proof_digest: replacement.registration_proof_digest.clone(),
            }]
        }));
        if let Some(OwnerChange::Revoke(principal_id)) = owner_change {
            operations.push(PolicyOperationV1::OwnerRevoke { principal_id });
        }
        operations.extend(role_change_operations(
            item,
            &input.access,
            prior.item_id,
            replacement,
        )?);
        if let Some(OwnerChange::Grant(principal_id)) = owner_change {
            operations.push(PolicyOperationV1::OwnerGrant { principal_id });
        }
        let prior_readers = policy.effective_reader_ids(&prior.item_id);
        let next_readers = next_reader_ids(policy, &input.access, replacement, owner_change);
        operations.push(PolicyOperationV1::ItemReaderSetChange {
            item_id: prior.item_id,
            prior_epoch: item.key_epoch,
            next_epoch: epoch,
            prior_reader_ids: prior_readers,
            next_reader_ids: next_readers,
            replacement_descriptor: descriptor_metadata,
            replacement_current_item_revision_hash: current_hash,
        });
        operations.push(PolicyOperationV1::ItemSlotsReplace {
            item_id: prior.item_id,
            next_epoch: epoch,
            direct_slots: slots.direct,
            witnessed_state: slots.witnessed,
        });
        Ok(PreparedItemBatchComponent {
            operations,
            envelope,
        })
    }
}

fn descriptor_metadata(
    revision: u64,
    epoch: u64,
    content: &SealedContent,
) -> Result<DescriptorMetadataV1, ItemError> {
    Ok(DescriptorMetadataV1 {
        revision,
        revision_seal_id: content.seal_id,
        nonce: content.nonce.clone(),
        ciphertext_length: u32::try_from(content.ciphertext.len())
            .map_err(|_| ItemError::new(ItemErrorKind::CapacityExhausted))?,
        ciphertext_digest: sha256(&content.ciphertext),
        plaintext_schema: 1,
        key_epoch: epoch,
    })
}

#[allow(clippy::too_many_arguments)]
fn sign_item_revision(
    author: &VaultPrincipalIdentity,
    policy: &PolicyState,
    item_id: ItemId,
    revision: u64,
    previous_hash: Digest32,
    epoch: u64,
    policy_sequence: u64,
    timestamp_ms: u64,
    bucket_id: u8,
    content: &SealedContent,
) -> Result<SignedItemRevisionV1, ItemError> {
    let mut record = SignedItemRevisionV1 {
        vault_id: policy.vault_id(),
        item_id,
        item_revision: revision,
        previous_item_revision_hash: previous_hash,
        key_epoch: epoch,
        policy_sequence,
        author_principal_id: author.principal_id(),
        timestamp_ms,
        revision_seal_id: content.seal_id,
        nonce: content.nonce.clone(),
        ciphertext_length: u32::try_from(content.ciphertext.len())
            .map_err(|_| ItemError::new(ItemErrorKind::CapacityExhausted))?,
        ciphertext_digest: sha256(&content.ciphertext),
        plaintext_schema: 1,
        bucket_id,
        signature: Signature64::new([0; 64]),
    };
    record.signature = author
        .sign_validated_statement(&record.signature_preimage())
        .map_err(|_| ItemError::new(ItemErrorKind::Unauthorized))?;
    Ok(record)
}

fn append_creation_grants(
    operations: &mut Vec<PolicyOperationV1>,
    access: &ItemAccessPlan,
    direct_roles: &BTreeMap<PrincipalId, AccessRole>,
    item_id: ItemId,
) {
    for grant in &access.grants {
        if !direct_roles.contains_key(&grant.principal_id) {
            operations.push(PolicyOperationV1::ItemRoleChange {
                item_id,
                principal_id: grant.principal_id,
                prior_role: None,
                next_role: Some(grant.role),
            });
        }
    }
}

fn role_change_operations(
    prior: &crate::policy::ItemPolicyState,
    access: &ItemAccessPlan,
    item_id: ItemId,
    replacement: Option<&PrincipalReplacement>,
) -> Result<Vec<PolicyOperationV1>, ItemError> {
    let next = access
        .grants
        .iter()
        .map(|grant| (grant.principal_id, grant.role))
        .collect::<BTreeMap<_, _>>();
    if next.len() != access.grants.len() {
        return Err(ItemError::new(ItemErrorKind::InvalidInput));
    }
    let mut effective_prior = prior.grants.clone();
    if let Some(replacement) = replacement
        && let Some(role) = effective_prior.remove(&replacement.prior_principal_id)
    {
        effective_prior.insert(replacement.next_descriptor.principal_id, role);
    }
    let ids = effective_prior
        .keys()
        .chain(next.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    Ok(ids
        .into_iter()
        .filter_map(|principal_id| {
            let prior_role = effective_prior.get(&principal_id).copied();
            let next_role = next.get(&principal_id).copied();
            (prior_role != next_role).then_some(PolicyOperationV1::ItemRoleChange {
                item_id,
                principal_id,
                prior_role,
                next_role,
            })
        })
        .collect())
}

fn next_reader_ids(
    policy: &PolicyState,
    access: &ItemAccessPlan,
    replacement: Option<&PrincipalReplacement>,
    owner_change: Option<OwnerChange>,
) -> Vec<PrincipalId> {
    let mut ids = next_owner_ids(policy, replacement, owner_change);
    ids.extend(access.grants.iter().map(|grant| grant.principal_id));
    ids.into_iter().collect()
}

fn next_owner_ids(
    policy: &PolicyState,
    replacement: Option<&PrincipalReplacement>,
    owner_change: Option<OwnerChange>,
) -> BTreeSet<PrincipalId> {
    let mut ids = policy
        .owner_ids()
        .map(|owner| {
            replacement
                .filter(|replacement| replacement.prior_principal_id == owner)
                .map_or(owner, |replacement| {
                    replacement.next_descriptor.principal_id
                })
        })
        .collect::<BTreeSet<_>>();
    if let Some(change) = owner_change {
        match change {
            OwnerChange::Grant(principal_id) => {
                ids.insert(principal_id);
            }
            OwnerChange::Revoke(principal_id) => {
                ids.remove(&principal_id);
            }
        }
    }
    ids
}

fn protect(bytes: &[u8], policy: ProtectionPolicy) -> Result<ProtectedMemory, ItemError> {
    let initialize = |output: &mut [u8]| {
        output.copy_from_slice(bytes);
        Ok::<usize, ()>(output.len())
    };
    let protected = ProtectedMemory::initialize_supported(bytes.len(), policy, initialize);
    protected.map_err(|_| ItemError::new(ItemErrorKind::ProtectionUnavailable))
}

fn sha256(bytes: &[u8]) -> Digest32 {
    FixedBytes::new(Sha256::digest(bytes).into())
}

fn next(value: u64) -> Result<u64, ItemError> {
    value
        .checked_add(1)
        .ok_or_else(|| ItemError::new(ItemErrorKind::CapacityExhausted))
}

fn map_identifier_error(error: IdentifierGenerationError) -> ItemError {
    ItemError::new(match error {
        IdentifierGenerationError::EntropyUnavailable => ItemErrorKind::EntropyUnavailable,
        IdentifierGenerationError::RetryExhausted => ItemErrorKind::RetryExhausted,
    })
}

fn map_crypto_error(error: CryptoError) -> ItemError {
    ItemError::new(match error {
        CryptoError::EntropyUnavailable => ItemErrorKind::EntropyUnavailable,
        CryptoError::MemoryProtection | CryptoError::ResourceUnavailable => {
            ItemErrorKind::ProtectionUnavailable
        }
        CryptoError::ProviderFailure => ItemErrorKind::ProviderFailure,
        CryptoError::AuthenticationFailed => ItemErrorKind::AuthenticationFailed,
    })
}

fn map_policy_error(error: crate::policy::PolicyError) -> ItemError {
    ItemError::new(match error.kind() {
        PolicyErrorKind::Unauthorized | PolicyErrorKind::InvalidRole => ItemErrorKind::Unauthorized,
        PolicyErrorKind::EntropyUnavailable => ItemErrorKind::EntropyUnavailable,
        PolicyErrorKind::RetryExhausted => ItemErrorKind::RetryExhausted,
        PolicyErrorKind::CapacityExhausted => ItemErrorKind::CapacityExhausted,
        PolicyErrorKind::InvalidAncestry => ItemErrorKind::InvalidAncestry,
        _ => ItemErrorKind::InvalidInput,
    })
}

#[cfg(test)]
#[path = "item_tests.rs"]
mod tests;
