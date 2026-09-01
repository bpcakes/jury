//! Revision-scoped item encryption and atomic policy/envelope mutations.

mod inventory;
mod opening;
mod random;

pub use inventory::ItemArtifactInventory;
pub(crate) use opening::{open_body, open_descriptor, verify_item_ancestry};
use random::{draw_nonce, draw_seal_id, draw_slot_id};

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

    #[allow(clippy::too_many_arguments)]
    fn seal_content(
        &mut self,
        policy: &PolicyState,
        item_id: ItemId,
        epoch: u64,
        role: ContentRole,
        revision: u64,
        bucket_id: u8,
        descriptor: &ItemDescriptorV1,
        state: &ItemStateV1,
        reserved: &mut ItemArtifactInventory,
    ) -> Result<SealedContent, ItemError> {
        let secret = ProtectedRevisionSecret {
            bytes: crypto::random_secret(32, self.protection, &mut self.source)
                .map_err(map_crypto_error)?,
        };
        let seal_id = draw_seal_id(&mut self.source, &mut reserved.revision_seal_ids)?;
        let nonce = draw_nonce(&mut self.source, &mut reserved.nonces)?;
        let aad = match role {
            ContentRole::Descriptor => item_descriptor_aad(
                policy.vault_id().as_bytes(),
                item_id.as_bytes(),
                epoch,
                revision,
                seal_id.as_bytes(),
            ),
            ContentRole::Body => item_body_aad(
                policy.vault_id().as_bytes(),
                item_id.as_bytes(),
                epoch,
                revision,
                seal_id.as_bytes(),
                bucket_id,
            ),
        };
        let plaintext_bytes = match role {
            ContentRole::Descriptor => Zeroizing::new(descriptor.encode().to_vec()),
            ContentRole::Body => Zeroizing::new(
                state
                    .frame(bucket_id)
                    .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?,
            ),
        };
        let plaintext = protect(&plaintext_bytes, self.protection)?;
        let ciphertext =
            crypto::seal(secret.memory(), &nonce, &aad, &plaintext).map_err(map_crypto_error)?;
        Ok(SealedContent {
            secret,
            seal_id,
            nonce,
            revision,
            ciphertext,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_slots(
        &mut self,
        policy: &PolicyState,
        item_id: ItemId,
        epoch: u64,
        sequence: u64,
        access: &ResolvedAccess<'_>,
        descriptor: &SealedContent,
        body: &SealedContent,
        reserved: &mut ItemArtifactInventory,
    ) -> Result<BuiltSlots, ItemError> {
        let mut direct = Vec::new();
        for content in [
            (ContentRole::Descriptor, descriptor),
            (ContentRole::Body, body),
        ] {
            for recipient in &access.direct {
                direct.push(build_direct_slot(
                    &mut self.source,
                    policy,
                    item_id,
                    epoch,
                    sequence,
                    access.mode,
                    content.0,
                    content.1,
                    recipient,
                )?);
            }
        }
        direct.sort_by(|left, right| {
            (
                left.content_role,
                left.recipient_principal_id,
                left.canonical_bytes(),
            )
                .cmp(&(
                    right.content_role,
                    right.recipient_principal_id,
                    right.canonical_bytes(),
                ))
        });
        let witnessed = access
            .witness_policy
            .map(|witness_policy| {
                let mut slots = Vec::new();
                for (role, content) in [
                    (ContentRole::Descriptor, descriptor),
                    (ContentRole::Body, body),
                ] {
                    slots.push(build_witnessed_slot(
                        &mut self.source,
                        self.protection,
                        policy,
                        witness_policy,
                        item_id,
                        epoch,
                        sequence,
                        access.mode,
                        role,
                        content,
                        reserved,
                    )?);
                }
                let mut state = WitnessedStateV1 {
                    slots,
                    digest: FixedBytes::new(ZERO_DIGEST),
                };
                state.digest = state
                    .recomputed_digest()
                    .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?;
                Ok(state)
            })
            .transpose()?;
        Ok(BuiltSlots { direct, witnessed })
    }
}

struct SealedContent {
    secret: ProtectedRevisionSecret,
    seal_id: RevisionSealId,
    nonce: Nonce12,
    revision: u64,
    ciphertext: Vec<u8>,
}

struct ResolvedDirect {
    principal_id: PrincipalId,
    public_key: RecipientPublicKey1216,
    role: AccessRole,
}

struct ResolvedAccess<'a> {
    direct: Vec<ResolvedDirect>,
    direct_roles: BTreeMap<PrincipalId, AccessRole>,
    witness_policy: Option<&'a WitnessPolicy>,
    mode: ItemAccessMode,
}

struct BuiltSlots {
    direct: Vec<DirectSlotV1>,
    witnessed: Option<WitnessedStateV1>,
}

fn resolve_access<'a>(
    policy: &'a PolicyState,
    sequence: u64,
    plan: &ItemAccessPlan,
    replacement: Option<&PrincipalReplacement>,
    registration: Option<&PrincipalRegistration>,
    owner_change: Option<OwnerChange>,
) -> Result<ResolvedAccess<'a>, ItemError> {
    if replacement.is_some_and(|replacement| {
        replacement.prior_principal_id == replacement.next_descriptor.principal_id
            || plan
                .grants
                .iter()
                .any(|grant| grant.principal_id == replacement.prior_principal_id)
            || plan
                .direct_recipient_ids
                .contains(&replacement.prior_principal_id)
    }) {
        return Err(ItemError::new(ItemErrorKind::InvalidInput));
    }
    if registration.is_some_and(|registration| {
        policy.principal_id_was_used(&registration.descriptor.principal_id) || replacement.is_some()
    }) {
        return Err(ItemError::new(ItemErrorKind::InvalidInput));
    }
    if owner_change.is_some_and(|change| match change {
        OwnerChange::Grant(principal_id) => policy.is_owner(&principal_id),
        OwnerChange::Revoke(principal_id) => !policy.is_owner(&principal_id),
    }) {
        return Err(ItemError::new(ItemErrorKind::InvalidInput));
    }
    let mut grants = BTreeMap::new();
    for grant in &plan.grants {
        let is_replacement_owner = replacement.is_some_and(|replacement| {
            replacement.next_descriptor.principal_id == grant.principal_id
                && policy.is_owner(&replacement.prior_principal_id)
        });
        if !matches!(grant.role, AccessRole::Reader | AccessRole::Writer)
            || grants.insert(grant.principal_id, grant.role).is_some()
            || policy.is_owner(&grant.principal_id)
            || is_replacement_owner
        {
            return Err(ItemError::new(ItemErrorKind::InvalidInput));
        }
        let principal_kind = replacement
            .filter(|replacement| replacement.next_descriptor.principal_id == grant.principal_id)
            .map(|replacement| replacement.next_descriptor.principal_kind)
            .or_else(|| {
                registration
                    .filter(|registration| {
                        registration.descriptor.principal_id == grant.principal_id
                    })
                    .map(|registration| registration.descriptor.principal_kind)
            })
            .or_else(|| {
                policy
                    .principal(&grant.principal_id)
                    .map(|principal| principal.descriptor.principal_kind)
            })
            .ok_or_else(|| ItemError::new(ItemErrorKind::InvalidInput))?;
        if !matches!(
            principal_kind,
            PrincipalKind::Human | PrincipalKind::Machine
        ) {
            return Err(ItemError::new(ItemErrorKind::InvalidInput));
        }
    }
    if plan
        .direct_recipient_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(ItemError::new(ItemErrorKind::InvalidInput));
    }
    let mut direct = Vec::new();
    let mut direct_roles = BTreeMap::new();
    for principal_id in &plan.direct_recipient_ids {
        let replaced = replacement
            .filter(|replacement| replacement.next_descriptor.principal_id == *principal_id);
        let registered = registration
            .filter(|registration| registration.descriptor.principal_id == *principal_id);
        let descriptor = replaced
            .map(|replacement| &replacement.next_descriptor)
            .or_else(|| registered.map(|registration| &registration.descriptor))
            .or_else(|| {
                policy
                    .principal(principal_id)
                    .map(|principal| &principal.descriptor)
            });
        let descriptor = descriptor.ok_or_else(|| ItemError::new(ItemErrorKind::InvalidInput))?;
        if !matches!(
            descriptor.principal_kind,
            PrincipalKind::Human | PrincipalKind::Machine
        ) {
            return Err(ItemError::new(ItemErrorKind::InvalidInput));
        }
        let is_replacement_owner =
            replaced.is_some_and(|replacement| policy.is_owner(&replacement.prior_principal_id));
        let will_be_owner = match owner_change {
            Some(OwnerChange::Grant(candidate)) if candidate == *principal_id => true,
            Some(OwnerChange::Revoke(candidate)) if candidate == *principal_id => false,
            _ => policy.is_owner(principal_id),
        };
        let role = if will_be_owner || is_replacement_owner {
            AccessRole::Owner
        } else {
            grants
                .get(principal_id)
                .copied()
                .ok_or_else(|| ItemError::new(ItemErrorKind::Unauthorized))?
        };
        direct_roles.insert(*principal_id, role);
        direct.push(ResolvedDirect {
            principal_id: *principal_id,
            public_key: descriptor.recipient_public_key.clone(),
            role,
        });
    }
    let witness_policy = plan
        .witness_policy_digest
        .as_ref()
        .map(|digest| {
            let witness = policy
                .witness_policy(digest)
                .ok_or_else(|| ItemError::new(ItemErrorKind::InvalidInput))?;
            witness
                .validate()
                .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?;
            if witness.vault_id != policy.vault_id()
                || witness.genesis_fingerprint != *policy.genesis_fingerprint()
                || witness.vault_policy_sequence != sequence
                || witness.digest().ok().as_ref() != Some(digest)
            {
                return Err(ItemError::new(ItemErrorKind::InvalidInput));
            }
            Ok(witness)
        })
        .transpose()?;
    let mode = match (direct.is_empty(), witness_policy.is_none()) {
        (false, true) => ItemAccessMode::DirectOnly,
        (true, false) => ItemAccessMode::WitnessedOnly,
        (false, false) => ItemAccessMode::Mixed,
        (true, true) => return Err(ItemError::new(ItemErrorKind::InvalidInput)),
    };
    Ok(ResolvedAccess {
        direct,
        direct_roles,
        witness_policy,
        mode,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_direct_slot(
    source: &mut impl RandomSource,
    policy: &PolicyState,
    item_id: ItemId,
    epoch: u64,
    sequence: u64,
    mode: ItemAccessMode,
    role: ContentRole,
    content: &SealedContent,
    recipient: &ResolvedDirect,
) -> Result<DirectSlotV1, ItemError> {
    let fingerprint = recipient_public_key_fingerprint(&recipient.public_key);
    let mut slot = DirectSlotV1 {
        slot_schema: 1,
        slot_algorithm: 1,
        suite: SUITE,
        kem: 0x647a,
        kdf: 1,
        aead: 3,
        vault_id: policy.vault_id(),
        item_id,
        key_epoch: epoch,
        content_role: role,
        revision: content.revision,
        revision_seal_id: content.seal_id,
        recipient_principal_id: recipient.principal_id,
        policy_sequence: sequence,
        recipient_public_key_fingerprint: fingerprint,
        access_role: recipient.role,
        item_access_mode: mode,
        encapsulation: Encapsulation1120::new([0; 1_120]),
        ciphertext: DirectCiphertext48::new([0; 48]),
    };
    let (encapsulation, ciphertext) = crypto::seal_hpke(
        &recipient.public_key,
        content.secret.memory(),
        &slot.info_preimage(),
        &slot.aad_preimage(),
        source,
    )
    .map_err(map_crypto_error)?;
    slot.encapsulation = encapsulation;
    slot.ciphertext = DirectCiphertext48::from_slice(&ciphertext)
        .map_err(|_| ItemError::new(ItemErrorKind::ProviderFailure))?;
    Ok(slot)
}

#[allow(clippy::too_many_arguments)]
fn build_witnessed_slot(
    source: &mut impl RandomSource,
    protection: ProtectionPolicy,
    policy: &PolicyState,
    witness_policy: &WitnessPolicy,
    item_id: ItemId,
    epoch: u64,
    sequence: u64,
    mode: ItemAccessMode,
    role: ContentRole,
    content: &SealedContent,
    reserved: &mut ItemArtifactInventory,
) -> Result<WitnessedSlotV1, ItemError> {
    let members = witness_policy
        .witness_descriptors
        .iter()
        .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
        .collect::<Vec<_>>();
    let share_indexes = members
        .iter()
        .map(|descriptor| descriptor.share_index)
        .collect::<BTreeSet<_>>();
    if members.len() > 32 || share_indexes.len() != members.len() {
        return Err(ItemError::new(ItemErrorKind::InvalidInput));
    }
    let member_count = u8::try_from(members.len())
        .map_err(|_| ItemError::new(ItemErrorKind::CapacityExhausted))?;
    let slot_id = draw_slot_id(source, &mut reserved.slot_ids)?;
    let policy_digest = witness_policy
        .digest()
        .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?;
    let share_seed = crypto::random_secret(32, protection, source).map_err(map_crypto_error)?;
    let shares = share_seed
        .expose(|seed| {
            content.secret.memory().expose(|secret| {
                let seed: &[u8; 32] = seed
                    .try_into()
                    .map_err(|_| ItemError::new(ItemErrorKind::ProviderFailure))?;
                let mut rng = ChaCha20Rng::from_seed(*seed);
                Gf256::split_bytes_with_participant_ids_iter(
                    usize::from(witness_policy.witness_threshold),
                    members.len(),
                    secret,
                    &mut rng,
                    members
                        .iter()
                        .map(|descriptor| IdentifierGf256(Gf256(descriptor.share_index))),
                )
                .map_err(|_| ItemError::new(ItemErrorKind::ProviderFailure))
            })
        })
        .map_err(|_| ItemError::new(ItemErrorKind::ProtectionUnavailable))?
        .map_err(|_| ItemError::new(ItemErrorKind::ProtectionUnavailable))??;
    let shares = Zeroizing::new(shares);
    let mut capsules = Vec::with_capacity(members.len());
    for (descriptor, bytes) in members.into_iter().zip(shares.iter()) {
        if bytes.first().copied() != Some(descriptor.share_index) {
            return Err(ItemError::new(ItemErrorKind::ProviderFailure));
        }
        let share = protect(bytes, protection)?;
        let mut capsule = WitnessShareCapsuleV1 {
            capsule_schema: 1,
            protocol: 1,
            construction: 1,
            vault_id: policy.vault_id(),
            genesis_fingerprint: policy.genesis_fingerprint().clone(),
            item_id,
            key_epoch: epoch,
            item_access_mode: mode,
            slot_id,
            content_role: role,
            revision: content.revision,
            revision_seal_id: content.seal_id,
            vault_policy_sequence: sequence,
            witness_policy_id: witness_policy.witness_policy_id,
            witness_policy_revision: witness_policy.revision,
            witness_policy_digest: policy_digest.clone(),
            threshold: witness_policy.witness_threshold,
            member_count,
            witness_id: descriptor.witness_id,
            contribution_key_fingerprint: descriptor.contribution_key_fingerprint.clone(),
            share_index: descriptor.share_index,
            context_digest: FixedBytes::new(ZERO_DIGEST),
            share_commitment: FixedBytes::new(ZERO_DIGEST),
            encapsulation: Encapsulation1120::new([0; 1_120]),
            ciphertext: ShareCiphertext49::new([0; 49]),
        };
        capsule.context_digest = capsule.recomputed_context_digest();
        capsule.share_commitment = share_commitment(&capsule.context_digest, &share)?;
        let (encapsulation, ciphertext) = crypto::seal_hpke(
            &descriptor.contribution_public_key,
            &share,
            &capsule.info_preimage(),
            &capsule.aad_preimage(),
            source,
        )
        .map_err(map_crypto_error)?;
        capsule.encapsulation = encapsulation;
        capsule.ciphertext = ShareCiphertext49::from_slice(&ciphertext)
            .map_err(|_| ItemError::new(ItemErrorKind::ProviderFailure))?;
        capsules.push(capsule);
    }
    capsules.sort_by_key(|capsule| capsule.share_index);
    let mut slot = WitnessedSlotV1 {
        slot_schema: 1,
        slot_algorithm: 2,
        suite: SUITE,
        protocol: 1,
        construction: 1,
        vault_id: policy.vault_id(),
        genesis_fingerprint: policy.genesis_fingerprint().clone(),
        item_id,
        key_epoch: epoch,
        item_access_mode: mode,
        slot_id,
        content_role: role,
        revision: content.revision,
        revision_seal_id: content.seal_id,
        vault_policy_sequence: sequence,
        witness_policy_id: witness_policy.witness_policy_id,
        witness_policy_revision: witness_policy.revision,
        witness_policy_digest: policy_digest,
        threshold: witness_policy.witness_threshold,
        member_count,
        capsules,
        capsule_set_digest: FixedBytes::new(ZERO_DIGEST),
    };
    slot.capsule_set_digest = slot
        .recomputed_capsule_set_digest()
        .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))?;
    Ok(slot)
}

fn share_commitment(
    context_digest: &Digest32,
    share: &ProtectedMemory,
) -> Result<Digest32, ItemError> {
    let mut digest = Sha256::new();
    digest.update(jce("jury-witness-v1/share/commitment"));
    digest.update(context_digest.as_bytes());
    share
        .expose(|bytes| digest.update(bytes))
        .map_err(|_| ItemError::new(ItemErrorKind::ProtectionUnavailable))?;
    Ok(FixedBytes::new(digest.finalize().into()))
}

fn jce(domain: &str) -> Vec<u8> {
    let mut output = domain.as_bytes().to_vec();
    output.push(0);
    output.extend_from_slice(&SUITE.to_be_bytes());
    output
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
    ids.extend(access.grants.iter().map(|grant| grant.principal_id));
    ids.into_iter().collect()
}

fn protect(bytes: &[u8], policy: ProtectionPolicy) -> Result<ProtectedMemory, ItemError> {
    let initialize = |output: &mut [u8]| {
        output.copy_from_slice(bytes);
        Ok::<usize, ()>(output.len())
    };
    let protected = if bytes.len() > jury_protected::MAX_PROTECTED_BYTES {
        ProtectedMemory::initialize_large(bytes.len(), policy, initialize)
    } else {
        ProtectedMemory::initialize(bytes.len(), policy, initialize)
    };
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
