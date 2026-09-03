use std::collections::{BTreeMap, BTreeSet};

use jury_protected::{OsRandom, RandomSource};
use jury_protocol::vault_v1::{
    AccessRole, DescriptorMetadataV1, Digest32, DirectSlotV1, EmptyGenesisEntryV1, FixedBytes,
    ItemId, MAX_ITEMS, MAX_POLICY_REVISIONS, MAX_PUBLIC_LABEL_BYTES, PolicyGenesisV1,
    PolicyJournalV1, PolicyOperationV1, PrincipalDescriptorV1, PrincipalId, PrincipalKind,
    Signature64, SignedPolicyRevisionV1, VaultId, WitnessedStateV1,
    validate_policy_operation_context,
};

use crate::{
    crypto,
    domain::{IdentifierGenerationError, NativeIdGenerator},
    identity::VaultPrincipalIdentity,
};

use super::state::{
    ItemPolicyState, PolicyError, PolicyErrorKind, PolicyState, PrincipalPolicyState,
    TombstoneState,
};
use super::witness::{WitnessPolicy, validate_item_policy_binding};

const SUITE: u16 = 1;
const ZERO_DIGEST: [u8; 32] = [0; 32];

pub struct CreatedPolicy {
    pub journal: PolicyJournalV1,
    pub state: PolicyState,
}

pub struct PreparedPolicyRevision {
    pub revision: SignedPolicyRevisionV1,
    pub state: PolicyState,
}

pub struct PolicyCreator<R = OsRandom> {
    source: R,
}

impl PolicyCreator<OsRandom> {
    #[must_use]
    pub const fn new() -> Self {
        Self { source: OsRandom }
    }
}

impl Default for PolicyCreator<OsRandom> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: RandomSource> PolicyCreator<R> {
    #[cfg(test)]
    pub(crate) fn from_source(source: R) -> Self {
        Self { source }
    }

    pub fn create(
        &mut self,
        owner: &VaultPrincipalIdentity,
        created_at_ms: u64,
        mut vault_is_known: impl FnMut(&VaultId) -> bool,
    ) -> Result<CreatedPolicy, PolicyError> {
        let descriptor = owner
            .public_descriptor()
            .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidSignature))?;
        self.create_with_signer(
            &IdentityPolicySigner { owner, descriptor },
            created_at_ms,
            &mut vault_is_known,
        )
    }

    pub fn generate_item_id(&mut self, state: &PolicyState) -> Result<ItemId, PolicyError> {
        let mut generator = NativeIdGenerator::from_source(&mut self.source);
        let generated = generator
            .generate_item_id(|candidate| {
                ItemId::from_bytes(*candidate.as_bytes())
                    .map_or(true, |wire| state.item_id_was_used(&wire))
            })
            .map_err(map_identifier_error)?;
        ItemId::from_bytes(*generated.as_bytes())
            .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidFormat))
    }

    fn create_with_signer(
        &mut self,
        signer: &impl PolicySigner,
        created_at_ms: u64,
        mut vault_is_known: impl FnMut(&VaultId) -> bool,
    ) -> Result<CreatedPolicy, PolicyError> {
        let owner = signer.descriptor()?;
        validate_descriptor(&owner)?;
        if owner.principal_kind != PrincipalKind::Human
            || signer.principal_id() != owner.principal_id
        {
            return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
        }
        let vault_id = {
            let mut generator = NativeIdGenerator::from_source(&mut self.source);
            let generated = generator
                .generate_vault_id(|candidate| {
                    VaultId::from_bytes(*candidate.as_bytes())
                        .map_or(true, |wire| vault_is_known(&wire))
                })
                .map_err(map_identifier_error)?;
            VaultId::from_bytes(*generated.as_bytes())
                .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidFormat))?
        };
        let mut genesis = PolicyGenesisV1 {
            vault_id,
            policy_sequence: 0,
            previous_policy_hash: FixedBytes::new(ZERO_DIGEST),
            created_at_ms,
            suite: SUITE,
            owner,
            source_attestation: None,
            item_inventory: Vec::<EmptyGenesisEntryV1>::new(),
            direct_grants: Vec::<EmptyGenesisEntryV1>::new(),
            owner_signature: Signature64::new([0; 64]),
        };
        let preimage = genesis
            .signature_preimage()
            .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
        genesis.owner_signature = signer.sign(&preimage)?;
        let journal = PolicyJournalV1 {
            genesis,
            revisions: Vec::new(),
        };
        let state = replay_policy(&journal)?;
        Ok(CreatedPolicy { journal, state })
    }
}

impl PolicyState {
    pub fn prepare_revision(
        &self,
        author: &VaultPrincipalIdentity,
        timestamp_ms: u64,
        operations: Vec<PolicyOperationV1>,
    ) -> Result<PreparedPolicyRevision, PolicyError> {
        let descriptor = author
            .public_descriptor()
            .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidSignature))?;
        self.prepare_with_signer(
            &IdentityPolicySigner {
                owner: author,
                descriptor,
            },
            timestamp_ms,
            operations,
        )
    }

    fn prepare_with_signer(
        &self,
        signer: &impl PolicySigner,
        timestamp_ms: u64,
        operations: Vec<PolicyOperationV1>,
    ) -> Result<PreparedPolicyRevision, PolicyError> {
        let author_id = signer.principal_id();
        if !self.owners.contains(&author_id) {
            return Err(PolicyError::new(PolicyErrorKind::Unauthorized));
        }
        let active = self
            .principals
            .get(&author_id)
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
        if signer.descriptor()? != active.descriptor {
            return Err(PolicyError::new(PolicyErrorKind::Unauthorized));
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::CapacityExhausted))?;
        if sequence > MAX_POLICY_REVISIONS as u64 {
            return Err(PolicyError::new(PolicyErrorKind::CapacityExhausted));
        }
        let mut state = apply_operations(self, sequence, &operations)?;
        let resulting_policy_state_hash = state.normalized_state_hash()?;
        let mut revision = SignedPolicyRevisionV1 {
            vault_id: self.vault_id,
            sequence,
            previous_revision_hash: self.terminal_revision_hash.clone(),
            timestamp_ms,
            author_principal_id: author_id,
            operations,
            resulting_policy_state_hash,
            signature: Signature64::new([0; 64]),
        };
        let preimage = revision
            .signature_preimage()
            .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
        revision.signature = signer.sign(&preimage)?;
        state.terminal_revision_hash = revision
            .recomputed_hash()
            .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
        state
            .revision_hashes
            .push(state.terminal_revision_hash.clone());
        Ok(PreparedPolicyRevision { revision, state })
    }
}

pub fn replay_policy(journal: &PolicyJournalV1) -> Result<PolicyState, PolicyError> {
    replay_policy_with_catalog(journal, BTreeMap::new())
}

pub(super) fn replay_policy_with_catalog(
    journal: &PolicyJournalV1,
    witness_policies: BTreeMap<Digest32, WitnessPolicy>,
) -> Result<PolicyState, PolicyError> {
    let genesis = &journal.genesis;
    if genesis.policy_sequence != 0
        || genesis.previous_policy_hash.as_bytes() != &ZERO_DIGEST
        || genesis.suite != SUITE
        || genesis.owner.principal_kind != PrincipalKind::Human
        || !genesis.item_inventory.is_empty()
        || !genesis.direct_grants.is_empty()
        || journal.revisions.len() > MAX_POLICY_REVISIONS
    {
        return Err(PolicyError::new(PolicyErrorKind::InvalidFormat));
    }
    validate_descriptor(&genesis.owner)?;
    let genesis_preimage = genesis
        .signature_preimage()
        .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
    crypto::verify_bytes(
        &genesis.owner.verification_public_key,
        &genesis_preimage,
        &genesis.owner_signature,
    )
    .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidSignature))?;
    let genesis_fingerprint = genesis
        .recomputed_fingerprint()
        .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
    let owner_id = genesis.owner.principal_id;
    let mut state = PolicyState {
        suite: SUITE,
        vault_id: genesis.vault_id,
        genesis_fingerprint: genesis_fingerprint.clone(),
        sequence: 0,
        terminal_revision_hash: genesis_fingerprint.clone(),
        revision_hashes: vec![genesis_fingerprint],
        principals: BTreeMap::from([(
            owner_id,
            PrincipalPolicyState {
                descriptor: genesis.owner.clone(),
                display_label: "owner".to_owned(),
            },
        )]),
        historical_principal_descriptors: BTreeMap::from([(owner_id, genesis.owner.clone())]),
        historical_principal_ids: BTreeSet::from([owner_id]),
        historical_recipient_keys: BTreeSet::from([genesis.owner.recipient_public_key.clone()]),
        historical_verification_keys: BTreeSet::from([genesis
            .owner
            .verification_public_key
            .clone()]),
        owners: BTreeSet::from([owner_id]),
        items: BTreeMap::new(),
        historical_item_ids: BTreeSet::new(),
        tombstones: BTreeMap::new(),
        witness_policies,
    };

    let mut prior_timestamp = genesis.created_at_ms;
    for (index, revision) in journal.revisions.iter().enumerate() {
        let sequence = u64::try_from(index)
            .map_err(|_| PolicyError::new(PolicyErrorKind::CapacityExhausted))?
            + 1;
        if revision.vault_id != state.vault_id
            || revision.sequence != sequence
            || revision.previous_revision_hash != state.terminal_revision_hash
            || revision.timestamp_ms < prior_timestamp
            || revision.operations.is_empty()
        {
            return Err(PolicyError::new(PolicyErrorKind::InvalidAncestry));
        }
        if !state.owners.contains(&revision.author_principal_id) {
            return Err(PolicyError::new(PolicyErrorKind::Unauthorized));
        }
        let author = state
            .principals
            .get(&revision.author_principal_id)
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
        let preimage = revision
            .signature_preimage()
            .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
        crypto::verify_bytes(
            &author.descriptor.verification_public_key,
            &preimage,
            &revision.signature,
        )
        .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidSignature))?;
        let mut next = apply_operations(&state, sequence, &revision.operations)?;
        if next.normalized_state_hash()? != revision.resulting_policy_state_hash {
            return Err(PolicyError::new(PolicyErrorKind::StateHashMismatch));
        }
        next.terminal_revision_hash = revision
            .recomputed_hash()
            .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
        next.revision_hashes
            .push(next.terminal_revision_hash.clone());
        state = next;
        prior_timestamp = revision.timestamp_ms;
    }
    Ok(state)
}

#[derive(Clone)]
struct ReaderRotation {
    prior_epoch: u64,
    next_epoch: u64,
    prior_reader_ids: Vec<PrincipalId>,
    next_reader_ids: Vec<PrincipalId>,
    replacement_descriptor: DescriptorMetadataV1,
    replacement_current_item_revision_hash: Digest32,
}

#[derive(Clone)]
struct SlotRotation {
    next_epoch: u64,
    direct_slots: Vec<DirectSlotV1>,
    witnessed_state: Option<WitnessedStateV1>,
}

fn apply_operations(
    prior: &PolicyState,
    sequence: u64,
    operations: &[PolicyOperationV1],
) -> Result<PolicyState, PolicyError> {
    if operations.is_empty() {
        return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
    }
    let mut next = prior.clone();
    next.sequence = sequence;
    let mut reader_rotations = BTreeMap::<ItemId, ReaderRotation>::new();
    let mut slot_rotations = BTreeMap::<ItemId, SlotRotation>::new();
    let mut mutation_keys = BTreeSet::new();

    for operation in operations {
        validate_policy_operation_context(
            operation,
            sequence,
            &prior.vault_id,
            &prior.genesis_fingerprint,
        )
        .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
        let key = operation_key(operation);
        if !mutation_keys.insert(key) {
            return Err(PolicyError::new(PolicyErrorKind::AmbiguousMutation));
        }
        match operation {
            PolicyOperationV1::PrincipalAdd {
                descriptor,
                display_label,
                ..
            } => add_principal(&mut next, descriptor, display_label)?,
            PolicyOperationV1::PrincipalLabelChange {
                principal_id,
                prior_label,
                next_label,
            } => {
                let principal = next
                    .principals
                    .get_mut(principal_id)
                    .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
                if principal.display_label != *prior_label
                    || next_label.is_empty()
                    || next_label.len() > MAX_PUBLIC_LABEL_BYTES
                    || prior_label == next_label
                {
                    return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
                }
                principal.display_label.clone_from(next_label);
            }
            PolicyOperationV1::PrincipalRemove { principal_id, .. } => {
                remove_principal(&mut next, principal_id)?;
            }
            PolicyOperationV1::OwnerGrant { principal_id } => {
                let principal = next
                    .principals
                    .get(principal_id)
                    .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
                if principal.descriptor.principal_kind != PrincipalKind::Human
                    || !next.owners.insert(*principal_id)
                {
                    return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
                }
            }
            PolicyOperationV1::OwnerRevoke { principal_id } => {
                if !next.owners.remove(principal_id) {
                    return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
                }
                if next.owners.is_empty() {
                    return Err(PolicyError::new(PolicyErrorKind::SoleOwner));
                }
            }
            PolicyOperationV1::ItemCreate {
                item_id,
                item_kind,
                key_epoch,
                descriptor,
                current_item_revision_hash,
                direct_slots,
                witnessed_state,
            } => create_item(
                &mut next,
                *item_id,
                *item_kind,
                *key_epoch,
                descriptor,
                current_item_revision_hash,
                direct_slots,
                witnessed_state.as_ref(),
            )?,
            PolicyOperationV1::ItemRename {
                item_id,
                prior_descriptor_revision,
                next_descriptor,
            } => {
                let item = next
                    .items
                    .get_mut(item_id)
                    .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownItem))?;
                if item.descriptor.revision != *prior_descriptor_revision
                    || next_descriptor.key_epoch != item.key_epoch
                {
                    return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
                }
                item.descriptor = next_descriptor.clone();
            }
            PolicyOperationV1::ItemDelete {
                item_id,
                final_descriptor_digest,
                final_item_revision_hash,
                deletion_policy_sequence,
            } => delete_item(
                &mut next,
                item_id,
                final_descriptor_digest,
                final_item_revision_hash,
                *deletion_policy_sequence,
            )?,
            PolicyOperationV1::ItemRoleChange {
                item_id,
                principal_id,
                prior_role,
                next_role,
            } => change_role(&mut next, item_id, principal_id, *prior_role, *next_role)?,
            PolicyOperationV1::ItemReaderSetChange {
                item_id,
                prior_epoch,
                next_epoch,
                prior_reader_ids,
                next_reader_ids,
                replacement_descriptor,
                replacement_current_item_revision_hash,
            } => {
                reader_rotations.insert(
                    *item_id,
                    ReaderRotation {
                        prior_epoch: *prior_epoch,
                        next_epoch: *next_epoch,
                        prior_reader_ids: prior_reader_ids.clone(),
                        next_reader_ids: next_reader_ids.clone(),
                        replacement_descriptor: replacement_descriptor.clone(),
                        replacement_current_item_revision_hash:
                            replacement_current_item_revision_hash.clone(),
                    },
                );
            }
            PolicyOperationV1::ItemSlotsReplace {
                item_id,
                next_epoch,
                direct_slots,
                witnessed_state,
            } => {
                slot_rotations.insert(
                    *item_id,
                    SlotRotation {
                        next_epoch: *next_epoch,
                        direct_slots: direct_slots.clone(),
                        witnessed_state: witnessed_state.clone(),
                    },
                );
            }
            PolicyOperationV1::PrincipalReplace {
                prior_principal_id,
                next_descriptor,
                ..
            } => replace_principal(&mut next, prior_principal_id, next_descriptor)?,
        }
    }

    apply_rotations(prior, &mut next, reader_rotations, slot_rotations)?;
    validate_complete_state(&next)?;
    if next.items.len() > MAX_ITEMS {
        return Err(PolicyError::new(PolicyErrorKind::CapacityExhausted));
    }
    Ok(next)
}

fn add_principal(
    state: &mut PolicyState,
    descriptor: &PrincipalDescriptorV1,
    display_label: &str,
) -> Result<(), PolicyError> {
    validate_descriptor(descriptor)?;
    if display_label.is_empty() || display_label.len() > MAX_PUBLIC_LABEL_BYTES {
        return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
    }
    if state
        .historical_principal_ids
        .contains(&descriptor.principal_id)
        || state
            .historical_recipient_keys
            .contains(&descriptor.recipient_public_key)
        || state
            .historical_verification_keys
            .contains(&descriptor.verification_public_key)
    {
        return Err(PolicyError::new(PolicyErrorKind::IdentifierReused));
    }
    state
        .historical_principal_ids
        .insert(descriptor.principal_id);
    state
        .historical_principal_descriptors
        .insert(descriptor.principal_id, descriptor.clone());
    state
        .historical_recipient_keys
        .insert(descriptor.recipient_public_key.clone());
    state
        .historical_verification_keys
        .insert(descriptor.verification_public_key.clone());
    state.principals.insert(
        descriptor.principal_id,
        PrincipalPolicyState {
            descriptor: descriptor.clone(),
            display_label: display_label.to_owned(),
        },
    );
    Ok(())
}

fn remove_principal(
    state: &mut PolicyState,
    principal_id: &PrincipalId,
) -> Result<(), PolicyError> {
    if state.owners.contains(principal_id) {
        return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
    }
    if state
        .items
        .values()
        .any(|item| item.grants.contains_key(principal_id))
    {
        return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
    }
    state
        .principals
        .remove(principal_id)
        .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_item(
    state: &mut PolicyState,
    item_id: ItemId,
    item_kind: jury_protocol::vault_v1::ItemKind,
    key_epoch: u64,
    descriptor: &DescriptorMetadataV1,
    current_hash: &Digest32,
    direct_slots: &[DirectSlotV1],
    witnessed_state: Option<&WitnessedStateV1>,
) -> Result<(), PolicyError> {
    if state.historical_item_ids.contains(&item_id) {
        return Err(PolicyError::new(PolicyErrorKind::IdentifierReused));
    }
    let mut grants = BTreeMap::new();
    for slot in direct_slots {
        if slot.access_role != AccessRole::Owner
            && let Some(existing) = grants.insert(slot.recipient_principal_id, slot.access_role)
            && existing != slot.access_role
        {
            return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
        }
    }
    state.historical_item_ids.insert(item_id);
    state.items.insert(
        item_id,
        ItemPolicyState {
            item_kind,
            key_epoch,
            descriptor: descriptor.clone(),
            current_item_revision_hash: current_hash.clone(),
            grants,
            direct_slots: direct_slots.to_vec(),
            witnessed_state: witnessed_state.cloned(),
        },
    );
    Ok(())
}

fn delete_item(
    state: &mut PolicyState,
    item_id: &ItemId,
    descriptor_digest: &Digest32,
    revision_hash: &Digest32,
    sequence: u64,
) -> Result<(), PolicyError> {
    let item = state
        .items
        .remove(item_id)
        .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownItem))?;
    if item.descriptor.ciphertext_digest != *descriptor_digest
        || item.current_item_revision_hash != *revision_hash
    {
        return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
    }
    state.tombstones.insert(
        *item_id,
        TombstoneState {
            deletion_policy_sequence: sequence,
            final_descriptor_digest: descriptor_digest.clone(),
            final_item_revision_hash: revision_hash.clone(),
        },
    );
    Ok(())
}

fn change_role(
    state: &mut PolicyState,
    item_id: &ItemId,
    principal_id: &PrincipalId,
    prior_role: Option<AccessRole>,
    next_role: Option<AccessRole>,
) -> Result<(), PolicyError> {
    let principal = state
        .principals
        .get(principal_id)
        .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
    if !matches!(
        principal.descriptor.principal_kind,
        PrincipalKind::Human | PrincipalKind::Machine
    ) || state.owners.contains(principal_id)
        || matches!(prior_role, Some(AccessRole::Owner))
        || matches!(next_role, Some(AccessRole::Owner))
    {
        return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
    }
    let item = state
        .items
        .get_mut(item_id)
        .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownItem))?;
    if item.grants.get(principal_id).copied() != prior_role {
        return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
    }
    match next_role {
        Some(role @ (AccessRole::Reader | AccessRole::Writer)) => {
            item.grants.insert(*principal_id, role);
        }
        None => {
            item.grants.remove(principal_id);
        }
        Some(AccessRole::Owner) => {
            return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
        }
    }
    Ok(())
}

fn replace_principal(
    state: &mut PolicyState,
    prior_id: &PrincipalId,
    next_descriptor: &PrincipalDescriptorV1,
) -> Result<(), PolicyError> {
    validate_descriptor(next_descriptor)?;
    let prior = state
        .principals
        .get(prior_id)
        .cloned()
        .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
    if prior.descriptor.principal_kind != next_descriptor.principal_kind {
        return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
    }
    if state
        .historical_principal_ids
        .contains(&next_descriptor.principal_id)
        || state
            .historical_recipient_keys
            .contains(&next_descriptor.recipient_public_key)
        || state
            .historical_verification_keys
            .contains(&next_descriptor.verification_public_key)
    {
        return Err(PolicyError::new(PolicyErrorKind::IdentifierReused));
    }
    state.principals.remove(prior_id);
    state.principals.insert(
        next_descriptor.principal_id,
        PrincipalPolicyState {
            descriptor: next_descriptor.clone(),
            display_label: prior.display_label,
        },
    );
    state
        .historical_principal_ids
        .insert(next_descriptor.principal_id);
    state
        .historical_principal_descriptors
        .insert(next_descriptor.principal_id, next_descriptor.clone());
    state
        .historical_recipient_keys
        .insert(next_descriptor.recipient_public_key.clone());
    state
        .historical_verification_keys
        .insert(next_descriptor.verification_public_key.clone());
    if state.owners.remove(prior_id) {
        state.owners.insert(next_descriptor.principal_id);
    }
    for item in state.items.values_mut() {
        if let Some(role) = item.grants.remove(prior_id) {
            item.grants.insert(next_descriptor.principal_id, role);
        }
    }
    Ok(())
}

fn apply_rotations(
    prior: &PolicyState,
    next: &mut PolicyState,
    mut reader_rotations: BTreeMap<ItemId, ReaderRotation>,
    mut slot_rotations: BTreeMap<ItemId, SlotRotation>,
) -> Result<(), PolicyError> {
    let common_items = prior
        .items
        .keys()
        .filter(|item_id| next.items.contains_key(item_id))
        .copied()
        .collect::<Vec<_>>();
    for item_id in common_items {
        let prior_readers = prior.effective_reader_ids(&item_id);
        let next_readers = next.effective_reader_ids(&item_id);
        let readers_changed = prior_readers != next_readers;
        let reader_rotation = reader_rotations.remove(&item_id);
        let slot_rotation = slot_rotations.remove(&item_id);
        if readers_changed && (reader_rotation.is_none() || slot_rotation.is_none()) {
            return Err(PolicyError::new(PolicyErrorKind::IncompleteRotation));
        }
        if reader_rotation.is_some() && slot_rotation.is_none() {
            return Err(PolicyError::new(PolicyErrorKind::IncompleteRotation));
        }
        let current_epoch = prior
            .items
            .get(&item_id)
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownItem))?
            .key_epoch;
        let expected_epoch = current_epoch
            .checked_add(1)
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::CapacityExhausted))?;
        if let Some(rotation) = reader_rotation {
            if rotation.prior_epoch != current_epoch
                || rotation.next_epoch != expected_epoch
                || rotation.prior_reader_ids != prior_readers
                || rotation.next_reader_ids != next_readers
                || rotation.replacement_descriptor.key_epoch != expected_epoch
            {
                return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
            }
            let item = next
                .items
                .get_mut(&item_id)
                .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownItem))?;
            item.descriptor = rotation.replacement_descriptor;
            item.current_item_revision_hash = rotation.replacement_current_item_revision_hash;
        }
        if let Some(rotation) = slot_rotation {
            if rotation.next_epoch != expected_epoch {
                return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
            }
            let item = next
                .items
                .get_mut(&item_id)
                .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownItem))?;
            if !readers_changed
                && item.direct_slots == rotation.direct_slots
                && item.witnessed_state == rotation.witnessed_state
            {
                return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
            }
            item.key_epoch = expected_epoch;
            item.direct_slots = rotation.direct_slots;
            item.witnessed_state = rotation.witnessed_state;
            if item.descriptor.key_epoch != expected_epoch {
                return Err(PolicyError::new(PolicyErrorKind::IncompleteRotation));
            }
        }
    }
    if !reader_rotations.is_empty() || !slot_rotations.is_empty() {
        return Err(PolicyError::new(PolicyErrorKind::UnknownItem));
    }
    Ok(())
}

fn validate_complete_state(state: &PolicyState) -> Result<(), PolicyError> {
    if state.owners.is_empty()
        || state.owners.iter().any(|owner| {
            state
                .principals
                .get(owner)
                .is_none_or(|principal| principal.descriptor.principal_kind != PrincipalKind::Human)
        })
    {
        return Err(PolicyError::new(PolicyErrorKind::SoleOwner));
    }
    for (item_id, item) in &state.items {
        let mode = item
            .access_mode()
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::InvalidTransition))?;
        for (principal_id, role) in &item.grants {
            let principal = state
                .principals
                .get(principal_id)
                .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
            if !matches!(
                principal.descriptor.principal_kind,
                PrincipalKind::Human | PrincipalKind::Machine
            ) || *role == AccessRole::Owner
            {
                return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
            }
        }
        for slot in &item.direct_slots {
            let principal = state
                .principals
                .get(&slot.recipient_principal_id)
                .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
            let effective_role = state.effective_role(item_id, &slot.recipient_principal_id);
            let slot_role_is_current = effective_role == Some(slot.access_role)
                || matches!(
                    (effective_role, slot.access_role),
                    (
                        Some(AccessRole::Reader | AccessRole::Writer),
                        AccessRole::Reader | AccessRole::Writer
                    )
                );
            if !matches!(
                principal.descriptor.principal_kind,
                PrincipalKind::Human | PrincipalKind::Machine
            ) || !slot_role_is_current
                || slot.recipient_public_key_fingerprint
                    != jury_protocol::vault_v1::recipient_public_key_fingerprint(
                        &principal.descriptor.recipient_public_key,
                    )
                || slot.item_access_mode != mode
                || slot.key_epoch != item.key_epoch
                || slot.policy_sequence == 0
                || slot.policy_sequence > state.sequence
            {
                return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
            }
        }
        if let Some(witnessed) = &item.witnessed_state {
            let first = witnessed
                .slots
                .first()
                .ok_or_else(|| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
            let first_members = first
                .capsules
                .iter()
                .map(|capsule| capsule.witness_id)
                .collect::<Vec<_>>();
            for slot in &witnessed.slots {
                let members = slot
                    .capsules
                    .iter()
                    .map(|capsule| capsule.witness_id)
                    .collect::<Vec<_>>();
                if slot.item_access_mode != mode
                    || slot.key_epoch != item.key_epoch
                    || slot.vault_policy_sequence == 0
                    || slot.vault_policy_sequence > state.sequence
                    || slot.threshold != first.threshold
                    || slot.witness_policy_id != first.witness_policy_id
                    || slot.witness_policy_revision != first.witness_policy_revision
                    || slot.witness_policy_digest != first.witness_policy_digest
                    || members != first_members
                {
                    return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
                }
            }
            for witness_id in first_members {
                if state.principals.get(&witness_id).is_none_or(|principal| {
                    principal.descriptor.principal_kind != PrincipalKind::Witness
                }) {
                    return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
                }
            }
            validate_item_policy_binding(state, item_id, witnessed)?;
        }
    }
    Ok(())
}

fn validate_descriptor(descriptor: &PrincipalDescriptorV1) -> Result<(), PolicyError> {
    if descriptor.descriptor_version != 1 {
        return Err(PolicyError::new(PolicyErrorKind::InvalidFormat));
    }
    let preimage = descriptor
        .self_signature_preimage()
        .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
    crypto::verify_bytes(
        &descriptor.verification_public_key,
        &preimage,
        &descriptor.self_signature,
    )
    .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidSignature))
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum OperationKey {
    Principal(u8, PrincipalId),
    Item(u8, ItemId),
    ItemPrincipal(u8, ItemId, PrincipalId),
}

fn operation_key(operation: &PolicyOperationV1) -> OperationKey {
    match operation {
        PolicyOperationV1::PrincipalAdd { descriptor, .. } => {
            OperationKey::Principal(1, descriptor.principal_id)
        }
        PolicyOperationV1::PrincipalLabelChange { principal_id, .. } => {
            OperationKey::Principal(2, *principal_id)
        }
        PolicyOperationV1::PrincipalRemove { principal_id, .. } => {
            OperationKey::Principal(3, *principal_id)
        }
        PolicyOperationV1::OwnerGrant { principal_id } => OperationKey::Principal(4, *principal_id),
        PolicyOperationV1::OwnerRevoke { principal_id } => {
            OperationKey::Principal(5, *principal_id)
        }
        PolicyOperationV1::ItemCreate { item_id, .. } => OperationKey::Item(6, *item_id),
        PolicyOperationV1::ItemRename { item_id, .. } => OperationKey::Item(7, *item_id),
        PolicyOperationV1::ItemDelete { item_id, .. } => OperationKey::Item(8, *item_id),
        PolicyOperationV1::ItemRoleChange {
            item_id,
            principal_id,
            ..
        } => OperationKey::ItemPrincipal(9, *item_id, *principal_id),
        PolicyOperationV1::ItemReaderSetChange { item_id, .. } => OperationKey::Item(10, *item_id),
        PolicyOperationV1::ItemSlotsReplace { item_id, .. } => OperationKey::Item(11, *item_id),
        PolicyOperationV1::PrincipalReplace {
            prior_principal_id, ..
        } => OperationKey::Principal(12, *prior_principal_id),
    }
}

fn map_identifier_error(error: IdentifierGenerationError) -> PolicyError {
    PolicyError::new(match error {
        IdentifierGenerationError::EntropyUnavailable => PolicyErrorKind::EntropyUnavailable,
        IdentifierGenerationError::RetryExhausted => PolicyErrorKind::RetryExhausted,
    })
}

pub(super) trait PolicySigner {
    fn principal_id(&self) -> PrincipalId;
    fn descriptor(&self) -> Result<PrincipalDescriptorV1, PolicyError>;
    fn sign(&self, preimage: &[u8]) -> Result<Signature64, PolicyError>;
}

struct IdentityPolicySigner<'a> {
    owner: &'a VaultPrincipalIdentity,
    descriptor: PrincipalDescriptorV1,
}

impl PolicySigner for IdentityPolicySigner<'_> {
    fn principal_id(&self) -> PrincipalId {
        self.owner.principal_id()
    }

    fn descriptor(&self) -> Result<PrincipalDescriptorV1, PolicyError> {
        Ok(self.descriptor.clone())
    }

    fn sign(&self, preimage: &[u8]) -> Result<Signature64, PolicyError> {
        self.owner
            .sign_validated_statement(preimage)
            .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidSignature))
    }
}

#[cfg(test)]
pub(super) fn create_with_test_signer<R: RandomSource>(
    creator: &mut PolicyCreator<R>,
    signer: &impl PolicySigner,
    created_at_ms: u64,
    vault_is_known: impl FnMut(&VaultId) -> bool,
) -> Result<CreatedPolicy, PolicyError> {
    creator.create_with_signer(signer, created_at_ms, vault_is_known)
}

#[cfg(test)]
pub(super) fn prepare_with_test_signer(
    state: &PolicyState,
    signer: &impl PolicySigner,
    timestamp_ms: u64,
    operations: Vec<PolicyOperationV1>,
) -> Result<PreparedPolicyRevision, PolicyError> {
    state.prepare_with_signer(signer, timestamp_ms, operations)
}
