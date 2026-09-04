use std::collections::{BTreeMap, BTreeSet};

use jury_protected::{OsRandom, RandomSource};
use jury_protocol::vault_v1::{
    AccessRole, ContentRole, DescriptorMetadataV1, Digest32, DirectSlotV1, EmptyGenesisEntryV1,
    FixedBytes, ItemAccessMode, ItemId, MAX_ITEMS, MAX_POLICY_REVISIONS, MAX_PUBLIC_LABEL_BYTES,
    PolicyGenesisV1, PolicyJournalV1, PolicyOperationV1, PrincipalDescriptorV1, PrincipalId,
    PrincipalKind, Signature64, SignedPolicyRevisionV1, VaultId, WitnessedStateV1,
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
