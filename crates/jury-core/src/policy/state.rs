use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use jury_protocol::vault_v1::{
    AccessRole, DescriptorMetadataV1, Digest32, DirectSlotV1, FixedBytes, ItemAccessMode, ItemId,
    ItemKind, PrincipalDescriptorV1, PrincipalId, PrincipalKind, VaultId, WitnessedSlotV1,
    WitnessedStateV1, witnessed_slot_set_digest,
};
use sha2::{Digest as _, Sha256};

use crate::domain::Capability;

use super::witness::WitnessPolicy;

const SUITE: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyErrorKind {
    InvalidFormat,
    InvalidSignature,
    InvalidAncestry,
    Unauthorized,
    UnknownPrincipal,
    UnknownItem,
    IdentifierReused,
    InvalidRole,
    SoleOwner,
    InvalidTransition,
    IncompleteRotation,
    AmbiguousMutation,
    StateHashMismatch,
    EntropyUnavailable,
    RetryExhausted,
    CapacityExhausted,
    MissingWitnessPolicy,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PolicyError {
    kind: PolicyErrorKind,
}

impl PolicyError {
    pub(crate) const fn new(kind: PolicyErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> PolicyErrorKind {
        self.kind
    }
}

impl fmt::Debug for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            PolicyErrorKind::InvalidFormat => "policy format is invalid",
            PolicyErrorKind::InvalidSignature => "policy signature is invalid",
            PolicyErrorKind::InvalidAncestry => "policy ancestry is invalid",
            PolicyErrorKind::Unauthorized => "policy operation is unauthorized",
            PolicyErrorKind::UnknownPrincipal => "policy principal is unavailable",
            PolicyErrorKind::UnknownItem => "policy item is unavailable",
            PolicyErrorKind::IdentifierReused => "policy identifier was already used",
            PolicyErrorKind::InvalidRole => "policy role is invalid",
            PolicyErrorKind::SoleOwner => "policy must retain one human owner",
            PolicyErrorKind::InvalidTransition => "policy transition is invalid",
            PolicyErrorKind::IncompleteRotation => "policy key rotation is incomplete",
            PolicyErrorKind::AmbiguousMutation => "policy mutation is ambiguous",
            PolicyErrorKind::StateHashMismatch => "normalized policy state differs",
            PolicyErrorKind::EntropyUnavailable => "operating-system entropy was unavailable",
            PolicyErrorKind::RetryExhausted => "policy generation exhausted its retry bound",
            PolicyErrorKind::CapacityExhausted => "policy capacity is exhausted",
            PolicyErrorKind::MissingWitnessPolicy => {
                "authenticated witnessed policy material is unavailable"
            }
        })
    }
}

impl std::error::Error for PolicyError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalPolicyState {
    pub descriptor: PrincipalDescriptorV1,
    pub display_label: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TombstoneState {
    pub deletion_policy_sequence: u64,
    pub final_descriptor_digest: Digest32,
    pub final_item_revision_hash: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemPolicyState {
    pub item_kind: ItemKind,
    pub key_epoch: u64,
    pub descriptor: DescriptorMetadataV1,
    pub current_item_revision_hash: Digest32,
    pub grants: BTreeMap<PrincipalId, AccessRole>,
    pub direct_slots: Vec<DirectSlotV1>,
    pub witnessed_state: Option<WitnessedStateV1>,
}

impl ItemPolicyState {
    #[must_use]
    pub const fn access_mode(&self) -> Option<ItemAccessMode> {
        match (self.direct_slots.is_empty(), self.witnessed_state.is_none()) {
            (false, false) => Some(ItemAccessMode::Mixed),
            (false, true) => Some(ItemAccessMode::DirectOnly),
            (true, false) => Some(ItemAccessMode::WitnessedOnly),
            (true, true) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessPath {
    Direct,
    Witnessed,
    Mixed,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessReason {
    Allowed,
    UnknownItem,
    UnknownPrincipal,
    RoleDenied,
    NoUsableDirectSlot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessExplanation {
    pub allowed: bool,
    pub effective_role: Option<AccessRole>,
    pub path: AccessPath,
    pub carries_quorum_claim: bool,
    pub reason: AccessReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessAuthority {
    pub policy_id: jury_protocol::vault_v1::WitnessPolicyId,
    pub policy_revision: u64,
    pub policy_digest: Digest32,
    pub threshold: u8,
    pub member_ids: Vec<PrincipalId>,
    pub reachable: bool,
    pub carries_quorum_claim: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyState {
    pub(crate) suite: u16,
    pub(crate) vault_id: VaultId,
    pub(crate) genesis_fingerprint: Digest32,
    pub(crate) sequence: u64,
    pub(crate) terminal_revision_hash: Digest32,
    pub(crate) principals: BTreeMap<PrincipalId, PrincipalPolicyState>,
    pub(crate) historical_principal_descriptors: BTreeMap<PrincipalId, PrincipalDescriptorV1>,
    pub(crate) historical_principal_ids: BTreeSet<PrincipalId>,
    pub(crate) historical_recipient_keys: BTreeSet<jury_protocol::vault_v1::RecipientPublicKey1216>,
    pub(crate) historical_verification_keys:
        BTreeSet<jury_protocol::vault_v1::VerificationPublicKey32>,
    pub(crate) owners: BTreeSet<PrincipalId>,
    pub(crate) items: BTreeMap<ItemId, ItemPolicyState>,
    pub(crate) historical_item_ids: BTreeSet<ItemId>,
    pub(crate) tombstones: BTreeMap<ItemId, TombstoneState>,
    pub(crate) witness_policies: BTreeMap<Digest32, WitnessPolicy>,
}

impl PolicyState {
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    #[must_use]
    pub const fn genesis_fingerprint(&self) -> &Digest32 {
        &self.genesis_fingerprint
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn terminal_revision_hash(&self) -> &Digest32 {
        &self.terminal_revision_hash
    }

    #[must_use]
    pub fn principal(&self, principal_id: &PrincipalId) -> Option<&PrincipalPolicyState> {
        self.principals.get(principal_id)
    }

    #[must_use]
    pub fn principal_count(&self) -> usize {
        self.principals.len()
    }

    #[must_use]
    pub fn owner_count(&self) -> usize {
        self.owners.len()
    }

    #[must_use]
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn item(&self, item_id: &ItemId) -> Option<&ItemPolicyState> {
        self.items.get(item_id)
    }

    pub(crate) fn witness_policy(&self, digest: &Digest32) -> Option<&WitnessPolicy> {
        self.witness_policies.get(digest)
    }

    pub(crate) fn verification_key(
        &self,
        principal_id: &PrincipalId,
    ) -> Option<jury_protocol::vault_v1::VerificationPublicKey32> {
        self.historical_principal_descriptors
            .get(principal_id)
            .map(|descriptor| descriptor.verification_public_key.clone())
    }

    #[must_use]
    pub fn tombstone(&self, item_id: &ItemId) -> Option<&TombstoneState> {
        self.tombstones.get(item_id)
    }

    #[must_use]
    pub fn is_owner(&self, principal_id: &PrincipalId) -> bool {
        self.owners.contains(principal_id)
    }

    #[must_use]
    pub fn principal_id_was_used(&self, principal_id: &PrincipalId) -> bool {
        self.historical_principal_ids.contains(principal_id)
    }

    #[must_use]
    pub fn item_id_was_used(&self, item_id: &ItemId) -> bool {
        self.historical_item_ids.contains(item_id)
    }

    #[must_use]
    pub fn access(
        &self,
        item_id: &ItemId,
        principal_id: &PrincipalId,
        capability: Capability,
    ) -> AccessExplanation {
        let Some(item) = self.items.get(item_id) else {
            return denied(AccessReason::UnknownItem);
        };
        if !self.principals.contains_key(principal_id) {
            return denied(AccessReason::UnknownPrincipal);
        }
        let role = self.effective_role(item_id, principal_id);
        let Some(role) = role else {
            return denied(AccessReason::RoleDenied);
        };
        if !role_permits(role, capability) {
            return AccessExplanation {
                effective_role: Some(role),
                ..denied(AccessReason::RoleDenied)
            };
        }
        let direct = item
            .direct_slots
            .iter()
            .any(|slot| slot.recipient_principal_id == *principal_id);
        let witnessed = item.witnessed_state.is_some();
        let path = match (direct, witnessed) {
            (true, true) => AccessPath::Mixed,
            (true, false) => AccessPath::Direct,
            (false, true) => AccessPath::Witnessed,
            (false, false) => AccessPath::Unavailable,
        };
        if matches!(path, AccessPath::Unavailable) {
            return AccessExplanation {
                effective_role: Some(role),
                ..denied(AccessReason::NoUsableDirectSlot)
            };
        }
        AccessExplanation {
            allowed: true,
            effective_role: Some(role),
            path,
            carries_quorum_claim: !direct && witnessed,
            reason: AccessReason::Allowed,
        }
    }

    pub fn witness_authority(
        &self,
        item_id: &ItemId,
    ) -> Result<Option<WitnessAuthority>, PolicyError> {
        let Some(item) = self.items.get(item_id) else {
            return Err(PolicyError::new(PolicyErrorKind::UnknownItem));
        };
        let Some(witnessed) = &item.witnessed_state else {
            return Ok(None);
        };
        let first = witnessed
            .slots
            .first()
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
        let member_ids = first
            .capsules
            .iter()
            .map(|capsule| capsule.witness_id)
            .collect::<Vec<_>>();
        let active_count = member_ids
            .iter()
            .filter(|id| {
                self.principals.get(id).is_some_and(|principal| {
                    principal.descriptor.principal_kind == PrincipalKind::Witness
                })
            })
            .count();
        Ok(Some(WitnessAuthority {
            policy_id: first.witness_policy_id,
            policy_revision: first.witness_policy_revision,
            policy_digest: first.witness_policy_digest.clone(),
            threshold: first.threshold,
            reachable: active_count >= usize::from(first.threshold),
            member_ids,
            carries_quorum_claim: item.direct_slots.is_empty(),
        }))
    }

    pub(crate) fn effective_role(
        &self,
        item_id: &ItemId,
        principal_id: &PrincipalId,
    ) -> Option<AccessRole> {
        if self.owners.contains(principal_id) {
            return Some(AccessRole::Owner);
        }
        self.items
            .get(item_id)
            .and_then(|item| item.grants.get(principal_id).copied())
    }

    pub(crate) fn effective_reader_ids(&self, item_id: &ItemId) -> Vec<PrincipalId> {
        let mut readers = self.owners.iter().copied().collect::<BTreeSet<_>>();
        if let Some(item) = self.items.get(item_id) {
            readers.extend(item.grants.keys().copied());
        }
        readers.into_iter().collect()
    }

    pub(crate) fn owner_ids(&self) -> impl Iterator<Item = PrincipalId> + '_ {
        self.owners.iter().copied()
    }

    pub fn normalized_state_hash(&self) -> Result<Digest32, PolicyError> {
        let mut output = jce("jury-v1/policy-state/hash");
        output.extend_from_slice(&self.suite.to_be_bytes());
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(&self.sequence.to_be_bytes());

        let principal_entries = self
            .principals
            .values()
            .map(|principal| principal.descriptor.canonical_bytes())
            .collect::<Vec<_>>();
        list_bytes(&mut output, &principal_entries)?;
        list_fixed(
            &mut output,
            self.owners.iter().map(|id| id.as_bytes().as_slice()),
        )?;

        let item_entries = self
            .items
            .iter()
            .map(|(item_id, item)| {
                let mut entry = Vec::with_capacity(171);
                entry.extend_from_slice(item_id.as_bytes());
                entry.push(item_kind_tag(item.item_kind));
                entry.push(access_mode_tag(item.access_mode().ok_or_else(|| {
                    PolicyError::new(PolicyErrorKind::InvalidTransition)
                })?));
                entry.extend_from_slice(&item.key_epoch.to_be_bytes());
                entry.extend_from_slice(&item.descriptor.canonical_bytes());
                entry.extend_from_slice(item.current_item_revision_hash.as_bytes());
                Ok(entry)
            })
            .collect::<Result<Vec<_>, PolicyError>>()?;
        list_fixed(&mut output, item_entries.iter().map(Vec::as_slice))?;

        let tombstone_entries = self
            .tombstones
            .iter()
            .map(|(item_id, tombstone)| {
                let mut entry = Vec::with_capacity(104);
                entry.extend_from_slice(item_id.as_bytes());
                entry.extend_from_slice(&tombstone.deletion_policy_sequence.to_be_bytes());
                entry.extend_from_slice(tombstone.final_descriptor_digest.as_bytes());
                entry.extend_from_slice(tombstone.final_item_revision_hash.as_bytes());
                entry
            })
            .collect::<Vec<_>>();
        list_fixed(&mut output, tombstone_entries.iter().map(Vec::as_slice))?;

        let grant_entries = self
            .items
            .iter()
            .flat_map(|(item_id, item)| {
                item.grants.iter().map(move |(principal_id, role)| {
                    let mut entry = Vec::with_capacity(65);
                    entry.extend_from_slice(item_id.as_bytes());
                    entry.extend_from_slice(principal_id.as_bytes());
                    entry.push(access_role_tag(*role));
                    entry
                })
            })
            .collect::<Vec<_>>();
        list_fixed(&mut output, grant_entries.iter().map(Vec::as_slice))?;

        let mut direct_entries = self
            .items
            .iter()
            .flat_map(|(item_id, item)| {
                item.direct_slots.iter().map(move |slot| {
                    (
                        *item_id,
                        slot.content_role,
                        slot.recipient_principal_id,
                        slot.canonical_bytes(),
                    )
                })
            })
            .collect::<Vec<_>>();
        direct_entries.sort();
        list_fixed(
            &mut output,
            direct_entries.iter().map(|entry| entry.3.as_slice()),
        )?;

        let mut witnessed_slots = self
            .items
            .values()
            .filter_map(|item| item.witnessed_state.as_ref())
            .flat_map(|state| state.slots.iter().cloned())
            .collect::<Vec<WitnessedSlotV1>>();
        witnessed_slots.sort_by(|left, right| {
            (
                left.item_id,
                left.content_role,
                left.revision,
                left.revision_seal_id,
                left.slot_id,
            )
                .cmp(&(
                    right.item_id,
                    right.content_role,
                    right.revision,
                    right.revision_seal_id,
                    right.slot_id,
                ))
        });
        if witnessed_slots.is_empty() {
            output.push(0);
        } else {
            output.push(1);
            output.extend_from_slice(
                witnessed_slot_set_digest(&witnessed_slots)
                    .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidFormat))?
                    .as_bytes(),
            );
        }

        let revision_entries = self
            .items
            .iter()
            .map(|(item_id, item)| {
                let mut entry = Vec::with_capacity(64);
                entry.extend_from_slice(item_id.as_bytes());
                entry.extend_from_slice(item.current_item_revision_hash.as_bytes());
                entry
            })
            .collect::<Vec<_>>();
        list_fixed(&mut output, revision_entries.iter().map(Vec::as_slice))?;

        Ok(FixedBytes::new(Sha256::digest(output).into()))
    }
}

fn denied(reason: AccessReason) -> AccessExplanation {
    AccessExplanation {
        allowed: false,
        effective_role: None,
        path: AccessPath::Unavailable,
        carries_quorum_claim: false,
        reason,
    }
}

fn role_permits(role: AccessRole, capability: Capability) -> bool {
    matches!(
        (role, capability),
        (AccessRole::Reader, Capability::Read)
            | (AccessRole::Writer, Capability::Read | Capability::Write)
            | (AccessRole::Owner, _)
    )
}

fn item_kind_tag(kind: ItemKind) -> u8 {
    match kind {
        ItemKind::Canonical => 1,
        ItemKind::Legacy => 2,
    }
}

fn access_mode_tag(mode: ItemAccessMode) -> u8 {
    match mode {
        ItemAccessMode::DirectOnly => 1,
        ItemAccessMode::WitnessedOnly => 2,
        ItemAccessMode::Mixed => 3,
    }
}

fn access_role_tag(role: AccessRole) -> u8 {
    match role {
        AccessRole::Reader => 1,
        AccessRole::Writer => 2,
        AccessRole::Owner => 3,
    }
}

fn jce(domain: &str) -> Vec<u8> {
    let mut output = domain.as_bytes().to_vec();
    output.push(0);
    output.extend_from_slice(&SUITE.to_be_bytes());
    output
}

fn list_fixed<'a>(
    output: &mut Vec<u8>,
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(), PolicyError> {
    let values = values.into_iter().collect::<Vec<_>>();
    let count = u32::try_from(values.len())
        .map_err(|_| PolicyError::new(PolicyErrorKind::CapacityExhausted))?;
    output.extend_from_slice(&count.to_be_bytes());
    for value in values {
        output.extend_from_slice(value);
    }
    Ok(())
}

fn list_bytes(output: &mut Vec<u8>, values: &[Vec<u8>]) -> Result<(), PolicyError> {
    let count = u32::try_from(values.len())
        .map_err(|_| PolicyError::new(PolicyErrorKind::CapacityExhausted))?;
    output.extend_from_slice(&count.to_be_bytes());
    for value in values {
        let length = u32::try_from(value.len())
            .map_err(|_| PolicyError::new(PolicyErrorKind::CapacityExhausted))?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(value);
    }
    Ok(())
}
