//! Complete, validated vault-artifact mutation plans.
//!
//! Planning is deliberately separate from durable publication. A plan owns the
//! exact canonical bytes that a later commit may publish, so dry-run output and
//! commit cannot silently re-plan with different entropy or ancestry.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use jury_protocol::vault_v1::{
    Digest32, FixedBytes, FormatError, ItemAccessMode, ItemEnvelopeV1, ItemId, PolicyOperationV1,
    VaultFileV1,
};
use sha2::{Digest as _, Sha256};

use crate::identity::VaultPrincipalIdentity;
use crate::item::{PreparedItemBatchComponent, PreparedItemMutation};
use crate::local_state::{
    AuditAction, AuditEventDraft, AuditItemScope, AuditOutcome, CheckpointCandidate,
};
use crate::policy::{
    PolicyErrorKind, PolicyState, PreparedPolicyRevision, WitnessOperation, WitnessPolicy,
    replay_policy_with_witness_policies,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationErrorKind {
    InvalidCurrentState,
    InvalidPlan,
    Unauthorized,
    NoChange,
    CapacityExhausted,
    DirectDowngradeRequiresAcknowledgement,
    MissingItemEnvelope,
    UnexpectedItemEnvelope,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MutationError {
    kind: MutationErrorKind,
}

impl MutationError {
    const fn new(kind: MutationErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> MutationErrorKind {
        self.kind
    }
}

impl fmt::Debug for MutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MutationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MutationErrorKind::InvalidCurrentState => "current vault state is invalid",
            MutationErrorKind::InvalidPlan => "vault mutation plan is invalid",
            MutationErrorKind::Unauthorized => "vault mutation is unauthorized",
            MutationErrorKind::NoChange => "vault mutation makes no change",
            MutationErrorKind::CapacityExhausted => "vault mutation exceeds a hard capacity",
            MutationErrorKind::DirectDowngradeRequiresAcknowledgement => {
                "direct-access downgrade requires explicit acknowledgement"
            }
            MutationErrorKind::MissingItemEnvelope => {
                "vault mutation is missing a changed item envelope"
            }
            MutationErrorKind::UnexpectedItemEnvelope => {
                "vault mutation contains an unexpected item envelope"
            }
        })
    }
}

impl std::error::Error for MutationError {}

/// An explicit caller choice. The owner signature authenticates the resulting
/// policy revision; this value prevents a caller from creating that signed
/// downgrade without first obtaining the separate operator acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectDowngradeAcknowledgement {
    Absent,
    Acknowledged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationKind {
    Policy,
    Item,
    PrivacyCover,
}

impl MutationKind {
    const fn audit_action(self) -> AuditAction {
        match self {
            Self::Policy => AuditAction::PolicyMutation,
            Self::Item => AuditAction::ItemMutation,
            Self::PrivacyCover => AuditAction::PrivacyCover,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationWarnings {
    pub redistribution_required: bool,
    pub external_credential_rotation_required: bool,
    pub pending_witness_requests_invalidated: bool,
    pub item_quorum_claim_suppressed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultRevisionPrecondition {
    pub vault_digest: Digest32,
    pub policy_sequence: u64,
    pub policy_revision_hash: Digest32,
    pub repository_ancestry: Option<[u8; 32]>,
}

/// Exact, single-use-by-convention output of mutation planning.
pub struct VaultMutationPlan {
    precondition: VaultRevisionPrecondition,
    target: VaultFileV1,
    target_bytes: Vec<u8>,
    target_digest: Digest32,
    target_policy: PolicyState,
    witness_policies: Vec<WitnessPolicy>,
    kind: MutationKind,
    timestamp_ms: u64,
    touched_items: Vec<ItemId>,
    warnings: MutationWarnings,
}

impl VaultMutationPlan {
    /// Plans one policy-only revision after validating the complete current
    /// public artifact and all authenticated item ancestry.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_policy(
        current: &VaultFileV1,
        witness_policies: &[WitnessPolicy],
        author: &VaultPrincipalIdentity,
        timestamp_ms: u64,
        operations: Vec<PolicyOperationV1>,
        downgrade: DirectDowngradeAcknowledgement,
        kind: MutationKind,
    ) -> Result<Self, MutationError> {
        if operations.is_empty() {
            return Err(MutationError::new(MutationErrorKind::NoChange));
        }
        let current_policy = validate_complete(current, witness_policies, true)?;
        let prepared = current_policy
            .prepare_revision(author, timestamp_ms, operations)
            .map_err(map_policy_error)?;
        Self::from_prepared(
            current,
            witness_policies,
            prepared,
            Vec::new(),
            timestamp_ms,
            downgrade,
            kind,
        )
    }

    /// Combines independently prepared item encryptions into one owner-signed
    /// policy revision and one complete artifact. Each item preparation must
    /// have been made from this exact current revision.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_item_batch(
        current: &VaultFileV1,
        witness_policies: &[WitnessPolicy],
        author: &VaultPrincipalIdentity,
        timestamp_ms: u64,
        additional_operations: Vec<PolicyOperationV1>,
        item_mutations: Vec<PreparedItemMutation>,
        downgrade: DirectDowngradeAcknowledgement,
        kind: MutationKind,
    ) -> Result<Self, MutationError> {
        if item_mutations.is_empty() && additional_operations.is_empty() {
            return Err(MutationError::new(MutationErrorKind::NoChange));
        }
        let current_policy = validate_complete(current, witness_policies, true)?;
        let expected_sequence = current_policy
            .sequence()
            .checked_add(1)
            .ok_or_else(|| MutationError::new(MutationErrorKind::CapacityExhausted))?;
        let mut operations = Vec::new();
        let mut envelopes = Vec::new();
        for mutation in item_mutations {
            let revision = mutation.policy.revision;
            if revision.sequence != expected_sequence
                || revision.previous_revision_hash != *current_policy.terminal_revision_hash()
                || revision.author_principal_id != author.principal_id()
                || revision.timestamp_ms != timestamp_ms
            {
                return Err(MutationError::new(MutationErrorKind::InvalidPlan));
            }
            for operation in revision.operations {
                push_batch_operation(&mut operations, operation)?;
            }
            envelopes.push(mutation.envelope);
        }
        let mut deferred_owner_grants = Vec::new();
        operations.retain(|operation| {
            if matches!(operation, PolicyOperationV1::OwnerGrant { .. }) {
                deferred_owner_grants.push(operation.clone());
                false
            } else {
                true
            }
        });
        operations.extend(deferred_owner_grants);
        for operation in additional_operations {
            push_batch_operation(&mut operations, operation)?;
        }
        let prepared = current_policy
            .prepare_revision(author, timestamp_ms, operations)
            .map_err(map_policy_error)?;
        Self::from_prepared(
            current,
            witness_policies,
            prepared,
            envelopes,
            timestamp_ms,
            downgrade,
            kind,
        )
    }

    /// Validates opaque multi-item encryption components as one policy
    /// revision. This is required for vault-wide owner transitions, where no
    /// single item is independently a complete transition.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_item_component_batch(
        current: &VaultFileV1,
        witness_policies: &[WitnessPolicy],
        author: &VaultPrincipalIdentity,
        timestamp_ms: u64,
        additional_operations: Vec<PolicyOperationV1>,
        components: Vec<PreparedItemBatchComponent>,
        downgrade: DirectDowngradeAcknowledgement,
        kind: MutationKind,
    ) -> Result<Self, MutationError> {
        if components.is_empty() && additional_operations.is_empty() {
            return Err(MutationError::new(MutationErrorKind::NoChange));
        }
        let current_policy = validate_complete(current, witness_policies, true)?;
        let expected_sequence = current_policy
            .sequence()
            .checked_add(1)
            .ok_or_else(|| MutationError::new(MutationErrorKind::CapacityExhausted))?;
        let mut operations = Vec::new();
        let mut envelopes = Vec::with_capacity(components.len());
        for component in components {
            if component.envelope.current_revision.policy_sequence != expected_sequence
                || component.envelope.current_revision.author_principal_id != author.principal_id()
                || component.envelope.current_revision.timestamp_ms != timestamp_ms
            {
                return Err(MutationError::new(MutationErrorKind::InvalidPlan));
            }
            for operation in component.operations {
                push_batch_operation(&mut operations, operation)?;
            }
            envelopes.push(component.envelope);
        }
        let mut deferred_owner_grants = Vec::new();
        operations.retain(|operation| {
            if matches!(operation, PolicyOperationV1::OwnerGrant { .. }) {
                deferred_owner_grants.push(operation.clone());
                false
            } else {
                true
            }
        });
        operations.extend(deferred_owner_grants);
        for operation in additional_operations {
            push_batch_operation(&mut operations, operation)?;
        }
        let prepared = current_policy
            .prepare_revision(author, timestamp_ms, operations)
            .map_err(map_policy_error)?;
        Self::from_prepared(
            current,
            witness_policies,
            prepared,
            envelopes,
            timestamp_ms,
            downgrade,
            kind,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_prepared(
        current: &VaultFileV1,
        witness_policies: &[WitnessPolicy],
        prepared: PreparedPolicyRevision,
        replacement_envelopes: Vec<ItemEnvelopeV1>,
        timestamp_ms: u64,
        downgrade_acknowledgement: DirectDowngradeAcknowledgement,
        kind: MutationKind,
    ) -> Result<Self, MutationError> {
        let current_policy = validate_complete(current, witness_policies, true)?;
        let source_bytes = current.to_json_bytes().map_err(map_current_format_error)?;
        let precondition = VaultRevisionPrecondition {
            vault_digest: sha256(&source_bytes),
            policy_sequence: current_policy.sequence(),
            policy_revision_hash: current_policy.terminal_revision_hash().clone(),
            repository_ancestry: None,
        };
        if prepared.revision.sequence != current_policy.sequence().saturating_add(1)
            || prepared.revision.previous_revision_hash != *current_policy.terminal_revision_hash()
            || prepared.revision.timestamp_ms != timestamp_ms
            || prepared.revision.operations.is_empty()
        {
            return Err(MutationError::new(MutationErrorKind::InvalidPlan));
        }

        let touched_items = touched_item_ids(&prepared.revision.operations);
        let deleted_items = deleted_item_ids(&prepared.revision.operations);
        let mut replacements = BTreeMap::new();
        for envelope in replacement_envelopes {
            if replacements.insert(envelope.item_id, envelope).is_some() {
                return Err(MutationError::new(
                    MutationErrorKind::UnexpectedItemEnvelope,
                ));
            }
        }

        let mut target = current.clone();
        target.policy.revisions.push(prepared.revision);
        target
            .items
            .retain(|item| !deleted_items.contains(&item.item_id));
        for (item_id, envelope) in replacements {
            match target
                .items
                .binary_search_by_key(&item_id, |item| item.item_id)
            {
                Ok(index) => target.items[index] = envelope,
                Err(index) => target.items.insert(index, envelope),
            }
        }

        let target_policy = validate_complete(&target, witness_policies, false)?;
        if target_policy != prepared.state {
            return Err(MutationError::new(MutationErrorKind::InvalidPlan));
        }
        validate_envelope_delta(current, &target, &current_policy, &target_policy)?;
        if kind == MutationKind::PrivacyCover {
            validate_privacy_cover(current, &target, &current_policy, &target_policy)?;
        }

        let latest_operations = target
            .policy
            .revisions
            .last()
            .map(|revision| revision.operations.as_slice())
            .unwrap_or(&[]);
        let (direct_downgrade, _witness_policy_changed, weakened_witness) = transition_flags(
            &current_policy,
            &target_policy,
            &touched_items,
            latest_operations,
        )?;
        if (direct_downgrade || weakened_witness)
            && downgrade_acknowledgement != DirectDowngradeAcknowledgement::Acknowledged
        {
            return Err(MutationError::new(
                MutationErrorKind::DirectDowngradeRequiresAcknowledgement,
            ));
        }

        let target_bytes = target.to_json_bytes().map_err(map_target_format_error)?;
        let target_digest = sha256(&target_bytes);
        if target_digest == precondition.vault_digest {
            return Err(MutationError::new(MutationErrorKind::NoChange));
        }
        let external_rotation = reader_removed(&current_policy, &target_policy);
        let warnings = MutationWarnings {
            redistribution_required: true,
            external_credential_rotation_required: external_rotation,
            pending_witness_requests_invalidated: true,
            item_quorum_claim_suppressed: direct_downgrade,
        };
        Ok(Self {
            precondition,
            target,
            target_bytes,
            target_digest,
            target_policy,
            witness_policies: witness_policies.to_vec(),
            kind,
            timestamp_ms,
            touched_items: touched_items.into_iter().collect(),
            warnings,
        })
    }

    #[must_use]
    pub const fn precondition(&self) -> &VaultRevisionPrecondition {
        &self.precondition
    }

    /// Binds a Git-backed plan to the repository observation made alongside
    /// the artifact preview. Detached/non-Git stores leave this unset.
    #[must_use]
    pub fn bind_repository_ancestry(mut self, digest: [u8; 32]) -> Self {
        self.precondition.repository_ancestry = Some(digest);
        self
    }

    #[must_use]
    pub fn target_bytes(&self) -> &[u8] {
        &self.target_bytes
    }

    #[must_use]
    pub const fn target_digest(&self) -> &Digest32 {
        &self.target_digest
    }

    #[must_use]
    pub const fn target_artifact(&self) -> &VaultFileV1 {
        &self.target
    }

    #[must_use]
    pub const fn target_policy(&self) -> &PolicyState {
        &self.target_policy
    }

    #[must_use]
    pub fn witness_policies(&self) -> &[WitnessPolicy] {
        &self.witness_policies
    }

    #[must_use]
    pub fn touched_items(&self) -> &[ItemId] {
        &self.touched_items
    }

    #[must_use]
    pub const fn warnings(&self) -> &MutationWarnings {
        &self.warnings
    }

    pub fn audit_intent(&self) -> AuditEventDraft {
        AuditEventDraft {
            timestamp_ms: self.timestamp_ms,
            operation_id: self.target_digest.clone(),
            policy_sequence: self.target_policy.sequence(),
            action: self.kind.audit_action(),
            outcome: AuditOutcome::Success,
            item: (self.touched_items.len() == 1).then(|| AuditItemScope {
                item_id: self.touched_items[0],
                permitted_item_name: None,
            }),
            witness: None,
        }
    }

    pub fn checkpoint_candidate(&self) -> Result<CheckpointCandidate, MutationError> {
        CheckpointCandidate::from_validated(
            &self.target_policy,
            &self.target.policy,
            &self.target.items,
        )
        .map_err(|_| MutationError::new(MutationErrorKind::InvalidPlan))
    }
}

fn push_batch_operation(
    operations: &mut Vec<PolicyOperationV1>,
    operation: PolicyOperationV1,
) -> Result<(), MutationError> {
    let matching = operations
        .iter()
        .find(|existing| match (existing, &operation) {
            (
                PolicyOperationV1::PrincipalAdd {
                    descriptor: left, ..
                },
                PolicyOperationV1::PrincipalAdd {
                    descriptor: right, ..
                },
            ) => left.principal_id == right.principal_id,
            (
                PolicyOperationV1::PrincipalReplace {
                    prior_principal_id: left_prior,
                    next_descriptor: left_next,
                    ..
                },
                PolicyOperationV1::PrincipalReplace {
                    prior_principal_id: right_prior,
                    next_descriptor: right_next,
                    ..
                },
            ) => left_prior == right_prior || left_next.principal_id == right_next.principal_id,
            (
                PolicyOperationV1::OwnerGrant { principal_id: left },
                PolicyOperationV1::OwnerGrant {
                    principal_id: right,
                },
            )
            | (
                PolicyOperationV1::OwnerRevoke { principal_id: left },
                PolicyOperationV1::OwnerRevoke {
                    principal_id: right,
                },
            ) => left == right,
            _ => false,
        });
    if let Some(existing) = matching {
        if existing == &operation {
            return Ok(());
        }
        return Err(MutationError::new(MutationErrorKind::InvalidPlan));
    }
    operations.push(operation);
    Ok(())
}

impl fmt::Debug for VaultMutationPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultMutationPlan")
            .field("precondition", &self.precondition)
            .field("target_digest", &self.target_digest)
            .field("target_policy_sequence", &self.target_policy.sequence())
            .field("target_bytes", &self.target_bytes.len())
            .field("touched_items", &self.touched_items)
            .field("warnings", &self.warnings)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

fn validate_complete(
    vault: &VaultFileV1,
    witness_policies: &[WitnessPolicy],
    current: bool,
) -> Result<PolicyState, MutationError> {
    vault.validate().map_err(|error| {
        if current {
            map_current_format_error(error)
        } else {
            map_target_format_error(error)
        }
    })?;
    let policy = replay_policy_with_witness_policies(&vault.policy, witness_policies)
        .map_err(|error| map_replay_error(error.kind(), current))?;
    CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items).map_err(|_| {
        MutationError::new(if current {
            MutationErrorKind::InvalidCurrentState
        } else {
            MutationErrorKind::InvalidPlan
        })
    })?;
    Ok(policy)
}

fn validate_envelope_delta(
    current: &VaultFileV1,
    target: &VaultFileV1,
    current_policy: &PolicyState,
    target_policy: &PolicyState,
) -> Result<(), MutationError> {
    let current_envelopes = current
        .items
        .iter()
        .map(|item| (item.item_id, item))
        .collect::<BTreeMap<_, _>>();
    let target_envelopes = target
        .items
        .iter()
        .map(|item| (item.item_id, item))
        .collect::<BTreeMap<_, _>>();
    for (item_id, target_item) in &target_policy.items {
        let target_envelope = target_envelopes
            .get(item_id)
            .ok_or_else(|| MutationError::new(MutationErrorKind::MissingItemEnvelope))?;
        let changed = current_policy.item(item_id).is_none_or(|current_item| {
            current_item.current_item_revision_hash != target_item.current_item_revision_hash
                || current_item.descriptor != target_item.descriptor
        });
        if changed
            && current_envelopes
                .get(item_id)
                .is_some_and(|current_envelope| *current_envelope == *target_envelope)
        {
            return Err(MutationError::new(MutationErrorKind::MissingItemEnvelope));
        }
        if !changed
            && current_envelopes
                .get(item_id)
                .is_some_and(|current_envelope| *current_envelope != *target_envelope)
        {
            return Err(MutationError::new(
                MutationErrorKind::UnexpectedItemEnvelope,
            ));
        }
    }
    if target_envelopes
        .keys()
        .any(|item_id| target_policy.item(item_id).is_none())
    {
        return Err(MutationError::new(
            MutationErrorKind::UnexpectedItemEnvelope,
        ));
    }
    Ok(())
}

fn validate_privacy_cover(
    current: &VaultFileV1,
    target: &VaultFileV1,
    current_policy: &PolicyState,
    target_policy: &PolicyState,
) -> Result<(), MutationError> {
    let operations = &target
        .policy
        .revisions
        .last()
        .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidPlan))?
        .operations;
    let touched = touched_item_ids(operations);
    if touched.is_empty()
        || operations.iter().any(|operation| {
            !matches!(
                operation,
                PolicyOperationV1::ItemReaderSetChange { .. }
                    | PolicyOperationV1::ItemSlotsReplace { .. }
            )
        })
    {
        return Err(MutationError::new(MutationErrorKind::InvalidPlan));
    }
    for item_id in touched {
        let prior_policy = current_policy
            .item(&item_id)
            .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidPlan))?;
        let next_policy = target_policy
            .item(&item_id)
            .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidPlan))?;
        let prior = current
            .items
            .binary_search_by_key(&item_id, |item| item.item_id)
            .ok()
            .and_then(|index| current.items.get(index))
            .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidCurrentState))?;
        let next = target
            .items
            .binary_search_by_key(&item_id, |item| item.item_id)
            .ok()
            .and_then(|index| target.items.get(index))
            .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidPlan))?;
        if prior_policy.grants != next_policy.grants
            || current_policy.effective_reader_ids(&item_id)
                != target_policy.effective_reader_ids(&item_id)
            || prior_policy.access_mode() != next_policy.access_mode()
            || prior.current_revision.bucket_id != next.current_revision.bucket_id
            || prior.current_revision.item_revision.checked_add(1)
                != Some(next.current_revision.item_revision)
        {
            return Err(MutationError::new(MutationErrorKind::InvalidPlan));
        }
    }
    Ok(())
}

fn touched_item_ids(operations: &[PolicyOperationV1]) -> BTreeSet<ItemId> {
    operations.iter().filter_map(operation_item_id).collect()
}

fn deleted_item_ids(operations: &[PolicyOperationV1]) -> BTreeSet<ItemId> {
    operations
        .iter()
        .filter_map(|operation| match operation {
            PolicyOperationV1::ItemDelete { item_id, .. } => Some(*item_id),
            _ => None,
        })
        .collect()
}

fn operation_item_id(operation: &PolicyOperationV1) -> Option<ItemId> {
    match operation {
        PolicyOperationV1::ItemCreate { item_id, .. }
        | PolicyOperationV1::ItemRename { item_id, .. }
        | PolicyOperationV1::ItemDelete { item_id, .. }
        | PolicyOperationV1::ItemRoleChange { item_id, .. }
        | PolicyOperationV1::ItemReaderSetChange { item_id, .. }
        | PolicyOperationV1::ItemSlotsReplace { item_id, .. } => Some(*item_id),
        _ => None,
    }
}

fn transition_flags(
    current: &PolicyState,
    target: &PolicyState,
    touched: &BTreeSet<ItemId>,
    operations: &[PolicyOperationV1],
) -> Result<(bool, bool, bool), MutationError> {
    let mut direct_downgrade = false;
    let mut witness_changed = false;
    let mut witness_weakened = false;
    let replacements = operations
        .iter()
        .filter_map(|operation| match operation {
            PolicyOperationV1::PrincipalReplace {
                prior_principal_id,
                next_descriptor,
                ..
            } => Some((*prior_principal_id, next_descriptor.principal_id)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    for item_id in touched {
        let Some(next) = target.item(item_id) else {
            continue;
        };
        let prior = current.item(item_id);
        let prior_direct_recipients = prior
            .into_iter()
            .flat_map(|item| &item.direct_slots)
            .map(|slot| {
                replacements
                    .get(&slot.recipient_principal_id)
                    .copied()
                    .unwrap_or(slot.recipient_principal_id)
            })
            .collect::<BTreeSet<_>>();
        let next_direct_recipients = next
            .direct_slots
            .iter()
            .map(|slot| slot.recipient_principal_id)
            .collect::<BTreeSet<_>>();
        if (!next_direct_recipients.is_empty()
            && !matches!(
                prior.and_then(crate::policy::ItemPolicyState::access_mode),
                Some(ItemAccessMode::DirectOnly | ItemAccessMode::Mixed)
            ))
            || next_direct_recipients
                .iter()
                .any(|principal| !prior_direct_recipients.contains(principal))
        {
            direct_downgrade = true;
        }
        let prior_digest = prior.and_then(witness_digest);
        let next_digest = witness_digest(next);
        if prior_digest != next_digest {
            witness_changed |= prior_digest.is_some() || next_digest.is_some();
            if let (Some(prior_digest), Some(next_digest)) = (prior_digest, next_digest) {
                let prior_policy = current
                    .witness_policy(prior_digest)
                    .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidCurrentState))?;
                let next_policy = target
                    .witness_policy(next_digest)
                    .ok_or_else(|| MutationError::new(MutationErrorKind::InvalidPlan))?;
                witness_weakened |= witness_policy_is_weaker(prior_policy, next_policy);
            }
        }
    }
    Ok((direct_downgrade, witness_changed, witness_weakened))
}

fn witness_digest(item: &crate::policy::ItemPolicyState) -> Option<&Digest32> {
    item.witnessed_state
        .as_ref()
        .and_then(|state| state.slots.first())
        .map(|slot| &slot.witness_policy_digest)
}

fn witness_policy_is_weaker(prior: &WitnessPolicy, next: &WitnessPolicy) -> bool {
    if next.witness_threshold < prior.witness_threshold {
        return true;
    }
    prior.operation_rules.iter().any(|prior_rule| {
        next.operation_rules
            .iter()
            .find(|next_rule| next_rule.operation == prior_rule.operation)
            .is_none_or(|next_rule| {
                next_rule.approval_threshold < prior_rule.approval_threshold
                    || next_rule.allowed_request_lifetime_ms
                        > prior_rule.allowed_request_lifetime_ms
                    || next_rule.max_timeout_ms > prior_rule.max_timeout_ms
                    || next_rule.max_output_bytes > prior_rule.max_output_bytes
                    || next_rule.max_target_count > prior_rule.max_target_count
                    || assurance_is_weaker(
                        prior_rule.required_platform_assurance,
                        next_rule.required_platform_assurance,
                    )
                    || eligible_set_is_broader(
                        &prior_rule.eligible_approver_ids,
                        &next_rule.eligible_approver_ids,
                    )
            })
    })
}

fn assurance_is_weaker(
    prior: crate::policy::PlatformAssurance,
    next: crate::policy::PlatformAssurance,
) -> bool {
    matches!(
        (prior, next),
        (
            crate::policy::PlatformAssurance::StableExecutableIdentity,
            crate::policy::PlatformAssurance::NormalizedPathOnly
        )
    )
}

fn eligible_set_is_broader(
    prior: &[jury_protocol::vault_v1::PrincipalId],
    next: &[jury_protocol::vault_v1::PrincipalId],
) -> bool {
    next.iter().any(|id| !prior.contains(id))
}

fn reader_removed(current: &PolicyState, target: &PolicyState) -> bool {
    current.items.iter().any(|(item_id, _)| {
        let prior = current.effective_reader_ids(item_id);
        let next = target.effective_reader_ids(item_id);
        prior.iter().any(|reader| !next.contains(reader))
    })
}

fn sha256(bytes: &[u8]) -> Digest32 {
    FixedBytes::new(Sha256::digest(bytes).into())
}

fn map_current_format_error(error: FormatError) -> MutationError {
    MutationError::new(if is_capacity(error) {
        MutationErrorKind::CapacityExhausted
    } else {
        MutationErrorKind::InvalidCurrentState
    })
}

fn map_target_format_error(error: FormatError) -> MutationError {
    MutationError::new(if is_capacity(error) {
        MutationErrorKind::CapacityExhausted
    } else {
        MutationErrorKind::InvalidPlan
    })
}

const fn is_capacity(error: FormatError) -> bool {
    matches!(
        error,
        FormatError::ArtifactTooLarge | FormatError::CapacityExhausted(_)
    )
}

fn map_replay_error(kind: PolicyErrorKind, current: bool) -> MutationError {
    MutationError::new(match kind {
        PolicyErrorKind::CapacityExhausted => MutationErrorKind::CapacityExhausted,
        PolicyErrorKind::Unauthorized | PolicyErrorKind::InvalidRole if !current => {
            MutationErrorKind::Unauthorized
        }
        _ if current => MutationErrorKind::InvalidCurrentState,
        _ => MutationErrorKind::InvalidPlan,
    })
}

fn map_policy_error(error: crate::policy::PolicyError) -> MutationError {
    MutationError::new(match error.kind() {
        PolicyErrorKind::CapacityExhausted => MutationErrorKind::CapacityExhausted,
        PolicyErrorKind::Unauthorized | PolicyErrorKind::InvalidRole => {
            MutationErrorKind::Unauthorized
        }
        _ => MutationErrorKind::InvalidPlan,
    })
}

// Keep the public enum imported in rustdoc and make accidental operation
// omissions visible when the witness operation set grows.
const _: [WitnessOperation; 9] = [
    WitnessOperation::ReadStdout,
    WitnessOperation::WritePrivateFile,
    WitnessOperation::TemplateInjection,
    WitnessOperation::ChildEnvironment,
    WitnessOperation::ChildStdin,
    WitnessOperation::ItemMutation,
    WitnessOperation::Backup,
    WitnessOperation::Recovery,
    WitnessOperation::AdministrativeRekey,
];

#[cfg(test)]
#[path = "mutation_tests.rs"]
mod tests;
