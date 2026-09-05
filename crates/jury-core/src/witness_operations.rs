//! Offline aggregation of per-witness durable checkpoint acknowledgements.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use jury_protocol::{
    vault_v1::{ContentRole, Digest32, PrincipalId},
    witness_v1::{
        RegistrationBytes, VaultPolicyCheckpointV1, WitnessCheckpointAcknowledgementV1,
        WitnessPolicyRotationV1, WitnessRecoveryV1, WitnessRotationReasonV1,
        signing_key_fingerprint, witness_registration_digest,
    },
};
use serde::Serialize;

use crate::{
    crypto,
    policy::{DescriptorStatus, PolicyState},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckpointPropagationPhase {
    Proposed,
    PartiallyPropagated,
    DurablyAccepted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedCheckpointAcknowledgement {
    pub witness_id: PrincipalId,
    pub state_generation: u64,
    pub anchor_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointPropagationStatus {
    pub checkpoint_digest: Digest32,
    pub phase: CheckpointPropagationPhase,
    pub expected_witness_count: usize,
    pub acknowledged_witness_count: usize,
    pub acknowledgements: Vec<VerifiedCheckpointAcknowledgement>,
    pub global_freshness_claimed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointStatusErrorKind {
    InvalidCheckpoint,
    InvalidAcknowledgement,
    InvalidSignature,
    DuplicateWitness,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationVerificationErrorKind {
    InvalidRecord,
    InvalidPolicyTransition,
    IncompleteItemRotation,
    InvalidSignature,
    UnsafeRecovery,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RotationVerificationError(RotationVerificationErrorKind);

impl RotationVerificationError {
    #[must_use]
    pub const fn kind(self) -> RotationVerificationErrorKind {
        self.0
    }
}

impl fmt::Debug for RotationVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotationVerificationError")
            .field("kind", &self.0)
            .finish()
    }
}

impl fmt::Display for RotationVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("witness rotation or recovery evidence is invalid")
    }
}

impl std::error::Error for RotationVerificationError {}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CheckpointStatusError(CheckpointStatusErrorKind);

impl CheckpointStatusError {
    #[must_use]
    pub const fn kind(self) -> CheckpointStatusErrorKind {
        self.0
    }
}

impl fmt::Debug for CheckpointStatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckpointStatusError")
            .field("kind", &self.0)
            .finish()
    }
}

impl fmt::Display for CheckpointStatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("witness checkpoint status evidence is invalid")
    }
}

impl std::error::Error for CheckpointStatusError {}

/// Verifies a target checkpoint and zero or more acknowledgements, then reports
/// only the evidence observed in this call. Even `DurablyAccepted` is not a
/// claim that the witnesses remain globally fresh after their signed anchors.
pub fn verify_checkpoint_propagation(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    acknowledgements: &[WitnessCheckpointAcknowledgementV1],
) -> Result<CheckpointPropagationStatus, CheckpointStatusError> {
    let checkpoint_digest = validate_checkpoint(policy, checkpoint)?;
    let witness_policy = policy
        .witness_policy(&checkpoint.witness_policy_digest)
        .ok_or_else(|| invalid(CheckpointStatusErrorKind::InvalidCheckpoint))?;
    let expected = witness_policy
        .witness_descriptors
        .iter()
        .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
        .collect::<Vec<_>>();
    let mut observed = BTreeSet::new();
    let mut verified = Vec::with_capacity(acknowledgements.len());
    for acknowledgement in acknowledgements {
        acknowledgement
            .validate_shape()
            .map_err(|_| invalid(CheckpointStatusErrorKind::InvalidAcknowledgement))?;
        if acknowledgement.vault_id != checkpoint.vault_id
            || acknowledgement.checkpoint_digest != checkpoint_digest
            || acknowledgement.vault_policy_sequence != checkpoint.vault_policy_sequence
            || acknowledgement.witness_policy_digest != checkpoint.witness_policy_digest
        {
            return Err(invalid(CheckpointStatusErrorKind::InvalidAcknowledgement));
        }
        if !observed.insert(acknowledgement.witness_id) {
            return Err(invalid(CheckpointStatusErrorKind::DuplicateWitness));
        }
        let descriptor = expected
            .iter()
            .find(|descriptor| descriptor.witness_id == acknowledgement.witness_id)
            .ok_or_else(|| invalid(CheckpointStatusErrorKind::InvalidAcknowledgement))?;
        let anchor = &acknowledgement.exact_anchor;
        if anchor.witness_signing_key_epoch != descriptor.signing_key_epoch
            || anchor.witness_signing_key_fingerprint != descriptor.signing_key_fingerprint
            || !anchor.vault_high_watermarks.iter().any(|watermark| {
                watermark.vault_id == checkpoint.vault_id
                    && watermark.genesis_fingerprint == checkpoint.genesis_fingerprint
                    && watermark.policy_sequence == checkpoint.vault_policy_sequence
                    && watermark.checkpoint_digest == checkpoint_digest
            })
        {
            return Err(invalid(CheckpointStatusErrorKind::InvalidAcknowledgement));
        }
        crypto::verify_bytes(
            &descriptor.signing_public_key,
            &anchor
                .signature_preimage()
                .map_err(|_| invalid(CheckpointStatusErrorKind::InvalidAcknowledgement))?,
            &anchor.signature,
        )
        .map_err(|_| invalid(CheckpointStatusErrorKind::InvalidSignature))?;
        verified.push(VerifiedCheckpointAcknowledgement {
            witness_id: acknowledgement.witness_id,
            state_generation: acknowledgement.state_generation,
            anchor_digest: acknowledgement.anchor_digest.clone(),
        });
    }
    verified.sort_unstable_by_key(|acknowledgement| acknowledgement.witness_id);
    let phase = if verified.is_empty() {
        CheckpointPropagationPhase::Proposed
    } else if verified.len() == expected.len() {
        CheckpointPropagationPhase::DurablyAccepted
    } else {
        CheckpointPropagationPhase::PartiallyPropagated
    };
    Ok(CheckpointPropagationStatus {
        checkpoint_digest,
        phase,
        expected_witness_count: expected.len(),
        acknowledged_witness_count: verified.len(),
        acknowledgements: verified,
        global_freshness_claimed: false,
    })
}

/// Verifies that a signed rotation record names one strict policy descendant
/// and every governed item was completely resealed under the next policy.
pub fn verify_witness_policy_rotation(
    prior: &PolicyState,
    next: &PolicyState,
    rotation: &WitnessPolicyRotationV1,
) -> Result<Digest32, RotationVerificationError> {
    rotation
        .validate_shape()
        .map_err(|_| rotation_error(RotationVerificationErrorKind::InvalidRecord))?;
    if prior.vault_id() != next.vault_id()
        || prior.genesis_fingerprint() != next.genesis_fingerprint()
        || rotation.vault_id != prior.vault_id()
        || &rotation.genesis_fingerprint != prior.genesis_fingerprint()
        || rotation.prior_vault_policy_sequence != prior.sequence()
        || rotation.prior_vault_policy_hash != *prior.terminal_revision_hash()
        || rotation.next_vault_policy_sequence != next.sequence()
        || rotation.next_vault_policy_hash != *next.terminal_revision_hash()
        || !next.is_direct_descendant_of(prior)
    {
        return Err(rotation_error(
            RotationVerificationErrorKind::InvalidPolicyTransition,
        ));
    }
    let prior_policy = prior
        .witness_policy(&rotation.prior_witness_policy_digest)
        .ok_or_else(|| rotation_error(RotationVerificationErrorKind::InvalidPolicyTransition))?;
    let next_policy = next
        .witness_policy(&rotation.next_witness_policy_digest)
        .ok_or_else(|| rotation_error(RotationVerificationErrorKind::InvalidPolicyTransition))?;
    if prior_policy.witness_policy_id != rotation.prior_witness_policy_id
        || prior_policy.revision != rotation.prior_witness_policy_revision
        || next_policy.witness_policy_id != rotation.next_witness_policy_id
        || next_policy.revision != rotation.next_witness_policy_revision
        || next_policy.witness_policy_id != prior_policy.witness_policy_id
        || next_policy.revision != prior_policy.revision.saturating_add(1)
        || next_policy.predecessor_policy_digest != rotation.prior_witness_policy_digest
        || prior_policy.digest().ok().as_ref() != Some(&rotation.prior_witness_policy_digest)
        || next_policy.digest().ok().as_ref() != Some(&rotation.next_witness_policy_digest)
        || rotation.reason != rotation_reason(prior_policy, next_policy)
    {
        return Err(rotation_error(
            RotationVerificationErrorKind::InvalidPolicyTransition,
        ));
    }

    let expected_items = prior
        .items()
        .filter(|(_, item)| item_uses_policy(item, &rotation.prior_witness_policy_digest))
        .map(|(item_id, _)| *item_id)
        .chain(
            next.items()
                .filter(|(_, item)| item_uses_policy(item, &rotation.next_witness_policy_digest))
                .map(|(item_id, _)| *item_id),
        )
        .collect::<BTreeSet<_>>();
    if expected_items.len() != rotation.affected_items.len() {
        return Err(rotation_error(
            RotationVerificationErrorKind::IncompleteItemRotation,
        ));
    }
    for (expected_id, recorded) in expected_items.iter().zip(&rotation.affected_items) {
        let prior_item = prior
            .item(expected_id)
            .ok_or_else(|| rotation_error(RotationVerificationErrorKind::IncompleteItemRotation))?;
        let next_item = next
            .item(expected_id)
            .ok_or_else(|| rotation_error(RotationVerificationErrorKind::IncompleteItemRotation))?;
        let next_state = next_item
            .witnessed_state
            .as_ref()
            .ok_or_else(|| rotation_error(RotationVerificationErrorKind::IncompleteItemRotation))?;
        let descriptor = next_state
            .slots
            .iter()
            .find(|slot| slot.content_role == ContentRole::Descriptor)
            .ok_or_else(|| rotation_error(RotationVerificationErrorKind::IncompleteItemRotation))?;
        let body = next_state
            .slots
            .iter()
            .find(|slot| slot.content_role == ContentRole::Body)
            .ok_or_else(|| rotation_error(RotationVerificationErrorKind::IncompleteItemRotation))?;
        if recorded.item_id != *expected_id
            || recorded.prior_key_epoch != prior_item.key_epoch
            || recorded.next_key_epoch != next_item.key_epoch
            || next_item.key_epoch != prior_item.key_epoch.saturating_add(1)
            || recorded.next_descriptor_revision != descriptor.revision
            || recorded.next_descriptor_revision_seal_id != descriptor.revision_seal_id
            || recorded.next_descriptor_capsule_set_digest != descriptor.capsule_set_digest
            || recorded.next_body_revision != body.revision
            || recorded.next_body_revision_seal_id != body.revision_seal_id
            || recorded.next_body_capsule_set_digest != body.capsule_set_digest
            || descriptor.witness_policy_digest != rotation.next_witness_policy_digest
            || body.witness_policy_digest != rotation.next_witness_policy_digest
        {
            return Err(rotation_error(
                RotationVerificationErrorKind::IncompleteItemRotation,
            ));
        }
    }
    verify_rotation_owner_signature(prior, rotation)?;
    rotation
        .digest()
        .map_err(|_| rotation_error(RotationVerificationErrorKind::InvalidRecord))
}

/// Verifies owner authorization for replacing an unavailable witness with a
/// new identity. It explicitly rejects any next policy that leaves the old
/// identity active; it does not authorize reuse of the old replay database.
pub fn verify_witness_recovery(
    prior: &PolicyState,
    next: &PolicyState,
    prior_checkpoint: &VaultPolicyCheckpointV1,
    next_checkpoint: &VaultPolicyCheckpointV1,
    rotation: &WitnessPolicyRotationV1,
    new_registration: &RegistrationBytes,
    recovery: &WitnessRecoveryV1,
) -> Result<Digest32, RotationVerificationError> {
    recovery
        .validate_shape()
        .map_err(|_| rotation_error(RotationVerificationErrorKind::InvalidRecord))?;
    let prior_policy = prior
        .witness_policy(&rotation.prior_witness_policy_digest)
        .ok_or_else(|| rotation_error(RotationVerificationErrorKind::UnsafeRecovery))?;
    let next_policy = next
        .witness_policy(&rotation.next_witness_policy_digest)
        .ok_or_else(|| rotation_error(RotationVerificationErrorKind::UnsafeRecovery))?;
    if next_policy.witness_threshold < prior_policy.witness_threshold {
        return Err(rotation_error(
            RotationVerificationErrorKind::UnsafeRecovery,
        ));
    }
    let rotation_digest = verify_witness_policy_rotation(prior, next, rotation)?;
    let prior_checkpoint_digest = validate_checkpoint(prior, prior_checkpoint)
        .map_err(|_| rotation_error(RotationVerificationErrorKind::UnsafeRecovery))?;
    let next_checkpoint_digest = validate_checkpoint(next, next_checkpoint)
        .map_err(|_| rotation_error(RotationVerificationErrorKind::UnsafeRecovery))?;
    let registration_digest = witness_registration_digest(new_registration)
        .map_err(|_| rotation_error(RotationVerificationErrorKind::InvalidRecord))?;
    let descriptor_matches = next_policy.witness_descriptors.iter().any(|descriptor| {
        descriptor.status == DescriptorStatus::Active
            && descriptor.canonical_bytes() == recovery.new_witness_descriptor.as_bytes()
    });
    let old_is_retired = recovery.unavailable_prior_witness_id.is_none_or(|old_id| {
        !next_policy.witness_descriptors.iter().any(|descriptor| {
            descriptor.status == DescriptorStatus::Active && descriptor.witness_id == old_id
        })
    });
    if recovery.vault_id != next.vault_id()
        || &recovery.genesis_fingerprint != next.genesis_fingerprint()
        || recovery.rotation_record_digest != rotation_digest
        || recovery.prior_checkpoint_digest != prior_checkpoint_digest
        || recovery.next_checkpoint_digest != next_checkpoint_digest
        || recovery.new_registration_digest != registration_digest
        || next_checkpoint.predecessor_checkpoint_digest != prior_checkpoint_digest
        || next_checkpoint.witness_policy_digest != rotation.next_witness_policy_digest
        || prior_checkpoint.witness_policy_digest != rotation.prior_witness_policy_digest
        || !descriptor_matches
        || !old_is_retired
        || recovery.owner_id != rotation.owner_id
    {
        return Err(rotation_error(
            RotationVerificationErrorKind::UnsafeRecovery,
        ));
    }
    let owner = next
        .principal(&recovery.owner_id)
        .filter(|_| next.is_owner(&recovery.owner_id))
        .ok_or_else(|| rotation_error(RotationVerificationErrorKind::InvalidSignature))?;
    if recovery.owner_key_epoch != 1
        || recovery.owner_key_fingerprint
            != signing_key_fingerprint(
                1,
                &recovery.owner_id,
                1,
                &owner.descriptor.verification_public_key,
            )
    {
        return Err(rotation_error(
            RotationVerificationErrorKind::InvalidSignature,
        ));
    }
    crypto::verify_bytes(
        &owner.descriptor.verification_public_key,
        &recovery
            .signature_preimage()
            .map_err(|_| rotation_error(RotationVerificationErrorKind::InvalidRecord))?,
        &recovery.signature,
    )
    .map_err(|_| rotation_error(RotationVerificationErrorKind::InvalidSignature))?;
    recovery
        .digest()
        .map_err(|_| rotation_error(RotationVerificationErrorKind::InvalidRecord))
}

fn item_uses_policy(item: &crate::policy::ItemPolicyState, policy_digest: &Digest32) -> bool {
    item.witnessed_state.as_ref().is_some_and(|state| {
        state
            .slots
            .iter()
            .any(|slot| &slot.witness_policy_digest == policy_digest)
    })
}

pub(crate) fn rotation_reason(
    prior: &crate::policy::WitnessPolicy,
    next: &crate::policy::WitnessPolicy,
) -> WitnessRotationReasonV1 {
    let prior_ids = prior
        .witness_descriptors
        .iter()
        .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
        .map(|descriptor| descriptor.witness_id)
        .collect::<Vec<_>>();
    let next_ids = next
        .witness_descriptors
        .iter()
        .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
        .map(|descriptor| descriptor.witness_id)
        .collect::<Vec<_>>();
    if prior_ids != next_ids {
        return WitnessRotationReasonV1::WitnessMembership;
    }
    if prior.witness_threshold != next.witness_threshold {
        return WitnessRotationReasonV1::WitnessThreshold;
    }
    let prior_descriptors = active_witness_descriptors(prior);
    let next_descriptors = active_witness_descriptors(next);
    if prior_descriptors.iter().any(|(id, prior)| {
        next_descriptors
            .get(id)
            .is_none_or(|next| prior.share_index != next.share_index)
    }) {
        return WitnessRotationReasonV1::ShareIndex;
    }
    if prior_descriptors.iter().any(|(id, prior)| {
        next_descriptors.get(id).is_none_or(|next| {
            prior.contribution_public_key != next.contribution_public_key
                || prior.contribution_key_epoch != next.contribution_key_epoch
        })
    }) {
        return WitnessRotationReasonV1::ContributionKey;
    }
    if prior.construction != next.construction {
        return WitnessRotationReasonV1::Construction;
    }
    if prior.suite != next.suite {
        return WitnessRotationReasonV1::Suite;
    }
    if prior_descriptors.iter().any(|(id, prior)| {
        next_descriptors.get(id).is_none_or(|next| {
            prior.signing_public_key != next.signing_public_key
                || prior.signing_key_epoch != next.signing_key_epoch
        })
    }) {
        return WitnessRotationReasonV1::WitnessSigningKey;
    }
    if prior.approver_descriptors != next.approver_descriptors
        || prior.operation_rules != next.operation_rules
        || prior.review_label_set_digest != next.review_label_set_digest
    {
        return WitnessRotationReasonV1::ApproverRuleOrLabel;
    }
    WitnessRotationReasonV1::DirectMode
}

fn active_witness_descriptors(
    policy: &crate::policy::WitnessPolicy,
) -> BTreeMap<PrincipalId, &crate::policy::WitnessPolicyDescriptor> {
    policy
        .witness_descriptors
        .iter()
        .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
        .map(|descriptor| (descriptor.witness_id, descriptor))
        .collect()
}

fn verify_rotation_owner_signature(
    prior: &PolicyState,
    rotation: &WitnessPolicyRotationV1,
) -> Result<(), RotationVerificationError> {
    let owner = prior
        .principal(&rotation.owner_id)
        .filter(|_| prior.is_owner(&rotation.owner_id))
        .ok_or_else(|| rotation_error(RotationVerificationErrorKind::InvalidSignature))?;
    if rotation.owner_key_epoch != 1
        || rotation.owner_key_fingerprint
            != signing_key_fingerprint(
                1,
                &rotation.owner_id,
                1,
                &owner.descriptor.verification_public_key,
            )
    {
        return Err(rotation_error(
            RotationVerificationErrorKind::InvalidSignature,
        ));
    }
    crypto::verify_bytes(
        &owner.descriptor.verification_public_key,
        &rotation
            .signature_preimage()
            .map_err(|_| rotation_error(RotationVerificationErrorKind::InvalidRecord))?,
        &rotation.signature,
    )
    .map_err(|_| rotation_error(RotationVerificationErrorKind::InvalidSignature))
}

fn validate_checkpoint(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
) -> Result<Digest32, CheckpointStatusError> {
    use crate::checkpoint_validation::{CheckpointPolicyError, validate_checkpoint_policy};
    validate_checkpoint_policy(policy, checkpoint).map_err(|error| {
        invalid(match error {
            CheckpointPolicyError::InvalidSignature => CheckpointStatusErrorKind::InvalidSignature,
            CheckpointPolicyError::Invalid
            | CheckpointPolicyError::ScopeMismatch
            | CheckpointPolicyError::MissingOwner => CheckpointStatusErrorKind::InvalidCheckpoint,
        })
    })?;
    checkpoint
        .digest()
        .map_err(|_| invalid(CheckpointStatusErrorKind::InvalidCheckpoint))
}

const fn invalid(kind: CheckpointStatusErrorKind) -> CheckpointStatusError {
    CheckpointStatusError(kind)
}

const fn rotation_error(kind: RotationVerificationErrorKind) -> RotationVerificationError {
    RotationVerificationError(kind)
}
