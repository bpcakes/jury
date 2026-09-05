//! Policy and signature checks common to checkpoint consumers.

use jury_protocol::witness_v1::{VaultPolicyCheckpointV1, signing_key_fingerprint};

use crate::{
    crypto,
    policy::{PolicyState, WitnessPolicy},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CheckpointPolicyError {
    Invalid,
    ScopeMismatch,
    MissingOwner,
    InvalidSignature,
}

pub(crate) fn validate_checkpoint_policy<'a>(
    policy: &'a PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
) -> Result<&'a WitnessPolicy, CheckpointPolicyError> {
    checkpoint
        .validate_shape()
        .map_err(|_| CheckpointPolicyError::Invalid)?;
    if checkpoint.vault_id != policy.vault_id()
        || checkpoint.genesis_fingerprint != *policy.genesis_fingerprint()
        || checkpoint.vault_policy_sequence != policy.sequence()
        || checkpoint.vault_policy_hash != *policy.terminal_revision_hash()
    {
        return Err(CheckpointPolicyError::ScopeMismatch);
    }
    let witness_policy = policy
        .witness_policy(&checkpoint.witness_policy_digest)
        .ok_or(CheckpointPolicyError::ScopeMismatch)?;
    let (approver_set_digest, witness_set_digest) = witness_policy
        .active_descriptor_set_digests()
        .map_err(|_| CheckpointPolicyError::Invalid)?;
    if checkpoint.witness_policy_id != witness_policy.witness_policy_id
        || checkpoint.witness_policy_revision != witness_policy.revision
        || checkpoint.witness_policy_digest
            != witness_policy
                .digest()
                .map_err(|_| CheckpointPolicyError::Invalid)?
        || checkpoint.witness_set_digest != witness_set_digest
        || checkpoint.approver_set_digest != approver_set_digest
        || checkpoint.review_label_set_digest != witness_policy.review_label_set_digest
        || witness_policy.vault_policy_sequence > policy.sequence()
        || policy.predecessor_hash_for_sequence(witness_policy.vault_policy_sequence)
            != Some(&witness_policy.vault_policy_hash)
    {
        return Err(CheckpointPolicyError::ScopeMismatch);
    }
    let owner = policy
        .principal(&checkpoint.issuer_owner_id)
        .filter(|_| policy.is_owner(&checkpoint.issuer_owner_id))
        .ok_or(CheckpointPolicyError::MissingOwner)?;
    if checkpoint.issuer_key_epoch != 1
        || checkpoint.issuer_key_fingerprint
            != signing_key_fingerprint(
                1,
                &checkpoint.issuer_owner_id,
                1,
                &owner.descriptor.verification_public_key,
            )
    {
        return Err(CheckpointPolicyError::InvalidSignature);
    }
    crypto::verify_bytes(
        &owner.descriptor.verification_public_key,
        &checkpoint
            .signature_preimage()
            .map_err(|_| CheckpointPolicyError::Invalid)?,
        &checkpoint.signature,
    )
    .map_err(|_| CheckpointPolicyError::InvalidSignature)?;
    Ok(witness_policy)
}
