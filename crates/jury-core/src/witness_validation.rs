//! Shared policy validation for witnessed requests.
//!
//! Live witnesses and offline receipt verification do not possess identical
//! evidence: only the live path has the complete action manifest and a current
//! wall clock. The policy, requester, intended-set, and item-slot invariants
//! below are common to both paths and must not drift.

use jury_protocol::{
    vault_v1::{PrincipalKind, WitnessedSlotV1},
    witness_v1::{
        IntendedWitnessV1, WitnessOperationV1, WitnessRequestV1, signing_key_fingerprint,
    },
};

use crate::{
    crypto,
    domain::Capability,
    policy::{
        DescriptorStatus, PolicyErrorKind, PolicyState, WitnessAccessRule, WitnessPolicy,
        core_operation,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestPolicyError {
    Invalid,
    InvalidSignature,
    PolicyDenied,
    StalePolicy,
    WrongScope,
}

#[derive(Clone)]
pub(crate) struct ValidatedRequestPolicy {
    pub(crate) rule: WitnessAccessRule,
    pub(crate) policy: WitnessPolicy,
    pub(crate) slot: WitnessedSlotV1,
}

pub(crate) fn validate_request_policy(
    policy: &PolicyState,
    request: &WitnessRequestV1,
) -> Result<ValidatedRequestPolicy, RequestPolicyError> {
    request
        .validate_shape()
        .map_err(|_| RequestPolicyError::Invalid)?;
    if request.vault_id != policy.vault_id()
        || request.genesis_fingerprint != *policy.genesis_fingerprint()
        || request.vault_policy_sequence != policy.sequence()
        || request.vault_policy_hash != *policy.terminal_revision_hash()
    {
        return Err(RequestPolicyError::StalePolicy);
    }

    let request_lifetime = request
        .expires_at_ms
        .checked_sub(request.issued_at_ms)
        .ok_or(RequestPolicyError::Invalid)?;
    let rule = policy
        .witness_access_rule(&request.item_id, core_operation(request.operation))
        .map_err(|error| match error.kind() {
            PolicyErrorKind::UnknownItem => RequestPolicyError::WrongScope,
            PolicyErrorKind::Unauthorized => RequestPolicyError::WrongScope,
            PolicyErrorKind::MissingWitnessPolicy => RequestPolicyError::StalePolicy,
            _ => RequestPolicyError::PolicyDenied,
        })?;
    if request.witness_policy_id != rule.policy_id
        || request.witness_policy_revision != rule.policy_revision
        || request.witness_policy_digest != rule.policy_digest
        || request_lifetime > rule.allowed_request_lifetime_ms
    {
        return Err(RequestPolicyError::StalePolicy);
    }

    let access = policy.access(
        &request.item_id,
        &request.requester_principal_id,
        operation_capability(request.operation),
    );
    if !access.allowed || access.effective_role != Some(request.requested_access_role) {
        return Err(RequestPolicyError::PolicyDenied);
    }
    let requester = policy
        .principal(&request.requester_principal_id)
        .ok_or(RequestPolicyError::PolicyDenied)?;
    if matches!(
        requester.descriptor.principal_kind,
        PrincipalKind::Approver | PrincipalKind::Witness
    ) || request.requester_signing_key_epoch != 1
        || request.requester_signing_key_fingerprint
            != signing_key_fingerprint(
                1,
                &request.requester_principal_id,
                1,
                &requester.descriptor.verification_public_key,
            )
    {
        return Err(RequestPolicyError::InvalidSignature);
    }
    crypto::verify_bytes(
        &requester.descriptor.verification_public_key,
        &request
            .signature_preimage()
            .map_err(|_| RequestPolicyError::Invalid)?,
        &request.client_signature,
    )
    .map_err(|_| RequestPolicyError::InvalidSignature)?;

    let witness_policy = policy
        .witness_policy(&request.witness_policy_digest)
        .ok_or(RequestPolicyError::StalePolicy)?
        .clone();
    if witness_policy.vault_policy_sequence > request.vault_policy_sequence
        || policy.predecessor_hash_for_sequence(witness_policy.vault_policy_sequence)
            != Some(&witness_policy.vault_policy_hash)
    {
        return Err(RequestPolicyError::StalePolicy);
    }
    let expected_witnesses = witness_policy
        .witness_descriptors
        .iter()
        .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
        .map(|descriptor| IntendedWitnessV1 {
            witness_id: descriptor.witness_id,
            share_index: descriptor.share_index,
            signing_key_fingerprint: descriptor.signing_key_fingerprint.clone(),
            contribution_key_fingerprint: descriptor.contribution_key_fingerprint.clone(),
        })
        .collect::<Vec<_>>();
    if request.intended_witness_set != expected_witnesses
        || request
            .intended_witness_set_digest()
            .map_err(|_| RequestPolicyError::Invalid)?
            != policy
                .intended_witness_set_digest(&request.item_id)
                .map_err(|_| RequestPolicyError::StalePolicy)?
    {
        return Err(RequestPolicyError::WrongScope);
    }

    let item = policy
        .item(&request.item_id)
        .ok_or(RequestPolicyError::WrongScope)?;
    if item.key_epoch != request.key_epoch || item.access_mode() != Some(request.item_access_mode) {
        return Err(RequestPolicyError::WrongScope);
    }
    let slot = item
        .witnessed_state
        .as_ref()
        .and_then(|witnessed| {
            witnessed.slots.iter().find(|slot| {
                slot.slot_id == request.slot_id
                    && slot.content_role == request.content_role
                    && slot.revision == request.revision
                    && slot.revision_seal_id == request.revision_seal_id
                    && slot.key_epoch == request.key_epoch
                    && slot.item_access_mode == request.item_access_mode
                    && slot.vault_policy_sequence == witness_policy.vault_policy_sequence
                    && slot.witness_policy_id == request.witness_policy_id
                    && slot.witness_policy_revision == request.witness_policy_revision
                    && slot.witness_policy_digest == request.witness_policy_digest
            })
        })
        .ok_or(RequestPolicyError::WrongScope)?;
    if slot.threshold != rule.witness_threshold
        || usize::from(slot.member_count) != expected_witnesses.len()
    {
        return Err(RequestPolicyError::WrongScope);
    }
    Ok(ValidatedRequestPolicy {
        rule,
        policy: witness_policy,
        slot: slot.clone(),
    })
}

pub const fn operation_capability(operation: WitnessOperationV1) -> Capability {
    match operation {
        WitnessOperationV1::ReadStdout
        | WitnessOperationV1::WritePrivateFile
        | WitnessOperationV1::TemplateInjection
        | WitnessOperationV1::ChildEnvironment
        | WitnessOperationV1::ChildStdin => Capability::Read,
        WitnessOperationV1::ItemMutation | WitnessOperationV1::Backup => Capability::Write,
        WitnessOperationV1::Recovery | WitnessOperationV1::AdministrativeRekey => {
            Capability::Administer
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_file_output_is_a_read_capability() {
        assert_eq!(
            operation_capability(WitnessOperationV1::WritePrivateFile),
            Capability::Read
        );
        assert_eq!(
            operation_capability(WitnessOperationV1::ItemMutation),
            Capability::Write
        );
    }
}
