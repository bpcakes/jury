use super::*;

pub(super) fn checkpoint_acknowledgement(
    state: &PersistedWitnessState,
    vault_id: &VaultId,
) -> Result<WitnessCheckpointAcknowledgementV1, WitnessEngineError> {
    let vault = state
        .logical
        .vaults
        .get(vault_id)
        .ok_or_else(|| refused(WitnessReasonV1::StalePolicy))?;
    let exact_anchor = state
        .published_anchor
        .clone()
        .ok_or_else(|| refused(WitnessReasonV1::AnchorConflict))?;
    let acknowledgement = WitnessCheckpointAcknowledgementV1 {
        schema: 1,
        witness_id: state.logical.witness_id,
        vault_id: *vault_id,
        checkpoint_digest: vault
            .current_checkpoint
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        vault_policy_sequence: vault.current_checkpoint.vault_policy_sequence,
        active_witness_policy_set_digest: vault
            .current_checkpoint
            .active_witness_policy_set_digest
            .clone(),
        state_generation: state.logical.state_generation,
        anchor_digest: exact_anchor
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        exact_anchor,
    };
    acknowledgement
        .validate_shape()
        .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
    Ok(acknowledgement)
}

pub(super) fn validate_checkpoint<I: WitnessEngineIdentity + ?Sized>(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    identity: &I,
) -> Result<(), WitnessEngineError> {
    let policies = validate_checkpoint_public(policy, checkpoint)?;
    let own_descriptor = identity
        .public_descriptor()
        .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
    if !policies
        .iter()
        .flat_map(|policy| &policy.witness_descriptors)
        .any(|descriptor| {
            descriptor.status == DescriptorStatus::Active
                && descriptor.witness_id == own_descriptor.principal_id
                && descriptor.signing_public_key == own_descriptor.verification_public_key
                && descriptor.contribution_public_key == own_descriptor.recipient_public_key
        })
    {
        return Err(refused(WitnessReasonV1::PolicyDenied));
    }
    Ok(())
}

pub(super) fn validate_registered_checkpoint<I: WitnessEngineIdentity + ?Sized>(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    identity: &I,
) -> Result<(), WitnessEngineError> {
    if checkpoint.vault_policy_sequence < policy.sequence() {
        return Err(refused(WitnessReasonV1::WitnessBehind));
    }
    if checkpoint.vault_policy_sequence > policy.sequence() {
        return Err(refused(WitnessReasonV1::StalePolicy));
    }
    validate_checkpoint(policy, checkpoint, identity)
}

pub(crate) fn validate_checkpoint_public<'a>(
    policy: &'a PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
) -> Result<Vec<&'a WitnessPolicy>, WitnessEngineError> {
    use crate::checkpoint_validation::{CheckpointPolicyError, validate_checkpoint_policy};
    validate_checkpoint_policy(policy, checkpoint).map_err(|error| {
        refused(match error {
            CheckpointPolicyError::Invalid => WitnessReasonV1::Invalid,
            CheckpointPolicyError::ScopeMismatch => WitnessReasonV1::CheckpointFork,
            CheckpointPolicyError::MissingOwner | CheckpointPolicyError::InvalidSignature => {
                WitnessReasonV1::InvalidSignature
            }
        })
    })
}

pub(super) fn validate_request_time(
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    now_ms: u64,
) -> Result<(), WitnessEngineError> {
    let skewed_now = now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS);
    if request.issued_at_ms > skewed_now {
        return Err(refused(WitnessReasonV1::NotYetValid));
    }
    if request
        .not_before_ms
        .is_some_and(|not_before| not_before > skewed_now)
    {
        return Err(refused(WitnessReasonV1::NotYetValid));
    }
    if now_ms >= request.expires_at_ms {
        return Err(refused(WitnessReasonV1::Expired));
    }
    Ok(())
}

pub(super) fn validate_automatic_rule(
    manifest: &ActionManifestV1,
    rule: &WitnessAccessRule,
) -> Result<(), WitnessEngineError> {
    if rule.approval_threshold != 0 {
        return Ok(());
    }
    let all_allowed = manifest.approval_target.entries.iter().all(|entry| {
        rule.automatic_read_targets.iter().any(|target| {
            target.item_id == entry.item_id
                && target.content_role == manifest.content_role
                && target.field_id == entry.field_id
        })
    });
    if !all_allowed || manifest.operation != WitnessOperationV1::ReadStdout {
        return Err(refused(WitnessReasonV1::PolicyDenied));
    }
    Ok(())
}

pub(super) fn validate_approval(
    approval: &ApprovalDecisionV1,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    validated: &ValidatedRequest,
    now_ms: u64,
) -> Result<(), WitnessEngineError> {
    validate_approval_static(approval, request, manifest, validated)?;
    if !approval_is_current(approval, now_ms) {
        return Err(refused(WitnessReasonV1::Invalid));
    }
    Ok(())
}

pub(super) fn validate_approval_static(
    approval: &ApprovalDecisionV1,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    validated: &ValidatedRequest,
) -> Result<(), WitnessEngineError> {
    validate_approval_against_policy(
        approval,
        request,
        manifest,
        &validated.rule,
        &validated.policy,
    )
}

include!("approval_validation.rs");

pub(super) fn approval_is_current(approval: &ApprovalDecisionV1, now_ms: u64) -> bool {
    approval.issued_at_ms <= now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS)
        && now_ms < approval.expires_at_ms
        && approval
            .not_before_ms
            .is_none_or(|not_before| not_before <= now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS))
}

/// Validates a cancellation against the exact signed request and current actor policy.
pub fn validate_request_cancellation(
    policy: &PolicyState,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    cancellation: &RequestCancellationV1,
    now_ms: u64,
) -> Result<(), WitnessEngineError> {
    cancellation
        .validate_shape()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    if cancellation.request_signature_preimage.as_bytes()
        != request
            .signature_preimage()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || cancellation.client_signature != request.client_signature
        || cancellation.request_id != request.request_id
        || cancellation.request_digest
            != request
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || cancellation.issued_at_ms > now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS)
        || cancellation.issued_at_ms < request.issued_at_ms
        || cancellation.canceller_key_epoch != 1
    {
        return Err(refused(WitnessReasonV1::Invalid));
    }
    let canceller = policy
        .principal(&cancellation.canceller_id)
        .ok_or_else(|| refused(WitnessReasonV1::PolicyDenied))?;
    let role_valid = match cancellation.canceller_role {
        CancellerRoleV1::OriginalRequester => {
            cancellation.canceller_id == request.requester_principal_id
        }
        CancellerRoleV1::CurrentOwner => policy.is_owner(&cancellation.canceller_id),
    };
    if !role_valid
        || cancellation.canceller_key_fingerprint
            != signing_key_fingerprint(
                1,
                &cancellation.canceller_id,
                1,
                &canceller.descriptor.verification_public_key,
            )
    {
        return Err(refused(WitnessReasonV1::PolicyDenied));
    }
    crypto::verify_bytes(
        &canceller.descriptor.verification_public_key,
        &cancellation
            .signature_preimage()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        &cancellation.signature,
    )
    .map_err(|_| refused(WitnessReasonV1::InvalidSignature))
}

pub(super) fn normalize_approvals(
    approvals: Vec<ApprovalDecisionV1>,
) -> Result<Vec<ApprovalDecisionV1>, WitnessEngineError> {
    let mut keyed = approvals
        .into_iter()
        .map(|approval| {
            let bytes = approval
                .canonical_bytes()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?;
            Ok((approval.approver_id, bytes, approval))
        })
        .collect::<Result<Vec<_>, WitnessEngineError>>()?;
    keyed.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    keyed.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
    let mut retained: Vec<(PrincipalId, Vec<u8>, ApprovalDecisionV1)> = Vec::new();
    for entry in keyed {
        let same_approver = retained
            .iter()
            .rev()
            .take_while(|prior| prior.0 == entry.0)
            .count();
        if same_approver < 2 {
            retained.push(entry);
        }
    }
    if retained.len() > MAX_RECORDED_APPROVALS {
        return Err(refused(WitnessReasonV1::CapacityExhausted));
    }
    Ok(retained
        .into_iter()
        .map(|(_, _, approval)| approval)
        .collect())
}

pub(super) fn tally_approvals(
    approvals: &[ApprovalDecisionV1],
    rule: &WitnessAccessRule,
) -> ApprovalTally {
    let mut approved = 0;
    let mut undecided = 0;
    let mut conflicted = false;
    for approver_id in &rule.eligible_approver_ids {
        let decisions = approvals
            .iter()
            .filter(|decision| decision.approver_id == *approver_id)
            .collect::<Vec<_>>();
        match decisions.as_slice() {
            [] => undecided += 1,
            [decision] if decision.decision == ApprovalDecisionKindV1::Approve => approved += 1,
            [_] => {}
            _ => conflicted = true,
        }
    }
    ApprovalTally {
        approved,
        undecided,
        conflicted,
    }
}

pub(super) fn same_request(
    left: &jury_protocol::witness_v1::WitnessRequestV1,
    right: &jury_protocol::witness_v1::WitnessRequestV1,
) -> Result<bool, WitnessEngineError> {
    Ok(left
        .canonical_bytes()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?
        == right
            .canonical_bytes()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?)
}

pub(super) fn exact_anchor_eq(
    left: &WitnessStateAnchorV1,
    right: &WitnessStateAnchorV1,
) -> Result<bool, WitnessEngineError> {
    Ok(left
        .canonical_bytes()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?
        == right
            .canonical_bytes()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?)
}

pub(super) fn random_response_id(
    source: &mut impl RandomSource,
) -> Result<ResponseId, WitnessEngineError> {
    let mut bytes = [0_u8; 32];
    source
        .fill(&mut bytes)
        .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
    ResponseId::from_bytes(bytes).map_err(|_| refused(WitnessReasonV1::InternalFailure))
}

pub(crate) fn validate_public_request(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
) -> Result<ValidatedPublicRequest, WitnessEngineError> {
    validate_request_manifest(request, manifest)?;
    validate_checkpoint_public(policy, checkpoint)?;
    let checkpoint_digest = checkpoint
        .digest()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    if request.vault_id != checkpoint.vault_id
        || request.genesis_fingerprint != checkpoint.genesis_fingerprint
        || request.vault_policy_sequence != checkpoint.vault_policy_sequence
        || request.vault_policy_hash != checkpoint.vault_policy_hash
        || request.policy_checkpoint_digest != checkpoint_digest
    {
        return Err(refused(WitnessReasonV1::WrongScope));
    }

    let validated = crate::witness_validation::validate_manifest_policy(policy, request, manifest)
        .map_err(map_request_policy_error)?;
    if manifest.timeout_ms > validated.rule.max_timeout_ms
        || manifest.output_limit_bytes > validated.rule.max_output_bytes
        || manifest.approval_target.entries.len() > usize::from(validated.rule.max_target_count)
        || manifest.platform_assurance.tag()
            < platform_assurance_tag(validated.rule.required_platform_assurance)
    {
        return Err(refused(WitnessReasonV1::WorkloadExceeded));
    }
    validate_automatic_rule(manifest, &validated.rule)?;
    Ok(ValidatedPublicRequest {
        rule: validated.rule,
        policy: validated.policy,
        slot: validated.slot,
    })
}

pub fn validate_request_manifest(
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
) -> Result<(), WitnessEngineError> {
    if request.schema != 1
        || request.protocol_version != jury_protocol::witness_v1::PROTOCOL_VERSION
        || request.construction != jury_protocol::witness_v1::CONSTRUCTION
        || manifest.schema != 1
    {
        return Err(refused(WitnessReasonV1::UnsupportedVersion));
    }
    request
        .validate_shape()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    manifest
        .validate_shape()
        .map_err(|_| refused(WitnessReasonV1::WrongScope))?;
    if manifest.approval_target.entries.iter().any(|entry| {
        entry.item_id != request.item_id
            || (request.content_role == jury_protocol::vault_v1::ContentRole::Descriptor
                && entry.field_id.is_some())
    }) {
        return Err(refused(WitnessReasonV1::WrongScope));
    }
    let manifest_digest = manifest
        .digest()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    let workload_digest = manifest
        .workload_digest()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    if request.request_id != manifest.request_id
        || request.vault_id != manifest.vault_id
        || request.genesis_fingerprint != manifest.genesis_fingerprint
        || request.item_id != manifest.item_id
        || request.key_epoch != manifest.key_epoch
        || request.item_access_mode != manifest.item_access_mode
        || request.slot_id != manifest.slot_id
        || request.content_role != manifest.content_role
        || request.revision != manifest.revision
        || request.revision_seal_id != manifest.revision_seal_id
        || request.vault_policy_sequence != manifest.vault_policy_sequence
        || request.vault_policy_hash != manifest.vault_policy_hash
        || request.witness_policy_id != manifest.witness_policy_id
        || request.witness_policy_revision != manifest.witness_policy_revision
        || request.witness_policy_digest != manifest.witness_policy_digest
        || request.requester_principal_id != manifest.requester_principal_id
        || request.requested_access_role != manifest.requested_access_role
        || request.operation != manifest.operation
        || request.approval_target_digest != manifest.approval_target_digest
        || request.action_manifest_digest != manifest_digest
        || request.workload_digest != workload_digest
        || request.issued_at_ms != manifest.issued_at_ms
        || request.not_before_ms != manifest.not_before_ms
        || request.expires_at_ms != manifest.expires_at_ms
    {
        return Err(refused(WitnessReasonV1::WrongScope));
    }
    Ok(())
}

pub fn validate_witness_response(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    response: &WitnessResponseV1,
) -> Result<(), WitnessEngineError> {
    let validated = validate_public_request(policy, checkpoint, request, manifest)?;
    let witness_policy = &validated.policy;
    let request_digest = request
        .digest()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    let manifest_digest = manifest
        .digest()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    let checkpoint_digest = checkpoint
        .digest()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    response
        .canonical_bytes()
        .map_err(|_| refused(WitnessReasonV1::InvalidContribution))?;
    let decision = &response.decision;
    if decision.request_id != request.request_id
        || decision.request_digest != request_digest
        || decision.action_manifest_digest != manifest_digest
        || decision.witness_policy_id != request.witness_policy_id
        || decision.witness_policy_revision != request.witness_policy_revision
        || decision.witness_policy_digest != request.witness_policy_digest
        || decision.policy_checkpoint_digest != checkpoint_digest
        || decision.policy_checkpoint_digest != request.policy_checkpoint_digest
        || decision.issued_at_ms < request.issued_at_ms
        || decision.expires_at_ms != request.expires_at_ms
    {
        return Err(refused(WitnessReasonV1::WrongScope));
    }
    let descriptor = witness_policy
        .witness_descriptors
        .iter()
        .find(|descriptor| {
            descriptor.status == DescriptorStatus::Active
                && descriptor.witness_id == decision.witness_id
        })
        .ok_or_else(|| refused(WitnessReasonV1::PolicyDenied))?;
    if decision.witness_signing_key_epoch != descriptor.signing_key_epoch
        || decision.witness_signing_key_fingerprint != descriptor.signing_key_fingerprint
    {
        return Err(refused(WitnessReasonV1::InvalidSignature));
    }
    crypto::verify_bytes(
        &descriptor.signing_public_key,
        &decision
            .signature_preimage()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        &decision.signature,
    )
    .map_err(|_| refused(WitnessReasonV1::InvalidSignature))?;
    if decision.decision != WitnessDecisionKindV1::Approve {
        return Ok(());
    }
    let contribution = response
        .contribution
        .as_ref()
        .ok_or_else(|| refused(WitnessReasonV1::InvalidContribution))?;
    let capsule = validated
        .slot
        .capsules
        .iter()
        .find(|capsule| capsule.witness_id == decision.witness_id)
        .ok_or_else(|| refused(WitnessReasonV1::InvalidContribution))?;
    if contribution.response_id != decision.response_id
        || decision.share_index != Some(contribution.share_index)
        || decision.share_commitment.as_ref() != Some(&contribution.share_commitment)
        || contribution.share_index != descriptor.share_index
        || contribution.share_index != capsule.share_index
        || contribution.share_commitment != capsule.share_commitment
        || contribution.capsule_context_digest != capsule.context_digest
        || contribution.capsule_set_digest != validated.slot.capsule_set_digest
        || contribution.request_session_key_fingerprint != request.request_session_key_fingerprint
    {
        return Err(refused(WitnessReasonV1::InvalidContribution));
    }
    Ok(())
}

pub fn validate_receipt_material(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    material: &WitnessReceiptMaterialV1,
) -> Result<(), WitnessEngineError> {
    let validated = validate_public_request(policy, checkpoint, request, manifest)?;
    material
        .canonical_bytes()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    let rule = &validated.rule;
    let valid_approvers = material
        .counted_approver_ids
        .iter()
        .all(|id| rule.eligible_approver_ids.contains(id));
    let valid_witnesses = material
        .counted_witness_ids
        .iter()
        .all(|id| rule.witness_ids.contains(id));
    let successful = material.reason == WitnessReasonV1::None;
    if material.request_digest
        != request
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || material.action_manifest_digest
            != manifest
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || material.presentation_digest != manifest.presentation_digest
        || material.policy_checkpoint_digest
            != checkpoint
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || material.witness_policy_digest != request.witness_policy_digest
        || material.approval_threshold != rule.approval_threshold
        || material.witness_threshold != rule.witness_threshold
        || material.issued_at_ms < request.issued_at_ms
        || material.expires_at_ms != request.expires_at_ms
        || !valid_approvers
        || !valid_witnesses
        || (successful
            && (material.counted_approver_ids.len() < usize::from(rule.approval_threshold)
                || material.counted_witness_ids.len() < usize::from(rule.witness_threshold)))
    {
        return Err(refused(WitnessReasonV1::WrongScope));
    }
    Ok(())
}

pub(super) const fn map_request_policy_error(error: RequestPolicyError) -> WitnessEngineError {
    match error {
        RequestPolicyError::Invalid => refused(WitnessReasonV1::Invalid),
        RequestPolicyError::InvalidSignature => refused(WitnessReasonV1::InvalidSignature),
        RequestPolicyError::PolicyDenied => refused(WitnessReasonV1::PolicyDenied),
        RequestPolicyError::StalePolicy => refused(WitnessReasonV1::StalePolicy),
        RequestPolicyError::WrongScope => refused(WitnessReasonV1::WrongScope),
    }
}

pub(super) const fn map_store_error(error: WitnessStoreError) -> WitnessEngineError {
    match error.kind() {
        WitnessStoreErrorKind::Unavailable => WitnessEngineError::store_unavailable(),
        WitnessStoreErrorKind::CapacityExhausted => refused(WitnessReasonV1::CapacityExhausted),
    }
}

pub(super) const fn map_anchor_error(error: WitnessAnchorError) -> WitnessEngineError {
    match error.kind() {
        WitnessAnchorErrorKind::Unavailable => WitnessEngineError::anchor_unavailable(),
        WitnessAnchorErrorKind::CapacityExhausted => refused(WitnessReasonV1::CapacityExhausted),
    }
}

pub(super) const fn refused(reason: WitnessReasonV1) -> WitnessEngineError {
    WitnessEngineError::refused(reason)
}
