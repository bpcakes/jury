/// Verifies one independently signed approval against the exact current request.
pub fn validate_approval_decision(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    approval: &ApprovalDecisionV1,
    now_ms: u64,
) -> Result<(), WitnessEngineError> {
    let validated = validate_public_request(policy, checkpoint, request, manifest)?;
    validate_approval_against_policy(
        approval,
        request,
        manifest,
        &validated.rule,
        &validated.policy,
    )?;
    if !approval_is_current(approval, now_ms) {
        return Err(refused(WitnessReasonV1::Invalid));
    }
    Ok(())
}
fn validate_approval_against_policy(
    approval: &ApprovalDecisionV1,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    rule: &WitnessAccessRule,
    policy: &WitnessPolicy,
) -> Result<(), WitnessEngineError> {
    approval
        .validate_shape()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    let descriptor = policy
        .approver_descriptors
        .iter()
        .find(|descriptor| {
            descriptor.status == DescriptorStatus::Active
                && descriptor.approver_id == approval.approver_id
        })
        .ok_or_else(|| refused(WitnessReasonV1::PolicyDenied))?;
    if !rule.eligible_approver_ids.contains(&approval.approver_id)
        || approval.request_id != request.request_id
        || approval.request_digest
            != request
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || approval.action_manifest_digest
            != manifest
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || approval.presentation_digest != manifest.presentation_digest
        || approval.witness_policy_id != request.witness_policy_id
        || approval.witness_policy_revision != request.witness_policy_revision
        || approval.witness_policy_digest != request.witness_policy_digest
        || approval.intended_witness_set_digest
            != request
                .intended_witness_set_digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || approval.approver_key_fingerprint != descriptor.signing_key_fingerprint
        || approval.approver_key_epoch != descriptor.signing_key_epoch
        || approval.approval_mode != protocol_approval_mode(descriptor.approval_mode)
        || approval.issued_at_ms < request.issued_at_ms
        || approval.expires_at_ms > request.expires_at_ms
    {
        return Err(refused(WitnessReasonV1::Invalid));
    }
    crypto::verify_bytes(
        &descriptor.signing_public_key,
        &approval
            .signature_preimage()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        &approval.signature,
    )
    .map_err(|_| refused(WitnessReasonV1::InvalidSignature))
}
