use super::*;

pub(super) fn receipt_inspect(arguments: &ReceiptInspectArgs) -> Result<CommandOutput, CliError> {
    let receipt = read_receipt(&arguments.receipt)?;
    let receipt_digest = receipt.digest().map_err(|_| invalid_receipt())?;
    let checkpoint_digest = receipt
        .policy_checkpoint
        .digest()
        .map_err(|_| invalid_receipt())?;
    Ok(CommandOutput::Safe {
        operation: "receipt-inspect",
        fields: serde_json::json!({
            "receipt_id": hex(receipt.receipt_id.as_bytes()),
            "receipt_digest": hex(receipt_digest.as_bytes()),
            "request_id": hex(receipt.public_scope.request_id.as_bytes()),
            "request_digest": hex(receipt.request_digest.as_bytes()),
            "action_manifest_digest": hex(receipt.action_manifest_digest.as_bytes()),
            "policy_checkpoint_digest": hex(checkpoint_digest.as_bytes()),
            "outcome": receipt.outcome,
            "reason": receipt.reason,
            "approval_decision_count": receipt.approval_decisions.len(),
            "witness_decision_count": receipt.witness_decisions.len(),
            "counted_approver_count": receipt.counted_approver_ids.len(),
            "counted_witness_count": receipt.counted_witness_ids.len(),
            "endpoint_acknowledgement_present": receipt.endpoint_acknowledgement.is_some(),
            "endpoint_completion_present": receipt.endpoint_completion.is_some(),
            "cryptographically_verified": false,
            "network_accessed": false,
            "identity_unlocked": false,
            "nonclaim": VerifiedWitnessReceipt::NONCLAIM,
        }),
        lines: vec![
            format!(
                "Receipt parsed: {}",
                grouped(&hex(receipt.receipt_id.as_bytes()))
            ),
            format!("Outcome (unverified): {:?}", receipt.outcome),
            format!(
                "Decisions: {} approver; {} witness",
                receipt.approval_decisions.len(),
                receipt.witness_decisions.len()
            ),
            "Cryptographically verified: false".to_owned(),
            format!("Nonclaim: {}", VerifiedWitnessReceipt::NONCLAIM),
        ],
    })
}

pub(super) fn receipt_verify(arguments: &ReceiptVerifyArgs) -> Result<CommandOutput, CliError> {
    let receipt = read_receipt(&arguments.receipt)?;
    let checkpoint = arguments
        .checkpoint
        .as_deref()
        .map(read_checkpoint)
        .transpose()?;
    let verified = verify_witness_receipt(&receipt, checkpoint.as_ref())
        .map_err(|_| receipt_verification_failed())?;
    verified_output(&verified)
}

fn verified_output(verified: &VerifiedWitnessReceipt) -> Result<CommandOutput, CliError> {
    let generations = verified
        .witness_generations
        .iter()
        .map(|generation| {
            serde_json::json!({
                "witness_id": hex(generation.witness_id.as_bytes()),
                "state_generation": generation.state_generation,
                "decision": generation.decision,
                "reason": generation.reason,
            })
        })
        .collect::<Vec<_>>();
    Ok(CommandOutput::Safe {
        operation: "receipt-verify",
        fields: serde_json::json!({
            "receipt_digest": hex(verified.receipt_digest.as_bytes()),
            "receipt_core_digest": hex(verified.receipt_core_digest.as_bytes()),
            "request_id": hex(verified.request_id.as_bytes()),
            "request_digest": hex(verified.request_digest.as_bytes()),
            "vault_id": hex(verified.vault_id.as_bytes()),
            "genesis_fingerprint": hex(verified.genesis_fingerprint.as_bytes()),
            "vault_policy_sequence": verified.vault_policy_sequence,
            "vault_policy_hash": hex(verified.vault_policy_hash.as_bytes()),
            "witness_policy_id": hex(verified.witness_policy_id.as_bytes()),
            "witness_policy_revision": verified.witness_policy_revision,
            "witness_policy_digest": hex(verified.witness_policy_digest.as_bytes()),
            "policy_checkpoint_digest": hex(verified.policy_checkpoint_digest.as_bytes()),
            "outcome": verified.outcome,
            "reported_reason": verified.reported_reason,
            "reported_issued_at_ms": verified.reported_issued_at_ms,
            "receipt_core_endpoint_authenticated": verified.receipt_core_endpoint_authenticated,
            "retained_checkpoint_matched": verified.retained_checkpoint_matched,
            "counted_approver_ids": verified.counted_approver_ids.iter()
                .map(|id| hex(id.as_bytes())).collect::<Vec<_>>(),
            "counted_witness_ids": verified.counted_witness_ids.iter()
                .map(|id| hex(id.as_bytes())).collect::<Vec<_>>(),
            "witness_generations": generations,
            "endpoint_acknowledgement_verified": verified.endpoint_acknowledged,
            "endpoint_completion_verified": verified.endpoint_completion_recorded,
            "signed_decision_evidence_verified": true,
            "embedded_policy_chain_verified": true,
            "offline": true,
            "network_accessed": false,
            "identity_unlocked": false,
            "private_key_used": false,
            "nonclaim": VerifiedWitnessReceipt::NONCLAIM,
        }),
        lines: vec![
            "Receipt evidence verified offline".to_owned(),
            format!(
                "Outcome from signed quorum evidence: {:?}",
                verified.outcome
            ),
            format!(
                "Collector-reported reason: {:?}; receipt core endpoint-authenticated: {}",
                verified.reported_reason, verified.receipt_core_endpoint_authenticated
            ),
            format!(
                "Trust root: embedded policy chain verified; retained checkpoint matched: {}",
                verified.retained_checkpoint_matched
            ),
            format!(
                "Counted identities: {} approver; {} witness",
                verified.counted_approver_ids.len(),
                verified.counted_witness_ids.len()
            ),
            "Network accessed: false; identity unlocked: false; private key used: false".to_owned(),
            format!("Nonclaim: {}", VerifiedWitnessReceipt::NONCLAIM),
        ],
    })
}

fn read_receipt(path: &Path) -> Result<WitnessReceiptV1, CliError> {
    let bytes = read_public_file(path, MAX_RECEIPT_JSON_BYTES).map_err(map_filesystem_error)?;
    WitnessReceiptV1::parse_json(&bytes).map_err(|_| invalid_receipt())
}

pub(super) fn read_checkpoint(path: &Path) -> Result<VaultPolicyCheckpointV1, CliError> {
    let bytes = read_public_file(path, MAX_RECEIPT_JSON_BYTES).map_err(map_filesystem_error)?;
    let checkpoint = serde_json::from_slice::<VaultPolicyCheckpointV1>(&bytes)
        .map_err(|_| invalid_checkpoint())?;
    if serde_json::to_vec(&checkpoint).ok().as_deref() != Some(bytes.as_slice()) {
        return Err(invalid_checkpoint());
    }
    checkpoint
        .validate_shape()
        .map_err(|_| invalid_checkpoint())?;
    Ok(checkpoint)
}

const fn invalid_receipt() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-receipt",
        "the receipt is not a bounded canonical Jury witness receipt",
    )
}

pub(super) const fn invalid_checkpoint() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-witness-checkpoint",
        "the checkpoint is not a bounded canonical Jury witness checkpoint",
    )
}

const fn receipt_verification_failed() -> CliError {
    CliError::new(
        CliErrorKind::AuthenticationFailed,
        "receipt-verification-failed",
        "the receipt's public evidence did not verify",
    )
}
