//! Offline verification for portable witnessed-decision receipts.
//!
//! Verification consumes only the receipt's bounded public bytes. It performs
//! no network access, unlocks no identity, and never handles contribution
//! envelopes or presentation values.

use std::fmt;

use jury_protocol::{
    vault_v1::{
        Digest32, PolicyJournalV1, PrincipalId, ReceiptId, RequestId, VaultId, WitnessPolicyId,
    },
    witness_v1::{
        ACCEPTED_CLOCK_SKEW_MS, ApprovalDecisionKindV1, ApprovalDecisionV1, PolicyMaterialBytes,
        PublicReceiptScopeV1, ReceiptOutcomeV1, RequestBytes, VaultPolicyCheckpointV1,
        WitnessDecisionKindV1, WitnessDecisionV1, WitnessReasonV1, WitnessReceiptV1,
        WitnessRequestV1, signing_key_fingerprint,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    crypto,
    policy::{
        ApprovalMode, DescriptorStatus, PolicyState, WitnessPolicy, core_operation,
        replay_policy_with_witness_policies,
    },
    witness_validation::{RequestPolicyError, validate_request_policy},
};

/// Exact public policy bundle embedded by the self-hosted witness protocol.
/// Compact JSON is transport framing only; every security-relevant value is
/// authenticated by policy replay and the canonical witness-policy digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPolicyMaterialV1 {
    pub schema: u16,
    pub journal: PolicyJournalV1,
    pub witness_policies: Vec<WitnessPolicy>,
}

impl ReceiptPolicyMaterialV1 {
    pub fn replay(&self) -> Result<PolicyState, ReceiptVerificationError> {
        if self.schema != 1 {
            return Err(invalid(ReceiptVerificationErrorKind::InvalidPolicy));
        }
        replay_policy_with_witness_policies(&self.journal, &self.witness_policies)
            .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidPolicy))
    }

    /// Encodes the one frozen v1 compact-JSON representation after replaying
    /// every owner-signed policy invariant.
    pub fn encode(&self) -> Result<PolicyMaterialBytes, ReceiptVerificationError> {
        self.replay()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidPolicy))?;
        PolicyMaterialBytes::new(bytes)
            .map_err(|_| invalid(ReceiptVerificationErrorKind::CapacityExhausted))
    }

    /// Parses only the exact bytes produced by [`Self::encode`]. JSON that is
    /// semantically equivalent but reordered or padded is not canonical v1
    /// policy material.
    pub fn decode(encoded: &PolicyMaterialBytes) -> Result<Self, ReceiptVerificationError> {
        let material: Self = serde_json::from_slice(encoded.as_bytes())
            .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidPolicy))?;
        if material.encode()?.as_bytes() != encoded.as_bytes() {
            return Err(invalid(ReceiptVerificationErrorKind::InvalidPolicy));
        }
        Ok(material)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptVerificationErrorKind {
    InvalidFormat,
    InvalidPolicy,
    InvalidScope,
    InvalidDigest,
    InvalidSignature,
    InvalidQuorum,
    CheckpointMismatch,
    CapacityExhausted,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReceiptVerificationError {
    kind: ReceiptVerificationErrorKind,
}

impl ReceiptVerificationError {
    #[must_use]
    pub const fn kind(self) -> ReceiptVerificationErrorKind {
        self.kind
    }
}

impl fmt::Debug for ReceiptVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiptVerificationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for ReceiptVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ReceiptVerificationErrorKind::InvalidFormat => "receipt format is invalid",
            ReceiptVerificationErrorKind::InvalidPolicy => "receipt policy material is invalid",
            ReceiptVerificationErrorKind::InvalidScope => "receipt scope differs",
            ReceiptVerificationErrorKind::InvalidDigest => "receipt digest differs",
            ReceiptVerificationErrorKind::InvalidSignature => {
                "receipt evidence signature is invalid"
            }
            ReceiptVerificationErrorKind::InvalidQuorum => "receipt quorum evidence is invalid",
            ReceiptVerificationErrorKind::CheckpointMismatch => {
                "receipt checkpoint differs from the supplied checkpoint"
            }
            ReceiptVerificationErrorKind::CapacityExhausted => {
                "receipt public material exceeds the protocol capacity"
            }
        })
    }
}

impl std::error::Error for ReceiptVerificationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedWitnessGeneration {
    pub witness_id: PrincipalId,
    pub state_generation: u64,
    pub decision: WitnessDecisionKindV1,
    pub reason: WitnessReasonV1,
}

/// Value-free result of a complete offline verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedWitnessReceipt {
    pub receipt_digest: Digest32,
    pub receipt_core_digest: Digest32,
    pub request_id: RequestId,
    pub request_digest: Digest32,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub vault_policy_sequence: u64,
    pub vault_policy_hash: Digest32,
    pub witness_policy_id: WitnessPolicyId,
    pub witness_policy_revision: u64,
    pub witness_policy_digest: Digest32,
    pub policy_checkpoint_digest: Digest32,
    pub outcome: ReceiptOutcomeV1,
    pub reported_reason: WitnessReasonV1,
    pub reported_issued_at_ms: u64,
    pub receipt_core_endpoint_authenticated: bool,
    pub retained_checkpoint_matched: bool,
    pub counted_approver_ids: Vec<PrincipalId>,
    pub counted_witness_ids: Vec<PrincipalId>,
    pub witness_generations: Vec<VerifiedWitnessGeneration>,
    pub endpoint_acknowledged: bool,
    pub endpoint_completion_recorded: bool,
}

impl VerifiedWitnessReceipt {
    /// A verified receipt proves signed decisions over public digests. It does
    /// not prove endpoint execution, output, non-exfiltration, or forgetting.
    pub const NONCLAIM: &'static str = "verified decisions only; does not prove endpoint execution, output, non-exfiltration, or forgetting";
}

pub struct WitnessReceiptEvidence {
    pub receipt_id: ReceiptId,
    pub presentation_digest: Digest32,
    pub policy_material: PolicyMaterialBytes,
    pub approval_decisions: Vec<ApprovalDecisionV1>,
    pub witness_decisions: Vec<WitnessDecisionV1>,
    pub reason: WitnessReasonV1,
    pub issued_at_ms: u64,
}

/// Assembles the portable, contribution-free decision record used by J22
/// endpoints. Quorum outcome and counted identities are derived from signed
/// decisions, then the completed receipt is independently verified before it
/// is returned.
pub fn assemble_witness_receipt(
    policy: &PolicyState,
    request: &WitnessRequestV1,
    checkpoint: VaultPolicyCheckpointV1,
    mut evidence: WitnessReceiptEvidence,
) -> Result<WitnessReceiptV1, ReceiptVerificationError> {
    let embedded = ReceiptPolicyMaterialV1::decode(&evidence.policy_material)?;
    if embedded.replay()? != *policy {
        return Err(invalid(ReceiptVerificationErrorKind::InvalidPolicy));
    }
    let rule = policy
        .witness_access_rule(&request.item_id, core_operation(request.operation))
        .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidPolicy))?;
    evidence
        .approval_decisions
        .sort_unstable_by_key(|decision| decision.approver_id);
    evidence
        .witness_decisions
        .sort_unstable_by_key(|decision| decision.witness_id);
    let counted_approver_ids = evidence
        .approval_decisions
        .iter()
        .filter(|decision| decision.decision == ApprovalDecisionKindV1::Approve)
        .map(|decision| decision.approver_id)
        .collect::<Vec<_>>();
    let counted_witness_ids = evidence
        .witness_decisions
        .iter()
        .filter(|decision| decision.decision == WitnessDecisionKindV1::Approve)
        .map(|decision| decision.witness_id)
        .collect::<Vec<_>>();
    let approved = counted_approver_ids.len() >= usize::from(rule.approval_threshold)
        && counted_witness_ids.len() >= usize::from(rule.witness_threshold);
    let outcome = if approved {
        if evidence.reason != WitnessReasonV1::None {
            return Err(invalid(ReceiptVerificationErrorKind::InvalidQuorum));
        }
        ReceiptOutcomeV1::Approved
    } else {
        if evidence.reason == WitnessReasonV1::None {
            return Err(invalid(ReceiptVerificationErrorKind::InvalidQuorum));
        }
        ReceiptOutcomeV1::Denied
    };
    let receipt = WitnessReceiptV1 {
        schema: 1,
        receipt_id: evidence.receipt_id,
        request_signature_preimage: RequestBytes::new(
            request
                .signature_preimage()
                .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidFormat))?,
        )
        .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidFormat))?,
        client_signature: request.client_signature.clone(),
        request_digest: request
            .digest()
            .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidDigest))?,
        action_manifest_digest: request.action_manifest_digest.clone(),
        presentation_digest: evidence.presentation_digest,
        public_scope: PublicReceiptScopeV1::from_request(request),
        approval_decisions: evidence.approval_decisions,
        witness_decisions: evidence.witness_decisions,
        policy_checkpoint: checkpoint,
        witness_policy_material: evidence.policy_material,
        approval_threshold: rule.approval_threshold,
        witness_threshold: rule.witness_threshold,
        counted_approver_ids,
        counted_witness_ids,
        outcome,
        reason: evidence.reason,
        issued_at_ms: evidence.issued_at_ms,
        expires_at_ms: request.expires_at_ms,
        endpoint_acknowledgement: None,
        endpoint_completion: None,
    };
    verify_witness_receipt_with_policy(&receipt, policy, Some(&receipt.policy_checkpoint))?;
    Ok(receipt)
}

/// Verifies a receipt using only its embedded public evidence. `checkpoint`
/// optionally pins an independently retained exact checkpoint; it never causes
/// network lookup or chooses a fresher value.
pub fn verify_witness_receipt(
    receipt: &WitnessReceiptV1,
    checkpoint: Option<&VaultPolicyCheckpointV1>,
) -> Result<VerifiedWitnessReceipt, ReceiptVerificationError> {
    let material = parse_policy_material(receipt)?;
    let policy = material.replay()?;
    verify_witness_receipt_with_policy(receipt, &policy, checkpoint)
}

/// Internal evidence verifier used after the caller has authenticated the
/// exact policy material. Production callers must enter through
/// [`verify_witness_receipt`], which parses and replays the embedded material;
/// this narrower seam exists for assembly and crate-level invariant tests.
pub(crate) fn verify_witness_receipt_with_policy(
    receipt: &WitnessReceiptV1,
    policy: &PolicyState,
    checkpoint: Option<&VaultPolicyCheckpointV1>,
) -> Result<VerifiedWitnessReceipt, ReceiptVerificationError> {
    let (receipt_core_digest, receipt_digest) = receipt
        .validated_digests()
        .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidFormat))?;
    if checkpoint.is_some_and(|expected| expected != &receipt.policy_checkpoint) {
        return Err(invalid(ReceiptVerificationErrorKind::CheckpointMismatch));
    }

    let request = WitnessRequestV1::from_signature_preimage(
        receipt.request_signature_preimage.as_bytes(),
        receipt.client_signature.clone(),
    )
    .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidFormat))?;
    let request_digest = request
        .digest()
        .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidDigest))?;
    if request_digest != receipt.request_digest
        || request.action_manifest_digest != receipt.action_manifest_digest
        || request.action_manifest_digest != receipt.public_scope.action_manifest_digest
        || receipt.public_scope
            != jury_protocol::witness_v1::PublicReceiptScopeV1::from_request(&request)
        || receipt.expires_at_ms != request.expires_at_ms
        || receipt.issued_at_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS) < request.issued_at_ms
        || (receipt.outcome == ReceiptOutcomeV1::Approved
            && receipt.issued_at_ms >= request.expires_at_ms)
    {
        return Err(invalid(ReceiptVerificationErrorKind::InvalidScope));
    }

    let validated = validate_request_policy(policy, &request).map_err(map_request_policy_error)?;
    let witness_policy = &validated.policy;
    validate_checkpoint(policy, witness_policy, &request, &receipt.policy_checkpoint)?;
    let rule = &validated.rule;
    if receipt.approval_threshold != rule.approval_threshold
        || receipt.witness_threshold != rule.witness_threshold
    {
        return Err(invalid(ReceiptVerificationErrorKind::InvalidQuorum));
    }

    let intended_digest = request
        .intended_witness_set_digest()
        .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidDigest))?;
    let expected_intended_digest = policy
        .intended_witness_set_digest(&request.item_id)
        .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidPolicy))?;
    if intended_digest != expected_intended_digest {
        return Err(invalid(ReceiptVerificationErrorKind::InvalidScope));
    }

    let counted_approvers = validate_approvals(receipt, &request, witness_policy)?;
    let (counted_witnesses, witness_generations) =
        validate_witness_decisions(receipt, &request, witness_policy)?;
    let quorum_approved = counted_approvers.len() >= usize::from(rule.approval_threshold)
        && counted_witnesses.len() >= usize::from(rule.witness_threshold);
    if counted_approvers != receipt.counted_approver_ids
        || counted_witnesses != receipt.counted_witness_ids
        || counted_approvers
            .iter()
            .any(|id| !rule.eligible_approver_ids.contains(id))
        || counted_witnesses
            .iter()
            .any(|id| !rule.witness_ids.contains(id))
        || (receipt.outcome == ReceiptOutcomeV1::Approved) != quorum_approved
    {
        return Err(invalid(ReceiptVerificationErrorKind::InvalidQuorum));
    }

    validate_endpoint_records(receipt, &request, policy)?;
    let receipt_core_endpoint_authenticated =
        receipt.endpoint_acknowledgement.is_some() || receipt.endpoint_completion.is_some();
    Ok(VerifiedWitnessReceipt {
        receipt_digest,
        receipt_core_digest,
        request_id: request.request_id,
        request_digest,
        vault_id: request.vault_id,
        genesis_fingerprint: request.genesis_fingerprint,
        vault_policy_sequence: request.vault_policy_sequence,
        vault_policy_hash: request.vault_policy_hash,
        witness_policy_id: request.witness_policy_id,
        witness_policy_revision: request.witness_policy_revision,
        witness_policy_digest: request.witness_policy_digest,
        policy_checkpoint_digest: receipt
            .policy_checkpoint
            .digest()
            .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidDigest))?,
        outcome: receipt.outcome,
        reported_reason: receipt.reason,
        reported_issued_at_ms: receipt.issued_at_ms,
        receipt_core_endpoint_authenticated,
        retained_checkpoint_matched: checkpoint.is_some(),
        counted_approver_ids: counted_approvers,
        counted_witness_ids: counted_witnesses,
        witness_generations,
        endpoint_acknowledged: receipt.endpoint_acknowledgement.is_some(),
        endpoint_completion_recorded: receipt.endpoint_completion.is_some(),
    })
}

fn parse_policy_material(
    receipt: &WitnessReceiptV1,
) -> Result<ReceiptPolicyMaterialV1, ReceiptVerificationError> {
    ReceiptPolicyMaterialV1::decode(&receipt.witness_policy_material)
}

fn validate_checkpoint(
    policy: &PolicyState,
    witness_policy: &WitnessPolicy,
    request: &WitnessRequestV1,
    checkpoint: &VaultPolicyCheckpointV1,
) -> Result<(), ReceiptVerificationError> {
    let checkpoint_digest = checkpoint
        .digest()
        .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidDigest))?;
    let (approver_set_digest, witness_set_digest) = witness_policy
        .active_descriptor_set_digests()
        .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidPolicy))?;
    if checkpoint_digest != request.policy_checkpoint_digest
        || checkpoint.vault_id != request.vault_id
        || checkpoint.genesis_fingerprint != request.genesis_fingerprint
        || checkpoint.vault_policy_sequence != request.vault_policy_sequence
        || checkpoint.vault_policy_hash != request.vault_policy_hash
        || checkpoint.witness_policy_id != request.witness_policy_id
        || checkpoint.witness_policy_revision != request.witness_policy_revision
        || checkpoint.witness_policy_digest != request.witness_policy_digest
        || checkpoint.witness_set_digest != witness_set_digest
        || checkpoint.approver_set_digest != approver_set_digest
        || checkpoint.review_label_set_digest != witness_policy.review_label_set_digest
    {
        return Err(invalid(ReceiptVerificationErrorKind::InvalidScope));
    }
    let owner = policy
        .principal(&checkpoint.issuer_owner_id)
        .filter(|_| policy.is_owner(&checkpoint.issuer_owner_id))
        .ok_or_else(|| invalid(ReceiptVerificationErrorKind::InvalidPolicy))?;
    if checkpoint.issuer_key_epoch != 1
        || checkpoint.issuer_key_fingerprint
            != signing_key_fingerprint(
                1,
                &checkpoint.issuer_owner_id,
                1,
                &owner.descriptor.verification_public_key,
            )
    {
        return Err(invalid(ReceiptVerificationErrorKind::InvalidSignature));
    }
    crypto::verify_bytes(
        &owner.descriptor.verification_public_key,
        &checkpoint
            .signature_preimage()
            .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidFormat))?,
        &checkpoint.signature,
    )
    .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidSignature))
}

fn validate_approvals(
    receipt: &WitnessReceiptV1,
    request: &WitnessRequestV1,
    witness_policy: &WitnessPolicy,
) -> Result<Vec<PrincipalId>, ReceiptVerificationError> {
    let intended_digest = request
        .intended_witness_set_digest()
        .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidDigest))?;
    let mut counted = Vec::new();
    for decision in &receipt.approval_decisions {
        if decision.request_id != request.request_id
            || decision.request_digest != receipt.request_digest
            || decision.action_manifest_digest != receipt.action_manifest_digest
            || decision.presentation_digest != receipt.presentation_digest
            || decision.witness_policy_id != request.witness_policy_id
            || decision.witness_policy_revision != request.witness_policy_revision
            || decision.witness_policy_digest != request.witness_policy_digest
            || decision.expires_at_ms > request.expires_at_ms
            || decision.issued_at_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS) < request.issued_at_ms
            || decision.intended_witness_set_digest != intended_digest
        {
            return Err(invalid(ReceiptVerificationErrorKind::InvalidScope));
        }
        let descriptor = witness_policy
            .approver_descriptors
            .iter()
            .find(|descriptor| {
                descriptor.status == DescriptorStatus::Active
                    && descriptor.approver_id == decision.approver_id
            })
            .ok_or_else(|| invalid(ReceiptVerificationErrorKind::InvalidPolicy))?;
        let mode_matches = matches!(
            (descriptor.approval_mode, decision.approval_mode),
            (
                ApprovalMode::Human,
                jury_protocol::witness_v1::ApprovalModeV1::Human
            ) | (
                ApprovalMode::Automatic,
                jury_protocol::witness_v1::ApprovalModeV1::Automatic
            )
        );
        if !mode_matches
            || !descriptor
                .allowed_operations
                .contains(&core_operation(request.operation))
            || descriptor.signing_key_epoch != decision.approver_key_epoch
            || descriptor.signing_key_fingerprint != decision.approver_key_fingerprint
        {
            return Err(invalid(ReceiptVerificationErrorKind::InvalidSignature));
        }
        crypto::verify_bytes(
            &descriptor.signing_public_key,
            &decision
                .signature_preimage()
                .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidFormat))?,
            &decision.signature,
        )
        .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidSignature))?;
        if decision.decision == ApprovalDecisionKindV1::Approve {
            counted.push(decision.approver_id);
        }
    }
    Ok(counted)
}

fn validate_witness_decisions(
    receipt: &WitnessReceiptV1,
    request: &WitnessRequestV1,
    witness_policy: &WitnessPolicy,
) -> Result<(Vec<PrincipalId>, Vec<VerifiedWitnessGeneration>), ReceiptVerificationError> {
    let mut counted = Vec::new();
    let mut generations = Vec::with_capacity(receipt.witness_decisions.len());
    for decision in &receipt.witness_decisions {
        if decision.request_id != request.request_id
            || decision.request_digest != receipt.request_digest
            || decision.action_manifest_digest != receipt.action_manifest_digest
            || decision.witness_policy_id != request.witness_policy_id
            || decision.witness_policy_revision != request.witness_policy_revision
            || decision.witness_policy_digest != request.witness_policy_digest
            || decision.policy_checkpoint_digest != request.policy_checkpoint_digest
            || decision.expires_at_ms > request.expires_at_ms
            || decision.issued_at_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS) < request.issued_at_ms
        {
            return Err(invalid(ReceiptVerificationErrorKind::InvalidScope));
        }
        let descriptor = witness_policy
            .witness_descriptors
            .iter()
            .find(|descriptor| {
                descriptor.status == DescriptorStatus::Active
                    && descriptor.witness_id == decision.witness_id
            })
            .ok_or_else(|| invalid(ReceiptVerificationErrorKind::InvalidPolicy))?;
        if descriptor.signing_key_epoch != decision.witness_signing_key_epoch
            || descriptor.signing_key_fingerprint != decision.witness_signing_key_fingerprint
            || (decision.decision == WitnessDecisionKindV1::Approve
                && decision.share_index != Some(descriptor.share_index))
        {
            return Err(invalid(ReceiptVerificationErrorKind::InvalidSignature));
        }
        crypto::verify_bytes(
            &descriptor.signing_public_key,
            &decision
                .signature_preimage()
                .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidFormat))?,
            &decision.signature,
        )
        .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidSignature))?;
        if decision.decision == WitnessDecisionKindV1::Approve {
            counted.push(decision.witness_id);
        }
        generations.push(VerifiedWitnessGeneration {
            witness_id: decision.witness_id,
            state_generation: decision.state_generation,
            decision: decision.decision,
            reason: decision.reason,
        });
    }
    Ok((counted, generations))
}

fn validate_endpoint_records(
    receipt: &WitnessReceiptV1,
    request: &WitnessRequestV1,
    policy: &PolicyState,
) -> Result<(), ReceiptVerificationError> {
    let requester = policy
        .principal(&request.requester_principal_id)
        .ok_or_else(|| invalid(ReceiptVerificationErrorKind::InvalidPolicy))?;
    let expected_fingerprint = signing_key_fingerprint(
        1,
        &request.requester_principal_id,
        1,
        &requester.descriptor.verification_public_key,
    );
    if let Some(acknowledgement) = &receipt.endpoint_acknowledgement {
        if acknowledgement.endpoint_principal_id != request.requester_principal_id
            || acknowledgement.endpoint_key_epoch != 1
            || acknowledgement.endpoint_key_fingerprint != expected_fingerprint
            || acknowledgement.started_at_ms < receipt.issued_at_ms
            || acknowledgement.started_at_ms > receipt.expires_at_ms
        {
            return Err(invalid(ReceiptVerificationErrorKind::InvalidScope));
        }
        crypto::verify_bytes(
            &requester.descriptor.verification_public_key,
            &acknowledgement
                .signature_preimage()
                .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidFormat))?,
            &acknowledgement.signature,
        )
        .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidSignature))?;
    }
    if let Some(completion) = &receipt.endpoint_completion {
        let earliest = receipt
            .endpoint_acknowledgement
            .as_ref()
            .map_or(receipt.issued_at_ms, |acknowledgement| {
                acknowledgement.started_at_ms
            });
        if completion.endpoint_principal_id != request.requester_principal_id
            || completion.endpoint_key_epoch != 1
            || completion.endpoint_key_fingerprint != expected_fingerprint
            || completion.completed_at_ms < earliest
        {
            return Err(invalid(ReceiptVerificationErrorKind::InvalidScope));
        }
        crypto::verify_bytes(
            &requester.descriptor.verification_public_key,
            &completion
                .signature_preimage()
                .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidFormat))?,
            &completion.signature,
        )
        .map_err(|_| invalid(ReceiptVerificationErrorKind::InvalidSignature))?;
    }
    Ok(())
}

const fn map_request_policy_error(error: RequestPolicyError) -> ReceiptVerificationError {
    match error {
        RequestPolicyError::Invalid => invalid(ReceiptVerificationErrorKind::InvalidFormat),
        RequestPolicyError::InvalidSignature => {
            invalid(ReceiptVerificationErrorKind::InvalidSignature)
        }
        RequestPolicyError::PolicyDenied | RequestPolicyError::WrongScope => {
            invalid(ReceiptVerificationErrorKind::InvalidScope)
        }
        RequestPolicyError::StalePolicy => invalid(ReceiptVerificationErrorKind::InvalidPolicy),
    }
}

const fn invalid(kind: ReceiptVerificationErrorKind) -> ReceiptVerificationError {
    ReceiptVerificationError { kind }
}
