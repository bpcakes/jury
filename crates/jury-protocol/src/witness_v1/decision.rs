impl fmt::Debug for WitnessRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessRequestV1")
            .field("request_id", &self.request_id)
            .field("vault_id", &self.vault_id)
            .field("item_id", &self.item_id)
            .field("operation", &self.operation)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecisionV1 {
    pub schema: u16,
    pub approval_id: ApprovalId,
    pub request_id: RequestId,
    pub request_digest: Digest32,
    pub action_manifest_digest: Digest32,
    pub presentation_digest: Digest32,
    pub witness_policy_id: WitnessPolicyId,
    pub witness_policy_revision: u64,
    pub witness_policy_digest: Digest32,
    pub approver_id: PrincipalId,
    pub approver_key_fingerprint: Digest32,
    pub approver_key_epoch: u64,
    pub approval_mode: ApprovalModeV1,
    pub decision: ApprovalDecisionKindV1,
    pub reason: WitnessReasonV1,
    pub issued_at_ms: u64,
    pub not_before_ms: Option<u64>,
    pub expires_at_ms: u64,
    pub nonce: ApprovalId,
    pub intended_witness_set_digest: Digest32,
    pub signature: Signature64,
}

impl ApprovalDecisionV1 {
    fn append_fields(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.approval_id.as_bytes());
        output.extend_from_slice(self.request_id.as_bytes());
        output.extend_from_slice(self.request_digest.as_bytes());
        output.extend_from_slice(self.action_manifest_digest.as_bytes());
        output.extend_from_slice(self.presentation_digest.as_bytes());
        output.extend_from_slice(self.witness_policy_id.as_bytes());
        output.extend_from_slice(&self.witness_policy_revision.to_be_bytes());
        output.extend_from_slice(self.witness_policy_digest.as_bytes());
        output.extend_from_slice(self.approver_id.as_bytes());
        output.extend_from_slice(self.approver_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.approver_key_epoch.to_be_bytes());
        output.push(self.approval_mode.tag());
        output.push(self.decision.tag());
        output.push(self.reason.tag());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        optional_u64(output, self.not_before_ms);
        output.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        output.extend_from_slice(self.nonce.as_bytes());
        output.extend_from_slice(self.intended_witness_set_digest.as_bytes());
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/approval-decision/signature");
        self.append_fields(&mut output);
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = Vec::new();
        self.append_fields(&mut output);
        output.extend_from_slice(self.signature.as_bytes());
        if output.len() > MAX_APPROVAL_BYTES {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::CapacityExhausted,
            ));
        }
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_signed(
            "jury-witness-v1/approval-decision/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        let reason_valid = match self.decision {
            ApprovalDecisionKindV1::Approve => self.reason == WitnessReasonV1::None,
            ApprovalDecisionKindV1::Deny => self.reason != WitnessReasonV1::None,
        };
        if self.schema != 1
            || self.witness_policy_revision == 0
            || self.approver_key_epoch == 0
            || !reason_valid
            || !valid_interval(self.issued_at_ms, self.not_before_ms, self.expires_at_ms)
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ApprovalDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalDecisionV1")
            .field("approval_id", &self.approval_id)
            .field("request_id", &self.request_id)
            .field("approver_id", &self.approver_id)
            .field("decision", &self.decision)
            .field("reason", &self.reason)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CancellerRoleV1 {
    OriginalRequester,
    CurrentOwner,
}

impl CancellerRoleV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::OriginalRequester => 1,
            Self::CurrentOwner => 2,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestCancellationV1 {
    pub schema: u16,
    pub cancellation_id: CancellationId,
    pub request_signature_preimage: RequestBytes,
    pub client_signature: Signature64,
    pub request_id: RequestId,
    pub request_digest: Digest32,
    pub canceller_id: PrincipalId,
    pub canceller_key_fingerprint: Digest32,
    pub canceller_key_epoch: u64,
    pub canceller_role: CancellerRoleV1,
    pub issued_at_ms: u64,
    pub reason: WitnessReasonV1,
    pub nonce: CancellationId,
    pub signature: Signature64,
}

impl RequestCancellationV1 {
    fn append_fields(&self, output: &mut Vec<u8>) -> Result<(), WitnessProtocolError> {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.cancellation_id.as_bytes());
        bytes_field(output, self.request_signature_preimage.as_bytes())?;
        output.extend_from_slice(self.client_signature.as_bytes());
        output.extend_from_slice(self.request_id.as_bytes());
        output.extend_from_slice(self.request_digest.as_bytes());
        output.extend_from_slice(self.canceller_id.as_bytes());
        output.extend_from_slice(self.canceller_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.canceller_key_epoch.to_be_bytes());
        output.push(self.canceller_role.tag());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        output.push(self.reason.tag());
        output.extend_from_slice(self.nonce.as_bytes());
        Ok(())
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/cancellation/signature");
        self.append_fields(&mut output)?;
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = Vec::new();
        self.append_fields(&mut output)?;
        output.extend_from_slice(self.signature.as_bytes());
        if output.len() > 48 * 1024 {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::CapacityExhausted,
            ));
        }
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_signed(
            "jury-witness-v1/cancellation/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        if self.schema != 1
            || self.canceller_key_epoch == 0
            || self.issued_at_ms == 0
            || self.reason != WitnessReasonV1::Cancelled
            || self.request_signature_preimage.is_empty()
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for RequestCancellationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestCancellationV1")
            .field("cancellation_id", &self.cancellation_id)
            .field("request_id", &self.request_id)
            .field("canceller_id", &self.canceller_id)
            .field("canceller_role", &self.canceller_role)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VaultPolicyCheckpointV1 {
    pub schema: u16,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub vault_policy_sequence: u64,
    pub vault_policy_hash: Digest32,
    pub witness_policy_id: WitnessPolicyId,
    pub witness_policy_revision: u64,
    pub witness_policy_digest: Digest32,
    pub witness_set_digest: Digest32,
    pub approver_set_digest: Digest32,
    pub review_label_set_digest: Digest32,
    pub predecessor_checkpoint_digest: Digest32,
    pub issued_at_ms: u64,
    pub issuer_owner_id: PrincipalId,
    pub issuer_key_fingerprint: Digest32,
    pub issuer_key_epoch: u64,
    pub signature: Signature64,
}

impl VaultPolicyCheckpointV1 {
    fn append_fields(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.genesis_fingerprint.as_bytes());
        output.extend_from_slice(&self.vault_policy_sequence.to_be_bytes());
        output.extend_from_slice(self.vault_policy_hash.as_bytes());
        output.extend_from_slice(self.witness_policy_id.as_bytes());
        output.extend_from_slice(&self.witness_policy_revision.to_be_bytes());
        output.extend_from_slice(self.witness_policy_digest.as_bytes());
        output.extend_from_slice(self.witness_set_digest.as_bytes());
        output.extend_from_slice(self.approver_set_digest.as_bytes());
        output.extend_from_slice(self.review_label_set_digest.as_bytes());
        output.extend_from_slice(self.predecessor_checkpoint_digest.as_bytes());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        output.extend_from_slice(self.issuer_owner_id.as_bytes());
        output.extend_from_slice(self.issuer_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.issuer_key_epoch.to_be_bytes());
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/checkpoint/signature");
        self.append_fields(&mut output);
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = Vec::new();
        self.append_fields(&mut output);
        output.extend_from_slice(self.signature.as_bytes());
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_signed(
            "jury-witness-v1/checkpoint/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        if self.schema != 1
            || self.vault_policy_sequence == 0
            || self.witness_policy_revision == 0
            || self.issued_at_ms == 0
            || self.issuer_key_epoch == 0
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for VaultPolicyCheckpointV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultPolicyCheckpointV1")
            .field("vault_id", &self.vault_id)
            .field("vault_policy_sequence", &self.vault_policy_sequence)
            .field("witness_policy_id", &self.witness_policy_id)
            .field("witness_policy_revision", &self.witness_policy_revision)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessContributionEnvelopeV1 {
    pub schema: u16,
    pub response_id: ResponseId,
    pub share_index: u8,
    pub share_commitment: Digest32,
    pub capsule_context_digest: Digest32,
    pub capsule_set_digest: Digest32,
    pub request_session_key_fingerprint: Digest32,
    pub encapsulation: Encapsulation1120,
    pub ciphertext: ShareCiphertext49,
}

impl WitnessContributionEnvelopeV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1_332);
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.response_id.as_bytes());
        output.push(self.share_index);
        output.extend_from_slice(self.share_commitment.as_bytes());
        output.extend_from_slice(self.capsule_context_digest.as_bytes());
        output.extend_from_slice(self.capsule_set_digest.as_bytes());
        output.extend_from_slice(self.request_session_key_fingerprint.as_bytes());
        output.extend_from_slice(self.encapsulation.as_bytes());
        output.extend_from_slice(self.ciphertext.as_bytes());
        output
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        if self.schema != 1 || self.share_index == 0 || self.share_index > 32 {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        hash_bytes("jury-witness-v1/contribution/hash", &self.canonical_bytes())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessDecisionV1 {
    pub schema: u16,
    pub response_id: ResponseId,
    pub request_id: RequestId,
    pub request_digest: Digest32,
    pub action_manifest_digest: Digest32,
    pub witness_id: PrincipalId,
    pub witness_signing_key_fingerprint: Digest32,
    pub witness_signing_key_epoch: u64,
    pub witness_policy_id: WitnessPolicyId,
    pub witness_policy_revision: u64,
    pub witness_policy_digest: Digest32,
    pub policy_checkpoint_digest: Digest32,
    pub state_generation: u64,
    pub decision: WitnessDecisionKindV1,
    pub reason: WitnessReasonV1,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub contribution_digest: Option<Digest32>,
    pub share_index: Option<u8>,
    pub share_commitment: Option<Digest32>,
    pub signature: Signature64,
}

impl WitnessDecisionV1 {
    fn append_fields(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.response_id.as_bytes());
        output.extend_from_slice(self.request_id.as_bytes());
        output.extend_from_slice(self.request_digest.as_bytes());
        output.extend_from_slice(self.action_manifest_digest.as_bytes());
        output.extend_from_slice(self.witness_id.as_bytes());
        output.extend_from_slice(self.witness_signing_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.witness_signing_key_epoch.to_be_bytes());
        output.extend_from_slice(self.witness_policy_id.as_bytes());
        output.extend_from_slice(&self.witness_policy_revision.to_be_bytes());
        output.extend_from_slice(self.witness_policy_digest.as_bytes());
        output.extend_from_slice(self.policy_checkpoint_digest.as_bytes());
        output.extend_from_slice(&self.state_generation.to_be_bytes());
        output.push(self.decision.tag());
        output.push(self.reason.tag());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        output.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        optional_fixed(
            output,
            self.contribution_digest.as_ref().map(FixedBytes::as_bytes),
        );
        optional_u8(output, self.share_index);
        optional_fixed(
            output,
            self.share_commitment.as_ref().map(FixedBytes::as_bytes),
        );
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/decision/signature");
        self.append_fields(&mut output);
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = Vec::new();
        self.append_fields(&mut output);
        output.extend_from_slice(self.signature.as_bytes());
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_signed(
            "jury-witness-v1/decision/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        let approving = self.decision == WitnessDecisionKindV1::Approve;
        let contribution = self.contribution_digest.is_some()
            && self.share_index.is_some()
            && self.share_commitment.is_some();
        if self.schema != 1
            || self.witness_signing_key_epoch == 0
            || self.witness_policy_revision == 0
            || self.state_generation == 0
            || self.issued_at_ms == 0
            || self.expires_at_ms == 0
            || (approving && self.expires_at_ms <= self.issued_at_ms)
            || approving != contribution
            || (approving && self.reason != WitnessReasonV1::None)
            || (!approving && self.reason == WitnessReasonV1::None)
            || self
                .share_index
                .is_some_and(|index| index == 0 || index > 32)
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for WitnessDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessDecisionV1")
            .field("response_id", &self.response_id)
            .field("request_id", &self.request_id)
            .field("witness_id", &self.witness_id)
            .field("decision", &self.decision)
            .field("reason", &self.reason)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessResponseV1 {
    pub decision: WitnessDecisionV1,
    pub contribution: Option<WitnessContributionEnvelopeV1>,
}

impl WitnessResponseV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        let mut output = self.decision.canonical_bytes()?;
        match (&self.decision.contribution_digest, &self.contribution) {
            (Some(expected), Some(contribution)) if contribution.digest()? == *expected => {
                output.extend_from_slice(&contribution.canonical_bytes());
            }
            (None, None) => {}
            _ => {
                return Err(WitnessProtocolError::new(
                    WitnessProtocolErrorKind::InvalidDigest,
                ));
            }
        }
        if output.len() > MAX_RESPONSE_BYTES {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::CapacityExhausted,
            ));
        }
        Ok(output)
    }
}
