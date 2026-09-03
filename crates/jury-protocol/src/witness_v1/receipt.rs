#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptOutcomeV1 {
    Approved,
    Denied,
}

impl ReceiptOutcomeV1 {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Approved => 1,
            Self::Denied => 2,
        }
    }
}

/// Value-free projection of the request fields that a receipt is permitted to
/// disclose. All fields are recomputed from the signed request preimage during
/// offline verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReceiptScopeV1 {
    pub schema: u16,
    pub request_id: RequestId,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub item_id: ItemId,
    pub key_epoch: u64,
    pub item_access_mode: ItemAccessMode,
    pub slot_id: SlotId,
    pub content_role: ContentRole,
    pub revision: u64,
    pub revision_seal_id: RevisionSealId,
    pub vault_policy_sequence: u64,
    pub vault_policy_hash: Digest32,
    pub witness_policy_id: WitnessPolicyId,
    pub witness_policy_revision: u64,
    pub witness_policy_digest: Digest32,
    pub requester_principal_id: PrincipalId,
    pub requested_access_role: AccessRole,
    pub operation: WitnessOperationV1,
    pub approval_target_digest: Digest32,
    pub action_manifest_digest: Digest32,
    pub workload_digest: Digest32,
    pub issued_at_ms: u64,
    pub not_before_ms: Option<u64>,
    pub expires_at_ms: u64,
}

impl PublicReceiptScopeV1 {
    #[must_use]
    pub fn from_request(request: &WitnessRequestV1) -> Self {
        Self {
            schema: 1,
            request_id: request.request_id,
            vault_id: request.vault_id,
            genesis_fingerprint: request.genesis_fingerprint.clone(),
            item_id: request.item_id,
            key_epoch: request.key_epoch,
            item_access_mode: request.item_access_mode,
            slot_id: request.slot_id,
            content_role: request.content_role,
            revision: request.revision,
            revision_seal_id: request.revision_seal_id,
            vault_policy_sequence: request.vault_policy_sequence,
            vault_policy_hash: request.vault_policy_hash.clone(),
            witness_policy_id: request.witness_policy_id,
            witness_policy_revision: request.witness_policy_revision,
            witness_policy_digest: request.witness_policy_digest.clone(),
            requester_principal_id: request.requester_principal_id,
            requested_access_role: request.requested_access_role,
            operation: request.operation,
            approval_target_digest: request.approval_target_digest.clone(),
            action_manifest_digest: request.action_manifest_digest.clone(),
            workload_digest: request.workload_digest.clone(),
            issued_at_ms: request.issued_at_ms,
            not_before_ms: request.not_before_ms,
            expires_at_ms: request.expires_at_ms,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        if self.schema != 1
            || self.key_epoch == 0
            || self.revision == 0
            || self.vault_policy_sequence == 0
            || self.witness_policy_revision == 0
            || !matches!(
                self.item_access_mode,
                ItemAccessMode::WitnessedOnly | ItemAccessMode::Mixed
            )
            || !valid_interval(self.issued_at_ms, self.not_before_ms, self.expires_at_ms)
        {
            return Err(invalid_format());
        }
        let mut output = Vec::new();
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.request_id.as_bytes());
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.genesis_fingerprint.as_bytes());
        output.extend_from_slice(self.item_id.as_bytes());
        output.extend_from_slice(&self.key_epoch.to_be_bytes());
        output.push(self.item_access_mode.tag());
        output.extend_from_slice(self.slot_id.as_bytes());
        output.push(self.content_role.tag());
        output.extend_from_slice(&self.revision.to_be_bytes());
        output.extend_from_slice(self.revision_seal_id.as_bytes());
        output.extend_from_slice(&self.vault_policy_sequence.to_be_bytes());
        output.extend_from_slice(self.vault_policy_hash.as_bytes());
        output.extend_from_slice(self.witness_policy_id.as_bytes());
        output.extend_from_slice(&self.witness_policy_revision.to_be_bytes());
        output.extend_from_slice(self.witness_policy_digest.as_bytes());
        output.extend_from_slice(self.requester_principal_id.as_bytes());
        output.push(self.requested_access_role.tag());
        output.push(self.operation.tag());
        output.extend_from_slice(self.approval_target_digest.as_bytes());
        output.extend_from_slice(self.action_manifest_digest.as_bytes());
        output.extend_from_slice(self.workload_digest.as_bytes());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        optional_u64(&mut output, self.not_before_ms);
        output.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        Ok(output)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptAcknowledgementV1 {
    pub schema: u16,
    pub receipt_id: ReceiptId,
    pub receipt_core_digest: Digest32,
    pub request_digest: Digest32,
    pub endpoint_principal_id: PrincipalId,
    pub endpoint_key_fingerprint: Digest32,
    pub endpoint_key_epoch: u64,
    pub started_at_ms: u64,
    pub signature: Signature64,
}

impl ReceiptAcknowledgementV1 {
    fn append_fields(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.receipt_id.as_bytes());
        output.extend_from_slice(self.receipt_core_digest.as_bytes());
        output.extend_from_slice(self.request_digest.as_bytes());
        output.extend_from_slice(self.endpoint_principal_id.as_bytes());
        output.extend_from_slice(self.endpoint_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.endpoint_key_epoch.to_be_bytes());
        output.extend_from_slice(&self.started_at_ms.to_be_bytes());
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/receipt/acknowledgement");
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
            "jury-witness-v1/receipt/acknowledgement/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        if self.schema != 1 || self.endpoint_key_epoch == 0 || self.started_at_ms == 0 {
            return Err(invalid_format());
        }
        Ok(())
    }
}

impl fmt::Debug for ReceiptAcknowledgementV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiptAcknowledgementV1")
            .field("receipt_id", &self.receipt_id)
            .field("endpoint_principal_id", &self.endpoint_principal_id)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptCompletionV1 {
    pub schema: u16,
    pub receipt_id: ReceiptId,
    pub receipt_core_digest: Digest32,
    pub acknowledgement_digest: Option<Digest32>,
    pub endpoint_principal_id: PrincipalId,
    pub endpoint_key_fingerprint: Digest32,
    pub endpoint_key_epoch: u64,
    pub outcome: ReceiptOutcomeV1,
    pub reason: WitnessReasonV1,
    pub completed_at_ms: u64,
    pub signature: Signature64,
}

impl ReceiptCompletionV1 {
    fn append_fields(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.receipt_id.as_bytes());
        output.extend_from_slice(self.receipt_core_digest.as_bytes());
        optional_fixed(
            output,
            self.acknowledgement_digest
                .as_ref()
                .map(FixedBytes::as_bytes),
        );
        output.extend_from_slice(self.endpoint_principal_id.as_bytes());
        output.extend_from_slice(self.endpoint_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.endpoint_key_epoch.to_be_bytes());
        output.push(self.outcome.tag());
        output.push(self.reason.tag());
        output.extend_from_slice(&self.completed_at_ms.to_be_bytes());
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/receipt/completion");
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
            "jury-witness-v1/receipt/completion/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        let outcome_matches = match self.outcome {
            ReceiptOutcomeV1::Approved => self.reason == WitnessReasonV1::None,
            ReceiptOutcomeV1::Denied => self.reason != WitnessReasonV1::None,
        };
        if self.schema != 1
            || self.endpoint_key_epoch == 0
            || self.completed_at_ms == 0
            || !outcome_matches
        {
            return Err(invalid_format());
        }
        Ok(())
    }
}

impl fmt::Debug for ReceiptCompletionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiptCompletionV1")
            .field("receipt_id", &self.receipt_id)
            .field("endpoint_principal_id", &self.endpoint_principal_id)
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

/// Complete portable receipt assembled from already signed public evidence.
/// It intentionally contains no contribution envelope or presentation bytes.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessReceiptV1 {
    pub schema: u16,
    pub receipt_id: ReceiptId,
    pub request_signature_preimage: RequestBytes,
    pub client_signature: Signature64,
    pub request_digest: Digest32,
    pub action_manifest_digest: Digest32,
    pub presentation_digest: Digest32,
    pub public_scope: PublicReceiptScopeV1,
    pub approval_decisions: Vec<ApprovalDecisionV1>,
    pub witness_decisions: Vec<WitnessDecisionV1>,
    pub policy_checkpoint: VaultPolicyCheckpointV1,
    pub witness_policy_material: PolicyMaterialBytes,
    pub approval_threshold: u8,
    pub witness_threshold: u8,
    pub counted_approver_ids: Vec<PrincipalId>,
    pub counted_witness_ids: Vec<PrincipalId>,
    pub outcome: ReceiptOutcomeV1,
    pub reason: WitnessReasonV1,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub endpoint_acknowledgement: Option<ReceiptAcknowledgementV1>,
    pub endpoint_completion: Option<ReceiptCompletionV1>,
}

impl WitnessReceiptV1 {
    fn core_bytes_unchecked(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        let approvals = self
            .approval_decisions
            .iter()
            .map(ApprovalDecisionV1::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        let decisions = self
            .witness_decisions
            .iter()
            .map(WitnessDecisionV1::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        let checkpoint = self.policy_checkpoint.canonical_bytes()?;
        let public_scope = self.public_scope.canonical_bytes()?;
        let mut output = Vec::new();
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.receipt_id.as_bytes());
        bytes_field(&mut output, self.request_signature_preimage.as_bytes())?;
        output.extend_from_slice(self.client_signature.as_bytes());
        output.extend_from_slice(self.request_digest.as_bytes());
        output.extend_from_slice(self.action_manifest_digest.as_bytes());
        output.extend_from_slice(self.presentation_digest.as_bytes());
        bytes_field(&mut output, &public_scope)?;
        list_bytes(&mut output, &approvals)?;
        list_bytes(&mut output, &decisions)?;
        bytes_field(&mut output, &checkpoint)?;
        bytes_field(&mut output, self.witness_policy_material.as_bytes())?;
        output.push(self.approval_threshold);
        output.push(self.witness_threshold);
        list_fixed(&mut output, &self.counted_approver_ids, |output, id| {
            output.extend_from_slice(id.as_bytes());
        })?;
        list_fixed(&mut output, &self.counted_witness_ids, |output, id| {
            output.extend_from_slice(id.as_bytes());
        })?;
        output.push(self.outcome.tag());
        output.push(self.reason.tag());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        output.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        Ok(output)
    }

    pub fn core_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validated_core().map(|(bytes, _)| bytes)
    }

    pub fn core_digest(&self) -> Result<Digest32, WitnessProtocolError> {
        self.validated_core().map(|(_, digest)| digest)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        let (mut output, _) = self.validated_core()?;
        self.append_endpoint_records(&mut output)?;
        Ok(output)
    }

    fn append_endpoint_records(&self, output: &mut Vec<u8>) -> Result<(), WitnessProtocolError> {
        let acknowledgement = self
            .endpoint_acknowledgement
            .as_ref()
            .map(ReceiptAcknowledgementV1::canonical_bytes)
            .transpose()?;
        let completion = self
            .endpoint_completion
            .as_ref()
            .map(ReceiptCompletionV1::canonical_bytes)
            .transpose()?;
        optional_bytes(output, acknowledgement.as_deref())?;
        optional_bytes(output, completion.as_deref())?;
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        self.validated_digests().map(|(_, digest)| digest)
    }

    /// Validates and encodes the receipt once, returning `(core, complete)`
    /// digests. Verification paths use this method to avoid repeatedly
    /// serializing maximum-size embedded policy material.
    pub fn validated_digests(&self) -> Result<(Digest32, Digest32), WitnessProtocolError> {
        let (mut complete, core_digest) = self.validated_core()?;
        self.append_endpoint_records(&mut complete)?;
        let complete_digest = hash_bytes("jury-witness-v1/receipt/hash", &complete)?;
        Ok((core_digest, complete_digest))
    }

    pub fn parse_json(bytes: &[u8]) -> Result<Self, WitnessProtocolError> {
        crate::artifact::validate_json_input(bytes, MAX_RECEIPT_JSON_BYTES)
            .map_err(|_| invalid_format())?;
        let receipt: Self =
            crate::artifact::deserialize_json(bytes).map_err(|_| invalid_format())?;
        receipt.validate_shape()?;
        Ok(receipt)
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        crate::artifact::pretty_json_bytes(self, MAX_RECEIPT_JSON_BYTES)
            .map_err(|_| WitnessProtocolError::new(WitnessProtocolErrorKind::CapacityExhausted))
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        self.validated_core().map(|_| ())
    }

    fn validated_core(&self) -> Result<(Vec<u8>, Digest32), WitnessProtocolError> {
        let outcome_matches = match self.outcome {
            ReceiptOutcomeV1::Approved => self.reason == WitnessReasonV1::None,
            ReceiptOutcomeV1::Denied => self.reason != WitnessReasonV1::None,
        };
        if self.schema != 1
            || self.request_signature_preimage.is_empty()
            || self.witness_policy_material.is_empty()
            || usize::from(self.approval_threshold) > MAX_POLICY_ACTORS
            || !(2..=u8::try_from(MAX_POLICY_ACTORS).unwrap_or(u8::MAX))
                .contains(&self.witness_threshold)
            || self.approval_decisions.len() > MAX_RECORDED_APPROVALS
            || self.witness_decisions.len() > MAX_POLICY_ACTORS
            || self.counted_approver_ids.len() > MAX_POLICY_ACTORS
            || self.counted_witness_ids.len() > MAX_POLICY_ACTORS
            || !strictly_sorted_unique(&self.approval_decisions, |left, right| {
                left.approver_id < right.approver_id
            })
            || !strictly_sorted_unique(&self.witness_decisions, |left, right| {
                left.witness_id < right.witness_id
            })
            || !strictly_sorted_unique(&self.counted_approver_ids, |left, right| left < right)
            || !strictly_sorted_unique(&self.counted_witness_ids, |left, right| left < right)
            || self.issued_at_ms == 0
            || self.expires_at_ms == 0
            || (self.outcome == ReceiptOutcomeV1::Approved
                && self.expires_at_ms <= self.issued_at_ms)
            || !outcome_matches
        {
            return Err(invalid_format());
        }
        let core_bytes = self.core_bytes_unchecked()?;
        let core_digest = hash_bytes("jury-witness-v1/receipt/core-hash", &core_bytes)?;
        if let Some(acknowledgement) = &self.endpoint_acknowledgement {
            acknowledgement.validate_shape()?;
            if acknowledgement.receipt_id != self.receipt_id
                || acknowledgement.receipt_core_digest != core_digest
                || acknowledgement.request_digest != self.request_digest
            {
                return Err(WitnessProtocolError::new(
                    WitnessProtocolErrorKind::InvalidDigest,
                ));
            }
        }
        if let Some(completion) = &self.endpoint_completion {
            completion.validate_shape()?;
            let acknowledgement_digest = self
                .endpoint_acknowledgement
                .as_ref()
                .map(ReceiptAcknowledgementV1::digest)
                .transpose()?;
            if completion.receipt_id != self.receipt_id
                || completion.receipt_core_digest != core_digest
                || completion.acknowledgement_digest != acknowledgement_digest
                || completion.outcome != self.outcome
                || completion.reason != self.reason
            {
                return Err(WitnessProtocolError::new(
                    WitnessProtocolErrorKind::InvalidDigest,
                ));
            }
        }
        Ok((core_bytes, core_digest))
    }
}

impl fmt::Debug for WitnessReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessReceiptV1")
            .field("receipt_id", &self.receipt_id)
            .field("request_id", &self.public_scope.request_id)
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .field("approval_count", &self.approval_decisions.len())
            .field("witness_decision_count", &self.witness_decisions.len())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessReceiptMaterialV1 {
    pub schema: u16,
    pub receipt_id: ReceiptId,
    pub request_digest: Digest32,
    pub action_manifest_digest: Digest32,
    pub presentation_digest: Digest32,
    pub policy_checkpoint_digest: Digest32,
    pub witness_policy_digest: Digest32,
    pub approval_threshold: u8,
    pub witness_threshold: u8,
    pub counted_approver_ids: Vec<PrincipalId>,
    pub counted_witness_ids: Vec<PrincipalId>,
    pub reason: WitnessReasonV1,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl WitnessReceiptMaterialV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        if self.schema != 1
            || usize::from(self.approval_threshold) > MAX_POLICY_ACTORS
            || self.witness_threshold < 2
            || usize::from(self.witness_threshold) > MAX_POLICY_ACTORS
            || self.counted_approver_ids.len() > MAX_POLICY_ACTORS
            || self.counted_witness_ids.len() > MAX_POLICY_ACTORS
            || self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
            || !strictly_sorted_unique(&self.counted_approver_ids, |left, right| left < right)
            || !strictly_sorted_unique(&self.counted_witness_ids, |left, right| left < right)
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        let mut output = Vec::new();
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.receipt_id.as_bytes());
        output.extend_from_slice(self.request_digest.as_bytes());
        output.extend_from_slice(self.action_manifest_digest.as_bytes());
        output.extend_from_slice(self.presentation_digest.as_bytes());
        output.extend_from_slice(self.policy_checkpoint_digest.as_bytes());
        output.extend_from_slice(self.witness_policy_digest.as_bytes());
        output.push(self.approval_threshold);
        output.push(self.witness_threshold);
        list_fixed(&mut output, &self.counted_approver_ids, |output, id| {
            output.extend_from_slice(id.as_bytes());
        })?;
        list_fixed(&mut output, &self.counted_witness_ids, |output, id| {
            output.extend_from_slice(id.as_bytes());
        })?;
        output.push(self.reason.tag());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        output.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        Ok(output)
    }
}
