#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VaultHighWatermarkV1 {
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub policy_sequence: u64,
    pub checkpoint_digest: Digest32,
    pub highest_retained_request_expiry_ms: u64,
}

impl VaultHighWatermarkV1 {
    fn canonical_bytes(&self) -> [u8; 112] {
        let mut output = [0_u8; 112];
        output[..32].copy_from_slice(self.vault_id.as_bytes());
        output[32..64].copy_from_slice(self.genesis_fingerprint.as_bytes());
        output[64..72].copy_from_slice(&self.policy_sequence.to_be_bytes());
        output[72..104].copy_from_slice(self.checkpoint_digest.as_bytes());
        output[104..].copy_from_slice(&self.highest_retained_request_expiry_ms.to_be_bytes());
        output
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStateAnchorV1 {
    pub schema: u16,
    pub witness_id: PrincipalId,
    pub witness_signing_key_fingerprint: Digest32,
    pub witness_signing_key_epoch: u64,
    pub state_generation: u64,
    pub database_state_digest: Digest32,
    pub vault_high_watermarks: Vec<VaultHighWatermarkV1>,
    pub replay_retain_through_ms: u64,
    pub last_accepted_wall_time_ms: u64,
    pub predecessor_anchor_digest: Digest32,
    pub issued_at_ms: u64,
    pub signature: Signature64,
}

impl WitnessStateAnchorV1 {
    fn append_fields(&self, output: &mut Vec<u8>) -> Result<(), WitnessProtocolError> {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.witness_id.as_bytes());
        output.extend_from_slice(self.witness_signing_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.witness_signing_key_epoch.to_be_bytes());
        output.extend_from_slice(&self.state_generation.to_be_bytes());
        output.extend_from_slice(self.database_state_digest.as_bytes());
        list_fixed(output, &self.vault_high_watermarks, |output, watermark| {
            output.extend_from_slice(&watermark.canonical_bytes())
        })?;
        output.extend_from_slice(&self.replay_retain_through_ms.to_be_bytes());
        output.extend_from_slice(&self.last_accepted_wall_time_ms.to_be_bytes());
        output.extend_from_slice(self.predecessor_anchor_digest.as_bytes());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        Ok(())
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/state-anchor/signature");
        self.append_fields(&mut output)?;
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = Vec::new();
        self.append_fields(&mut output)?;
        output.extend_from_slice(self.signature.as_bytes());
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_signed(
            "jury-witness-v1/state-anchor/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        if self.schema != 1
            || self.witness_signing_key_epoch == 0
            || self.state_generation == 0
            || self.issued_at_ms == 0
            || !strictly_sorted_unique(&self.vault_high_watermarks, |left, right| {
                left.vault_id < right.vault_id
            })
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for WitnessStateAnchorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessStateAnchorV1")
            .field("witness_id", &self.witness_id)
            .field("state_generation", &self.state_generation)
            .field("vault_count", &self.vault_high_watermarks.len())
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

/// Per-witness evidence that one exact policy checkpoint survived the witness
/// database commit and external-anchor compare-and-swap/readback sequence.
///
/// This is deliberately not an aggregate freshness statement. The embedded
/// signed anchor speaks only for `witness_id` and its own state generation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessCheckpointAcknowledgementV1 {
    pub schema: u16,
    pub witness_id: PrincipalId,
    pub vault_id: VaultId,
    pub checkpoint_digest: Digest32,
    pub vault_policy_sequence: u64,
    pub witness_policy_digest: Digest32,
    pub state_generation: u64,
    pub anchor_digest: Digest32,
    pub exact_anchor: WitnessStateAnchorV1,
}

impl WitnessCheckpointAcknowledgementV1 {
    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        self.exact_anchor.validate_shape()?;
        let anchor_digest = self.exact_anchor.digest()?;
        let matching_watermark = self
            .exact_anchor
            .vault_high_watermarks
            .iter()
            .find(|watermark| watermark.vault_id == self.vault_id)
            .is_some_and(|watermark| {
                watermark.policy_sequence == self.vault_policy_sequence
                    && watermark.checkpoint_digest == self.checkpoint_digest
            });
        if self.schema != 1
            || self.vault_policy_sequence == 0
            || self.state_generation == 0
            || self.witness_id != self.exact_anchor.witness_id
            || self.state_generation != self.exact_anchor.state_generation
            || self.anchor_digest != anchor_digest
            || !matching_watermark
        {
            return Err(invalid_format());
        }
        Ok(())
    }
}

impl fmt::Debug for WitnessCheckpointAcknowledgementV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessCheckpointAcknowledgementV1")
            .field("witness_id", &self.witness_id)
            .field("vault_id", &self.vault_id)
            .field("vault_policy_sequence", &self.vault_policy_sequence)
            .field("state_generation", &self.state_generation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReplayStateV1 {
    Reserved,
    Approved,
    Denied,
    Cancelled,
}

impl ReplayStateV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Reserved => 1,
            Self::Approved => 2,
            Self::Denied => 3,
            Self::Cancelled => 4,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessReplayRecordV1 {
    pub schema: u16,
    pub vault_id: VaultId,
    pub request_id: RequestId,
    pub request_digest: Digest32,
    pub request_message: RequestBytes,
    pub action_manifest_digest: Digest32,
    pub state: ReplayStateV1,
    pub expires_at_ms: u64,
    pub retain_through_ms: u64,
    pub approval_decisions: Vec<ApprovalBytes>,
    pub cancellation: Option<BoundedBytes<{ 48 * 1024 }>>,
    pub witness_response: Option<ResponseBytes>,
}

impl WitnessReplayRecordV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        if self.schema != 1
            || self.retain_through_ms < self.expires_at_ms.saturating_add(REPLAY_RETENTION_MS)
            || self.approval_decisions.len() > MAX_RECORDED_APPROVALS
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        let approvals = self
            .approval_decisions
            .iter()
            .map(|decision| decision.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let mut output = Vec::new();
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.request_id.as_bytes());
        output.extend_from_slice(self.request_digest.as_bytes());
        bytes_field(&mut output, self.request_message.as_bytes())?;
        output.extend_from_slice(self.action_manifest_digest.as_bytes());
        output.push(self.state.tag());
        output.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        output.extend_from_slice(&self.retain_through_ms.to_be_bytes());
        list_bytes(&mut output, &approvals)?;
        optional_bytes(
            &mut output,
            self.cancellation.as_ref().map(BoundedBytes::as_bytes),
        )?;
        optional_bytes(
            &mut output,
            self.witness_response.as_ref().map(BoundedBytes::as_bytes),
        )?;
        Ok(output)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessVaultStateV1 {
    pub schema: u16,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub accepted_registration: RegistrationBytes,
    pub current_checkpoint: BoundedBytes<{ 64 * 1024 }>,
    pub current_policy_material: PolicyMaterialBytes,
}

impl WitnessVaultStateV1 {
    fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        if self.schema != 1 {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        let mut output = Vec::new();
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.genesis_fingerprint.as_bytes());
        bytes_field(&mut output, self.accepted_registration.as_bytes())?;
        bytes_field(&mut output, self.current_checkpoint.as_bytes())?;
        bytes_field(&mut output, self.current_policy_material.as_bytes())?;
        Ok(output)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessDatabaseStateV1 {
    pub schema: u16,
    pub witness_id: PrincipalId,
    pub state_generation: u64,
    pub vault_states: Vec<WitnessVaultStateV1>,
    pub replay_records: Vec<WitnessReplayRecordV1>,
    pub last_accepted_wall_time_ms: u64,
}

impl WitnessDatabaseStateV1 {
    pub fn canonical_body(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        if self.schema != 1
            || !strictly_sorted_unique(&self.vault_states, |left, right| {
                left.vault_id < right.vault_id
            })
            || !strictly_sorted_unique(&self.replay_records, |left, right| {
                (&left.vault_id, &left.request_id) < (&right.vault_id, &right.request_id)
            })
            || self.replay_records.len() > MAX_REPLAY_RECORDS_PER_SERVICE
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidOrdering,
            ));
        }
        let vaults = self
            .vault_states
            .iter()
            .map(WitnessVaultStateV1::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        let records = self
            .replay_records
            .iter()
            .map(WitnessReplayRecordV1::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        let mut output = Vec::new();
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.witness_id.as_bytes());
        output.extend_from_slice(&self.state_generation.to_be_bytes());
        list_bytes(&mut output, &vaults)?;
        list_bytes(&mut output, &records)?;
        output.extend_from_slice(&self.last_accepted_wall_time_ms.to_be_bytes());
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_bytes(
            "jury-witness-v1/database-state/hash",
            &self.canonical_body()?,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRefusalV1 {
    pub schema: u16,
    pub reason: WitnessReasonV1,
    pub request_id: Option<RequestId>,
    pub vault_id: Option<VaultId>,
    pub witness_id: Option<PrincipalId>,
}

impl ProtocolRefusalV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        if self.schema != 1 || self.reason == WitnessReasonV1::None {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        let mut output = self.schema.to_be_bytes().to_vec();
        output.push(self.reason.tag());
        optional_fixed(
            &mut output,
            self.request_id.as_ref().map(RequestId::as_bytes),
        );
        optional_fixed(&mut output, self.vault_id.as_ref().map(VaultId::as_bytes));
        optional_fixed(
            &mut output,
            self.witness_id.as_ref().map(PrincipalId::as_bytes),
        );
        Ok(output)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WitnessRotationReasonV1 {
    WitnessMembership,
    WitnessThreshold,
    ShareIndex,
    ContributionKey,
    Construction,
    Suite,
    WitnessSigningKey,
    ApproverRuleOrLabel,
    DirectMode,
}

impl WitnessRotationReasonV1 {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::WitnessMembership => 1,
            Self::WitnessThreshold => 2,
            Self::ShareIndex => 3,
            Self::ContributionKey => 4,
            Self::Construction => 5,
            Self::Suite => 6,
            Self::WitnessSigningKey => 7,
            Self::ApproverRuleOrLabel => 8,
            Self::DirectMode => 9,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRotationItemV1 {
    pub item_id: ItemId,
    pub prior_key_epoch: u64,
    pub next_key_epoch: u64,
    pub next_descriptor_revision: u64,
    pub next_descriptor_revision_seal_id: RevisionSealId,
    pub next_descriptor_capsule_set_digest: Digest32,
    pub next_body_revision: u64,
    pub next_body_revision_seal_id: RevisionSealId,
    pub next_body_capsule_set_digest: Digest32,
}

impl WitnessRotationItemV1 {
    fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        if self.prior_key_epoch == 0
            || self.next_key_epoch != self.prior_key_epoch.saturating_add(1)
            || self.next_descriptor_revision == 0
            || self.next_body_revision == 0
        {
            return Err(invalid_format());
        }
        let mut output = Vec::with_capacity(192);
        output.extend_from_slice(self.item_id.as_bytes());
        output.extend_from_slice(&self.prior_key_epoch.to_be_bytes());
        output.extend_from_slice(&self.next_key_epoch.to_be_bytes());
        output.extend_from_slice(&self.next_descriptor_revision.to_be_bytes());
        output.extend_from_slice(self.next_descriptor_revision_seal_id.as_bytes());
        output.extend_from_slice(self.next_descriptor_capsule_set_digest.as_bytes());
        output.extend_from_slice(&self.next_body_revision.to_be_bytes());
        output.extend_from_slice(self.next_body_revision_seal_id.as_bytes());
        output.extend_from_slice(self.next_body_capsule_set_digest.as_bytes());
        Ok(output)
    }
}

/// Owner-signed proof that a witness-policy change was paired with complete
/// fresh item epochs and capsule sets.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessPolicyRotationV1 {
    pub schema: u16,
    pub rotation_id: RotationId,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub prior_vault_policy_sequence: u64,
    pub prior_vault_policy_hash: Digest32,
    pub next_vault_policy_sequence: u64,
    pub next_vault_policy_hash: Digest32,
    pub prior_witness_policy_id: WitnessPolicyId,
    pub prior_witness_policy_revision: u64,
    pub prior_witness_policy_digest: Digest32,
    pub next_witness_policy_id: WitnessPolicyId,
    pub next_witness_policy_revision: u64,
    pub next_witness_policy_digest: Digest32,
    pub reason: WitnessRotationReasonV1,
    pub affected_items: Vec<WitnessRotationItemV1>,
    pub issued_at_ms: u64,
    pub owner_id: PrincipalId,
    pub owner_key_fingerprint: Digest32,
    pub owner_key_epoch: u64,
    pub signature: Signature64,
}

impl WitnessPolicyRotationV1 {
    fn append_fields(&self, output: &mut Vec<u8>) -> Result<(), WitnessProtocolError> {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.rotation_id.as_bytes());
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.genesis_fingerprint.as_bytes());
        output.extend_from_slice(&self.prior_vault_policy_sequence.to_be_bytes());
        output.extend_from_slice(self.prior_vault_policy_hash.as_bytes());
        output.extend_from_slice(&self.next_vault_policy_sequence.to_be_bytes());
        output.extend_from_slice(self.next_vault_policy_hash.as_bytes());
        output.extend_from_slice(self.prior_witness_policy_id.as_bytes());
        output.extend_from_slice(&self.prior_witness_policy_revision.to_be_bytes());
        output.extend_from_slice(self.prior_witness_policy_digest.as_bytes());
        output.extend_from_slice(self.next_witness_policy_id.as_bytes());
        output.extend_from_slice(&self.next_witness_policy_revision.to_be_bytes());
        output.extend_from_slice(self.next_witness_policy_digest.as_bytes());
        output.push(self.reason.tag());
        let items = self
            .affected_items
            .iter()
            .map(WitnessRotationItemV1::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        list_bytes(output, &items)?;
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        output.extend_from_slice(self.owner_id.as_bytes());
        output.extend_from_slice(self.owner_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.owner_key_epoch.to_be_bytes());
        Ok(())
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/rotation/signature");
        self.append_fields(&mut output)?;
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        let mut output = Vec::new();
        self.append_fields(&mut output)?;
        self.validate_shape()?;
        output.extend_from_slice(self.signature.as_bytes());
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_signed(
            "jury-witness-v1/rotation/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        if self.schema != 1
            || self.prior_vault_policy_sequence == 0
            || self.next_vault_policy_sequence != self.prior_vault_policy_sequence.saturating_add(1)
            || self.prior_witness_policy_revision == 0
            || self.next_witness_policy_revision == 0
            || self.affected_items.is_empty()
            || self.affected_items.len() > MAX_ROTATION_ITEMS
            || !strictly_sorted_unique(&self.affected_items, |left, right| {
                left.item_id < right.item_id
            })
            || self.issued_at_ms == 0
            || self.owner_key_epoch == 0
        {
            return Err(invalid_format());
        }
        for item in &self.affected_items {
            item.canonical_bytes()?;
        }
        Ok(())
    }
}

impl fmt::Debug for WitnessPolicyRotationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessPolicyRotationV1")
            .field("rotation_id", &self.rotation_id)
            .field("vault_id", &self.vault_id)
            .field("reason", &self.reason)
            .field("affected_item_count", &self.affected_items.len())
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

/// Owner-signed replacement record for a witness that cannot prove replay
/// continuity. It authorizes only the new identity and never revives the old
/// service state.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRecoveryV1 {
    pub schema: u16,
    pub recovery_id: RecoveryId,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub unavailable_prior_witness_id: Option<PrincipalId>,
    pub new_witness_descriptor: WitnessDescriptorBytes,
    pub new_registration_digest: Digest32,
    pub prior_checkpoint_digest: Digest32,
    pub next_checkpoint_digest: Digest32,
    pub rotation_record_digest: Digest32,
    pub statement: u8,
    pub issued_at_ms: u64,
    pub owner_id: PrincipalId,
    pub owner_key_fingerprint: Digest32,
    pub owner_key_epoch: u64,
    pub signature: Signature64,
}

impl WitnessRecoveryV1 {
    fn append_fields(&self, output: &mut Vec<u8>) -> Result<(), WitnessProtocolError> {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.recovery_id.as_bytes());
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.genesis_fingerprint.as_bytes());
        optional_fixed(
            output,
            self.unavailable_prior_witness_id
                .as_ref()
                .map(PrincipalId::as_bytes),
        );
        bytes_field(output, self.new_witness_descriptor.as_bytes())?;
        output.extend_from_slice(self.new_registration_digest.as_bytes());
        output.extend_from_slice(self.prior_checkpoint_digest.as_bytes());
        output.extend_from_slice(self.next_checkpoint_digest.as_bytes());
        output.extend_from_slice(self.rotation_record_digest.as_bytes());
        output.push(self.statement);
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        output.extend_from_slice(self.owner_id.as_bytes());
        output.extend_from_slice(self.owner_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.owner_key_epoch.to_be_bytes());
        Ok(())
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/recovery/signature");
        self.append_fields(&mut output)?;
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = Vec::new();
        self.append_fields(&mut output)?;
        output.extend_from_slice(self.signature.as_bytes());
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_signed(
            "jury-witness-v1/recovery/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        if self.schema != 1
            || self.new_witness_descriptor.is_empty()
            || self.statement != 1
            || self.issued_at_ms == 0
            || self.owner_key_epoch == 0
        {
            return Err(invalid_format());
        }
        Ok(())
    }
}

impl fmt::Debug for WitnessRecoveryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessRecoveryV1")
            .field("recovery_id", &self.recovery_id)
            .field("vault_id", &self.vault_id)
            .field(
                "unavailable_prior_witness_id",
                &self.unavailable_prior_witness_id,
            )
            .field("signature", &"[REDACTED]")
            .finish()
    }
}
