impl ActionManifestV1 {
    pub fn canonical_body(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let context = self.operation_context.canonical_bytes()?;
        let target = self.approval_target.canonical_bytes()?;
        let arguments = self
            .arguments
            .iter()
            .map(ManifestArgumentV1::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        let environment = self
            .environment_injections
            .iter()
            .map(EnvironmentInjectionV1::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
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
        bytes_field(&mut output, &context)?;
        bytes_field(&mut output, &target)?;
        output.extend_from_slice(self.approval_target_digest.as_bytes());
        optional_bytes(
            &mut output,
            self.executable_identity
                .as_ref()
                .map(BoundedBytes::as_bytes),
        )?;
        list_bytes(&mut output, &arguments)?;
        optional_fixed(
            &mut output,
            self.working_directory_commitment
                .as_ref()
                .map(FixedBytes::as_bytes),
        );
        list_bytes(&mut output, &environment)?;
        optional_bytes(
            &mut output,
            self.stdin_target
                .as_ref()
                .map(WitnessTargetV1::canonical_bytes)
                .as_deref(),
        )?;
        output.push(self.stdin_mode.tag());
        output.push(self.output_sink.tag());
        optional_fixed(
            &mut output,
            self.output_sink_commitment
                .as_ref()
                .map(FixedBytes::as_bytes),
        );
        output.push(self.platform_assurance.tag());
        output.extend_from_slice(&self.timeout_ms.to_be_bytes());
        output.extend_from_slice(&self.output_limit_bytes.to_be_bytes());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        optional_u64(&mut output, self.not_before_ms);
        output.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        output.extend_from_slice(self.presentation_digest.as_bytes());
        if output.len() > MAX_MANIFEST_BYTES {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::CapacityExhausted,
            ));
        }
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_bytes(
            "jury-witness-v1/action-manifest/hash",
            &self.canonical_body()?,
        )
    }

    pub fn workload_digest(&self) -> Result<Digest32, WitnessProtocolError> {
        self.validate_shape()?;
        let context = self.operation_context.canonical_bytes()?;
        let arguments = self
            .arguments
            .iter()
            .map(ManifestArgumentV1::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        let environment = self
            .environment_injections
            .iter()
            .map(EnvironmentInjectionV1::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        let mut output = jce("jury-witness-v1/workload/hash");
        output.push(self.operation.tag());
        bytes_field(&mut output, &context)?;
        optional_bytes(
            &mut output,
            self.executable_identity
                .as_ref()
                .map(BoundedBytes::as_bytes),
        )?;
        list_bytes(&mut output, &arguments)?;
        optional_fixed(
            &mut output,
            self.working_directory_commitment
                .as_ref()
                .map(FixedBytes::as_bytes),
        );
        list_bytes(&mut output, &environment)?;
        optional_bytes(
            &mut output,
            self.stdin_target
                .as_ref()
                .map(WitnessTargetV1::canonical_bytes)
                .as_deref(),
        )?;
        output.push(self.stdin_mode.tag());
        output.push(self.output_sink.tag());
        optional_fixed(
            &mut output,
            self.output_sink_commitment
                .as_ref()
                .map(FixedBytes::as_bytes),
        );
        output.push(self.platform_assurance.tag());
        output.extend_from_slice(&self.timeout_ms.to_be_bytes());
        output.extend_from_slice(&self.output_limit_bytes.to_be_bytes());
        Ok(digest(&output))
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        if self.schema != 1
            || self.key_epoch == 0
            || self.revision == 0
            || self.vault_policy_sequence == 0
            || self.witness_policy_revision == 0
            || !matches!(
                self.item_access_mode,
                ItemAccessMode::WitnessedOnly | ItemAccessMode::Mixed
            )
            || self.operation != self.operation_context.operation()
            || self.approval_target_digest != self.approval_target.digest()?
            || self.presentation_digest != self.approval_target.presentation_digest
            || self.arguments.len() > MAX_ARGUMENTS
            || self.environment_injections.len() > MAX_ENVIRONMENT_NAMES
            || !valid_interval(self.issued_at_ms, self.not_before_ms, self.expires_at_ms)
            || self
                .approval_target
                .entries
                .iter()
                .any(|entry| entry.item_id != self.item_id)
            || (self.content_role == ContentRole::Descriptor
                && self
                    .approval_target
                    .entries
                    .iter()
                    .any(|entry| entry.field_id.is_some()))
            || self
                .environment_injections
                .iter()
                .any(|entry| !entry.valid_name())
            || !strictly_sorted_unique(&self.environment_injections, |left, right| {
                left.name.as_bytes() < right.name.as_bytes()
            })
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        self.validate_workload_shape()
    }

    fn validate_workload_shape(&self) -> Result<(), WitnessProtocolError> {
        let no_child = self.executable_identity.is_none()
            && self.arguments.is_empty()
            && self.working_directory_commitment.is_none()
            && self.environment_injections.is_empty()
            && self.stdin_target.is_none()
            && self.stdin_mode == StdinModeV1::None;
        let secret_arguments_match = self.arguments.iter().all(|argument| match argument {
            ManifestArgumentV1::PublicLiteral { .. } => true,
            ManifestArgumentV1::SecretPlaceholder { target } => self.target_is_approved(target),
        });
        let environment_matches = self
            .environment_injections
            .iter()
            .all(|entry| self.target_is_approved(&entry.target));
        let sink_shape = match self.output_sink {
            OutputSinkV1::PrivateFile => self.output_sink_commitment.is_some(),
            OutputSinkV1::Stdout
            | OutputSinkV1::ChildStdin
            | OutputSinkV1::ChildEnvironment
            | OutputSinkV1::None => self.output_sink_commitment.is_none(),
        };
        let valid = match self.operation {
            WitnessOperationV1::ReadStdout => {
                no_child
                    && self.output_sink == OutputSinkV1::Stdout
                    && self.output_sink_commitment.is_none()
            }
            WitnessOperationV1::WritePrivateFile => {
                no_child
                    && self.output_sink == OutputSinkV1::PrivateFile
                    && self.output_sink_commitment.is_some()
            }
            WitnessOperationV1::TemplateInjection => {
                self.executable_identity.is_some()
                    && !self.arguments.is_empty()
                    && self.working_directory_commitment.is_some()
                    && self.environment_injections.is_empty()
                    && self.stdin_target.is_none()
                    && self.stdin_mode == StdinModeV1::None
                    && self.output_sink != OutputSinkV1::None
                    && sink_shape
                    && secret_arguments_match
                    && self.arguments.iter().any(|argument| {
                        matches!(argument, ManifestArgumentV1::SecretPlaceholder { .. })
                    })
            }
            WitnessOperationV1::ChildEnvironment => {
                self.executable_identity.is_some()
                    && !self.arguments.is_empty()
                    && !self.environment_injections.is_empty()
                    && self.stdin_target.is_none()
                    && self.stdin_mode == StdinModeV1::None
                    && self.output_sink != OutputSinkV1::None
                    && sink_shape
                    && secret_arguments_match
                    && environment_matches
            }
            WitnessOperationV1::ChildStdin => {
                self.executable_identity.is_some()
                    && !self.arguments.is_empty()
                    && self.approval_target.entries.len() == 1
                    && self.environment_injections.is_empty()
                    && self
                        .stdin_target
                        .as_ref()
                        .is_some_and(|target| self.target_is_approved(target))
                    && self.stdin_mode == StdinModeV1::SecretBytes
                    && self.output_sink != OutputSinkV1::None
                    && sink_shape
                    && secret_arguments_match
            }
            WitnessOperationV1::ItemMutation => {
                let context_matches = match &self.operation_context {
                    OperationContextV1::ItemMutation {
                        mutation_kind,
                        affected_field_ids,
                        ..
                    } => {
                        let target_fields = self
                            .approval_target
                            .entries
                            .iter()
                            .filter_map(|entry| entry.field_id)
                            .collect::<Vec<_>>();
                        affected_field_ids == &target_fields
                            && (matches!(mutation_kind, 1 | 4) == affected_field_ids.is_empty())
                    }
                    _ => false,
                };
                no_child
                    && self.output_sink == OutputSinkV1::None
                    && self.output_sink_commitment.is_none()
                    && context_matches
            }
            WitnessOperationV1::Backup => {
                let context_matches = match &self.operation_context {
                    OperationContextV1::Backup {
                        destination_commitment,
                        ..
                    } => self.output_sink_commitment.as_ref() == Some(destination_commitment),
                    _ => false,
                };
                no_child
                    && self.approval_target.entries.len() == 1
                    && self.approval_target.entries[0].field_id.is_none()
                    && self.output_sink == OutputSinkV1::PrivateFile
                    && context_matches
            }
            WitnessOperationV1::Recovery => {
                let context_matches = match &self.operation_context {
                    OperationContextV1::Recovery {
                        destination_commitment,
                        ..
                    } => self.output_sink_commitment.as_ref() == Some(destination_commitment),
                    _ => false,
                };
                no_child
                    && self.approval_target.entries.len() == 1
                    && self.approval_target.entries[0].field_id.is_none()
                    && self.output_sink == OutputSinkV1::PrivateFile
                    && context_matches
            }
            WitnessOperationV1::AdministrativeRekey => {
                no_child
                    && self.approval_target.entries.len() == 1
                    && self.approval_target.entries[0].field_id.is_none()
                    && self.output_sink == OutputSinkV1::None
                    && self.output_sink_commitment.is_none()
            }
        };
        if !valid {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidScope,
            ));
        }
        Ok(())
    }

    fn target_is_approved(&self, target: &WitnessTargetV1) -> bool {
        self.approval_target
            .entries
            .iter()
            .any(|entry| entry.item_id == target.item_id && entry.field_id == target.field_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntendedWitnessV1 {
    pub witness_id: PrincipalId,
    pub share_index: u8,
    pub signing_key_fingerprint: Digest32,
    pub contribution_key_fingerprint: Digest32,
}

impl IntendedWitnessV1 {
    fn canonical_bytes(&self) -> [u8; 97] {
        let mut output = [0_u8; 97];
        output[..32].copy_from_slice(self.witness_id.as_bytes());
        output[32] = self.share_index;
        output[33..65].copy_from_slice(self.signing_key_fingerprint.as_bytes());
        output[65..].copy_from_slice(self.contribution_key_fingerprint.as_bytes());
        output
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRequestV1 {
    pub schema: u16,
    pub protocol_version: u16,
    pub construction: u16,
    pub request_id: RequestId,
    pub client_nonce: RequestId,
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
    pub policy_checkpoint_digest: Digest32,
    pub witness_policy_id: WitnessPolicyId,
    pub witness_policy_revision: u64,
    pub witness_policy_digest: Digest32,
    pub requester_principal_id: PrincipalId,
    pub requester_signing_key_fingerprint: Digest32,
    pub requester_signing_key_epoch: u64,
    pub requested_access_role: AccessRole,
    pub operation: WitnessOperationV1,
    pub approval_target_digest: Digest32,
    pub action_manifest_digest: Digest32,
    pub workload_digest: Digest32,
    pub issued_at_ms: u64,
    pub not_before_ms: Option<u64>,
    pub expires_at_ms: u64,
    pub request_session_public_key: RecipientPublicKey1216,
    pub request_session_key_fingerprint: Digest32,
    pub intended_witness_set: Vec<IntendedWitnessV1>,
    pub client_signature: Signature64,
}

impl WitnessRequestV1 {
    fn append_fields(&self, output: &mut Vec<u8>) -> Result<(), WitnessProtocolError> {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(&self.protocol_version.to_be_bytes());
        output.extend_from_slice(&self.construction.to_be_bytes());
        output.extend_from_slice(self.request_id.as_bytes());
        output.extend_from_slice(self.client_nonce.as_bytes());
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
        output.extend_from_slice(self.policy_checkpoint_digest.as_bytes());
        output.extend_from_slice(self.witness_policy_id.as_bytes());
        output.extend_from_slice(&self.witness_policy_revision.to_be_bytes());
        output.extend_from_slice(self.witness_policy_digest.as_bytes());
        output.extend_from_slice(self.requester_principal_id.as_bytes());
        output.extend_from_slice(self.requester_signing_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.requester_signing_key_epoch.to_be_bytes());
        output.push(self.requested_access_role.tag());
        output.push(self.operation.tag());
        output.extend_from_slice(self.approval_target_digest.as_bytes());
        output.extend_from_slice(self.action_manifest_digest.as_bytes());
        output.extend_from_slice(self.workload_digest.as_bytes());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        optional_u64(output, self.not_before_ms);
        output.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        output.extend_from_slice(self.request_session_public_key.as_bytes());
        output.extend_from_slice(self.request_session_key_fingerprint.as_bytes());
        list_fixed(output, &self.intended_witness_set, |output, witness| {
            output.extend_from_slice(&witness.canonical_bytes());
        })
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/request/signature");
        self.append_fields(&mut output)?;
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = Vec::new();
        self.append_fields(&mut output)?;
        output.extend_from_slice(self.client_signature.as_bytes());
        if output.len() > MAX_REQUEST_BYTES {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::CapacityExhausted,
            ));
        }
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        let preimage = self.signature_preimage()?;
        hash_signed(
            "jury-witness-v1/request/hash",
            &preimage,
            &self.client_signature,
        )
    }

    pub fn intended_witness_set_digest(&self) -> Result<Digest32, WitnessProtocolError> {
        let mut output = jce("jury-witness-v1/intended-witness-set/hash");
        list_fixed(
            &mut output,
            &self.intended_witness_set,
            |output, witness| output.extend_from_slice(&witness.canonical_bytes()),
        )?;
        Ok(digest(&output))
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        if self.schema != 1
            || self.protocol_version != PROTOCOL_VERSION
            || self.construction != CONSTRUCTION
            || self.key_epoch == 0
            || self.revision == 0
            || self.vault_policy_sequence == 0
            || self.witness_policy_revision == 0
            || self.requester_signing_key_epoch == 0
            || !matches!(
                self.item_access_mode,
                ItemAccessMode::WitnessedOnly | ItemAccessMode::Mixed
            )
            || !valid_interval(self.issued_at_ms, self.not_before_ms, self.expires_at_ms)
            || self.intended_witness_set.len() < 2
            || self.intended_witness_set.len() > MAX_POLICY_ACTORS
            || !strictly_sorted_unique(&self.intended_witness_set, |left, right| {
                left.witness_id < right.witness_id
            })
            || self
                .intended_witness_set
                .iter()
                .any(|entry| entry.share_index == 0 || entry.share_index > 32)
            || self
                .intended_witness_set
                .iter()
                .enumerate()
                .any(|(index, entry)| {
                    self.intended_witness_set[index + 1..].iter().any(|other| {
                        entry.share_index == other.share_index
                            || entry.signing_key_fingerprint == other.signing_key_fingerprint
                            || entry.contribution_key_fingerprint
                                == other.contribution_key_fingerprint
                    })
                })
            || self.request_session_key_fingerprint
                != crate::vault_v1::recipient_public_key_fingerprint(
                    &self.request_session_public_key,
                )
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        Ok(())
    }

    /// Reconstructs the exact typed request carried by a receipt.
    ///
    /// Receipt verification uses this parser instead of trusting a second,
    /// independently supplied projection of the signed request. The parser is
    /// deliberately limited to the frozen v1 signature preimage and rejects
    /// trailing bytes and non-canonical encodings.
    pub fn from_signature_preimage(
        preimage: &[u8],
        client_signature: Signature64,
    ) -> Result<Self, WitnessProtocolError> {
        if preimage.len() > MAX_REQUEST_BYTES {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::CapacityExhausted,
            ));
        }
        let mut input = CanonicalInput::new(preimage);
        input.domain("jury-witness-v1/request/signature")?;
        let schema = input.u16()?;
        let protocol_version = input.u16()?;
        let construction = input.u16()?;
        let request_id = input.identifier(RequestId::from_bytes)?;
        let client_nonce = input.identifier(RequestId::from_bytes)?;
        let vault_id = input.identifier(VaultId::from_bytes)?;
        let genesis_fingerprint = input.fixed()?;
        let item_id = input.identifier(ItemId::from_bytes)?;
        let key_epoch = input.u64()?;
        let item_access_mode = match input.u8()? {
            1 => ItemAccessMode::DirectOnly,
            2 => ItemAccessMode::WitnessedOnly,
            3 => ItemAccessMode::Mixed,
            _ => return Err(invalid_format()),
        };
        let slot_id = input.identifier(SlotId::from_bytes)?;
        let content_role = match input.u8()? {
            1 => ContentRole::Descriptor,
            2 => ContentRole::Body,
            _ => return Err(invalid_format()),
        };
        let revision = input.u64()?;
        let revision_seal_id = input.identifier(RevisionSealId::from_bytes)?;
        let vault_policy_sequence = input.u64()?;
        let vault_policy_hash = input.fixed()?;
        let policy_checkpoint_digest = input.fixed()?;
        let witness_policy_id = input.identifier(WitnessPolicyId::from_bytes)?;
        let witness_policy_revision = input.u64()?;
        let witness_policy_digest = input.fixed()?;
        let requester_principal_id = input.identifier(PrincipalId::from_bytes)?;
        let requester_signing_key_fingerprint = input.fixed()?;
        let requester_signing_key_epoch = input.u64()?;
        let requested_access_role = match input.u8()? {
            1 => AccessRole::Reader,
            2 => AccessRole::Writer,
            3 => AccessRole::Owner,
            _ => return Err(invalid_format()),
        };
        let operation = witness_operation_from_tag(input.u8()?)?;
        let approval_target_digest = input.fixed()?;
        let action_manifest_digest = input.fixed()?;
        let workload_digest = input.fixed()?;
        let issued_at_ms = input.u64()?;
        let not_before_ms = input.optional_u64()?;
        let expires_at_ms = input.u64()?;
        let request_session_public_key = input.fixed()?;
        let request_session_key_fingerprint = input.fixed()?;
        let witness_count = input.length(MAX_POLICY_ACTORS)?;
        let mut intended_witness_set = Vec::with_capacity(witness_count);
        for _ in 0..witness_count {
            intended_witness_set.push(IntendedWitnessV1 {
                witness_id: input.identifier(PrincipalId::from_bytes)?,
                share_index: input.u8()?,
                signing_key_fingerprint: input.fixed()?,
                contribution_key_fingerprint: input.fixed()?,
            });
        }
        input.finish()?;
        let request = Self {
            schema,
            protocol_version,
            construction,
            request_id,
            client_nonce,
            vault_id,
            genesis_fingerprint,
            item_id,
            key_epoch,
            item_access_mode,
            slot_id,
            content_role,
            revision,
            revision_seal_id,
            vault_policy_sequence,
            vault_policy_hash,
            policy_checkpoint_digest,
            witness_policy_id,
            witness_policy_revision,
            witness_policy_digest,
            requester_principal_id,
            requester_signing_key_fingerprint,
            requester_signing_key_epoch,
            requested_access_role,
            operation,
            approval_target_digest,
            action_manifest_digest,
            workload_digest,
            issued_at_ms,
            not_before_ms,
            expires_at_ms,
            request_session_public_key,
            request_session_key_fingerprint,
            intended_witness_set,
            client_signature,
        };
        if request.signature_preimage()?.as_slice() != preimage {
            return Err(invalid_format());
        }
        Ok(request)
    }
}
