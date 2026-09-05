//! Endpoint-side construction of exact, request-session-bound witness requests.

use std::fmt;

use jury_protected::{OsRandom, ProtectedMemory, ProtectionPolicy, RandomSource};
use jury_protocol::{
    vault_v1::{
        CancellationId, ContentRole, Digest32, FieldId, ItemId, PresentationNonce, PrincipalKind,
        RecipientPublicKey1216, RequestId, Signature64, WitnessedSlotV1,
        recipient_public_key_fingerprint,
    },
    witness_v1::{
        ActionManifestV1, ApprovalPresentationEntryV1, ApprovalPresentationV1,
        ApprovalTargetEntryV1, ApprovalTargetV1, CancellerRoleV1, EnvironmentInjectionV1,
        IntendedWitnessV1, ManifestArgumentV1, OperationBytes, OperationContextV1, OutputSinkV1,
        OwnerReviewLabelV1, PresentationDisplayBytes, PresentationKindV1, PresentationSubjectV1,
        RequestBytes, RequestCancellationV1, StdinModeV1, WitnessOperationV1, WitnessReasonV1,
        WitnessRequestV1, WitnessTargetV1, normalized_subject_commitment, signing_key_fingerprint,
    },
};

use crate::{
    crypto::{self, CryptoError},
    domain::Capability,
    identity::VaultPrincipalIdentity,
    policy::{
        DescriptorStatus, PolicyState, WitnessOperation, core_operation,
        protocol_platform_assurance,
    },
    witness_approval::{ApprovalReviewInput, validate_policy_authenticated_presentation},
    witness_engine::{
        validate_checkpoint_public, validate_public_request, validate_request_cancellation,
    },
};

const IDENTIFIER_RETRY_ATTEMPTS: usize = 8;

include!("witness_client/control.rs");

/// Fresh HPKE receiver state for exactly one signed request.
///
/// It has no serialization or private-byte accessor. Losing this process-local
/// value requires creating a new request rather than persisting the key.
pub struct RequestSessionIdentity {
    pub(crate) private_key: ProtectedMemory,
    public_key: RecipientPublicKey1216,
    fingerprint: Digest32,
}

impl RequestSessionIdentity {
    #[must_use]
    pub const fn public_key(&self) -> &RecipientPublicKey1216 {
        &self.public_key
    }

    #[must_use]
    pub const fn fingerprint(&self) -> &Digest32 {
        &self.fingerprint
    }

    #[must_use]
    pub(crate) fn protection_policy(&self) -> ProtectionPolicy {
        self.private_key.status().policy()
    }
}

impl fmt::Debug for RequestSessionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestSessionIdentity")
            .field("fingerprint", &self.fingerprint)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// One validated public request bundle plus its non-persistable session receiver.
pub struct PreparedWitnessRequest {
    pub request: WitnessRequestV1,
    pub manifest: ActionManifestV1,
    pub presentation: ApprovalPresentationV1,
    pub review_labels: Vec<OwnerReviewLabelV1>,
    pub session: RequestSessionIdentity,
}

impl fmt::Debug for PreparedWitnessRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedWitnessRequest")
            .field("request", &self.request)
            .field("manifest", &self.manifest)
            .field("presentation", &self.presentation)
            .field("review_label_count", &self.review_labels.len())
            .field("session", &self.session)
            .finish()
    }
}

pub struct WitnessRequestCreator<R = OsRandom> {
    source: R,
    protection: ProtectionPolicy,
}

/// Public, value-free action dimensions used to construct one exact request.
pub struct WitnessActionRequest {
    pub item_id: ItemId,
    pub field_ids: Vec<FieldId>,
    pub operation_context: OperationContextV1,
    pub executable_identity: Option<OperationBytes>,
    pub arguments: Vec<ManifestArgumentV1>,
    pub working_directory: Option<OperationBytes>,
    pub environment_injections: Vec<EnvironmentInjectionV1>,
    pub stdin_target: Option<WitnessTargetV1>,
    pub stdin_mode: StdinModeV1,
    pub output_sink: OutputSinkV1,
    pub output_destination: Option<OperationBytes>,
    pub timeout_ms: u64,
    pub output_limit_bytes: u32,
}

pub struct WitnessRequestContext<'a> {
    pub policy: &'a PolicyState,
    pub checkpoint: &'a jury_protocol::witness_v1::VaultPolicyCheckpointV1,
    pub requester: &'a VaultPrincipalIdentity,
    pub review_labels: Vec<OwnerReviewLabelV1>,
    pub now_ms: u64,
}

type HumanPresentation = (
    ApprovalPresentationV1,
    Vec<ApprovalTargetEntryV1>,
    Option<Digest32>,
    Option<Digest32>,
);

impl WitnessRequestCreator<OsRandom> {
    #[must_use]
    pub const fn new(protection: ProtectionPolicy) -> Self {
        Self {
            source: OsRandom,
            protection,
        }
    }
}

impl<R: RandomSource> WitnessRequestCreator<R> {
    #[cfg(test)]
    pub(crate) const fn from_source(source: R, protection: ProtectionPolicy) -> Self {
        Self { source, protection }
    }

    /// Creates a complete request for one body field written to stdout.
    ///
    /// The selected field remains an opaque public identifier. A human-review
    /// policy requires an exact owner-signed field label in the complete label
    /// set; automatic approval uses the canonical empty presentation.
    pub fn create_read_stdout(
        &mut self,
        context: WitnessRequestContext<'_>,
        item_id: ItemId,
        field_id: FieldId,
    ) -> Result<PreparedWitnessRequest, WitnessRequestError> {
        let policy = context.policy;
        let checkpoint = context.checkpoint;
        let requester = context.requester;
        let review_labels = &context.review_labels;
        let now_ms = context.now_ms;
        let rule = policy
            .witness_access_rule(&item_id, WitnessOperation::ReadStdout)
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::StalePolicy))?;
        let item = policy
            .item(&item_id)
            .ok_or_else(|| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?;
        let slot = item
            .witnessed_state
            .as_ref()
            .and_then(|state| {
                let matching = state
                    .slots
                    .iter()
                    .filter(|slot| {
                        slot.content_role == ContentRole::Body
                            && slot.witness_policy_digest == rule.policy_digest
                    })
                    .collect::<Vec<_>>();
                if matching.len() == 1 {
                    matching.first().copied()
                } else {
                    None
                }
            })
            .ok_or_else(|| WitnessRequestError::new(WitnessRequestErrorKind::StalePolicy))?;
        let requested_access_role = policy
            .access(&item_id, &requester.principal_id(), Capability::Read)
            .effective_role
            .ok_or_else(|| WitnessRequestError::new(WitnessRequestErrorKind::WrongIdentity))?;
        let (presentation, presentation_commitment) = if rule.approval_threshold == 0 {
            (ApprovalPresentationV1::default(), Digest32::new([0; 32]))
        } else {
            let label = review_labels
                .iter()
                .find(|label| {
                    label.subject_kind == PresentationSubjectV1::Field
                        && label.item_id == Some(item_id)
                        && label.field_id == Some(field_id)
                })
                .cloned()
                .ok_or_else(|| {
                    WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation)
                })?;
            let mut nonce_bytes = [0_u8; 32];
            self.source.fill(&mut nonce_bytes).map_err(|_| {
                WitnessRequestError::new(WitnessRequestErrorKind::EntropyUnavailable)
            })?;
            let blinding_nonce = PresentationNonce::from_bytes(nonce_bytes).map_err(|_| {
                WitnessRequestError::new(WitnessRequestErrorKind::EntropyUnavailable)
            })?;
            let entry = ApprovalPresentationEntryV1 {
                subject_kind: PresentationSubjectV1::Field,
                item_id: Some(item_id),
                field_id: Some(field_id),
                subject_commitment: None,
                presentation_kind: PresentationKindV1::OwnerReviewLabel,
                display_bytes: PresentationDisplayBytes::new(
                    label.public_label.as_bytes().to_vec(),
                )
                .map_err(|_| {
                    WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation)
                })?,
                source_revision: Some(slot.revision),
                source_revision_seal_id: Some(slot.revision_seal_id),
                owner_review_label: Some(label),
                blinding_nonce,
            };
            let commitment = entry.commitment().map_err(|_| {
                WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation)
            })?;
            (
                ApprovalPresentationV1 {
                    entries: vec![entry],
                },
                commitment,
            )
        };
        let presentation_digest = presentation
            .digest()
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation))?;
        let approval_target = ApprovalTargetV1 {
            entries: vec![ApprovalTargetEntryV1 {
                item_id,
                field_id: Some(field_id),
                presentation_commitment,
            }],
            presentation_digest: presentation_digest.clone(),
        };
        let approval_target_digest = approval_target
            .digest()
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation))?;
        let expires_at_ms = now_ms
            .checked_add(rule.allowed_request_lifetime_ms)
            .ok_or_else(|| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?;
        let manifest = ActionManifestV1 {
            schema: 1,
            request_id: RequestId::from_bytes([1; 32])
                .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?,
            vault_id: policy.vault_id(),
            genesis_fingerprint: policy.genesis_fingerprint().clone(),
            item_id,
            key_epoch: slot.key_epoch,
            item_access_mode: slot.item_access_mode,
            slot_id: slot.slot_id,
            content_role: slot.content_role,
            revision: slot.revision,
            revision_seal_id: slot.revision_seal_id,
            vault_policy_sequence: checkpoint.vault_policy_sequence,
            vault_policy_hash: checkpoint.vault_policy_hash.clone(),
            witness_policy_id: slot.witness_policy_id,
            witness_policy_revision: slot.witness_policy_revision,
            witness_policy_digest: slot.witness_policy_digest.clone(),
            requester_principal_id: requester.principal_id(),
            requested_access_role,
            operation: WitnessOperationV1::ReadStdout,
            operation_context: OperationContextV1::ReadStdout,
            approval_target,
            approval_target_digest,
            executable_identity: None,
            arguments: Vec::new(),
            working_directory_commitment: None,
            environment_injections: Vec::new(),
            stdin_target: None,
            stdin_mode: StdinModeV1::None,
            output_sink: OutputSinkV1::Stdout,
            output_sink_commitment: None,
            platform_assurance: protocol_platform_assurance(rule.required_platform_assurance),
            timeout_ms: 0,
            output_limit_bytes: 0,
            issued_at_ms: now_ms,
            not_before_ms: None,
            expires_at_ms,
            presentation_digest,
        };
        self.create(context, manifest, presentation)
    }

    /// Constructs and signs an exact non-read action from authenticated policy
    /// state and value-free operation dimensions.
    pub fn create_action(
        &mut self,
        context: WitnessRequestContext<'_>,
        mut action: WitnessActionRequest,
    ) -> Result<PreparedWitnessRequest, WitnessRequestError> {
        let policy = context.policy;
        let checkpoint = context.checkpoint;
        let requester = context.requester;
        let review_labels = &context.review_labels;
        let now_ms = context.now_ms;
        let operation = action.operation_context.operation();
        let rule = policy
            .witness_access_rule(&action.item_id, core_operation(operation))
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::StalePolicy))?;
        let item = policy
            .item(&action.item_id)
            .ok_or_else(|| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?;
        let slot = item
            .witnessed_state
            .as_ref()
            .and_then(|state| {
                let matching = state
                    .slots
                    .iter()
                    .filter(|slot| {
                        slot.content_role == ContentRole::Body
                            && slot.witness_policy_digest == rule.policy_digest
                    })
                    .collect::<Vec<_>>();
                (matching.len() == 1).then(|| matching[0].clone())
            })
            .ok_or_else(|| WitnessRequestError::new(WitnessRequestErrorKind::StalePolicy))?;
        let requested_access_role = policy
            .access(&action.item_id, &requester.principal_id(), Capability::Read)
            .effective_role
            .ok_or_else(|| WitnessRequestError::new(WitnessRequestErrorKind::WrongIdentity))?;
        action.field_ids.sort_unstable();
        if action.field_ids.is_empty() || action.field_ids.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(WitnessRequestError::new(
                WitnessRequestErrorKind::InvalidInput,
            ));
        }
        let (presentation, approval_entries, working_directory_commitment, output_sink_commitment) =
            if rule.approval_threshold == 0 {
                let entries = action
                    .field_ids
                    .iter()
                    .map(|field_id| ApprovalTargetEntryV1 {
                        item_id: action.item_id,
                        field_id: Some(*field_id),
                        presentation_commitment: Digest32::new([0; 32]),
                    })
                    .collect();
                (ApprovalPresentationV1::default(), entries, None, None)
            } else {
                self.human_presentation(&action, &slot, review_labels)?
            };
        let presentation_digest = presentation
            .digest()
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation))?;
        let approval_target = ApprovalTargetV1 {
            entries: approval_entries,
            presentation_digest: presentation_digest.clone(),
        };
        let approval_target_digest = approval_target
            .digest()
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation))?;
        let expires_at_ms = now_ms
            .checked_add(rule.allowed_request_lifetime_ms)
            .ok_or_else(|| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?;
        let manifest = ActionManifestV1 {
            schema: 1,
            request_id: RequestId::from_bytes([1; 32])
                .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?,
            vault_id: policy.vault_id(),
            genesis_fingerprint: policy.genesis_fingerprint().clone(),
            item_id: action.item_id,
            key_epoch: slot.key_epoch,
            item_access_mode: slot.item_access_mode,
            slot_id: slot.slot_id,
            content_role: slot.content_role,
            revision: slot.revision,
            revision_seal_id: slot.revision_seal_id,
            vault_policy_sequence: checkpoint.vault_policy_sequence,
            vault_policy_hash: checkpoint.vault_policy_hash.clone(),
            witness_policy_id: slot.witness_policy_id,
            witness_policy_revision: slot.witness_policy_revision,
            witness_policy_digest: slot.witness_policy_digest.clone(),
            requester_principal_id: requester.principal_id(),
            requested_access_role,
            operation,
            operation_context: action.operation_context,
            approval_target,
            approval_target_digest,
            executable_identity: action.executable_identity,
            arguments: action.arguments,
            working_directory_commitment,
            environment_injections: action.environment_injections,
            stdin_target: action.stdin_target,
            stdin_mode: action.stdin_mode,
            output_sink: action.output_sink,
            output_sink_commitment,
            platform_assurance: protocol_platform_assurance(rule.required_platform_assurance),
            timeout_ms: action.timeout_ms,
            output_limit_bytes: action.output_limit_bytes,
            issued_at_ms: now_ms,
            not_before_ms: None,
            expires_at_ms,
            presentation_digest,
        };
        self.create(context, manifest, presentation)
    }

    fn human_presentation(
        &mut self,
        action: &WitnessActionRequest,
        slot: &WitnessedSlotV1,
        review_labels: &[OwnerReviewLabelV1],
    ) -> Result<HumanPresentation, WitnessRequestError> {
        let mut presentation_entries = Vec::new();
        let mut approval_entries = Vec::new();
        let item_entry = self.label_presentation_entry(
            PresentationSubjectV1::Item,
            action.item_id,
            None,
            slot,
            review_labels,
        )?;
        approval_entries.push(ApprovalTargetEntryV1 {
            item_id: action.item_id,
            field_id: None,
            presentation_commitment: presentation_commitment(&item_entry)?,
        });
        presentation_entries.push(item_entry);
        for field_id in &action.field_ids {
            let entry = self.label_presentation_entry(
                PresentationSubjectV1::Field,
                action.item_id,
                Some(*field_id),
                slot,
                review_labels,
            )?;
            approval_entries.push(ApprovalTargetEntryV1 {
                item_id: action.item_id,
                field_id: Some(*field_id),
                presentation_commitment: presentation_commitment(&entry)?,
            });
            presentation_entries.push(entry);
        }
        let working_directory_commitment = if let Some(display) = &action.working_directory {
            let entry = self
                .normalized_presentation_entry(PresentationSubjectV1::WorkingDirectory, display)?;
            let commitment = entry.subject_commitment.clone();
            presentation_entries.push(entry);
            commitment
        } else {
            None
        };
        let output_sink_commitment = if let Some(display) = &action.output_destination {
            let entry =
                self.normalized_presentation_entry(PresentationSubjectV1::OutputSink, display)?;
            let commitment = entry.subject_commitment.clone();
            presentation_entries.push(entry);
            commitment
        } else {
            None
        };
        Ok((
            ApprovalPresentationV1 {
                entries: presentation_entries,
            },
            approval_entries,
            working_directory_commitment,
            output_sink_commitment,
        ))
    }

    fn label_presentation_entry(
        &mut self,
        subject_kind: PresentationSubjectV1,
        item_id: ItemId,
        field_id: Option<FieldId>,
        slot: &WitnessedSlotV1,
        review_labels: &[OwnerReviewLabelV1],
    ) -> Result<ApprovalPresentationEntryV1, WitnessRequestError> {
        let label = review_labels
            .iter()
            .find(|label| {
                label.subject_kind == subject_kind
                    && label.item_id == Some(item_id)
                    && label.field_id == field_id
            })
            .cloned()
            .ok_or_else(|| {
                WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation)
            })?;
        Ok(ApprovalPresentationEntryV1 {
            subject_kind,
            item_id: Some(item_id),
            field_id,
            subject_commitment: None,
            presentation_kind: PresentationKindV1::OwnerReviewLabel,
            display_bytes: PresentationDisplayBytes::new(label.public_label.as_bytes().to_vec())
                .map_err(|_| {
                    WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation)
                })?,
            source_revision: Some(slot.revision),
            source_revision_seal_id: Some(slot.revision_seal_id),
            owner_review_label: Some(label),
            blinding_nonce: self.draw_presentation_nonce()?,
        })
    }

    fn normalized_presentation_entry(
        &mut self,
        subject_kind: PresentationSubjectV1,
        display: &OperationBytes,
    ) -> Result<ApprovalPresentationEntryV1, WitnessRequestError> {
        let blinding_nonce = self.draw_presentation_nonce()?;
        let subject_commitment =
            normalized_subject_commitment(subject_kind, blinding_nonce, display.as_bytes())
                .map_err(|_| {
                    WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation)
                })?;
        Ok(ApprovalPresentationEntryV1 {
            subject_kind,
            item_id: None,
            field_id: None,
            subject_commitment: Some(subject_commitment),
            presentation_kind: PresentationKindV1::ExactNormalizedDisplay,
            display_bytes: PresentationDisplayBytes::new(display.as_bytes().to_vec()).map_err(
                |_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation),
            )?,
            source_revision: None,
            source_revision_seal_id: None,
            owner_review_label: None,
            blinding_nonce,
        })
    }

    fn draw_presentation_nonce(&mut self) -> Result<PresentationNonce, WitnessRequestError> {
        for _ in 0..IDENTIFIER_RETRY_ATTEMPTS {
            let mut nonce_bytes = [0_u8; 32];
            self.source.fill(&mut nonce_bytes).map_err(|_| {
                WitnessRequestError::new(WitnessRequestErrorKind::EntropyUnavailable)
            })?;
            if let Ok(nonce) = PresentationNonce::from_bytes(nonce_bytes) {
                return Ok(nonce);
            }
        }
        Err(WitnessRequestError::new(
            WitnessRequestErrorKind::EntropyUnavailable,
        ))
    }

    pub fn create(
        &mut self,
        context: WitnessRequestContext<'_>,
        mut manifest: ActionManifestV1,
        presentation: ApprovalPresentationV1,
    ) -> Result<PreparedWitnessRequest, WitnessRequestError> {
        let WitnessRequestContext {
            policy,
            checkpoint,
            requester,
            review_labels,
            now_ms,
        } = context;
        let witness_policy = validate_checkpoint_public(policy, checkpoint)
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::StalePolicy))?;
        let requester_descriptor = requester
            .public_descriptor()
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::ProviderFailure))?;
        if !matches!(
            requester_descriptor.principal_kind,
            PrincipalKind::Human | PrincipalKind::Machine
        ) || policy
            .principal(&requester.principal_id())
            .is_none_or(|principal| principal.descriptor != requester_descriptor)
            || manifest.requester_principal_id != requester.principal_id()
        {
            return Err(WitnessRequestError::new(
                WitnessRequestErrorKind::WrongIdentity,
            ));
        }

        let request_id = self.draw_request_id(None)?;
        let client_nonce = self.draw_request_id(Some(request_id))?;
        manifest.request_id = request_id;
        manifest
            .validate_shape()
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?;
        let (private_key, public_key) =
            crypto::generate_recipient_keypair(self.protection, &mut self.source)
                .map_err(map_crypto_error)?;
        let fingerprint = recipient_public_key_fingerprint(&public_key);
        let intended_witness_set = witness_policy
            .witness_descriptors
            .iter()
            .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
            .map(|descriptor| IntendedWitnessV1 {
                witness_id: descriptor.witness_id,
                share_index: descriptor.share_index,
                signing_key_fingerprint: descriptor.signing_key_fingerprint.clone(),
                contribution_key_fingerprint: descriptor.contribution_key_fingerprint.clone(),
            })
            .collect();
        let mut request = WitnessRequestV1 {
            schema: 1,
            protocol_version: 1,
            construction: 1,
            request_id,
            client_nonce,
            vault_id: manifest.vault_id,
            genesis_fingerprint: manifest.genesis_fingerprint.clone(),
            item_id: manifest.item_id,
            key_epoch: manifest.key_epoch,
            item_access_mode: manifest.item_access_mode,
            slot_id: manifest.slot_id,
            content_role: manifest.content_role,
            revision: manifest.revision,
            revision_seal_id: manifest.revision_seal_id,
            vault_policy_sequence: manifest.vault_policy_sequence,
            vault_policy_hash: manifest.vault_policy_hash.clone(),
            policy_checkpoint_digest: checkpoint
                .digest()
                .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?,
            witness_policy_id: manifest.witness_policy_id,
            witness_policy_revision: manifest.witness_policy_revision,
            witness_policy_digest: manifest.witness_policy_digest.clone(),
            requester_principal_id: requester.principal_id(),
            requester_signing_key_fingerprint: signing_key_fingerprint(
                1,
                &requester.principal_id(),
                1,
                &requester_descriptor.verification_public_key,
            ),
            requester_signing_key_epoch: 1,
            requested_access_role: manifest.requested_access_role,
            operation: manifest.operation,
            approval_target_digest: manifest.approval_target_digest.clone(),
            action_manifest_digest: manifest
                .digest()
                .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?,
            workload_digest: manifest
                .workload_digest()
                .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?,
            issued_at_ms: manifest.issued_at_ms,
            not_before_ms: manifest.not_before_ms,
            expires_at_ms: manifest.expires_at_ms,
            request_session_public_key: public_key.clone(),
            request_session_key_fingerprint: fingerprint.clone(),
            intended_witness_set,
            client_signature: Signature64::new([0; 64]),
        };
        request.client_signature = requester
            .sign_validated_statement(
                &request
                    .signature_preimage()
                    .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?,
            )
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::ProviderFailure))?;
        validate_public_request(policy, checkpoint, &request, &manifest)
            .map_err(|error| map_witness_reason(error.reason()))?;
        validate_policy_authenticated_presentation(ApprovalReviewInput {
            policy,
            checkpoint,
            request: &request,
            manifest: &manifest,
            presentation: &presentation,
            review_labels: &review_labels,
            now_ms,
        })
        .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation))?;

        Ok(PreparedWitnessRequest {
            request,
            manifest,
            presentation,
            review_labels,
            session: RequestSessionIdentity {
                private_key,
                public_key,
                fingerprint,
            },
        })
    }

    fn draw_request_id(
        &mut self,
        disallowed: Option<RequestId>,
    ) -> Result<RequestId, WitnessRequestError> {
        for _ in 0..IDENTIFIER_RETRY_ATTEMPTS {
            let mut bytes = [0_u8; 32];
            self.source.fill(&mut bytes).map_err(|_| {
                WitnessRequestError::new(WitnessRequestErrorKind::EntropyUnavailable)
            })?;
            if let Ok(value) = RequestId::from_bytes(bytes)
                && Some(value) != disallowed
            {
                return Ok(value);
            }
        }
        Err(WitnessRequestError::new(
            WitnessRequestErrorKind::EntropyUnavailable,
        ))
    }
}

fn map_crypto_error(error: CryptoError) -> WitnessRequestError {
    WitnessRequestError::new(match error {
        CryptoError::EntropyUnavailable => WitnessRequestErrorKind::EntropyUnavailable,
        CryptoError::MemoryProtection => WitnessRequestErrorKind::ProtectionUnavailable,
        CryptoError::ResourceUnavailable | CryptoError::ProviderFailure => {
            WitnessRequestErrorKind::ProviderFailure
        }
        CryptoError::AuthenticationFailed => WitnessRequestErrorKind::InvalidInput,
    })
}

fn presentation_commitment(
    entry: &ApprovalPresentationEntryV1,
) -> Result<Digest32, WitnessRequestError> {
    entry
        .commitment()
        .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidPresentation))
}

fn map_witness_reason(reason: WitnessReasonV1) -> WitnessRequestError {
    WitnessRequestError::new(match reason {
        WitnessReasonV1::InvalidSignature => WitnessRequestErrorKind::WrongIdentity,
        WitnessReasonV1::StalePolicy
        | WitnessReasonV1::WitnessBehind
        | WitnessReasonV1::CheckpointFork => WitnessRequestErrorKind::StalePolicy,
        _ => WitnessRequestErrorKind::InvalidInput,
    })
}
