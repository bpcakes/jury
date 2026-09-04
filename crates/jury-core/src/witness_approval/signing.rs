#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalCreationErrorKind {
    InvalidReview,
    WrongIdentity,
    InvalidDecision,
    EntropyUnavailable,
    ProviderFailure,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApprovalCreationError {
    kind: ApprovalCreationErrorKind,
}

impl ApprovalCreationError {
    const fn new(kind: ApprovalCreationErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> ApprovalCreationErrorKind {
        self.kind
    }
}

impl fmt::Debug for ApprovalCreationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalCreationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for ApprovalCreationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ApprovalCreationErrorKind::InvalidReview => "approval review is invalid",
            ApprovalCreationErrorKind::WrongIdentity => "approver identity differs",
            ApprovalCreationErrorKind::InvalidDecision => "approval decision is invalid",
            ApprovalCreationErrorKind::EntropyUnavailable => "approval entropy was unavailable",
            ApprovalCreationErrorKind::ProviderFailure => "approval signing provider failed",
        })
    }
}

impl std::error::Error for ApprovalCreationError {}

pub struct ApprovalDecisionCreator<R = OsRandom> {
    source: R,
}

impl ApprovalDecisionCreator<OsRandom> {
    #[must_use]
    pub const fn new() -> Self {
        Self { source: OsRandom }
    }
}

impl Default for ApprovalDecisionCreator<OsRandom> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalDecisionChoice {
    pub decision: ApprovalDecisionKindV1,
    pub reason: WitnessReasonV1,
    pub now_ms: u64,
}

impl<R: RandomSource> ApprovalDecisionCreator<R> {
    #[cfg(test)]
    pub(crate) const fn from_source(source: R) -> Self {
        Self { source }
    }

    pub fn create(
        &mut self,
        policy: &PolicyState,
        checkpoint: &VaultPolicyCheckpointV1,
        review: &CompleteApprovalReview<'_>,
        approver: &ApproverIdentity,
        choice: ApprovalDecisionChoice,
    ) -> Result<ApprovalDecisionV1, ApprovalCreationError> {
        let ApprovalDecisionChoice {
            decision,
            reason,
            now_ms,
        } = choice;
        let request = review.request;
        let manifest = review.validated.manifest;
        if !review.validated.human
            || validate_request_manifest(request, manifest).is_err()
            || now_ms < request.issued_at_ms
            || now_ms >= request.expires_at_ms
        {
            return Err(ApprovalCreationError::new(
                ApprovalCreationErrorKind::InvalidReview,
            ));
        }
        let validated = validate_public_request(policy, checkpoint, request, manifest)
            .map_err(|_| ApprovalCreationError::new(ApprovalCreationErrorKind::InvalidReview))?;
        let descriptor = validated
            .policy
            .approver_descriptors
            .iter()
            .find(|descriptor| {
                descriptor.status == DescriptorStatus::Active
                    && descriptor.approver_id == approver.principal_id()
                    && validated
                        .rule
                        .eligible_approver_ids
                        .contains(&descriptor.approver_id)
            })
            .ok_or_else(|| ApprovalCreationError::new(ApprovalCreationErrorKind::WrongIdentity))?;
        let public = approver
            .public_descriptor()
            .map_err(|_| ApprovalCreationError::new(ApprovalCreationErrorKind::ProviderFailure))?;
        if public.principal_kind != PrincipalKind::Approver
            || public.verification_public_key != descriptor.signing_public_key
            || policy
                .principal(&public.principal_id)
                .is_none_or(|principal| principal.descriptor != public)
        {
            return Err(ApprovalCreationError::new(
                ApprovalCreationErrorKind::WrongIdentity,
            ));
        }
        let reason_valid = match decision {
            ApprovalDecisionKindV1::Approve => reason == WitnessReasonV1::None,
            ApprovalDecisionKindV1::Deny => reason != WitnessReasonV1::None,
        };
        if !reason_valid {
            return Err(ApprovalCreationError::new(
                ApprovalCreationErrorKind::InvalidDecision,
            ));
        }
        let approval_id = self.draw_approval_id(None)?;
        let nonce = self.draw_approval_id(Some(approval_id))?;
        let mut approval = ApprovalDecisionV1 {
            schema: 1,
            approval_id,
            request_id: request.request_id,
            request_digest: request.digest().map_err(|_| {
                ApprovalCreationError::new(ApprovalCreationErrorKind::InvalidReview)
            })?,
            action_manifest_digest: manifest.digest().map_err(|_| {
                ApprovalCreationError::new(ApprovalCreationErrorKind::InvalidReview)
            })?,
            presentation_digest: manifest.presentation_digest.clone(),
            witness_policy_id: request.witness_policy_id,
            witness_policy_revision: request.witness_policy_revision,
            witness_policy_digest: request.witness_policy_digest.clone(),
            approver_id: descriptor.approver_id,
            approver_key_fingerprint: descriptor.signing_key_fingerprint.clone(),
            approver_key_epoch: descriptor.signing_key_epoch,
            approval_mode: protocol_approval_mode(descriptor.approval_mode),
            decision,
            reason,
            issued_at_ms: now_ms,
            not_before_ms: None,
            expires_at_ms: request.expires_at_ms,
            nonce,
            intended_witness_set_digest: request.intended_witness_set_digest().map_err(|_| {
                ApprovalCreationError::new(ApprovalCreationErrorKind::InvalidReview)
            })?,
            signature: Signature64::new([0; 64]),
        };
        approval.signature = approver
            .sign_validated_approval(&approval.signature_preimage().map_err(|_| {
                ApprovalCreationError::new(ApprovalCreationErrorKind::InvalidDecision)
            })?)
            .map_err(|_| ApprovalCreationError::new(ApprovalCreationErrorKind::ProviderFailure))?;
        validate_approval_decision(policy, checkpoint, request, manifest, &approval, now_ms)
            .map_err(|_| ApprovalCreationError::new(ApprovalCreationErrorKind::InvalidDecision))?;
        Ok(approval)
    }

    fn draw_approval_id(
        &mut self,
        disallowed: Option<ApprovalId>,
    ) -> Result<ApprovalId, ApprovalCreationError> {
        for _ in 0..IDENTIFIER_ZERO_RETRY_ATTEMPTS {
            let mut bytes = [0_u8; 32];
            self.source.fill(&mut bytes).map_err(|_| {
                ApprovalCreationError::new(ApprovalCreationErrorKind::EntropyUnavailable)
            })?;
            if let Ok(value) = ApprovalId::from_bytes(bytes)
                && Some(value) != disallowed
            {
                return Ok(value);
            }
        }
        Err(ApprovalCreationError::new(
            ApprovalCreationErrorKind::EntropyUnavailable,
        ))
    }
}

pub struct OwnerReviewLabelCreator<R = OsRandom> {
    source: R,
}

impl OwnerReviewLabelCreator<OsRandom> {
    #[must_use]
    pub const fn new() -> Self {
        Self { source: OsRandom }
    }
}

impl Default for OwnerReviewLabelCreator<OsRandom> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct OwnerReviewLabelInput<'a> {
    pub policy: &'a PolicyState,
    pub owner: &'a VaultPrincipalIdentity,
    pub label_revision: u64,
    pub subject: ReviewLabelSubject,
    pub public_label: ReviewLabelBytes,
    pub target_policy_sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: Option<u64>,
}

impl<R: RandomSource> OwnerReviewLabelCreator<R> {
    #[cfg(test)]
    pub(crate) fn from_source(source: R) -> Self {
        Self { source }
    }

    pub fn create(
        &mut self,
        input: OwnerReviewLabelInput<'_>,
        mut label_id_was_used: impl FnMut(&LabelId) -> bool,
    ) -> Result<OwnerReviewLabelV1, ReviewLabelError> {
        let OwnerReviewLabelInput {
            policy,
            owner,
            label_revision,
            subject,
            public_label,
            target_policy_sequence,
            issued_at_ms,
            expires_at_ms,
        } = input;
        let next_sequence = policy.sequence().checked_add(1);
        if target_policy_sequence == 0
            || !policy.is_owner(&owner.principal_id())
            || (target_policy_sequence != policy.sequence()
                && Some(target_policy_sequence) != next_sequence)
        {
            return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope));
        }
        let descriptor = owner
            .public_descriptor()
            .map_err(|_| ReviewLabelError::new(ReviewLabelErrorKind::InvalidSignature))?;
        let registered = policy
            .principal(&owner.principal_id())
            .filter(|principal| principal.descriptor == descriptor)
            .filter(|principal| principal.descriptor.principal_kind == PrincipalKind::Human)
            .ok_or_else(|| ReviewLabelError::new(ReviewLabelErrorKind::InvalidSignature))?;
        let label_id = self.generate_label_id(&mut label_id_was_used)?;
        let (subject_kind, item_id, field_id, subject_commitment) = subject.parts();
        let mut label = OwnerReviewLabelV1 {
            schema: 1,
            label_id,
            label_revision,
            subject_kind,
            vault_id: policy.vault_id(),
            genesis_fingerprint: policy.genesis_fingerprint().clone(),
            item_id,
            field_id,
            subject_commitment,
            public_label,
            vault_policy_sequence: target_policy_sequence,
            issued_at_ms,
            expires_at_ms,
            issuer_owner_id: owner.principal_id(),
            issuer_key_fingerprint: signing_key_fingerprint(
                1,
                &owner.principal_id(),
                1,
                &registered.descriptor.verification_public_key,
            ),
            issuer_key_epoch: 1,
            signature: Signature64::new([0; 64]),
        };
        let preimage = label
            .signature_preimage()
            .map_err(|_| ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope))?;
        label.signature = owner
            .sign_validated_statement(&preimage)
            .map_err(|_| ReviewLabelError::new(ReviewLabelErrorKind::InvalidSignature))?;
        verify_owner_review_label(policy, &label, target_policy_sequence, issued_at_ms)?;
        Ok(label)
    }

    fn generate_label_id(
        &mut self,
        label_id_was_used: &mut impl FnMut(&LabelId) -> bool,
    ) -> Result<LabelId, ReviewLabelError> {
        for _ in 0..IDENTIFIER_ZERO_RETRY_ATTEMPTS {
            let mut bytes = [0_u8; 32];
            self.source
                .fill(&mut bytes)
                .map_err(|_| ReviewLabelError::new(ReviewLabelErrorKind::EntropyUnavailable))?;
            if let Ok(label_id) = LabelId::from_bytes(bytes)
                && !label_id_was_used(&label_id)
            {
                return Ok(label_id);
            }
        }
        Err(ReviewLabelError::new(
            ReviewLabelErrorKind::EntropyUnavailable,
        ))
    }
}

pub fn verify_owner_review_label(
    policy: &PolicyState,
    label: &OwnerReviewLabelV1,
    expected_policy_sequence: u64,
    now_ms: u64,
) -> Result<(), ReviewLabelError> {
    label
        .validate_shape()
        .map_err(|_| ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope))?;
    if label.vault_id != policy.vault_id()
        || label.genesis_fingerprint != *policy.genesis_fingerprint()
        || label.vault_policy_sequence != expected_policy_sequence
    {
        return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope));
    }
    if label.issued_at_ms > now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS)
        || label
            .expires_at_ms
            .is_some_and(|expires_at| now_ms >= expires_at)
    {
        return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidTime));
    }
    let owner = policy
        .principal(&label.issuer_owner_id)
        .filter(|_| policy.is_owner(&label.issuer_owner_id))
        .filter(|principal| principal.descriptor.principal_kind == PrincipalKind::Human)
        .ok_or_else(|| ReviewLabelError::new(ReviewLabelErrorKind::InvalidSignature))?;
    if label.issuer_key_epoch != 1
        || label.issuer_key_fingerprint
            != signing_key_fingerprint(
                1,
                &label.issuer_owner_id,
                label.issuer_key_epoch,
                &owner.descriptor.verification_public_key,
            )
    {
        return Err(ReviewLabelError::new(
            ReviewLabelErrorKind::InvalidSignature,
        ));
    }
    crypto::verify_bytes(
        &owner.descriptor.verification_public_key,
        &label
            .signature_preimage()
            .map_err(|_| ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope))?,
        &label.signature,
    )
    .map_err(|_| ReviewLabelError::new(ReviewLabelErrorKind::InvalidSignature))
}
