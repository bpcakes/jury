//! Construction and verification of meaningful approval display material.

use std::fmt;

use jury_protected::{OsRandom, RandomSource};
use jury_protocol::{
    vault_v1::{ApprovalId, Digest32, FieldId, ItemId, LabelId, PrincipalKind, Signature64},
    witness_v1::{
        ACCEPTED_CLOCK_SKEW_MS, ActionManifestV1, ApprovalDecisionKindV1, ApprovalDecisionV1,
        ApprovalPresentationV1, ManifestArgumentV1, OwnerReviewLabelV1, PresentationKindV1,
        PresentationSubjectV1, ReviewLabelBytes, VaultPolicyCheckpointV1, WitnessReasonV1,
        WitnessRequestV1, WitnessTargetV1, normalized_subject_commitment,
        owner_review_label_set_digest, signing_key_fingerprint,
    },
};
use serde::Serialize;

use crate::{
    crypto,
    identity::{ApproverIdentity, VaultPrincipalIdentity},
    policy::{DescriptorStatus, PolicyState, protocol_approval_mode},
    witness_engine::{
        WitnessEngineError, validate_approval_decision, validate_public_request,
        validate_request_manifest,
    },
};

const IDENTIFIER_ZERO_RETRY_ATTEMPTS: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewLabelSubject {
    Item(ItemId),
    Field { item_id: ItemId, field_id: FieldId },
    WorkingDirectory(Digest32),
    OutputSink(Digest32),
}

impl ReviewLabelSubject {
    fn parts(
        &self,
    ) -> (
        PresentationSubjectV1,
        Option<ItemId>,
        Option<FieldId>,
        Option<Digest32>,
    ) {
        match self {
            Self::Item(item_id) => (PresentationSubjectV1::Item, Some(*item_id), None, None),
            Self::Field { item_id, field_id } => (
                PresentationSubjectV1::Field,
                Some(*item_id),
                Some(*field_id),
                None,
            ),
            Self::WorkingDirectory(commitment) => (
                PresentationSubjectV1::WorkingDirectory,
                None,
                None,
                Some(commitment.clone()),
            ),
            Self::OutputSink(commitment) => (
                PresentationSubjectV1::OutputSink,
                None,
                None,
                Some(commitment.clone()),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewLabelErrorKind {
    InvalidScope,
    InvalidTime,
    InvalidSignature,
    MissingEntitlement,
    EntropyUnavailable,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReviewLabelError {
    kind: ReviewLabelErrorKind,
}

impl ReviewLabelError {
    const fn new(kind: ReviewLabelErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> ReviewLabelErrorKind {
        self.kind
    }
}

impl fmt::Debug for ReviewLabelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewLabelError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for ReviewLabelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ReviewLabelErrorKind::InvalidScope => "approval review label scope differs",
            ReviewLabelErrorKind::InvalidTime => "approval review label is not current",
            ReviewLabelErrorKind::InvalidSignature => "approval review label signature is invalid",
            ReviewLabelErrorKind::MissingEntitlement => {
                "approval private-name entitlement is unavailable"
            }
            ReviewLabelErrorKind::EntropyUnavailable => {
                "approval review label entropy was unavailable"
            }
        })
    }
}

impl std::error::Error for ReviewLabelError {}

/// A complete manifest/presentation pair whose commitments and cardinality agree.
///
/// Construction is private so approval signing can require this value instead
/// of trusting an adapter's boolean validation result.
pub struct ValidatedApprovalPresentation<'a> {
    manifest: &'a ActionManifestV1,
    presentation: &'a ApprovalPresentationV1,
    human: bool,
}

impl ValidatedApprovalPresentation<'_> {
    #[must_use]
    pub const fn manifest(&self) -> &ActionManifestV1 {
        self.manifest
    }

    #[must_use]
    pub const fn presentation(&self) -> &ApprovalPresentationV1 {
        self.presentation
    }

    #[must_use]
    pub const fn is_human(&self) -> bool {
        self.human
    }
}

/// Verifies public-to-private presentation commitments before policy or display use.
pub fn validate_manifest_presentation<'a>(
    manifest: &'a ActionManifestV1,
    presentation: &'a ApprovalPresentationV1,
    human: bool,
) -> Result<ValidatedApprovalPresentation<'a>, ReviewLabelError> {
    manifest
        .validate_shape()
        .map_err(|_| ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope))?;
    presentation
        .validate_shape()
        .map_err(|_| ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope))?;
    if presentation.digest().ok().as_ref() != Some(&manifest.presentation_digest) {
        return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope));
    }

    if !human {
        let empty_digest = ApprovalPresentationV1::default()
            .digest()
            .map_err(|_| ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope))?;
        if !presentation.entries.is_empty()
            || manifest.presentation_digest != empty_digest
            || manifest
                .approval_target
                .entries
                .iter()
                .any(|entry| entry.presentation_commitment.as_bytes() != &[0_u8; 32])
        {
            return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope));
        }
        return Ok(ValidatedApprovalPresentation {
            manifest,
            presentation,
            human,
        });
    }

    let item_fields = presentation
        .entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.subject_kind,
                PresentationSubjectV1::Item | PresentationSubjectV1::Field
            )
        })
        .collect::<Vec<_>>();
    if item_fields.len() != manifest.approval_target.entries.len() {
        return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope));
    }
    for target in &manifest.approval_target.entries {
        let mut matching = item_fields.iter().filter(|entry| {
            entry.item_id == Some(target.item_id) && entry.field_id == target.field_id
        });
        let entry = matching
            .next()
            .ok_or_else(|| ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope))?;
        if matching.next().is_some()
            || entry.commitment().ok().as_ref() != Some(&target.presentation_commitment)
        {
            return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope));
        }
    }

    validate_normalized_subject(
        presentation,
        PresentationSubjectV1::WorkingDirectory,
        manifest.working_directory_commitment.as_ref(),
    )?;
    validate_normalized_subject(
        presentation,
        PresentationSubjectV1::OutputSink,
        manifest.output_sink_commitment.as_ref(),
    )?;

    let expected_entries = manifest
        .approval_target
        .entries
        .len()
        .saturating_add(usize::from(manifest.working_directory_commitment.is_some()))
        .saturating_add(usize::from(manifest.output_sink_commitment.is_some()));
    if presentation.entries.len() != expected_entries
        || manifest
            .approval_target
            .entries
            .iter()
            .any(|entry| entry.presentation_commitment.as_bytes() == &[0_u8; 32])
    {
        return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope));
    }
    Ok(ValidatedApprovalPresentation {
        manifest,
        presentation,
        human,
    })
}

/// Verifies the full public request and every policy-authenticated display opening.
///
/// Entitled private-name entries require a separate exact-revision access pass;
/// until such evidence is supplied, this function rejects them rather than
/// treating their committed display bytes as authority.
#[derive(Clone, Copy)]
pub struct ApprovalReviewInput<'a> {
    pub policy: &'a PolicyState,
    pub checkpoint: &'a VaultPolicyCheckpointV1,
    pub request: &'a WitnessRequestV1,
    pub manifest: &'a ActionManifestV1,
    pub presentation: &'a ApprovalPresentationV1,
    pub review_labels: &'a [OwnerReviewLabelV1],
    pub now_ms: u64,
}

pub fn validate_policy_authenticated_presentation<'a>(
    input: ApprovalReviewInput<'a>,
) -> Result<ValidatedApprovalPresentation<'a>, ReviewLabelError> {
    let ApprovalReviewInput {
        policy,
        checkpoint,
        request,
        manifest,
        presentation,
        review_labels,
        now_ms,
    } = input;
    let validated =
        validate_public_request(policy, checkpoint, request, manifest).map_err(map_engine_error)?;
    if request.issued_at_ms > now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS)
        || request
            .not_before_ms
            .is_some_and(|not_before| not_before > now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS))
        || now_ms >= request.expires_at_ms
    {
        return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidTime));
    }
    let human = validated.rule.approval_threshold != 0;
    let verified = validate_manifest_presentation(manifest, presentation, human)?;
    if checkpoint.review_label_set_digest != validated.policy.review_label_set_digest
        || owner_review_label_set_digest(review_labels).ok().as_ref()
            != Some(&validated.policy.review_label_set_digest)
    {
        return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope));
    }
    for label in review_labels {
        verify_owner_review_label(policy, label, request.vault_policy_sequence, now_ms)?;
    }
    for entry in &presentation.entries {
        if entry.source_revision.is_some()
            && (entry.source_revision != Some(request.revision)
                || entry.source_revision_seal_id != Some(request.revision_seal_id))
        {
            return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope));
        }
        let display = entry.display_bytes.as_bytes();
        if std::str::from_utf8(display).is_err()
            || display.iter().any(|byte| byte.is_ascii_control())
        {
            return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope));
        }
        match entry.presentation_kind {
            PresentationKindV1::EntitledPrivateName => {
                return Err(ReviewLabelError::new(
                    ReviewLabelErrorKind::MissingEntitlement,
                ));
            }
            PresentationKindV1::OwnerReviewLabel => {
                let embedded = entry
                    .owner_review_label
                    .as_ref()
                    .ok_or_else(|| ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope))?;
                if !review_labels.iter().any(|label| label == embedded) {
                    return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope));
                }
            }
            PresentationKindV1::ExactNormalizedDisplay => {
                let commitment = normalized_subject_commitment(
                    entry.subject_kind,
                    entry.blinding_nonce,
                    display,
                )
                .map_err(|_| ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope))?;
                if entry.subject_commitment.as_ref() != Some(&commitment) {
                    return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope));
                }
            }
        }
    }
    Ok(verified)
}

fn map_engine_error(error: WitnessEngineError) -> ReviewLabelError {
    let kind = match error.reason() {
        WitnessReasonV1::InvalidSignature => ReviewLabelErrorKind::InvalidSignature,
        WitnessReasonV1::Expired | WitnessReasonV1::NotYetValid => {
            ReviewLabelErrorKind::InvalidTime
        }
        _ => ReviewLabelErrorKind::InvalidScope,
    };
    ReviewLabelError::new(kind)
}

fn validate_normalized_subject(
    presentation: &ApprovalPresentationV1,
    subject: PresentationSubjectV1,
    expected_commitment: Option<&Digest32>,
) -> Result<(), ReviewLabelError> {
    let matching = presentation
        .entries
        .iter()
        .filter(|entry| entry.subject_kind == subject)
        .collect::<Vec<_>>();
    match (expected_commitment, matching.as_slice()) {
        (None, []) => Ok(()),
        (Some(expected), [entry]) if entry.subject_commitment.as_ref() == Some(expected) => Ok(()),
        _ => Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope)),
    }
}

/// Complete, non-truncated review output required before an approval signature.
pub struct CompleteApprovalReview<'a> {
    request: &'a WitnessRequestV1,
    validated: ValidatedApprovalPresentation<'a>,
    text: String,
}

impl CompleteApprovalReview<'_> {
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub const fn request(&self) -> &WitnessRequestV1 {
        self.request
    }

    #[must_use]
    pub const fn validated(&self) -> &ValidatedApprovalPresentation<'_> {
        &self.validated
    }
}

impl fmt::Debug for CompleteApprovalReview<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompleteApprovalReview")
            .field("request_id", &self.request.request_id)
            .field("rendered_bytes", &self.text.len())
            .finish()
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalReviewDocument<'a> {
    request: &'a WitnessRequestV1,
    action_manifest: &'a ActionManifestV1,
    presentation: &'a ApprovalPresentationV1,
    meaningful_displays: Vec<&'a str>,
    meaningful_subjects: Vec<MeaningfulSubjectDisplay<'a>>,
    operation_display: OperationDisplay<'a>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct MeaningfulSubjectDisplay<'a> {
    subject_kind: &'a PresentationSubjectV1,
    item_id: Option<&'a ItemId>,
    field_id: Option<&'a FieldId>,
    exact_display: &'a str,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct OperationDisplay<'a> {
    executable_identity: Option<String>,
    arguments: Vec<ArgumentDisplay<'a>>,
    environment_injections: Vec<EnvironmentDisplay<'a>>,
    stdin_target: Option<&'a WitnessTargetV1>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ArgumentDisplay<'a> {
    PublicLiteral {
        position: usize,
        exact_bytes: String,
    },
    SecretPlaceholder {
        position: usize,
        target: &'a WitnessTargetV1,
    },
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentDisplay<'a> {
    exact_name_bytes: String,
    target: &'a WitnessTargetV1,
}

/// Authenticates and renders every approval-bearing field without truncation.
pub fn render_complete_approval_review<'a>(
    input: ApprovalReviewInput<'a>,
) -> Result<CompleteApprovalReview<'a>, ReviewLabelError> {
    let validated = validate_policy_authenticated_presentation(input)?;
    let request = input.request;
    let manifest = input.manifest;
    let presentation = input.presentation;
    let meaningful_displays = presentation
        .entries
        .iter()
        .map(|entry| std::str::from_utf8(entry.display_bytes.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope))?;
    let meaningful_subjects = presentation
        .entries
        .iter()
        .zip(&meaningful_displays)
        .map(|(entry, display)| MeaningfulSubjectDisplay {
            subject_kind: &entry.subject_kind,
            item_id: entry.item_id.as_ref(),
            field_id: entry.field_id.as_ref(),
            exact_display: display,
        })
        .collect();
    let text = serde_json::to_string_pretty(&ApprovalReviewDocument {
        request,
        action_manifest: manifest,
        presentation,
        meaningful_displays,
        meaningful_subjects,
        operation_display: operation_display(manifest),
    })
    .map_err(|_| ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope))?;
    if text.is_empty() || text.contains("…") {
        return Err(ReviewLabelError::new(ReviewLabelErrorKind::InvalidScope));
    }
    Ok(CompleteApprovalReview {
        request,
        validated,
        text,
    })
}

fn operation_display(manifest: &ActionManifestV1) -> OperationDisplay<'_> {
    OperationDisplay {
        executable_identity: manifest
            .executable_identity
            .as_ref()
            .map(|identity| exact_byte_display(identity.as_bytes())),
        arguments: manifest
            .arguments
            .iter()
            .enumerate()
            .map(|(position, argument)| match argument {
                ManifestArgumentV1::PublicLiteral { bytes } => ArgumentDisplay::PublicLiteral {
                    position,
                    exact_bytes: exact_byte_display(bytes.as_bytes()),
                },
                ManifestArgumentV1::SecretPlaceholder { target } => {
                    ArgumentDisplay::SecretPlaceholder { position, target }
                }
            })
            .collect(),
        environment_injections: manifest
            .environment_injections
            .iter()
            .map(|injection| EnvironmentDisplay {
                exact_name_bytes: exact_byte_display(injection.name.as_bytes()),
                target: &injection.target,
            })
            .collect(),
        stdin_target: manifest.stdin_target.as_ref(),
    }
}

fn exact_byte_display(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut display = String::with_capacity(bytes.len().saturating_mul(4).saturating_add(7));
    display.push_str("bytes\"");
    for byte in bytes {
        match byte {
            b'"' => display.push_str("\\\""),
            b'\\' => display.push_str("\\\\"),
            0x20..=0x7e => display.push(char::from(*byte)),
            _ => {
                display.push_str("\\x");
                display.push(char::from(HEX[usize::from(byte >> 4)]));
                display.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
    display.push('"');
    display
}

include!("witness_approval/signing.rs");

#[cfg(test)]
mod tests {
    use jury_protected::EntropyError;
    use jury_protocol::{
        vault_v1::{
            AccessRole, ContentRole, ItemAccessMode, PresentationNonce, PrincipalId, RequestId,
            RevisionSealId, SlotId, VaultId, WitnessPolicyId,
        },
        witness_v1::{
            ApprovalPresentationEntryV1, ApprovalTargetEntryV1, ApprovalTargetV1,
            OperationContextV1, OutputSinkV1, PlatformAssuranceV1, PresentationDisplayBytes,
            PresentationKindV1, StdinModeV1, WitnessOperationV1,
        },
    };

    use super::*;
    use crate::{
        identity::{UnlockedIdentity, unlocked_identity_for_test},
        policy::PolicyCreator,
    };

    struct RepeatedRandom(u8);

    impl RandomSource for RepeatedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }

    #[test]
    fn operation_byte_display_is_exact_and_human_readable() {
        assert_eq!(exact_byte_display(b"TOKEN"), "bytes\"TOKEN\"");
        let escaped = exact_byte_display(b"A\n\xff\\\"");
        assert!(escaped.starts_with("bytes\"A"));
        assert!(escaped.ends_with('"'));
        assert!(escaped.contains("\\x0a"));
        assert!(escaped.contains("\\xff"));
        assert!(escaped.contains("\\\\"));
        assert!(escaped.contains("\\\""));
    }

    fn owner_and_policy()
    -> Result<(VaultPrincipalIdentity, PolicyState), Box<dyn std::error::Error>> {
        let mut identity_random = RepeatedRandom(0x21);
        let identity = unlocked_identity_for_test(
            PrincipalId::from_bytes([0x11; 32])?,
            PrincipalKind::Human,
            &mut identity_random,
        )?;
        let UnlockedIdentity::VaultPrincipal(owner) = identity else {
            return Err("test identity role differs".into());
        };
        let mut policy_creator = PolicyCreator::from_source(RepeatedRandom(0x31));
        let created = policy_creator.create(&owner, 1_700_000_000_000, |_: &VaultId| false)?;
        Ok((owner, created.state))
    }

    fn read_manifest(
        policy: &PolicyState,
        item_id: ItemId,
        entry: &ApprovalPresentationEntryV1,
        presentation_digest: Digest32,
    ) -> Result<ActionManifestV1, Box<dyn std::error::Error>> {
        let approval_target = ApprovalTargetV1 {
            entries: vec![ApprovalTargetEntryV1 {
                item_id,
                field_id: None,
                presentation_commitment: entry.commitment()?,
            }],
            presentation_digest: presentation_digest.clone(),
        };
        Ok(ActionManifestV1 {
            schema: 1,
            request_id: RequestId::from_bytes([0x81; 32])?,
            vault_id: policy.vault_id(),
            genesis_fingerprint: policy.genesis_fingerprint().clone(),
            item_id,
            key_epoch: 1,
            item_access_mode: ItemAccessMode::WitnessedOnly,
            slot_id: SlotId::from_bytes([0x82; 32])?,
            content_role: ContentRole::Body,
            revision: 1,
            revision_seal_id: RevisionSealId::from_bytes([0x83; 32])?,
            vault_policy_sequence: 1,
            vault_policy_hash: Digest32::new([0x84; 32]),
            witness_policy_id: WitnessPolicyId::from_bytes([0x85; 32])?,
            witness_policy_revision: 1,
            witness_policy_digest: Digest32::new([0x86; 32]),
            requester_principal_id: PrincipalId::from_bytes([0x87; 32])?,
            requested_access_role: AccessRole::Reader,
            operation: WitnessOperationV1::ReadStdout,
            operation_context: OperationContextV1::ReadStdout,
            approval_target_digest: approval_target.digest()?,
            approval_target,
            executable_identity: None,
            arguments: Vec::new(),
            working_directory_commitment: None,
            environment_injections: Vec::new(),
            stdin_target: None,
            stdin_mode: StdinModeV1::None,
            output_sink: OutputSinkV1::Stdout,
            output_sink_commitment: None,
            platform_assurance: PlatformAssuranceV1::NormalizedPathOnly,
            timeout_ms: 30_000,
            output_limit_bytes: 4_096,
            issued_at_ms: 1_700_000_001_000,
            not_before_ms: None,
            expires_at_ms: 1_700_000_301_000,
            presentation_digest,
        })
    }

    #[test]
    fn owner_label_creation_signs_exact_current_or_next_policy_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let (owner, policy) = owner_and_policy()?;
        let mut creator = OwnerReviewLabelCreator::from_source(RepeatedRandom(0x41));
        let item_id = ItemId::from_bytes([0x51; 32])?;
        let target_sequence = policy.sequence() + 1;
        let label = creator.create(
            OwnerReviewLabelInput {
                policy: &policy,
                owner: &owner,
                label_revision: 1,
                subject: ReviewLabelSubject::Item(item_id),
                public_label: ReviewLabelBytes::new(b"ExampleItem".to_vec())?,
                target_policy_sequence: target_sequence,
                issued_at_ms: 1_700_000_001_000,
                expires_at_ms: Some(1_700_000_301_000),
            },
            |_| false,
        )?;

        assert_eq!(label.subject_kind, PresentationSubjectV1::Item);
        assert_eq!(label.item_id, Some(item_id));
        assert_eq!(label.vault_policy_sequence, target_sequence);
        verify_owner_review_label(&policy, &label, target_sequence, 1_700_000_002_000)?;
        assert!(format!("{label:?}").contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn owner_label_verification_rejects_forgery_staleness_and_wrong_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let (owner, policy) = owner_and_policy()?;
        let mut creator = OwnerReviewLabelCreator::from_source(RepeatedRandom(0x61));
        let sequence = policy.sequence() + 1;
        let label = creator
            .create(
                OwnerReviewLabelInput {
                    policy: &policy,
                    owner: &owner,
                    label_revision: 1,
                    subject: ReviewLabelSubject::Item(ItemId::from_bytes([0x71; 32])?),
                    public_label: ReviewLabelBytes::new(b"ExampleField".to_vec())?,
                    target_policy_sequence: sequence,
                    issued_at_ms: 1_700_000_001_000,
                    expires_at_ms: Some(1_700_000_003_000),
                },
                |_| false,
            )
            .map_err(|error| format!("label creation failed: {error:?}"))?;

        let mut forged = label.clone();
        forged.public_label = ReviewLabelBytes::new(b"AnotherField".to_vec())?;
        assert_eq!(
            verify_owner_review_label(&policy, &forged, sequence, 1_700_000_002_000)
                .map_err(|error| error.kind()),
            Err(ReviewLabelErrorKind::InvalidSignature)
        );
        assert_eq!(
            verify_owner_review_label(&policy, &label, sequence, 1_700_000_003_000)
                .map_err(|error| error.kind()),
            Err(ReviewLabelErrorKind::InvalidTime)
        );
        assert_eq!(
            verify_owner_review_label(&policy, &label, sequence + 1, 1_700_000_002_000)
                .map_err(|error| error.kind()),
            Err(ReviewLabelErrorKind::InvalidScope)
        );
        Ok(())
    }

    #[test]
    fn manifest_presentation_validation_requires_every_meaningful_opening()
    -> Result<(), Box<dyn std::error::Error>> {
        let (owner, policy) = owner_and_policy()?;
        let item_id = ItemId::from_bytes([0x91; 32])?;
        let mut creator = OwnerReviewLabelCreator::from_source(RepeatedRandom(0x92));
        let label = creator.create(
            OwnerReviewLabelInput {
                policy: &policy,
                owner: &owner,
                label_revision: 1,
                subject: ReviewLabelSubject::Item(item_id),
                public_label: ReviewLabelBytes::new(b"ExampleItem".to_vec())?,
                target_policy_sequence: 1,
                issued_at_ms: 1_700_000_001_000,
                expires_at_ms: None,
            },
            |_| false,
        )?;
        let entry = ApprovalPresentationEntryV1 {
            subject_kind: PresentationSubjectV1::Item,
            item_id: Some(item_id),
            field_id: None,
            subject_commitment: None,
            presentation_kind: PresentationKindV1::OwnerReviewLabel,
            display_bytes: PresentationDisplayBytes::new(b"ExampleItem".to_vec())?,
            source_revision: Some(1),
            source_revision_seal_id: Some(RevisionSealId::from_bytes([0x83; 32])?),
            owner_review_label: Some(label),
            blinding_nonce: PresentationNonce::from_bytes([0x93; 32])?,
        };
        let presentation = ApprovalPresentationV1 {
            entries: vec![entry.clone()],
        };
        let manifest = read_manifest(&policy, item_id, &entry, presentation.digest()?)?;

        let validated = validate_manifest_presentation(&manifest, &presentation, true)?;
        assert!(validated.is_human());
        assert_eq!(validated.presentation(), &presentation);

        let missing = ApprovalPresentationV1::default();
        assert!(matches!(
            validate_manifest_presentation(&manifest, &missing, true),
            Err(error) if error.kind() == ReviewLabelErrorKind::InvalidScope
        ));

        let mut changed = presentation;
        changed.entries[0].blinding_nonce = PresentationNonce::from_bytes([0x94; 32])?;
        assert!(matches!(
            validate_manifest_presentation(&manifest, &changed, true),
            Err(error) if error.kind() == ReviewLabelErrorKind::InvalidScope
        ));
        Ok(())
    }
}
