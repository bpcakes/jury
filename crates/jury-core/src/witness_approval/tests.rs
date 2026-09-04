use jury_protected::EntropyError;
use jury_protocol::{
    vault_v1::{
        AccessRole, ContentRole, ItemAccessMode, PresentationNonce, PrincipalId, RequestId,
        RevisionSealId, SlotId, VaultId, WitnessPolicyId,
    },
    witness_v1::{
        ApprovalPresentationEntryV1, ApprovalTargetEntryV1, ApprovalTargetV1, OperationContextV1,
        OutputSinkV1, PlatformAssuranceV1, PresentationDisplayBytes, PresentationKindV1,
        StdinModeV1, WitnessOperationV1,
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

fn owner_and_policy() -> Result<(VaultPrincipalIdentity, PolicyState), Box<dyn std::error::Error>> {
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
fn owner_label_creation_rejects_control_characters() -> Result<(), Box<dyn std::error::Error>> {
    let (owner, policy) = owner_and_policy()?;
    let mut creator = OwnerReviewLabelCreator::from_source(RepeatedRandom(0x71));
    let error = match creator.create(
        OwnerReviewLabelInput {
            policy: &policy,
            owner: &owner,
            label_revision: 1,
            subject: ReviewLabelSubject::Item(ItemId::from_bytes([0x72; 32])?),
            public_label: ReviewLabelBytes::new(b"Example\nItem".to_vec())?,
            target_policy_sequence: policy.sequence() + 1,
            issued_at_ms: 1_700_000_001_000,
            expires_at_ms: None,
        },
        |_| false,
    ) {
        Err(error) => error,
        Ok(_) => return Err("control characters entered a signed review label".into()),
    };
    assert_eq!(error.kind(), ReviewLabelErrorKind::InvalidScope);
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
