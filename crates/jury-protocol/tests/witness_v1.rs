use std::{error::Error, io};

use jury_protocol::{
    vault_v1::{
        AccessRole, ApprovalId, CancellationId, ContentRole, Digest32, FixedBytes, ItemAccessMode,
        ItemId, PrincipalId, ReceiptId, RecipientPublicKey1216, RecoveryId, RequestId, ResponseId,
        RevisionSealId, RotationId, SlotId, VaultId, WitnessPolicyId,
        recipient_public_key_fingerprint,
    },
    witness_v1::{
        ActionManifestV1, ApprovalDecisionKindV1, ApprovalDecisionV1, ApprovalModeV1,
        ApprovalTargetEntryV1, ApprovalTargetV1, CancellerRoleV1, IntendedWitnessV1,
        OperationContextV1, OutputSinkV1, PlatformAssuranceV1, PolicyMaterialBytes,
        PublicReceiptScopeV1, ReceiptAcknowledgementV1, ReceiptCompletionV1, ReceiptOutcomeV1,
        RegistrationBytes, RequestBytes, RequestCancellationV1, StdinModeV1, VaultHighWatermarkV1,
        VaultPolicyCheckpointV1, WitnessContributionEnvelopeV1, WitnessDecisionKindV1,
        WitnessDecisionV1, WitnessDescriptorBytes, WitnessOperationV1, WitnessPolicyRotationV1,
        WitnessReasonV1, WitnessReceiptMaterialV1, WitnessReceiptV1, WitnessRecoveryV1,
        WitnessRequestV1, WitnessResponseV1, WitnessRotationItemV1, WitnessRotationReasonV1,
        WitnessStateAnchorV1, signing_key_fingerprint, witness_registration_digest,
    },
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const ISSUED_AT: u64 = 1_700_000_000_000;
const EXPIRES_AT: u64 = ISSUED_AT + 300_000;

fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn corpus() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../conformance/witness-v1/vectors.json"
    ))?)
}

fn vector_hex(corpus: &Value, name: &str, key: &str) -> TestResult<Vec<u8>> {
    Ok(hex::decode(
        corpus["vectors"][name][key]
            .as_str()
            .ok_or_else(|| failure("missing witness vector field"))?,
    )?)
}

fn fixed_hex<const N: usize>(bytes: Vec<u8>) -> TestResult<FixedBytes<N>> {
    Ok(FixedBytes::from_slice(&bytes)?)
}

fn digest_hex(corpus: &Value, name: &str, key: &str) -> TestResult<Digest32> {
    fixed_hex(vector_hex(corpus, name, key)?)
}

fn repeated_digest(byte: u8) -> Digest32 {
    FixedBytes::new([byte; 32])
}

fn length_prefixed(bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut output = u32::try_from(bytes.len())?.to_be_bytes().to_vec();
    output.extend_from_slice(bytes);
    Ok(output)
}

fn action_manifest(corpus: &Value) -> TestResult<ActionManifestV1> {
    let presentation_digest = digest_hex(corpus, "approval_presentation", "digest_hex")?;
    Ok(ActionManifestV1 {
        schema: 1,
        request_id: RequestId::from_bytes([0x07; 32])?,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: repeated_digest(0x02),
        item_id: ItemId::from_bytes([0x03; 32])?,
        key_epoch: 3,
        item_access_mode: ItemAccessMode::WitnessedOnly,
        slot_id: SlotId::from_bytes([0x05; 32])?,
        content_role: ContentRole::Body,
        revision: 4,
        revision_seal_id: RevisionSealId::from_bytes([0x06; 32])?,
        vault_policy_sequence: 7,
        vault_policy_hash: repeated_digest(0x72),
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: digest_hex(corpus, "witness_policy", "digest_hex")?,
        requester_principal_id: PrincipalId::from_bytes([0x08; 32])?,
        requested_access_role: AccessRole::Reader,
        operation: WitnessOperationV1::ReadStdout,
        operation_context: OperationContextV1::ReadStdout,
        approval_target: ApprovalTargetV1 {
            entries: vec![ApprovalTargetEntryV1 {
                item_id: ItemId::from_bytes([0x03; 32])?,
                field_id: None,
                presentation_commitment: digest_hex(
                    corpus,
                    "approval_presentation",
                    "entry_commitment_hex",
                )?,
            }],
            presentation_digest: presentation_digest.clone(),
        },
        approval_target_digest: digest_hex(corpus, "approval_target", "digest_hex")?,
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
        issued_at_ms: ISSUED_AT,
        not_before_ms: None,
        expires_at_ms: EXPIRES_AT,
        presentation_digest,
    })
}

fn witness_request(corpus: &Value) -> TestResult<WitnessRequestV1> {
    let session_public_key: RecipientPublicKey1216 = fixed_hex(hex::decode(
        corpus["construction_vector"]["contributions"][0]["request_session_public_key_hex"]
            .as_str()
            .ok_or_else(|| failure("missing request session public key"))?,
    )?)?;
    let mut intended_witness_set = Vec::new();
    for index in 0..3_u8 {
        let vector_name = format!("witness_descriptor_{}", index + 1);
        let signing_public_key = fixed_hex(hex::decode(
            corpus["vectors"][&vector_name]["signing_public_key_hex"]
                .as_str()
                .ok_or_else(|| failure("missing witness signing public key"))?,
        )?)?;
        let contribution_public_key: RecipientPublicKey1216 = fixed_hex(hex::decode(
            corpus["construction_vector"]["capsules"][usize::from(index)]
                ["recipient_public_key_hex"]
                .as_str()
                .ok_or_else(|| failure("missing witness contribution public key"))?,
        )?)?;
        let witness_id = PrincipalId::from_bytes([0x51 + index; 32])?;
        intended_witness_set.push(IntendedWitnessV1 {
            witness_id,
            share_index: index + 1,
            signing_key_fingerprint: signing_key_fingerprint(
                3,
                &witness_id,
                1,
                &signing_public_key,
            ),
            contribution_key_fingerprint: recipient_public_key_fingerprint(
                &contribution_public_key,
            ),
        });
    }
    Ok(WitnessRequestV1 {
        schema: 1,
        protocol_version: 1,
        construction: 1,
        request_id: RequestId::from_bytes([0x07; 32])?,
        client_nonce: RequestId::from_bytes([0x75; 32])?,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: repeated_digest(0x02),
        item_id: ItemId::from_bytes([0x03; 32])?,
        key_epoch: 3,
        item_access_mode: ItemAccessMode::WitnessedOnly,
        slot_id: SlotId::from_bytes([0x05; 32])?,
        content_role: ContentRole::Body,
        revision: 4,
        revision_seal_id: RevisionSealId::from_bytes([0x06; 32])?,
        vault_policy_sequence: 7,
        vault_policy_hash: repeated_digest(0x72),
        policy_checkpoint_digest: digest_hex(corpus, "policy_checkpoint", "digest_hex")?,
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: digest_hex(corpus, "witness_policy", "digest_hex")?,
        requester_principal_id: PrincipalId::from_bytes([0x08; 32])?,
        requester_signing_key_fingerprint: fixed_hex(hex::decode(
            "35f1855bea5300000e81997b4e41acfffa69fc25897afccd5f640fc8b37ca32a",
        )?)?,
        requester_signing_key_epoch: 1,
        requested_access_role: AccessRole::Reader,
        operation: WitnessOperationV1::ReadStdout,
        approval_target_digest: digest_hex(corpus, "approval_target", "digest_hex")?,
        action_manifest_digest: digest_hex(corpus, "action_manifest", "digest_hex")?,
        workload_digest: digest_hex(corpus, "workload", "digest_hex")?,
        issued_at_ms: ISSUED_AT,
        not_before_ms: None,
        expires_at_ms: EXPIRES_AT,
        request_session_key_fingerprint: recipient_public_key_fingerprint(&session_public_key),
        request_session_public_key: session_public_key,
        intended_witness_set,
        client_signature: fixed_hex(vector_hex(corpus, "witness_request", "signature_hex")?)?,
    })
}

fn approval_decision(corpus: &Value, index: u8) -> TestResult<ApprovalDecisionV1> {
    let vector_name = format!("approval_decision_{}", index + 1);
    let descriptor_name = format!("approver_descriptor_{}", index + 1);
    let approver_id = PrincipalId::from_bytes([0x41 + index; 32])?;
    let signing_public_key = fixed_hex(vector_hex(
        corpus,
        &descriptor_name,
        "signing_public_key_hex",
    )?)?;
    Ok(ApprovalDecisionV1 {
        schema: 1,
        approval_id: ApprovalId::from_bytes([0x80 + index; 32])?,
        request_id: RequestId::from_bytes([0x07; 32])?,
        request_digest: digest_hex(corpus, "witness_request", "digest_hex")?,
        action_manifest_digest: digest_hex(corpus, "action_manifest", "digest_hex")?,
        presentation_digest: digest_hex(corpus, "approval_presentation", "digest_hex")?,
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: digest_hex(corpus, "witness_policy", "digest_hex")?,
        approver_id,
        approver_key_fingerprint: signing_key_fingerprint(2, &approver_id, 1, &signing_public_key),
        approver_key_epoch: 1,
        approval_mode: ApprovalModeV1::Human,
        decision: ApprovalDecisionKindV1::Approve,
        reason: WitnessReasonV1::None,
        issued_at_ms: ISSUED_AT + 1_000,
        not_before_ms: None,
        expires_at_ms: EXPIRES_AT,
        nonce: ApprovalId::from_bytes([0x82 + index; 32])?,
        intended_witness_set_digest: fixed_hex(hex::decode(
            "67aa234cb2c72a8d9301dd1a41ccb89980488a19ed903bccba6a2ba2ef46fe5a",
        )?)?,
        signature: fixed_hex(vector_hex(corpus, &vector_name, "signature_hex")?)?,
    })
}

fn policy_checkpoint(corpus: &Value) -> TestResult<VaultPolicyCheckpointV1> {
    Ok(VaultPolicyCheckpointV1 {
        schema: 1,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: repeated_digest(0x02),
        vault_policy_sequence: 7,
        vault_policy_hash: repeated_digest(0x72),
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: digest_hex(corpus, "witness_policy", "digest_hex")?,
        witness_set_digest: fixed_hex(hex::decode(
            "1ca3be89d2e1d2de0bf25cfcfe82569fd63228031feea946b1fff38ee30b200a",
        )?)?,
        approver_set_digest: fixed_hex(hex::decode(
            "95ac3364e23be58775128029e79a3bd9f447011cc96bf95a98bc2e193d8d6bb5",
        )?)?,
        review_label_set_digest: fixed_hex(hex::decode(
            "da3e0c4bc71493d609254bd71fc7f182947aa6f61bb63129cdcb3baea42082c5",
        )?)?,
        predecessor_checkpoint_digest: repeated_digest(0),
        issued_at_ms: ISSUED_AT - 500,
        issuer_owner_id: PrincipalId::from_bytes([0x09; 32])?,
        issuer_key_fingerprint: fixed_hex(hex::decode(
            "20367a13894f8ebbb319f692e58c68369ddd3d547ed886b08fcb05ef74f1932c",
        )?)?,
        issuer_key_epoch: 1,
        signature: fixed_hex(vector_hex(corpus, "policy_checkpoint", "signature_hex")?)?,
    })
}

fn witness_decision(corpus: &Value, index: u8) -> TestResult<WitnessDecisionV1> {
    let vector_name = format!("witness_decision_{}", index + 1);
    let descriptor_name = format!("witness_descriptor_{}", index + 1);
    let witness_id = PrincipalId::from_bytes([0x51 + index; 32])?;
    let signing_public_key = fixed_hex(vector_hex(
        corpus,
        &descriptor_name,
        "signing_public_key_hex",
    )?)?;
    Ok(WitnessDecisionV1 {
        schema: 1,
        response_id: ResponseId::from_bytes([0xb0 + index; 32])?,
        request_id: RequestId::from_bytes([0x07; 32])?,
        request_digest: digest_hex(corpus, "witness_request", "digest_hex")?,
        action_manifest_digest: digest_hex(corpus, "action_manifest", "digest_hex")?,
        witness_id,
        witness_signing_key_fingerprint: signing_key_fingerprint(
            3,
            &witness_id,
            1,
            &signing_public_key,
        ),
        witness_signing_key_epoch: 1,
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: digest_hex(corpus, "witness_policy", "digest_hex")?,
        policy_checkpoint_digest: digest_hex(corpus, "policy_checkpoint", "digest_hex")?,
        state_generation: 2 + u64::from(index),
        decision: WitnessDecisionKindV1::Approve,
        reason: WitnessReasonV1::None,
        issued_at_ms: ISSUED_AT + 2_000,
        expires_at_ms: EXPIRES_AT,
        contribution_digest: Some(fixed_hex(hex::decode(
            corpus["construction_vector"]["contributions"][usize::from(index)]["digest_hex"]
                .as_str()
                .ok_or_else(|| failure("missing contribution digest"))?,
        )?)?),
        share_index: Some(index + 1),
        share_commitment: Some(fixed_hex(hex::decode(
            corpus["construction_vector"]["capsules"][usize::from(index)]["share_commitment_hex"]
                .as_str()
                .ok_or_else(|| failure("missing share commitment"))?,
        )?)?),
        signature: fixed_hex(vector_hex(corpus, &vector_name, "signature_hex")?)?,
    })
}

#[test]
fn action_manifest_matches_the_frozen_vector() -> TestResult {
    let corpus = corpus()?;
    let manifest = action_manifest(&corpus)?;
    assert_eq!(
        manifest.canonical_body()?,
        vector_hex(&corpus, "action_manifest", "body_hex")?
    );
    assert_eq!(
        manifest.digest()?,
        digest_hex(&corpus, "action_manifest", "digest_hex")?
    );
    assert_eq!(
        manifest.workload_digest()?,
        digest_hex(&corpus, "workload", "digest_hex")?
    );
    Ok(())
}

#[test]
fn request_matches_the_frozen_vector_and_rejects_unknown_versions() -> TestResult {
    let corpus = corpus()?;
    let request = witness_request(&corpus)?;
    assert_eq!(
        request.signature_preimage()?,
        vector_hex(&corpus, "witness_request", "preimage_hex")?
    );
    assert_eq!(
        request.canonical_bytes()?,
        vector_hex(&corpus, "witness_request", "message_hex")?
    );
    assert_eq!(
        request.digest()?,
        digest_hex(&corpus, "witness_request", "digest_hex")?
    );
    assert_eq!(
        WitnessRequestV1::from_signature_preimage(
            &request.signature_preimage()?,
            request.client_signature.clone(),
        )?,
        request
    );

    let mut trailing = request.signature_preimage()?;
    trailing.push(0);
    assert!(
        WitnessRequestV1::from_signature_preimage(&trailing, request.client_signature.clone())
            .is_err()
    );

    let mut unknown_protocol = request.clone();
    unknown_protocol.protocol_version = 2;
    assert!(unknown_protocol.signature_preimage().is_err());
    let mut unknown_construction = request;
    unknown_construction.construction = 2;
    assert!(unknown_construction.signature_preimage().is_err());
    Ok(())
}

#[test]
fn approval_and_checkpoint_match_the_frozen_vectors() -> TestResult {
    let corpus = corpus()?;
    let approval = ApprovalDecisionV1 {
        schema: 1,
        approval_id: ApprovalId::from_bytes([0x80; 32])?,
        request_id: RequestId::from_bytes([0x07; 32])?,
        request_digest: digest_hex(&corpus, "witness_request", "digest_hex")?,
        action_manifest_digest: digest_hex(&corpus, "action_manifest", "digest_hex")?,
        presentation_digest: digest_hex(&corpus, "approval_presentation", "digest_hex")?,
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: digest_hex(&corpus, "witness_policy", "digest_hex")?,
        approver_id: PrincipalId::from_bytes([0x41; 32])?,
        approver_key_fingerprint: fixed_hex(hex::decode(
            "896a715e557e5fd595d5ba99aac1f19e66698087f15a0f465db6c67753b4624e",
        )?)?,
        approver_key_epoch: 1,
        approval_mode: ApprovalModeV1::Human,
        decision: ApprovalDecisionKindV1::Approve,
        reason: WitnessReasonV1::None,
        issued_at_ms: ISSUED_AT + 1_000,
        not_before_ms: None,
        expires_at_ms: EXPIRES_AT,
        nonce: ApprovalId::from_bytes([0x82; 32])?,
        intended_witness_set_digest: fixed_hex(hex::decode(
            "67aa234cb2c72a8d9301dd1a41ccb89980488a19ed903bccba6a2ba2ef46fe5a",
        )?)?,
        signature: fixed_hex(vector_hex(&corpus, "approval_decision_1", "signature_hex")?)?,
    };
    assert_eq!(
        approval.signature_preimage()?,
        vector_hex(&corpus, "approval_decision_1", "preimage_hex")?
    );
    assert_eq!(
        approval.canonical_bytes()?,
        vector_hex(&corpus, "approval_decision_1", "message_hex")?
    );
    assert_eq!(
        approval.digest()?,
        digest_hex(&corpus, "approval_decision_1", "digest_hex")?
    );

    let checkpoint = VaultPolicyCheckpointV1 {
        schema: 1,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: repeated_digest(0x02),
        vault_policy_sequence: 7,
        vault_policy_hash: repeated_digest(0x72),
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: digest_hex(&corpus, "witness_policy", "digest_hex")?,
        witness_set_digest: fixed_hex(hex::decode(
            "1ca3be89d2e1d2de0bf25cfcfe82569fd63228031feea946b1fff38ee30b200a",
        )?)?,
        approver_set_digest: fixed_hex(hex::decode(
            "95ac3364e23be58775128029e79a3bd9f447011cc96bf95a98bc2e193d8d6bb5",
        )?)?,
        review_label_set_digest: fixed_hex(hex::decode(
            "da3e0c4bc71493d609254bd71fc7f182947aa6f61bb63129cdcb3baea42082c5",
        )?)?,
        predecessor_checkpoint_digest: repeated_digest(0),
        issued_at_ms: ISSUED_AT - 500,
        issuer_owner_id: PrincipalId::from_bytes([0x09; 32])?,
        issuer_key_fingerprint: fixed_hex(hex::decode(
            "20367a13894f8ebbb319f692e58c68369ddd3d547ed886b08fcb05ef74f1932c",
        )?)?,
        issuer_key_epoch: 1,
        signature: fixed_hex(vector_hex(&corpus, "policy_checkpoint", "signature_hex")?)?,
    };
    assert_eq!(
        checkpoint.signature_preimage()?,
        vector_hex(&corpus, "policy_checkpoint", "preimage_hex")?
    );
    assert_eq!(
        checkpoint.canonical_bytes()?,
        vector_hex(&corpus, "policy_checkpoint", "message_hex")?
    );
    assert_eq!(
        checkpoint.digest()?,
        digest_hex(&corpus, "policy_checkpoint", "digest_hex")?
    );
    Ok(())
}

#[test]
fn decision_and_anchor_match_the_frozen_vectors() -> TestResult {
    let corpus = corpus()?;
    let witness_fingerprint = fixed_hex(hex::decode(
        "82ccd975752822c52ea537cb8aba52a957768b40d49748419e72c5b0dbd49fda",
    )?)?;
    let decision = WitnessDecisionV1 {
        schema: 1,
        response_id: ResponseId::from_bytes([0xb0; 32])?,
        request_id: RequestId::from_bytes([0x07; 32])?,
        request_digest: digest_hex(&corpus, "witness_request", "digest_hex")?,
        action_manifest_digest: digest_hex(&corpus, "action_manifest", "digest_hex")?,
        witness_id: PrincipalId::from_bytes([0x51; 32])?,
        witness_signing_key_fingerprint: witness_fingerprint.clone(),
        witness_signing_key_epoch: 1,
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: digest_hex(&corpus, "witness_policy", "digest_hex")?,
        policy_checkpoint_digest: digest_hex(&corpus, "policy_checkpoint", "digest_hex")?,
        state_generation: 2,
        decision: WitnessDecisionKindV1::Approve,
        reason: WitnessReasonV1::None,
        issued_at_ms: ISSUED_AT + 2_000,
        expires_at_ms: EXPIRES_AT,
        contribution_digest: Some(fixed_hex(hex::decode(
            "878e3f50c5199d22573d5320dd6ad264f0e3b427982536fbb82cf8dd72fb3511",
        )?)?),
        share_index: Some(1),
        share_commitment: Some(fixed_hex(hex::decode(
            "7ab077ffd8c344846de4250d24dc092f372087842217d884325b59f7f4cbbaa0",
        )?)?),
        signature: fixed_hex(vector_hex(&corpus, "witness_decision_1", "signature_hex")?)?,
    };
    assert_eq!(
        decision.signature_preimage()?,
        vector_hex(&corpus, "witness_decision_1", "preimage_hex")?
    );
    assert_eq!(
        decision.canonical_bytes()?,
        vector_hex(&corpus, "witness_decision_1", "message_hex")?
    );
    assert_eq!(
        decision.digest()?,
        digest_hex(&corpus, "witness_decision_1", "digest_hex")?
    );
    let contribution_vector = &corpus["construction_vector"]["contributions"][0];
    let capsule_vector = &corpus["construction_vector"]["capsules"][0];
    let contribution = WitnessContributionEnvelopeV1 {
        schema: 1,
        response_id: ResponseId::from_bytes([0xb0; 32])?,
        share_index: 1,
        share_commitment: fixed_hex(hex::decode(
            capsule_vector["share_commitment_hex"]
                .as_str()
                .ok_or_else(|| failure("missing share commitment"))?,
        )?)?,
        capsule_context_digest: fixed_hex(hex::decode(
            capsule_vector["context_digest_hex"]
                .as_str()
                .ok_or_else(|| failure("missing capsule context digest"))?,
        )?)?,
        capsule_set_digest: fixed_hex(hex::decode(
            corpus["construction_vector"]["capsule_set_digest_hex"]
                .as_str()
                .ok_or_else(|| failure("missing capsule set digest"))?,
        )?)?,
        request_session_key_fingerprint: recipient_public_key_fingerprint(&fixed_hex::<1216>(
            hex::decode(
                contribution_vector["request_session_public_key_hex"]
                    .as_str()
                    .ok_or_else(|| failure("missing request session public key"))?,
            )?,
        )?),
        encapsulation: fixed_hex::<1120>(hex::decode(
            contribution_vector["enc_hex"]
                .as_str()
                .ok_or_else(|| failure("missing contribution encapsulation"))?,
        )?)?,
        ciphertext: fixed_hex::<49>(hex::decode(
            contribution_vector["ciphertext_hex"]
                .as_str()
                .ok_or_else(|| failure("missing contribution ciphertext"))?,
        )?)?,
    };
    let response = WitnessResponseV1 {
        decision,
        contribution: Some(contribution),
    };
    assert_eq!(
        response.canonical_bytes()?,
        hex::decode(
            contribution_vector["response_hex"]
                .as_str()
                .ok_or_else(|| failure("missing response vector"))?,
        )?
    );
    let mut unknown_response = response;
    unknown_response.decision.schema = 2;
    assert!(unknown_response.canonical_bytes().is_err());

    let anchor = WitnessStateAnchorV1 {
        schema: 1,
        witness_id: PrincipalId::from_bytes([0x51; 32])?,
        witness_signing_key_fingerprint: witness_fingerprint,
        witness_signing_key_epoch: 1,
        state_generation: 4,
        database_state_digest: fixed_hex(hex::decode(
            "d09a95ebdbb009c5eb4f587410479e1df5974c30b182578c4ffe794ae02fa4fa",
        )?)?,
        vault_high_watermarks: vec![VaultHighWatermarkV1 {
            vault_id: VaultId::from_bytes([0x01; 32])?,
            genesis_fingerprint: repeated_digest(0x02),
            policy_sequence: 7,
            checkpoint_digest: digest_hex(&corpus, "policy_checkpoint", "digest_hex")?,
            highest_retained_request_expiry_ms: EXPIRES_AT,
        }],
        replay_retain_through_ms: EXPIRES_AT + 86_400_000,
        last_accepted_wall_time_ms: ISSUED_AT + 2_000,
        predecessor_anchor_digest: repeated_digest(0xd5),
        issued_at_ms: ISSUED_AT + 2_100,
        signature: fixed_hex(vector_hex(
            &corpus,
            "witness_state_anchor",
            "signature_hex",
        )?)?,
    };
    assert_eq!(
        anchor.signature_preimage()?,
        vector_hex(&corpus, "witness_state_anchor", "preimage_hex")?
    );
    assert_eq!(
        anchor.canonical_bytes()?,
        vector_hex(&corpus, "witness_state_anchor", "message_hex")?
    );
    assert_eq!(
        anchor.digest()?,
        digest_hex(&corpus, "witness_state_anchor", "digest_hex")?
    );
    Ok(())
}

#[test]
fn cancellation_matches_the_frozen_vector() -> TestResult {
    let corpus = corpus()?;
    let mut cancellation = RequestCancellationV1 {
        schema: 1,
        cancellation_id: CancellationId::from_bytes([0xd0; 32])?,
        request_signature_preimage: RequestBytes::new(vector_hex(
            &corpus,
            "witness_request",
            "preimage_hex",
        )?)?,
        client_signature: fixed_hex(vector_hex(&corpus, "witness_request", "signature_hex")?)?,
        request_id: RequestId::from_bytes([0x07; 32])?,
        request_digest: digest_hex(&corpus, "witness_request", "digest_hex")?,
        canceller_id: PrincipalId::from_bytes([0x08; 32])?,
        canceller_key_fingerprint: fixed_hex(hex::decode(
            "35f1855bea5300000e81997b4e41acfffa69fc25897afccd5f640fc8b37ca32a",
        )?)?,
        canceller_key_epoch: 1,
        canceller_role: CancellerRoleV1::OriginalRequester,
        issued_at_ms: ISSUED_AT + 3_000,
        reason: WitnessReasonV1::Cancelled,
        nonce: CancellationId::from_bytes([0xd1; 32])?,
        signature: FixedBytes::new([0; 64]),
    };
    cancellation.signature = fixed_hex(vector_hex(
        &corpus,
        "request_cancellation",
        "signature_hex",
    )?)?;
    assert_eq!(
        cancellation.signature_preimage()?,
        vector_hex(&corpus, "request_cancellation", "preimage_hex")?
    );
    assert_eq!(
        cancellation.canonical_bytes()?,
        vector_hex(&corpus, "request_cancellation", "message_hex")?
    );
    assert_eq!(
        cancellation.digest()?,
        digest_hex(&corpus, "request_cancellation", "digest_hex")?
    );
    Ok(())
}

#[test]
fn rotation_and_recovery_match_the_frozen_vectors() -> TestResult {
    let corpus = corpus()?;
    assert_eq!(
        witness_registration_digest(&RegistrationBytes::new(vector_hex(
            &corpus,
            "witness_registration",
            "body_hex",
        )?)?)?,
        digest_hex(&corpus, "witness_registration", "digest_hex")?
    );
    let owner_fingerprint = fixed_hex(hex::decode(
        "20367a13894f8ebbb319f692e58c68369ddd3d547ed886b08fcb05ef74f1932c",
    )?)?;
    let rotation = WitnessPolicyRotationV1 {
        schema: 1,
        rotation_id: RotationId::from_bytes([0xda; 32])?,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: repeated_digest(0x02),
        prior_vault_policy_sequence: 7,
        prior_vault_policy_hash: repeated_digest(0x72),
        next_vault_policy_sequence: 8,
        next_vault_policy_hash: repeated_digest(0xdb),
        prior_witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        prior_witness_policy_revision: 1,
        prior_witness_policy_digest: digest_hex(&corpus, "witness_policy", "digest_hex")?,
        next_witness_policy_id: WitnessPolicyId::from_bytes([0xdc; 32])?,
        next_witness_policy_revision: 2,
        next_witness_policy_digest: repeated_digest(0xdd),
        reason: WitnessRotationReasonV1::ApproverRuleOrLabel,
        affected_items: vec![WitnessRotationItemV1 {
            item_id: ItemId::from_bytes([0x03; 32])?,
            prior_key_epoch: 3,
            next_key_epoch: 4,
            next_descriptor_revision: 5,
            next_descriptor_revision_seal_id: RevisionSealId::from_bytes([0xd6; 32])?,
            next_descriptor_capsule_set_digest: repeated_digest(0xd7),
            next_body_revision: 5,
            next_body_revision_seal_id: RevisionSealId::from_bytes([0xd8; 32])?,
            next_body_capsule_set_digest: repeated_digest(0xd9),
        }],
        issued_at_ms: ISSUED_AT + 4_000,
        owner_id: PrincipalId::from_bytes([0x09; 32])?,
        owner_key_fingerprint: owner_fingerprint.clone(),
        owner_key_epoch: 1,
        signature: fixed_hex(vector_hex(
            &corpus,
            "witness_policy_rotation",
            "signature_hex",
        )?)?,
    };
    assert_eq!(
        rotation.signature_preimage()?,
        vector_hex(&corpus, "witness_policy_rotation", "preimage_hex")?
    );
    assert_eq!(
        rotation.canonical_bytes()?,
        vector_hex(&corpus, "witness_policy_rotation", "message_hex")?
    );
    assert_eq!(
        rotation.digest()?,
        digest_hex(&corpus, "witness_policy_rotation", "digest_hex")?
    );

    let recovery = WitnessRecoveryV1 {
        schema: 1,
        recovery_id: RecoveryId::from_bytes([0xde; 32])?,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: repeated_digest(0x02),
        unavailable_prior_witness_id: Some(PrincipalId::from_bytes([0x51; 32])?),
        new_witness_descriptor: WitnessDescriptorBytes::new(vector_hex(
            &corpus,
            "witness_descriptor_3",
            "message_hex",
        )?)?,
        new_registration_digest: digest_hex(&corpus, "witness_registration", "digest_hex")?,
        prior_checkpoint_digest: digest_hex(&corpus, "policy_checkpoint", "digest_hex")?,
        next_checkpoint_digest: repeated_digest(0xdf),
        rotation_record_digest: rotation.digest()?,
        statement: 1,
        issued_at_ms: ISSUED_AT + 5_000,
        owner_id: PrincipalId::from_bytes([0x09; 32])?,
        owner_key_fingerprint: owner_fingerprint,
        owner_key_epoch: 1,
        signature: fixed_hex(vector_hex(&corpus, "witness_recovery", "signature_hex")?)?,
    };
    assert_eq!(
        recovery.signature_preimage()?,
        vector_hex(&corpus, "witness_recovery", "preimage_hex")?
    );
    assert_eq!(
        recovery.canonical_bytes()?,
        vector_hex(&corpus, "witness_recovery", "message_hex")?
    );
    assert_eq!(
        recovery.digest()?,
        digest_hex(&corpus, "witness_recovery", "digest_hex")?
    );
    Ok(())
}

#[test]
fn complete_receipt_matches_the_frozen_vector_and_round_trips_json() -> TestResult {
    let corpus = corpus()?;
    let request = witness_request(&corpus)?;
    let mut policy_material = length_prefixed(&vector_hex(
        &corpus,
        "owner_policy_revision",
        "message_hex",
    )?)?;
    policy_material.extend_from_slice(&length_prefixed(&vector_hex(
        &corpus,
        "witness_policy",
        "body_hex",
    )?)?);
    let core_digest = digest_hex(&corpus, "receipt_core", "digest_hex")?;
    let endpoint_fingerprint = request.requester_signing_key_fingerprint.clone();
    let acknowledgement = ReceiptAcknowledgementV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0xe0; 32])?,
        receipt_core_digest: core_digest.clone(),
        request_digest: request.digest()?,
        endpoint_principal_id: request.requester_principal_id,
        endpoint_key_fingerprint: endpoint_fingerprint.clone(),
        endpoint_key_epoch: 1,
        started_at_ms: ISSUED_AT + 1_500,
        signature: fixed_hex(vector_hex(
            &corpus,
            "receipt_acknowledgement",
            "signature_hex",
        )?)?,
    };
    assert_eq!(
        acknowledgement.canonical_bytes()?,
        vector_hex(&corpus, "receipt_acknowledgement", "message_hex")?
    );
    let completion = ReceiptCompletionV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0xe0; 32])?,
        receipt_core_digest: core_digest,
        acknowledgement_digest: Some(acknowledgement.digest()?),
        endpoint_principal_id: request.requester_principal_id,
        endpoint_key_fingerprint: endpoint_fingerprint,
        endpoint_key_epoch: 1,
        outcome: ReceiptOutcomeV1::Approved,
        reason: WitnessReasonV1::None,
        completed_at_ms: ISSUED_AT + 3_000,
        signature: fixed_hex(vector_hex(&corpus, "receipt_completion", "signature_hex")?)?,
    };
    assert_eq!(
        completion.canonical_bytes()?,
        vector_hex(&corpus, "receipt_completion", "message_hex")?
    );
    let receipt = WitnessReceiptV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0xe0; 32])?,
        request_signature_preimage: RequestBytes::new(request.signature_preimage()?)?,
        client_signature: request.client_signature.clone(),
        request_digest: request.digest()?,
        action_manifest_digest: digest_hex(&corpus, "action_manifest", "digest_hex")?,
        presentation_digest: digest_hex(&corpus, "approval_presentation", "digest_hex")?,
        public_scope: PublicReceiptScopeV1::from_request(&request),
        approval_decisions: vec![
            approval_decision(&corpus, 0)?,
            approval_decision(&corpus, 1)?,
        ],
        witness_decisions: vec![witness_decision(&corpus, 0)?, witness_decision(&corpus, 1)?],
        policy_checkpoint: policy_checkpoint(&corpus)?,
        witness_policy_material: PolicyMaterialBytes::new(policy_material)?,
        approval_threshold: 2,
        witness_threshold: 2,
        counted_approver_ids: vec![
            PrincipalId::from_bytes([0x41; 32])?,
            PrincipalId::from_bytes([0x42; 32])?,
        ],
        counted_witness_ids: vec![
            PrincipalId::from_bytes([0x51; 32])?,
            PrincipalId::from_bytes([0x52; 32])?,
        ],
        outcome: ReceiptOutcomeV1::Approved,
        reason: WitnessReasonV1::None,
        issued_at_ms: ISSUED_AT + 3_000,
        expires_at_ms: EXPIRES_AT,
        endpoint_acknowledgement: Some(acknowledgement),
        endpoint_completion: Some(completion),
    };
    assert_eq!(
        receipt.core_bytes()?,
        vector_hex(&corpus, "receipt_core", "body_hex")?
    );
    assert_eq!(
        receipt.core_digest()?,
        digest_hex(&corpus, "receipt_core", "digest_hex")?
    );
    assert_eq!(
        receipt.canonical_bytes()?,
        vector_hex(&corpus, "witness_receipt", "body_hex")?
    );
    assert_eq!(
        receipt.digest()?,
        digest_hex(&corpus, "witness_receipt", "digest_hex")?
    );
    assert_eq!(
        receipt.validated_digests()?,
        (
            digest_hex(&corpus, "receipt_core", "digest_hex")?,
            digest_hex(&corpus, "witness_receipt", "digest_hex")?,
        )
    );
    let encoded = receipt.to_json_bytes()?;
    assert_eq!(WitnessReceiptV1::parse_json(&encoded)?, receipt);
    Ok(())
}

#[test]
fn receipt_material_is_canonical_and_rejects_unknown_schema() -> TestResult {
    let corpus = corpus()?;
    let material = WitnessReceiptMaterialV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0xe0; 32])?,
        request_digest: digest_hex(&corpus, "witness_request", "digest_hex")?,
        action_manifest_digest: digest_hex(&corpus, "action_manifest", "digest_hex")?,
        presentation_digest: digest_hex(&corpus, "approval_presentation", "digest_hex")?,
        policy_checkpoint_digest: digest_hex(&corpus, "policy_checkpoint", "digest_hex")?,
        witness_policy_digest: digest_hex(&corpus, "witness_policy", "digest_hex")?,
        approval_threshold: 2,
        witness_threshold: 2,
        counted_approver_ids: vec![
            PrincipalId::from_bytes([0x41; 32])?,
            PrincipalId::from_bytes([0x42; 32])?,
        ],
        counted_witness_ids: vec![
            PrincipalId::from_bytes([0x51; 32])?,
            PrincipalId::from_bytes([0x52; 32])?,
        ],
        reason: WitnessReasonV1::None,
        issued_at_ms: ISSUED_AT + 3_000,
        expires_at_ms: EXPIRES_AT,
    };
    let canonical = material.canonical_bytes()?;
    let mut changed = material.clone();
    changed.presentation_digest = repeated_digest(0xff);
    assert_ne!(changed.canonical_bytes()?, canonical);
    let mut unknown = material;
    unknown.schema = 2;
    assert!(unknown.canonical_bytes().is_err());
    Ok(())
}

#[test]
fn signed_messages_reject_one_bit_scope_changes() -> TestResult {
    let corpus = corpus()?;
    let mut manifest = action_manifest(&corpus)?;
    let expected = manifest.digest()?;
    manifest.output_limit_bytes ^= 1;
    assert_ne!(manifest.digest()?, expected);

    let mut checkpoint_bytes = vector_hex(&corpus, "policy_checkpoint", "message_hex")?;
    let last = checkpoint_bytes
        .last_mut()
        .ok_or_else(|| failure("empty checkpoint vector"))?;
    *last ^= 1;
    assert_ne!(
        checkpoint_bytes,
        vector_hex(&corpus, "policy_checkpoint", "message_hex")?
    );
    Ok(())
}
