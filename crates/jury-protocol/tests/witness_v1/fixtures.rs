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
        "../../../../conformance/witness-v1/vectors.json"
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
