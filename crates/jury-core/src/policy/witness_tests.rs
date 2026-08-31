use std::io;

use jury_protocol::vault_v1::{
    Digest32, FixedBytes, PrincipalId, RecipientPublicKey1216, Signature64, VaultId,
    VerificationPublicKey32, WitnessPolicyId,
};
use serde_json::Value;

use super::{
    ApprovalMode, ApproverPolicyDescriptor, DescriptorStatus, OperationRule, PlatformAssurance,
    PolicyErrorKind, WitnessOperation, WitnessPolicy, WitnessPolicyDescriptor,
};

pub(crate) type AnyResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> AnyResult<[u8; N]> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or_else(|| failure("cursor overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| failure("truncated vector"))?
            .try_into()?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> AnyResult<u8> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> AnyResult<u16> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> AnyResult<u32> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> AnyResult<u64> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn done(&self) -> AnyResult {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(failure("trailing vector bytes").into())
        }
    }
}

fn corpus() -> AnyResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../../conformance/witness-v1/vectors.json"
    ))?)
}

fn vector_bytes(corpus: &Value, name: &str, field: &str) -> AnyResult<Vec<u8>> {
    let encoded = corpus["vectors"][name][field]
        .as_str()
        .ok_or_else(|| failure("missing vector field"))?;
    Ok(hex::decode(encoded)?)
}

fn descriptor_status(tag: u8) -> AnyResult<DescriptorStatus> {
    match tag {
        1 => Ok(DescriptorStatus::Active),
        2 => Ok(DescriptorStatus::Revoked),
        _ => Err(failure("unknown descriptor status").into()),
    }
}

fn approval_mode(tag: u8) -> AnyResult<ApprovalMode> {
    match tag {
        1 => Ok(ApprovalMode::Human),
        2 => Ok(ApprovalMode::Automatic),
        _ => Err(failure("unknown approval mode").into()),
    }
}

fn operation(tag: u8) -> AnyResult<WitnessOperation> {
    match tag {
        1 => Ok(WitnessOperation::ReadStdout),
        2 => Ok(WitnessOperation::WritePrivateFile),
        3 => Ok(WitnessOperation::TemplateInjection),
        4 => Ok(WitnessOperation::ChildEnvironment),
        5 => Ok(WitnessOperation::ChildStdin),
        6 => Ok(WitnessOperation::ItemMutation),
        7 => Ok(WitnessOperation::Backup),
        8 => Ok(WitnessOperation::Recovery),
        9 => Ok(WitnessOperation::AdministrativeRekey),
        _ => Err(failure("unknown operation").into()),
    }
}

fn parse_approver(bytes: &[u8]) -> AnyResult<ApproverPolicyDescriptor> {
    let mut cursor = Cursor::new(bytes);
    let schema = cursor.u16()?;
    let approver_id = PrincipalId::from_bytes(cursor.take()?)?;
    let signing_public_key = VerificationPublicKey32::new(cursor.take()?);
    let signing_key_fingerprint = Digest32::new(cursor.take()?);
    let signing_key_epoch = cursor.u64()?;
    let status = descriptor_status(cursor.u8()?)?;
    let mode = approval_mode(cursor.u8()?)?;
    let count = usize::try_from(cursor.u32()?)?;
    let mut allowed_operations = Vec::with_capacity(count);
    for _ in 0..count {
        allowed_operations.push(operation(cursor.u8()?)?);
    }
    let created_at_ms = cursor.u64()?;
    let self_signature = Signature64::new(cursor.take()?);
    cursor.done()?;
    Ok(ApproverPolicyDescriptor {
        schema,
        approver_id,
        signing_public_key,
        signing_key_fingerprint,
        signing_key_epoch,
        status,
        approval_mode: mode,
        allowed_operations,
        created_at_ms,
        self_signature,
    })
}

fn parse_witness(bytes: &[u8]) -> AnyResult<WitnessPolicyDescriptor> {
    let mut cursor = Cursor::new(bytes);
    let descriptor = WitnessPolicyDescriptor {
        schema: cursor.u16()?,
        witness_id: PrincipalId::from_bytes(cursor.take()?)?,
        share_index: cursor.u8()?,
        signing_public_key: VerificationPublicKey32::new(cursor.take()?),
        signing_key_fingerprint: Digest32::new(cursor.take()?),
        signing_key_epoch: cursor.u64()?,
        contribution_public_key: RecipientPublicKey1216::new(cursor.take()?),
        contribution_key_fingerprint: Digest32::new(cursor.take()?),
        contribution_key_epoch: cursor.u64()?,
        status: descriptor_status(cursor.u8()?)?,
        created_at_ms: cursor.u64()?,
        self_signature: Signature64::new(cursor.take()?),
    };
    cursor.done()?;
    Ok(descriptor)
}

pub(crate) fn frozen_policy() -> AnyResult<(WitnessPolicy, Vec<u8>, Digest32)> {
    let corpus = corpus()?;
    let approvers = ["approver_descriptor_1", "approver_descriptor_2"]
        .iter()
        .map(|name| parse_approver(&vector_bytes(&corpus, name, "message_hex")?))
        .collect::<AnyResult<Vec<_>>>()?;
    let witnesses = [
        "witness_descriptor_1",
        "witness_descriptor_2",
        "witness_descriptor_3",
    ]
    .iter()
    .map(|name| parse_witness(&vector_bytes(&corpus, name, "message_hex")?))
    .collect::<AnyResult<Vec<_>>>()?;
    let expected_body = vector_bytes(&corpus, "witness_policy", "body_hex")?;
    let expected_digest = Digest32::new(
        vector_bytes(&corpus, "witness_policy", "digest_hex")?
            .try_into()
            .map_err(|_| failure("wrong digest length"))?,
    );
    let review_offset = expected_body
        .len()
        .checked_sub(33)
        .ok_or_else(|| failure("short policy body"))?;
    let review_label_set_digest =
        Digest32::new(expected_body[review_offset..review_offset + 32].try_into()?);
    let policy = WitnessPolicy {
        schema: 1,
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        revision: 1,
        predecessor_policy_digest: FixedBytes::new([0; 32]),
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: FixedBytes::new([0x02; 32]),
        vault_policy_sequence: 7,
        vault_policy_hash: FixedBytes::new([0x72; 32]),
        construction: 1,
        suite: 1,
        approver_descriptors: approvers,
        witness_descriptors: witnesses,
        witness_threshold: 2,
        operation_rules: vec![OperationRule {
            operation: WitnessOperation::ReadStdout,
            eligible_approver_ids: vec![
                PrincipalId::from_bytes([0x41; 32])?,
                PrincipalId::from_bytes([0x42; 32])?,
            ],
            approval_threshold: 2,
            allowed_request_lifetime_ms: 300_000,
            max_timeout_ms: 30_000,
            max_output_bytes: 4_096,
            max_target_count: 1,
            required_platform_assurance: PlatformAssurance::NormalizedPathOnly,
            automatic_read_targets: Vec::new(),
        }],
        review_label_set_digest,
        direct_fallback: false,
    };
    Ok((policy, expected_body, expected_digest))
}

#[test]
fn witnessed_policy_matches_the_frozen_protocol_corpus_exactly() -> AnyResult {
    let (policy, expected_body, expected_digest) = frozen_policy()?;

    policy.validate()?;
    assert_eq!(policy.canonical_body()?, expected_body);
    assert_eq!(policy.digest()?, expected_digest);
    Ok(())
}

#[test]
fn witnessed_policy_rejects_quorum_membership_lifetime_and_downgrade_errors() -> AnyResult {
    let (policy, _, _) = frozen_policy()?;

    let mut invalid = policy.clone();
    invalid.witness_threshold = 4;
    assert!(
        matches!(invalid.validate(), Err(error) if error.kind() == PolicyErrorKind::InvalidTransition)
    );

    let mut invalid = policy.clone();
    invalid.operation_rules[0].eligible_approver_ids[1] =
        invalid.operation_rules[0].eligible_approver_ids[0];
    assert!(
        matches!(invalid.validate(), Err(error) if error.kind() == PolicyErrorKind::InvalidTransition)
    );

    let mut invalid = policy.clone();
    invalid.operation_rules[0].allowed_request_lifetime_ms = 900_001;
    assert!(
        matches!(invalid.validate(), Err(error) if error.kind() == PolicyErrorKind::InvalidTransition)
    );

    let mut invalid = policy.clone();
    invalid.operation_rules[0].eligible_approver_ids[1] = PrincipalId::from_bytes([0x43; 32])?;
    assert!(
        matches!(invalid.validate(), Err(error) if error.kind() == PolicyErrorKind::InvalidRole)
    );

    let mut invalid = policy;
    invalid.direct_fallback = true;
    assert!(
        matches!(invalid.validate(), Err(error) if error.kind() == PolicyErrorKind::InvalidFormat)
    );
    Ok(())
}
