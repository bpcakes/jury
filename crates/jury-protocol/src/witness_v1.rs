//! Canonical public messages for Jury witnessed-access protocol v1.
//!
//! These are pre-alpha wire values. They contain public authorization scope and
//! encrypted contributions only; plaintext shares and private presentation
//! material are never represented here.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::canonical::{self, jce_v1 as jce, optional_u8, optional_u64};
use crate::vault_v1::{
    AccessRole, ApprovalId, BoundedBytes, CancellationId, ContentRole, Digest32, Encapsulation1120,
    FieldId, FixedBytes, ItemAccessMode, ItemId, PrincipalId, ReceiptId, RecipientPublicKey1216,
    RequestId, ResponseId, RevisionSealId, ShareCiphertext49, Signature64, SlotId, VaultId,
    VerificationPublicKey32, WitnessPolicyId,
};

pub const SUITE: u16 = 1;
pub const PROTOCOL_VERSION: u16 = 1;
pub const CONSTRUCTION: u16 = 1;
pub const MAX_POLICY_ACTORS: usize = 32;
pub const MAX_RECORDED_APPROVALS: usize = MAX_POLICY_ACTORS * 2;
pub const MAX_MANIFEST_TARGETS: usize = 64;
pub const MAX_ARGUMENTS: usize = 128;
pub const MAX_ENVIRONMENT_NAMES: usize = 64;
pub const MAX_REQUEST_LIFETIME_MS: u64 = 900_000;
pub const ACCEPTED_CLOCK_SKEW_MS: u64 = 60_000;
pub const REPLAY_RETENTION_MS: u64 = 86_400_000;
pub const MAX_REQUEST_BYTES: usize = 32 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_APPROVAL_BYTES: usize = 16 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024;
pub const MAX_REPLAY_RECORDS_PER_VAULT: usize = 65_536;
pub const MAX_REPLAY_RECORDS_PER_SERVICE: usize = 1_048_576;

pub type OperationBytes = BoundedBytes<4096>;
pub type ManifestBytes = BoundedBytes<MAX_MANIFEST_BYTES>;
pub type RequestBytes = BoundedBytes<MAX_REQUEST_BYTES>;
pub type ApprovalBytes = BoundedBytes<MAX_APPROVAL_BYTES>;
pub type ResponseBytes = BoundedBytes<MAX_RESPONSE_BYTES>;
pub type CancellationBytes = BoundedBytes<{ 48 * 1024 }>;
pub type RegistrationBytes = BoundedBytes<{ 64 * 1024 }>;
pub type PolicyMaterialBytes = BoundedBytes<{ 16 * 1024 * 1024 }>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessProtocolErrorKind {
    InvalidFormat,
    InvalidOrdering,
    InvalidDigest,
    InvalidScope,
    InvalidTime,
    CapacityExhausted,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WitnessProtocolError {
    kind: WitnessProtocolErrorKind,
}

impl WitnessProtocolError {
    const fn new(kind: WitnessProtocolErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> WitnessProtocolErrorKind {
        self.kind
    }
}

impl fmt::Debug for WitnessProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessProtocolError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for WitnessProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            WitnessProtocolErrorKind::InvalidFormat => "witness message format is invalid",
            WitnessProtocolErrorKind::InvalidOrdering => "witness message ordering is invalid",
            WitnessProtocolErrorKind::InvalidDigest => "witness message digest differs",
            WitnessProtocolErrorKind::InvalidScope => "witness message scope differs",
            WitnessProtocolErrorKind::InvalidTime => "witness message time bounds are invalid",
            WitnessProtocolErrorKind::CapacityExhausted => "witness message capacity is exhausted",
        })
    }
}

impl std::error::Error for WitnessProtocolError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WitnessOperationV1 {
    ReadStdout,
    WritePrivateFile,
    TemplateInjection,
    ChildEnvironment,
    ChildStdin,
    ItemMutation,
    Backup,
    Recovery,
    AdministrativeRekey,
}

impl WitnessOperationV1 {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::ReadStdout => 1,
            Self::WritePrivateFile => 2,
            Self::TemplateInjection => 3,
            Self::ChildEnvironment => 4,
            Self::ChildStdin => 5,
            Self::ItemMutation => 6,
            Self::Backup => 7,
            Self::Recovery => 8,
            Self::AdministrativeRekey => 9,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalModeV1 {
    Human,
    Automatic,
}

impl ApprovalModeV1 {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Human => 1,
            Self::Automatic => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalDecisionKindV1 {
    Approve,
    Deny,
}

impl ApprovalDecisionKindV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Approve => 1,
            Self::Deny => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WitnessDecisionKindV1 {
    Approve,
    Deny,
    Error,
}

impl WitnessDecisionKindV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Approve => 1,
            Self::Deny => 2,
            Self::Error => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WitnessReasonV1 {
    None,
    PolicyDenied,
    MissingApproval,
    ApprovalDenied,
    ApprovalConflict,
    StalePolicy,
    WitnessBehind,
    CheckpointFork,
    ReplayConflict,
    Expired,
    NotYetValid,
    Cancelled,
    WrongScope,
    WrongOperation,
    WorkloadExceeded,
    DirectDowngrade,
    Invalid,
    UnsupportedVersion,
    InvalidSignature,
    InvalidContribution,
    InsufficientQuorum,
    Unavailable,
    UnsafeClock,
    AnchorConflict,
    CapacityExhausted,
    RestoredStateUnsafe,
    InternalFailure,
    CancellationTooLate,
}

impl WitnessReasonV1 {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::PolicyDenied => 0x01,
            Self::MissingApproval => 0x02,
            Self::ApprovalDenied => 0x03,
            Self::ApprovalConflict => 0x04,
            Self::StalePolicy => 0x05,
            Self::WitnessBehind => 0x06,
            Self::CheckpointFork => 0x07,
            Self::ReplayConflict => 0x08,
            Self::Expired => 0x09,
            Self::NotYetValid => 0x0a,
            Self::Cancelled => 0x0b,
            Self::WrongScope => 0x0c,
            Self::WrongOperation => 0x0d,
            Self::WorkloadExceeded => 0x0e,
            Self::DirectDowngrade => 0x0f,
            Self::Invalid => 0x10,
            Self::UnsupportedVersion => 0x11,
            Self::InvalidSignature => 0x12,
            Self::InvalidContribution => 0x13,
            Self::InsufficientQuorum => 0x14,
            Self::Unavailable => 0x15,
            Self::UnsafeClock => 0x16,
            Self::AnchorConflict => 0x17,
            Self::CapacityExhausted => 0x18,
            Self::RestoredStateUnsafe => 0x19,
            Self::InternalFailure => 0x1a,
            Self::CancellationTooLate => 0x1b,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlatformAssuranceV1 {
    NormalizedPathOnly,
    StableExecutableIdentity,
}

impl PlatformAssuranceV1 {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::NormalizedPathOnly => 1,
            Self::StableExecutableIdentity => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StdinModeV1 {
    None,
    SecretBytes,
    PublicBytes,
}

impl StdinModeV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::None => 1,
            Self::SecretBytes => 2,
            Self::PublicBytes => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputSinkV1 {
    Stdout,
    PrivateFile,
    ChildStdin,
    ChildEnvironment,
    None,
}

impl OutputSinkV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Stdout => 1,
            Self::PrivateFile => 2,
            Self::ChildStdin => 3,
            Self::ChildEnvironment => 4,
            Self::None => 5,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessTargetV1 {
    pub item_id: ItemId,
    pub field_id: Option<FieldId>,
}

impl WitnessTargetV1 {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = self.item_id.as_bytes().to_vec();
        optional_fixed(&mut output, self.field_id.as_ref().map(FieldId::as_bytes));
        output
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ManifestArgumentV1 {
    PublicLiteral { bytes: OperationBytes },
    SecretPlaceholder { target: WitnessTargetV1 },
}

impl ManifestArgumentV1 {
    fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        let mut output = Vec::new();
        match self {
            Self::PublicLiteral { bytes } => {
                output.push(1);
                bytes_field(&mut output, bytes.as_bytes())?;
            }
            Self::SecretPlaceholder { target } => {
                output.push(2);
                output.extend_from_slice(&target.canonical_bytes());
            }
        }
        Ok(output)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentInjectionV1 {
    pub name: BoundedBytes<128>,
    pub target: WitnessTargetV1,
}

impl EnvironmentInjectionV1 {
    fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        let mut output = Vec::new();
        bytes_field(&mut output, self.name.as_bytes())?;
        output.extend_from_slice(&self.target.canonical_bytes());
        Ok(output)
    }

    fn valid_name(&self) -> bool {
        let name = self.name.as_bytes();
        !name.is_empty()
            && name.len() <= 128
            && (name[0].is_ascii_alphabetic() || name[0] == b'_')
            && name[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OperationContextV1 {
    ReadStdout,
    WritePrivateFile,
    TemplateInjection,
    ChildEnvironment,
    ChildStdin,
    ItemMutation {
        mutation_kind: u8,
        affected_field_ids: Vec<FieldId>,
        proposed_public_revision_digest: Digest32,
    },
    Backup {
        scope: u8,
        archive_format: u16,
        destination_commitment: Digest32,
    },
    Recovery {
        mode: u8,
        destination_commitment: Digest32,
        next_item_access_mode: ItemAccessMode,
    },
    AdministrativeRekey {
        next_vault_policy_sequence: u64,
        next_vault_policy_hash: Digest32,
        next_witness_policy_id: WitnessPolicyId,
        next_witness_policy_revision: u64,
        next_witness_policy_digest: Digest32,
        rotation_record_digest: Digest32,
    },
}

impl OperationContextV1 {
    #[must_use]
    pub const fn operation(&self) -> WitnessOperationV1 {
        match self {
            Self::ReadStdout => WitnessOperationV1::ReadStdout,
            Self::WritePrivateFile => WitnessOperationV1::WritePrivateFile,
            Self::TemplateInjection => WitnessOperationV1::TemplateInjection,
            Self::ChildEnvironment => WitnessOperationV1::ChildEnvironment,
            Self::ChildStdin => WitnessOperationV1::ChildStdin,
            Self::ItemMutation { .. } => WitnessOperationV1::ItemMutation,
            Self::Backup { .. } => WitnessOperationV1::Backup,
            Self::Recovery { .. } => WitnessOperationV1::Recovery,
            Self::AdministrativeRekey { .. } => WitnessOperationV1::AdministrativeRekey,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        let suffix = match self {
            Self::ReadStdout => "read-stdout",
            Self::WritePrivateFile => "write-private-file",
            Self::TemplateInjection => "template-injection",
            Self::ChildEnvironment => "child-environment",
            Self::ChildStdin => "child-stdin",
            Self::ItemMutation { .. } => "item-mutation",
            Self::Backup { .. } => "backup",
            Self::Recovery { .. } => "recovery",
            Self::AdministrativeRekey { .. } => "administrative-rekey",
        };
        let mut output = jce(&format!("jury-witness-v1/operation-context/{suffix}"));
        output.extend_from_slice(&1_u16.to_be_bytes());
        match self {
            Self::ItemMutation {
                mutation_kind,
                affected_field_ids,
                proposed_public_revision_digest,
            } => {
                if !(1..=4).contains(mutation_kind)
                    || !strictly_sorted_unique(affected_field_ids, |left, right| left < right)
                {
                    return Err(WitnessProtocolError::new(
                        WitnessProtocolErrorKind::InvalidOrdering,
                    ));
                }
                output.push(*mutation_kind);
                list_fixed(&mut output, affected_field_ids, |output, id| {
                    output.extend_from_slice(id.as_bytes());
                })?;
                output.extend_from_slice(proposed_public_revision_digest.as_bytes());
            }
            Self::Backup {
                scope,
                archive_format,
                destination_commitment,
            } => {
                if !(1..=2).contains(scope) || *archive_format == 0 {
                    return Err(WitnessProtocolError::new(
                        WitnessProtocolErrorKind::InvalidFormat,
                    ));
                }
                output.push(*scope);
                output.extend_from_slice(&archive_format.to_be_bytes());
                output.extend_from_slice(destination_commitment.as_bytes());
            }
            Self::Recovery {
                mode,
                destination_commitment,
                next_item_access_mode,
            } => {
                if !(1..=2).contains(mode) {
                    return Err(WitnessProtocolError::new(
                        WitnessProtocolErrorKind::InvalidFormat,
                    ));
                }
                output.push(*mode);
                output.extend_from_slice(destination_commitment.as_bytes());
                output.push(next_item_access_mode.tag());
            }
            Self::AdministrativeRekey {
                next_vault_policy_sequence,
                next_vault_policy_hash,
                next_witness_policy_id,
                next_witness_policy_revision,
                next_witness_policy_digest,
                rotation_record_digest,
            } => {
                if *next_vault_policy_sequence == 0 || *next_witness_policy_revision == 0 {
                    return Err(WitnessProtocolError::new(
                        WitnessProtocolErrorKind::InvalidFormat,
                    ));
                }
                output.extend_from_slice(&next_vault_policy_sequence.to_be_bytes());
                output.extend_from_slice(next_vault_policy_hash.as_bytes());
                output.extend_from_slice(next_witness_policy_id.as_bytes());
                output.extend_from_slice(&next_witness_policy_revision.to_be_bytes());
                output.extend_from_slice(next_witness_policy_digest.as_bytes());
                output.extend_from_slice(rotation_record_digest.as_bytes());
            }
            Self::ReadStdout
            | Self::WritePrivateFile
            | Self::TemplateInjection
            | Self::ChildEnvironment
            | Self::ChildStdin => {}
        }
        Ok(output)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalTargetEntryV1 {
    pub item_id: ItemId,
    pub field_id: Option<FieldId>,
    pub presentation_commitment: Digest32,
}

impl ApprovalTargetEntryV1 {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = self.item_id.as_bytes().to_vec();
        optional_fixed(&mut output, self.field_id.as_ref().map(FieldId::as_bytes));
        output.extend_from_slice(self.presentation_commitment.as_bytes());
        output
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalTargetV1 {
    pub entries: Vec<ApprovalTargetEntryV1>,
    pub presentation_digest: Digest32,
}

impl ApprovalTargetV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        if self.entries.is_empty()
            || self.entries.len() > MAX_MANIFEST_TARGETS
            || !strictly_sorted_unique(&self.entries, |left, right| {
                (&left.item_id, &left.field_id) < (&right.item_id, &right.field_id)
            })
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidOrdering,
            ));
        }
        let entries = self
            .entries
            .iter()
            .map(ApprovalTargetEntryV1::canonical_bytes)
            .collect::<Vec<_>>();
        let mut output = Vec::new();
        list_bytes(&mut output, &entries)?;
        output.extend_from_slice(self.presentation_digest.as_bytes());
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_bytes(
            "jury-witness-v1/approval-target/hash",
            &self.canonical_bytes()?,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionManifestV1 {
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
    pub operation_context: OperationContextV1,
    pub approval_target: ApprovalTargetV1,
    pub approval_target_digest: Digest32,
    pub executable_identity: Option<OperationBytes>,
    pub arguments: Vec<ManifestArgumentV1>,
    pub working_directory_commitment: Option<Digest32>,
    pub environment_injections: Vec<EnvironmentInjectionV1>,
    pub stdin_target: Option<WitnessTargetV1>,
    pub stdin_mode: StdinModeV1,
    pub output_sink: OutputSinkV1,
    pub output_sink_commitment: Option<Digest32>,
    pub platform_assurance: PlatformAssuranceV1,
    pub timeout_ms: u64,
    pub output_limit_bytes: u32,
    pub issued_at_ms: u64,
    pub not_before_ms: Option<u64>,
    pub expires_at_ms: u64,
    pub presentation_digest: Digest32,
}

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
}

impl fmt::Debug for WitnessRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessRequestV1")
            .field("request_id", &self.request_id)
            .field("vault_id", &self.vault_id)
            .field("item_id", &self.item_id)
            .field("operation", &self.operation)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecisionV1 {
    pub schema: u16,
    pub approval_id: ApprovalId,
    pub request_id: RequestId,
    pub request_digest: Digest32,
    pub action_manifest_digest: Digest32,
    pub presentation_digest: Digest32,
    pub witness_policy_id: WitnessPolicyId,
    pub witness_policy_revision: u64,
    pub witness_policy_digest: Digest32,
    pub approver_id: PrincipalId,
    pub approver_key_fingerprint: Digest32,
    pub approver_key_epoch: u64,
    pub approval_mode: ApprovalModeV1,
    pub decision: ApprovalDecisionKindV1,
    pub reason: WitnessReasonV1,
    pub issued_at_ms: u64,
    pub not_before_ms: Option<u64>,
    pub expires_at_ms: u64,
    pub nonce: ApprovalId,
    pub intended_witness_set_digest: Digest32,
    pub signature: Signature64,
}

impl ApprovalDecisionV1 {
    fn append_fields(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.approval_id.as_bytes());
        output.extend_from_slice(self.request_id.as_bytes());
        output.extend_from_slice(self.request_digest.as_bytes());
        output.extend_from_slice(self.action_manifest_digest.as_bytes());
        output.extend_from_slice(self.presentation_digest.as_bytes());
        output.extend_from_slice(self.witness_policy_id.as_bytes());
        output.extend_from_slice(&self.witness_policy_revision.to_be_bytes());
        output.extend_from_slice(self.witness_policy_digest.as_bytes());
        output.extend_from_slice(self.approver_id.as_bytes());
        output.extend_from_slice(self.approver_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.approver_key_epoch.to_be_bytes());
        output.push(self.approval_mode.tag());
        output.push(self.decision.tag());
        output.push(self.reason.tag());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        optional_u64(output, self.not_before_ms);
        output.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        output.extend_from_slice(self.nonce.as_bytes());
        output.extend_from_slice(self.intended_witness_set_digest.as_bytes());
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/approval-decision/signature");
        self.append_fields(&mut output);
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = Vec::new();
        self.append_fields(&mut output);
        output.extend_from_slice(self.signature.as_bytes());
        if output.len() > MAX_APPROVAL_BYTES {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::CapacityExhausted,
            ));
        }
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_signed(
            "jury-witness-v1/approval-decision/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        let reason_valid = match self.decision {
            ApprovalDecisionKindV1::Approve => self.reason == WitnessReasonV1::None,
            ApprovalDecisionKindV1::Deny => self.reason != WitnessReasonV1::None,
        };
        if self.schema != 1
            || self.witness_policy_revision == 0
            || self.approver_key_epoch == 0
            || !reason_valid
            || !valid_interval(self.issued_at_ms, self.not_before_ms, self.expires_at_ms)
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ApprovalDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalDecisionV1")
            .field("approval_id", &self.approval_id)
            .field("request_id", &self.request_id)
            .field("approver_id", &self.approver_id)
            .field("decision", &self.decision)
            .field("reason", &self.reason)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CancellerRoleV1 {
    OriginalRequester,
    CurrentOwner,
}

impl CancellerRoleV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::OriginalRequester => 1,
            Self::CurrentOwner => 2,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestCancellationV1 {
    pub schema: u16,
    pub cancellation_id: CancellationId,
    pub request_signature_preimage: RequestBytes,
    pub client_signature: Signature64,
    pub request_id: RequestId,
    pub request_digest: Digest32,
    pub canceller_id: PrincipalId,
    pub canceller_key_fingerprint: Digest32,
    pub canceller_key_epoch: u64,
    pub canceller_role: CancellerRoleV1,
    pub issued_at_ms: u64,
    pub reason: WitnessReasonV1,
    pub nonce: CancellationId,
    pub signature: Signature64,
}

impl RequestCancellationV1 {
    fn append_fields(&self, output: &mut Vec<u8>) -> Result<(), WitnessProtocolError> {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.cancellation_id.as_bytes());
        bytes_field(output, self.request_signature_preimage.as_bytes())?;
        output.extend_from_slice(self.client_signature.as_bytes());
        output.extend_from_slice(self.request_id.as_bytes());
        output.extend_from_slice(self.request_digest.as_bytes());
        output.extend_from_slice(self.canceller_id.as_bytes());
        output.extend_from_slice(self.canceller_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.canceller_key_epoch.to_be_bytes());
        output.push(self.canceller_role.tag());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        output.push(self.reason.tag());
        output.extend_from_slice(self.nonce.as_bytes());
        Ok(())
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/cancellation/signature");
        self.append_fields(&mut output)?;
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = Vec::new();
        self.append_fields(&mut output)?;
        output.extend_from_slice(self.signature.as_bytes());
        if output.len() > 48 * 1024 {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::CapacityExhausted,
            ));
        }
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        hash_signed(
            "jury-witness-v1/cancellation/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        if self.schema != 1
            || self.canceller_key_epoch == 0
            || self.issued_at_ms == 0
            || self.reason != WitnessReasonV1::Cancelled
            || self.request_signature_preimage.is_empty()
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for RequestCancellationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestCancellationV1")
            .field("cancellation_id", &self.cancellation_id)
            .field("request_id", &self.request_id)
            .field("canceller_id", &self.canceller_id)
            .field("canceller_role", &self.canceller_role)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VaultPolicyCheckpointV1 {
    pub schema: u16,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub vault_policy_sequence: u64,
    pub vault_policy_hash: Digest32,
    pub witness_policy_id: WitnessPolicyId,
    pub witness_policy_revision: u64,
    pub witness_policy_digest: Digest32,
    pub witness_set_digest: Digest32,
    pub approver_set_digest: Digest32,
    pub review_label_set_digest: Digest32,
    pub predecessor_checkpoint_digest: Digest32,
    pub issued_at_ms: u64,
    pub issuer_owner_id: PrincipalId,
    pub issuer_key_fingerprint: Digest32,
    pub issuer_key_epoch: u64,
    pub signature: Signature64,
}

impl VaultPolicyCheckpointV1 {
    fn append_fields(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.genesis_fingerprint.as_bytes());
        output.extend_from_slice(&self.vault_policy_sequence.to_be_bytes());
        output.extend_from_slice(self.vault_policy_hash.as_bytes());
        output.extend_from_slice(self.witness_policy_id.as_bytes());
        output.extend_from_slice(&self.witness_policy_revision.to_be_bytes());
        output.extend_from_slice(self.witness_policy_digest.as_bytes());
        output.extend_from_slice(self.witness_set_digest.as_bytes());
        output.extend_from_slice(self.approver_set_digest.as_bytes());
        output.extend_from_slice(self.review_label_set_digest.as_bytes());
        output.extend_from_slice(self.predecessor_checkpoint_digest.as_bytes());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        output.extend_from_slice(self.issuer_owner_id.as_bytes());
        output.extend_from_slice(self.issuer_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.issuer_key_epoch.to_be_bytes());
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/checkpoint/signature");
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
            "jury-witness-v1/checkpoint/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        if self.schema != 1
            || self.vault_policy_sequence == 0
            || self.witness_policy_revision == 0
            || self.issued_at_ms == 0
            || self.issuer_key_epoch == 0
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for VaultPolicyCheckpointV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultPolicyCheckpointV1")
            .field("vault_id", &self.vault_id)
            .field("vault_policy_sequence", &self.vault_policy_sequence)
            .field("witness_policy_id", &self.witness_policy_id)
            .field("witness_policy_revision", &self.witness_policy_revision)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessContributionEnvelopeV1 {
    pub schema: u16,
    pub response_id: ResponseId,
    pub share_index: u8,
    pub share_commitment: Digest32,
    pub capsule_context_digest: Digest32,
    pub capsule_set_digest: Digest32,
    pub request_session_key_fingerprint: Digest32,
    pub encapsulation: Encapsulation1120,
    pub ciphertext: ShareCiphertext49,
}

impl WitnessContributionEnvelopeV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1_332);
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.response_id.as_bytes());
        output.push(self.share_index);
        output.extend_from_slice(self.share_commitment.as_bytes());
        output.extend_from_slice(self.capsule_context_digest.as_bytes());
        output.extend_from_slice(self.capsule_set_digest.as_bytes());
        output.extend_from_slice(self.request_session_key_fingerprint.as_bytes());
        output.extend_from_slice(self.encapsulation.as_bytes());
        output.extend_from_slice(self.ciphertext.as_bytes());
        output
    }

    pub fn digest(&self) -> Result<Digest32, WitnessProtocolError> {
        if self.schema != 1 || self.share_index == 0 || self.share_index > 32 {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        hash_bytes("jury-witness-v1/contribution/hash", &self.canonical_bytes())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessDecisionV1 {
    pub schema: u16,
    pub response_id: ResponseId,
    pub request_id: RequestId,
    pub request_digest: Digest32,
    pub action_manifest_digest: Digest32,
    pub witness_id: PrincipalId,
    pub witness_signing_key_fingerprint: Digest32,
    pub witness_signing_key_epoch: u64,
    pub witness_policy_id: WitnessPolicyId,
    pub witness_policy_revision: u64,
    pub witness_policy_digest: Digest32,
    pub policy_checkpoint_digest: Digest32,
    pub state_generation: u64,
    pub decision: WitnessDecisionKindV1,
    pub reason: WitnessReasonV1,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub contribution_digest: Option<Digest32>,
    pub share_index: Option<u8>,
    pub share_commitment: Option<Digest32>,
    pub signature: Signature64,
}

impl WitnessDecisionV1 {
    fn append_fields(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.response_id.as_bytes());
        output.extend_from_slice(self.request_id.as_bytes());
        output.extend_from_slice(self.request_digest.as_bytes());
        output.extend_from_slice(self.action_manifest_digest.as_bytes());
        output.extend_from_slice(self.witness_id.as_bytes());
        output.extend_from_slice(self.witness_signing_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.witness_signing_key_epoch.to_be_bytes());
        output.extend_from_slice(self.witness_policy_id.as_bytes());
        output.extend_from_slice(&self.witness_policy_revision.to_be_bytes());
        output.extend_from_slice(self.witness_policy_digest.as_bytes());
        output.extend_from_slice(self.policy_checkpoint_digest.as_bytes());
        output.extend_from_slice(&self.state_generation.to_be_bytes());
        output.push(self.decision.tag());
        output.push(self.reason.tag());
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        output.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        optional_fixed(
            output,
            self.contribution_digest.as_ref().map(FixedBytes::as_bytes),
        );
        optional_u8(output, self.share_index);
        optional_fixed(
            output,
            self.share_commitment.as_ref().map(FixedBytes::as_bytes),
        );
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        self.validate_shape()?;
        let mut output = jce("jury-witness-v1/decision/signature");
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
            "jury-witness-v1/decision/hash",
            &self.signature_preimage()?,
            &self.signature,
        )
    }

    pub fn validate_shape(&self) -> Result<(), WitnessProtocolError> {
        let approving = self.decision == WitnessDecisionKindV1::Approve;
        let contribution = self.contribution_digest.is_some()
            && self.share_index.is_some()
            && self.share_commitment.is_some();
        if self.schema != 1
            || self.witness_signing_key_epoch == 0
            || self.witness_policy_revision == 0
            || self.state_generation == 0
            || self.issued_at_ms == 0
            || self.expires_at_ms == 0
            || (approving && self.expires_at_ms <= self.issued_at_ms)
            || approving != contribution
            || (approving && self.reason != WitnessReasonV1::None)
            || (!approving && self.reason == WitnessReasonV1::None)
            || self
                .share_index
                .is_some_and(|index| index == 0 || index > 32)
        {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::InvalidFormat,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for WitnessDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessDecisionV1")
            .field("response_id", &self.response_id)
            .field("request_id", &self.request_id)
            .field("witness_id", &self.witness_id)
            .field("decision", &self.decision)
            .field("reason", &self.reason)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessResponseV1 {
    pub decision: WitnessDecisionV1,
    pub contribution: Option<WitnessContributionEnvelopeV1>,
}

impl WitnessResponseV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessProtocolError> {
        let mut output = self.decision.canonical_bytes()?;
        match (&self.decision.contribution_digest, &self.contribution) {
            (Some(expected), Some(contribution)) if contribution.digest()? == *expected => {
                output.extend_from_slice(&contribution.canonical_bytes());
            }
            (None, None) => {}
            _ => {
                return Err(WitnessProtocolError::new(
                    WitnessProtocolErrorKind::InvalidDigest,
                ));
            }
        }
        if output.len() > MAX_RESPONSE_BYTES {
            return Err(WitnessProtocolError::new(
                WitnessProtocolErrorKind::CapacityExhausted,
            ));
        }
        Ok(output)
    }
}

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

/// Computes the protocol signing-key fingerprint for one exact public key.
#[must_use]
pub fn signing_key_fingerprint(
    role_tag: u8,
    subject_id: &PrincipalId,
    key_epoch: u64,
    public_key: &VerificationPublicKey32,
) -> Digest32 {
    let mut output = jce("jury-witness-v1/signing-key/fingerprint");
    output.push(role_tag);
    output.extend_from_slice(subject_id.as_bytes());
    output.extend_from_slice(&key_epoch.to_be_bytes());
    output.extend_from_slice(public_key.as_bytes());
    digest(&output)
}

fn valid_interval(issued_at_ms: u64, not_before_ms: Option<u64>, expires_at_ms: u64) -> bool {
    issued_at_ms > 0
        && expires_at_ms
            .checked_sub(issued_at_ms)
            .is_some_and(|lifetime| (1..=MAX_REQUEST_LIFETIME_MS).contains(&lifetime))
        && not_before_ms
            .is_none_or(|not_before| issued_at_ms <= not_before && not_before <= expires_at_ms)
}

fn digest(bytes: &[u8]) -> Digest32 {
    FixedBytes::new(Sha256::digest(bytes).into())
}

fn hash_bytes(domain: &str, body: &[u8]) -> Result<Digest32, WitnessProtocolError> {
    let mut output = jce(domain);
    bytes_field(&mut output, body)?;
    Ok(digest(&output))
}

fn hash_signed(
    domain: &str,
    signature_preimage: &[u8],
    signature: &Signature64,
) -> Result<Digest32, WitnessProtocolError> {
    let mut output = jce(domain);
    bytes_field(&mut output, signature_preimage)?;
    output.extend_from_slice(signature.as_bytes());
    Ok(digest(&output))
}

fn bytes_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), WitnessProtocolError> {
    canonical::bytes_field(output, value).map_err(|_| capacity_exhausted())
}

fn list_bytes(output: &mut Vec<u8>, values: &[Vec<u8>]) -> Result<(), WitnessProtocolError> {
    canonical::list_bytes(output, values).map_err(|_| capacity_exhausted())
}

fn list_fixed<T>(
    output: &mut Vec<u8>,
    values: &[T],
    append: impl FnMut(&mut Vec<u8>, &T),
) -> Result<(), WitnessProtocolError> {
    canonical::list_fixed(output, values, append).map_err(|_| capacity_exhausted())
}

fn optional_fixed<const N: usize>(output: &mut Vec<u8>, value: Option<&[u8; N]>) {
    canonical::optional_fixed(output, value.map(<[u8; N]>::as_slice));
}

fn optional_bytes(output: &mut Vec<u8>, value: Option<&[u8]>) -> Result<(), WitnessProtocolError> {
    canonical::optional_bytes(output, value).map_err(|_| capacity_exhausted())
}

const fn capacity_exhausted() -> WitnessProtocolError {
    WitnessProtocolError::new(WitnessProtocolErrorKind::CapacityExhausted)
}

fn strictly_sorted_unique<T>(values: &[T], less_than: impl Fn(&T, &T) -> bool) -> bool {
    values.windows(2).all(|pair| less_than(&pair[0], &pair[1]))
}
