/// Digests the exact three-message witness-registration composite.
///
/// The bytes remain opaque at this protocol layer, but the digest framing is
/// frozen by protocol v1 and is also used by witness recovery records.
pub fn witness_registration_digest(
    registration: &RegistrationBytes,
) -> Result<Digest32, WitnessProtocolError> {
    if registration.is_empty() {
        return Err(invalid_format());
    }
    hash_bytes("jury-witness-v1/registration/hash", registration.as_bytes())
}

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
