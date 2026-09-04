use super::*;

#[derive(Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoreMarker {
    pub(super) version: u16,
    pub(super) transaction_id: String,
    pub(super) backup_id: String,
    pub(super) vault_target: String,
    pub(super) identity_target: String,
    pub(super) state_root: String,
    pub(super) vault_id: String,
    pub(super) genesis_fingerprint: String,
    pub(super) payload_digest: String,
    pub(super) timestamp_ms: u64,
    pub(super) identity_reused: bool,
    pub(super) identity_published: bool,
    pub(super) approver_identity_target: Option<String>,
    pub(super) approver_identity_published: bool,
    pub(super) witness_identity_target: Option<String>,
    pub(super) witness_identity_published: bool,
    pub(super) vault_published: bool,
    pub(super) state_published: bool,
}

pub(super) struct RestoreRequest<'a> {
    pub(super) cli: &'a Cli,
    pub(super) input: &'a Path,
    pub(super) target_home: &'a mut VaultHomeLocation,
    pub(super) source_home: Option<&'a VaultHomeLocation>,
    pub(super) identity_target: &'a Path,
    pub(super) approver_identity_target: Option<&'a Path>,
    pub(super) witness_identity_target: Option<&'a Path>,
    pub(super) reuse_identity: bool,
    pub(super) identity_profile: KdfProfile,
    pub(super) state_root: &'a Path,
    pub(super) require_absent_state_root: bool,
    pub(super) environment: &'a Environment,
    pub(super) protection: ProtectionPolicy,
    pub(super) validate_access: bool,
}

pub(super) struct RestoredInstallation {
    pub(super) header: jury_protocol::backup_v1::BackupHeaderV1,
    pub(super) coverage: RecoveryCoverage,
    pub(super) output_digest: Digest32,
    pub(super) marker_removed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::cli::backup_commands) enum RestorePublicationPoint {
    MarkerCreated,
    OwnerIdentityPublished,
    ApproverIdentityPublished,
    WitnessIdentityPublished,
    VaultPublished,
    StateFilePublished,
}
