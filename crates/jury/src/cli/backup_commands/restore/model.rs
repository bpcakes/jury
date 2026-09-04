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
    pub(super) mode: RestoreMode<'a>,
    pub(super) identity_target: RestoreIdentityTarget<'a>,
    pub(super) approver_identity_target: Option<&'a Path>,
    pub(super) witness_identity_target: Option<&'a Path>,
    pub(super) identity_profile: KdfProfile,
    pub(super) state_root: &'a Path,
    pub(super) environment: &'a Environment,
    pub(super) protection: ProtectionPolicy,
}

pub(super) enum RestoreMode<'a> {
    Installation,
    Drill {
        source_home: &'a VaultHomeLocation,
        expected: RestoreSourceExpectation,
    },
}

pub(super) struct RestoreSourceExpectation {
    pub(super) vault_id: jury_protocol::vault_v1::VaultId,
    pub(super) genesis_fingerprint: Digest32,
    pub(super) owner_principal_id: PrincipalId,
}

impl RestoreMode<'_> {
    pub(super) const fn source_home(&self) -> Option<&VaultHomeLocation> {
        match self {
            Self::Installation => None,
            Self::Drill { source_home, .. } => Some(source_home),
        }
    }

    pub(super) const fn requires_absent_state_root(&self) -> bool {
        matches!(self, Self::Drill { .. })
    }

    pub(super) const fn validates_access(&self) -> bool {
        matches!(self, Self::Drill { .. })
    }

    pub(super) fn validate_recovered(
        &self,
        recovered: &jury_core::backup::RecoveredBackup,
    ) -> Result<(), CliError> {
        let Self::Drill { expected, .. } = self else {
            return Ok(());
        };
        if recovered.header().vault_id != expected.vault_id
            || recovered.header().genesis_fingerprint != expected.genesis_fingerprint
            || recovered.header().owner_principal_id != expected.owner_principal_id
        {
            return Err(CliError::new(
                CliErrorKind::Conflict,
                "drill-source-mismatch",
                "the backup does not match the selected source owner and vault",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RestoreIdentityTarget<'a> {
    Create(&'a Path),
    Reuse(&'a Path),
}

impl<'a> RestoreIdentityTarget<'a> {
    pub(super) const fn path(self) -> &'a Path {
        match self {
            Self::Create(path) | Self::Reuse(path) => path,
        }
    }

    pub(super) const fn is_reuse(self) -> bool {
        matches!(self, Self::Reuse(_))
    }
}

pub(super) struct RestoredInstallation {
    pub(super) header: jury_protocol::backup_v1::BackupHeaderV1,
    pub(super) coverage: RecoveryCoverage,
    pub(super) output_digest: Digest32,
    pub(super) marker_removed: bool,
    pub(super) protection_degraded: bool,
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
