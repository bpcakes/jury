use std::fmt;

use jury_protocol::backup_v1::BackupFormatError;

use crate::{
    crypto::CryptoError,
    identity::{IdentityError, IdentityErrorKind},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupErrorKind {
    InvalidFormat,
    InvalidVault,
    InvalidCatalog,
    InvalidLocalState,
    AuthenticationFailed,
    InvalidPassphrase,
    IdentityMismatch,
    UnauthorizedOwner,
    OwnerRequired,
    DuplicateRole,
    DirectRecoveryUnavailable,
    StaleCheckpoint,
    NonCanonicalPadding,
    EntropyUnavailable,
    ProtectionUnavailable,
    ResourceUnavailable,
    CapacityExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupCapacityClass {
    Envelope,
    Vault,
    Catalog,
    Identity,
    Audit,
    Checkpoint,
    Receipts,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BackupError {
    kind: BackupErrorKind,
    capacity_class: Option<BackupCapacityClass>,
}

impl BackupError {
    pub(super) const fn new(kind: BackupErrorKind) -> Self {
        Self {
            kind,
            capacity_class: None,
        }
    }

    pub(super) const fn capacity(class: BackupCapacityClass) -> Self {
        Self {
            kind: BackupErrorKind::CapacityExhausted,
            capacity_class: Some(class),
        }
    }

    #[must_use]
    pub const fn kind(self) -> BackupErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn capacity_class(self) -> Option<BackupCapacityClass> {
        self.capacity_class
    }
}

impl fmt::Debug for BackupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("BackupError");
        debug.field("kind", &self.kind);
        if let Some(capacity_class) = self.capacity_class {
            debug.field("capacity_class", &capacity_class);
        }
        debug.finish()
    }
}

impl fmt::Display for BackupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            BackupErrorKind::InvalidFormat => "backup recovery payload is invalid",
            BackupErrorKind::InvalidVault => "backup vault state is invalid",
            BackupErrorKind::InvalidCatalog => "backup policy catalog is invalid",
            BackupErrorKind::InvalidLocalState => "backup local state is invalid",
            BackupErrorKind::AuthenticationFailed => "backup authentication failed",
            BackupErrorKind::InvalidPassphrase => {
                "backup passphrase does not meet the exact profile"
            }
            BackupErrorKind::IdentityMismatch => {
                "backup identity differs from authenticated policy"
            }
            BackupErrorKind::UnauthorizedOwner => "backup creator is not an active owner",
            BackupErrorKind::OwnerRequired => "backup requires one active vault-principal owner",
            BackupErrorKind::DuplicateRole => "backup role selection is duplicated",
            BackupErrorKind::DirectRecoveryUnavailable => {
                "owner direct recovery material is incomplete"
            }
            BackupErrorKind::StaleCheckpoint => "backup checkpoint is not current",
            BackupErrorKind::NonCanonicalPadding => "backup padding is invalid",
            BackupErrorKind::EntropyUnavailable => "backup entropy was unavailable",
            BackupErrorKind::ProtectionUnavailable => {
                "backup private-memory protection is unavailable"
            }
            BackupErrorKind::ResourceUnavailable => {
                "backup cryptographic resources are unavailable"
            }
            BackupErrorKind::CapacityExhausted => "backup exceeds a hard capacity",
        })
    }
}

impl std::error::Error for BackupError {}

pub(super) const fn map_format_error(error: BackupFormatError) -> BackupError {
    let kind = match error {
        BackupFormatError::ArtifactTooLarge | BackupFormatError::ResourceUnavailable => {
            return BackupError::capacity(BackupCapacityClass::Envelope);
        }
        BackupFormatError::UnsupportedProfile => BackupErrorKind::InvalidFormat,
        _ => BackupErrorKind::InvalidFormat,
    };
    BackupError::new(kind)
}

pub(super) const fn map_identity_error(error: IdentityError) -> BackupError {
    BackupError::new(match error.kind() {
        IdentityErrorKind::InvalidPassphrase => BackupErrorKind::InvalidPassphrase,
        IdentityErrorKind::AuthenticationFailed => BackupErrorKind::AuthenticationFailed,
        IdentityErrorKind::EntropyUnavailable | IdentityErrorKind::RetryExhausted => {
            BackupErrorKind::EntropyUnavailable
        }
        IdentityErrorKind::ResourceUnavailable => BackupErrorKind::ResourceUnavailable,
        IdentityErrorKind::ProtectionUnavailable => BackupErrorKind::ProtectionUnavailable,
        _ => BackupErrorKind::InvalidFormat,
    })
}

pub(super) const fn map_crypto_error(error: CryptoError) -> BackupError {
    BackupError::new(match error {
        CryptoError::EntropyUnavailable => BackupErrorKind::EntropyUnavailable,
        CryptoError::MemoryProtection => BackupErrorKind::ProtectionUnavailable,
        CryptoError::ResourceUnavailable => BackupErrorKind::ResourceUnavailable,
        CryptoError::AuthenticationFailed => BackupErrorKind::AuthenticationFailed,
        CryptoError::ProviderFailure => BackupErrorKind::InvalidFormat,
    })
}
