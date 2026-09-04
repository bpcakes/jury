//! Capability-held filesystem primitives for Jury.
//!
//! Jury is pre-alpha and these controls do not make it safe for real secrets.

#![forbid(unsafe_code)]

mod capability;
mod identity_selection;
mod local_state;
mod lock;
mod private_input;
mod private_output;
mod repository;
mod state_root;

use std::fmt;

pub use identity_selection::{
    IdentityName, IdentitySelectionError, IdentitySelector, MAX_NAMED_IDENTITIES,
    list_named_identities,
};
pub use local_state::{
    LockedPrincipalState, LockedVaultState, MAX_AUDIT_BYTES, MAX_CHECKPOINT_BYTES,
    MAX_POLICY_CATALOG_BYTES, MAX_RECEIPTS_BYTES, PrincipalStateDirectory, PrincipalStateFile,
    StatePathError, VaultStateDirectory, VaultStateFile, resolve_linux_state_root,
    resolve_state_root_from_environment,
};
pub use lock::{ExclusiveStateLock, LockError};
pub use private_input::{read_private_file, read_public_file};
pub use private_output::{
    PreparedPrivateFile, PreparedPublicFile, PrivateFilePrecondition, PublicFilePrecondition,
    PublicationOutcome, PublicationPolicy, preview_public_file,
};
pub use repository::RepositoryLocation;
pub use state_root::{HardenedStateRoot, PrivateFileCleanupOutcome};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemOperation {
    Open,
    DiscoverRepository,
    OpenStateRoot,
    Read,
    Preview,
    Prepare,
    Publish,
    SyncParent,
    Cleanup,
    Lock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemErrorKind {
    NotFound,
    Permission,
    Nul,
    Traversal,
    LinkOrWrongType,
    HardLinkOrSize,
    Capacity,
    Alias,
    Containment,
    IdentityChanged,
    InvalidMarker,
    AlreadyExists,
    Unsupported,
    Io,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FilesystemError {
    operation: FilesystemOperation,
    kind: FilesystemErrorKind,
}

impl FilesystemError {
    pub(crate) const fn new(operation: FilesystemOperation, kind: FilesystemErrorKind) -> Self {
        Self { operation, kind }
    }

    #[must_use]
    pub const fn operation(&self) -> FilesystemOperation {
        self.operation
    }

    #[must_use]
    pub const fn kind(&self) -> FilesystemErrorKind {
        self.kind
    }
}

impl fmt::Debug for FilesystemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilesystemError")
            .field("operation", &self.operation)
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for FilesystemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "filesystem {:?} failed: {:?}",
            self.operation, self.kind
        )
    }
}

impl std::error::Error for FilesystemError {}
