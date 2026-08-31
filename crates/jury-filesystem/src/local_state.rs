use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};

use jury_protected::ProtectedMemory;

use crate::{
    ExclusiveStateLock, FilesystemError, HardenedStateRoot, PreparedPrivateFile,
    PrivateFilePrecondition, PublicationOutcome, RepositoryLocation,
};

pub const MAX_CHECKPOINT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_AUDIT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_RECEIPTS_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatePathError {
    Unsupported,
    MissingHome,
    NotAbsolute,
    Nul,
}

impl fmt::Display for StatePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unsupported => "the platform state root is unsupported",
            Self::MissingHome => "the platform state root has no home directory",
            Self::NotAbsolute => "the platform state root is not absolute",
            Self::Nul => "the platform state root contains a NUL byte",
        })
    }
}

impl std::error::Error for StatePathError {}

/// Resolves the Linux state-root contract from caller-supplied environment
/// values. This function does not read process-global environment state.
pub fn resolve_linux_state_root(
    jury_state_home: Option<&OsStr>,
    xdg_state_home: Option<&OsStr>,
    user_home: Option<&OsStr>,
) -> Result<PathBuf, StatePathError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (jury_state_home, xdg_state_home, user_home);
        return Err(StatePathError::Unsupported);
    }
    #[cfg(target_os = "linux")]
    {
        let path = if let Some(path) = jury_state_home.filter(|value| !value.is_empty()) {
            PathBuf::from(path)
        } else if let Some(path) = xdg_state_home.filter(|value| !value.is_empty()) {
            PathBuf::from(path).join("jury/vaults")
        } else {
            PathBuf::from(user_home.ok_or(StatePathError::MissingHome)?)
                .join(".local/state/jury/vaults")
        };
        validate_resolved_path(path)
    }
}

/// Reads the state-root inputs once and applies [`resolve_linux_state_root`].
pub fn resolve_state_root_from_environment() -> Result<PathBuf, StatePathError> {
    let jury = std::env::var_os("JURY_STATE_HOME");
    let xdg = std::env::var_os("XDG_STATE_HOME");
    let home = std::env::var_os("HOME");
    resolve_linux_state_root(jury.as_deref(), xdg.as_deref(), home.as_deref())
}

fn validate_resolved_path(path: PathBuf) -> Result<PathBuf, StatePathError> {
    if !path.is_absolute() {
        return Err(StatePathError::NotAbsolute);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        if path.as_os_str().as_bytes().contains(&0) {
            return Err(StatePathError::Nul);
        }
    }
    #[cfg(not(unix))]
    if path.to_string_lossy().contains('\0') {
        return Err(StatePathError::Nul);
    }
    Ok(path)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalStateFile {
    Audit,
    Checkpoint,
    Receipts,
}

impl PrincipalStateFile {
    const fn name(self) -> &'static str {
        match self {
            Self::Audit => "audit.jsonl",
            Self::Checkpoint => "checkpoint.json",
            Self::Receipts => "receipts.json",
        }
    }

    const fn maximum_bytes(self) -> usize {
        match self {
            Self::Audit => MAX_AUDIT_BYTES,
            Self::Checkpoint => MAX_CHECKPOINT_BYTES,
            Self::Receipts => MAX_RECEIPTS_BYTES,
        }
    }
}

/// Capability for one vault/genesis/principal state tuple.
pub struct PrincipalStateDirectory {
    root: HardenedStateRoot,
}

impl PrincipalStateDirectory {
    pub fn open_or_create(
        state_root: &Path,
        vault_id: &[u8; 32],
        genesis_fingerprint: &[u8; 32],
        principal_id: &[u8; 32],
        repositories: &[&RepositoryLocation],
        vault_homes: &[&Path],
    ) -> Result<Self, FilesystemError> {
        let root =
            HardenedStateRoot::open_or_create_excluding(state_root, repositories, vault_homes)?;
        let root = descend_hex(&root, vault_id)?;
        let root = descend_hex(&root, genesis_fingerprint)?;
        let root = descend_hex(&root, principal_id)?;
        Ok(Self { root })
    }

    pub fn try_lock(&self) -> Result<LockedPrincipalState<'_>, crate::LockError> {
        let lock = ExclusiveStateLock::try_acquire(&self.root, Path::new("local-state.lock"))?;
        Ok(LockedPrincipalState {
            directory: self,
            _lock: lock,
        })
    }
}

impl fmt::Debug for PrincipalStateDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrincipalStateDirectory")
            .field("path", &"[REDACTED]")
            .finish()
    }
}

pub struct LockedPrincipalState<'a> {
    directory: &'a PrincipalStateDirectory,
    _lock: ExclusiveStateLock,
}

impl LockedPrincipalState<'_> {
    pub fn read(&self, file: PrincipalStateFile) -> Result<Vec<u8>, FilesystemError> {
        self.directory
            .root
            .read_private_file(Path::new(file.name()), file.maximum_bytes())
    }

    pub fn preview(
        &self,
        file: PrincipalStateFile,
    ) -> Result<PrivateFilePrecondition, FilesystemError> {
        self.directory
            .root
            .preview_private_file(Path::new(file.name()))
    }

    pub fn prepare(
        &self,
        file: PrincipalStateFile,
        contents: &ProtectedMemory,
    ) -> Result<PreparedPrivateFile, FilesystemError> {
        if contents.len() > file.maximum_bytes() {
            return Err(FilesystemError::new(
                crate::FilesystemOperation::Prepare,
                crate::FilesystemErrorKind::HardLinkOrSize,
            ));
        }
        let precondition = self.preview(file)?;
        PreparedPrivateFile::prepare_if_unchanged(precondition, contents, true)
    }

    pub fn publish(
        &self,
        file: PrincipalStateFile,
        contents: &ProtectedMemory,
    ) -> Result<PublicationOutcome, FilesystemError> {
        self.prepare(file, contents)?.publish()
    }
}

impl fmt::Debug for LockedPrincipalState<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedPrincipalState")
            .field("path", &"[REDACTED]")
            .finish()
    }
}

fn descend_hex(
    parent: &HardenedStateRoot,
    bytes: &[u8; 32],
) -> Result<HardenedStateRoot, FilesystemError> {
    let mut name = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut name, "{byte:02x}");
    }
    parent.open_or_create_private_child(Path::new(&name))
}
