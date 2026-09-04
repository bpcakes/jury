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
pub const MAX_POLICY_CATALOG_BYTES: usize = 4 * 1024 * 1024;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultStateFile {
    PolicyCatalog,
}

impl VaultStateFile {
    const fn name(self) -> &'static str {
        match self {
            Self::PolicyCatalog => "policy-catalog.json",
        }
    }

    const fn maximum_bytes(self) -> usize {
        match self {
            Self::PolicyCatalog => MAX_POLICY_CATALOG_BYTES,
        }
    }
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

/// Capability for one vault/genesis state tuple. Its edit lock is shared by
/// every principal and every linked worktree for that vault lineage.
pub struct VaultStateDirectory {
    root: HardenedStateRoot,
}

impl VaultStateDirectory {
    pub fn open_existing(
        state_root: &Path,
        vault_id: &[u8; 32],
        genesis_fingerprint: &[u8; 32],
        repositories: &[&RepositoryLocation],
    ) -> Result<Self, FilesystemError> {
        Self::open_existing_excluding(state_root, vault_id, genesis_fingerprint, repositories, &[])
    }

    pub fn open_existing_excluding(
        state_root: &Path,
        vault_id: &[u8; 32],
        genesis_fingerprint: &[u8; 32],
        repositories: &[&RepositoryLocation],
        excluded_paths: &[&Path],
    ) -> Result<Self, FilesystemError> {
        let root =
            HardenedStateRoot::open_existing_excluding(state_root, repositories, excluded_paths)?;
        let root = descend_hex_existing(&root, vault_id)?;
        let root = descend_hex_existing(&root, genesis_fingerprint)?;
        Ok(Self { root })
    }

    pub fn open_or_create(
        state_root: &Path,
        vault_id: &[u8; 32],
        genesis_fingerprint: &[u8; 32],
        repositories: &[&RepositoryLocation],
        vault_homes: &[&Path],
    ) -> Result<Self, FilesystemError> {
        let root = open_vault_scope(
            state_root,
            vault_id,
            genesis_fingerprint,
            repositories,
            vault_homes,
        )?;
        Ok(Self { root })
    }

    pub fn try_lock(&self) -> Result<LockedVaultState<'_>, crate::LockError> {
        let lock = ExclusiveStateLock::try_acquire(&self.root, Path::new("vault-edit.lock"))?;
        Ok(LockedVaultState {
            directory: self,
            _lock: lock,
        })
    }

    /// Reads one existing principal-local file without creating state. The
    /// underlying bounded read rejects links, aliases, permission drift, and
    /// identity changes while the file is open.
    pub fn read_principal_state(
        &self,
        principal_id: &[u8; 32],
        file: PrincipalStateFile,
    ) -> Result<Vec<u8>, FilesystemError> {
        read_state_file(
            &principal_root_existing(&self.root, principal_id)?,
            file.name(),
            file.maximum_bytes(),
        )
    }

    pub fn read_vault_state(&self, file: VaultStateFile) -> Result<Vec<u8>, FilesystemError> {
        read_state_file(&self.root, file.name(), file.maximum_bytes())
    }
}

impl fmt::Debug for VaultStateDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultStateDirectory")
            .field("path", &"[REDACTED]")
            .finish()
    }
}

pub struct LockedVaultState<'a> {
    directory: &'a VaultStateDirectory,
    _lock: ExclusiveStateLock,
}

impl LockedVaultState<'_> {
    pub fn read(
        &self,
        principal_id: &[u8; 32],
        file: PrincipalStateFile,
    ) -> Result<Vec<u8>, FilesystemError> {
        read_state_file(
            &principal_root(&self.directory.root, principal_id)?,
            file.name(),
            file.maximum_bytes(),
        )
    }

    pub fn preview(
        &self,
        principal_id: &[u8; 32],
        file: PrincipalStateFile,
    ) -> Result<PrivateFilePrecondition, FilesystemError> {
        principal_root(&self.directory.root, principal_id)?
            .preview_private_file(Path::new(file.name()))
    }

    pub fn prepare(
        &self,
        principal_id: &[u8; 32],
        file: PrincipalStateFile,
        contents: &ProtectedMemory,
    ) -> Result<PreparedPrivateFile, FilesystemError> {
        prepare_state_file(
            || self.preview(principal_id, file),
            file.maximum_bytes(),
            contents,
        )
    }

    pub fn publish(
        &self,
        principal_id: &[u8; 32],
        file: PrincipalStateFile,
        contents: &ProtectedMemory,
    ) -> Result<PublicationOutcome, FilesystemError> {
        self.prepare(principal_id, file, contents)?.publish()
    }

    pub fn read_vault_state(&self, file: VaultStateFile) -> Result<Vec<u8>, FilesystemError> {
        read_state_file(&self.directory.root, file.name(), file.maximum_bytes())
    }

    pub fn prepare_vault_state(
        &self,
        file: VaultStateFile,
        contents: &ProtectedMemory,
    ) -> Result<PreparedPrivateFile, FilesystemError> {
        prepare_state_file(
            || {
                self.directory
                    .root
                    .preview_private_file(Path::new(file.name()))
            },
            file.maximum_bytes(),
            contents,
        )
    }
}

impl fmt::Debug for LockedVaultState<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedVaultState")
            .field("path", &"[REDACTED]")
            .finish()
    }
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
        let root = open_vault_scope(
            state_root,
            vault_id,
            genesis_fingerprint,
            repositories,
            vault_homes,
        )?;
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
        read_state_file(&self.directory.root, file.name(), file.maximum_bytes())
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
        prepare_state_file(|| self.preview(file), file.maximum_bytes(), contents)
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

fn open_vault_scope(
    state_root: &Path,
    vault_id: &[u8; 32],
    genesis_fingerprint: &[u8; 32],
    repositories: &[&RepositoryLocation],
    vault_homes: &[&Path],
) -> Result<HardenedStateRoot, FilesystemError> {
    let root = HardenedStateRoot::open_or_create_excluding(state_root, repositories, vault_homes)?;
    let root = descend_hex(&root, vault_id)?;
    descend_hex(&root, genesis_fingerprint)
}

fn read_state_file(
    root: &HardenedStateRoot,
    name: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, FilesystemError> {
    root.read_private_file(Path::new(name), maximum_bytes)
}

fn prepare_state_file(
    preview: impl FnOnce() -> Result<PrivateFilePrecondition, FilesystemError>,
    maximum_bytes: usize,
    contents: &ProtectedMemory,
) -> Result<PreparedPrivateFile, FilesystemError> {
    if contents.len() > maximum_bytes {
        return Err(FilesystemError::new(
            crate::FilesystemOperation::Prepare,
            crate::FilesystemErrorKind::HardLinkOrSize,
        ));
    }
    PreparedPrivateFile::prepare_if_unchanged(preview()?, contents, true)
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

fn descend_hex_existing(
    parent: &HardenedStateRoot,
    bytes: &[u8; 32],
) -> Result<HardenedStateRoot, FilesystemError> {
    let mut name = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut name, "{byte:02x}");
    }
    parent.open_private_child(Path::new(&name))
}

fn principal_root(
    root: &HardenedStateRoot,
    principal_id: &[u8; 32],
) -> Result<HardenedStateRoot, FilesystemError> {
    descend_hex(root, principal_id)
}

fn principal_root_existing(
    root: &HardenedStateRoot,
    principal_id: &[u8; 32],
) -> Result<HardenedStateRoot, FilesystemError> {
    descend_hex_existing(root, principal_id)
}
