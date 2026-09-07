use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::Path;

use cap_fs_ext::MetadataExt;
use cap_std::fs::Dir;
#[cfg(unix)]
use cap_std::fs::PermissionsExt;
use jury_protected::ProtectedMemory;

use crate::capability::{RegularFileSnapshot, single_component};

mod prepare;
use crate::{
    FilesystemError, FilesystemErrorKind, FilesystemOperation, HardenedStateRoot,
    RepositoryLocation,
};
use prepare::write_prepared;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationPolicy {
    CreateNew,
    ReplaceExisting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationOutcome {
    PublishedAndSynced,
    PublishedButParentUnsynced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestinationState {
    Absent,
    Existing(RegularFileSnapshot),
}

/// Opaque, single-use observation of one destination identity.
pub struct PrivateFilePrecondition {
    parent: Dir,
    destination: OsString,
    state: DestinationState,
    visibility: FileVisibility,
}

/// Opaque, single-use observation of a caller-selected public destination.
pub struct PublicFilePrecondition {
    inner: PrivateFilePrecondition,
}

impl PublicFilePrecondition {
    #[must_use]
    pub const fn destination_exists(&self) -> bool {
        self.inner.destination_exists()
    }
}

impl fmt::Debug for PublicFilePrecondition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicFilePrecondition")
            .field("destination_exists", &self.destination_exists())
            .field("destination", &"[REDACTED]")
            .finish()
    }
}

impl PrivateFilePrecondition {
    #[must_use]
    pub const fn destination_exists(&self) -> bool {
        matches!(self.state, DestinationState::Existing(_))
    }
}

impl fmt::Debug for PrivateFilePrecondition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateFilePrecondition")
            .field("destination_exists", &self.destination_exists())
            .field("destination", &"[REDACTED]")
            .finish()
    }
}

/// Fully written and file-synced sibling awaiting atomic namespace publication.
pub struct PreparedPrivateFile {
    parent: Dir,
    destination: OsString,
    temporary: OsString,
    temporary_identity: RegularFileSnapshot,
    file: cap_std::fs::File,
    expected: DestinationState,
    replace: bool,
    byte_len: usize,
    published: bool,
}

/// Fully written bounded public bytes awaiting atomic namespace publication.
pub struct PreparedPublicFile {
    inner: PreparedPrivateFile,
}

impl PreparedPublicFile {
    /// Prepares public bytes only if the destination still matches an earlier
    /// public preview. This path never routes ciphertext through secret memory.
    pub fn prepare_bounded_if_unchanged(
        precondition: PublicFilePrecondition,
        contents: &[u8],
        maximum_bytes: usize,
        allow_replace: bool,
    ) -> Result<Self, FilesystemError> {
        if contents.len() > maximum_bytes {
            return Err(FilesystemError::new(
                FilesystemOperation::Prepare,
                FilesystemErrorKind::HardLinkOrSize,
            ));
        }
        let precondition = precondition.inner;
        if precondition.destination_exists() && !allow_replace {
            return Err(FilesystemError::new(
                FilesystemOperation::Prepare,
                FilesystemErrorKind::AlreadyExists,
            ));
        }
        validate_expected(
            &precondition.parent,
            &precondition.destination,
            precondition.state,
        )?;
        let replace = precondition.destination_exists();
        write_prepared(
            precondition.parent,
            precondition.destination,
            PreparedContents::Public(contents),
            precondition.state,
            replace,
            FileVisibility::PublicEncryptedArtifact,
        )
        .map(|inner| Self { inner })
    }

    /// Atomically publishes the complete prepared bytes, then syncs the parent.
    pub fn publish(self) -> Result<PublicationOutcome, FilesystemError> {
        self.inner.publish()
    }
}

impl fmt::Debug for PreparedPublicFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPublicFile")
            .field("inner", &self.inner)
            .finish()
    }
}

impl PreparedPrivateFile {
    /// Prepares bounded non-plaintext bytes for an owner-only destination.
    /// This is used for already-encrypted large archives which must not become
    /// world-readable but need not consume protected-memory capacity.
    pub fn prepare_bounded_private_bytes_if_unchanged(
        precondition: PrivateFilePrecondition,
        contents: &[u8],
        maximum_bytes: usize,
        allow_replace: bool,
    ) -> Result<Self, FilesystemError> {
        if contents.len() > maximum_bytes {
            return Err(FilesystemError::new(
                FilesystemOperation::Prepare,
                FilesystemErrorKind::HardLinkOrSize,
            ));
        }
        if precondition.destination_exists() && !allow_replace {
            return Err(FilesystemError::new(
                FilesystemOperation::Prepare,
                FilesystemErrorKind::AlreadyExists,
            ));
        }
        validate_expected(
            &precondition.parent,
            &precondition.destination,
            precondition.state,
        )?;
        let replace = precondition.destination_exists();
        write_prepared(
            precondition.parent,
            precondition.destination,
            PreparedContents::Public(contents),
            precondition.state,
            replace,
            FileVisibility::OwnerOnly,
        )
    }

    /// Prepares private state below the separate hardened state root.
    pub fn prepare_state(
        state_root: &HardenedStateRoot,
        name: &Path,
        contents: &ProtectedMemory,
        policy: PublicationPolicy,
    ) -> Result<Self, FilesystemError> {
        let parent = state_root.root.dir.try_clone().map_err(|_| {
            FilesystemError::new(FilesystemOperation::Prepare, FilesystemErrorKind::Io)
        })?;
        prepare(parent, name, contents, policy, FileVisibility::OwnerOnly)
    }

    /// Prepares the encrypted shared artifact below a pre-existing hardened
    /// `.jury` worktree directory. No other worktree leaf is exposed here.
    pub fn prepare_encrypted_shared_artifact(
        repository: &RepositoryLocation,
        contents: &ProtectedMemory,
        policy: PublicationPolicy,
    ) -> Result<Self, FilesystemError> {
        let parent = repository.jury_dir_clone()?;
        prepare(
            parent,
            Path::new("vault.json"),
            contents,
            policy,
            FileVisibility::PublicEncryptedArtifact,
        )
    }

    /// Prepares only if the destination still matches an earlier preview.
    pub fn prepare_if_unchanged(
        precondition: PrivateFilePrecondition,
        contents: &ProtectedMemory,
        allow_replace: bool,
    ) -> Result<Self, FilesystemError> {
        if precondition.destination_exists() && !allow_replace {
            return Err(FilesystemError::new(
                FilesystemOperation::Prepare,
                FilesystemErrorKind::AlreadyExists,
            ));
        }
        validate_expected(
            &precondition.parent,
            &precondition.destination,
            precondition.state,
        )?;
        let replace = precondition.destination_exists();
        write_prepared(
            precondition.parent,
            precondition.destination,
            PreparedContents::Protected(contents),
            precondition.state,
            replace,
            precondition.visibility,
        )
    }

    /// Atomically publishes the complete prepared bytes, then syncs the parent.
    pub fn publish(self) -> Result<PublicationOutcome, FilesystemError> {
        self.publish_with_sync(sync_parent)
    }

    fn publish_with_sync(
        mut self,
        parent_sync: impl FnOnce(&Dir) -> std::io::Result<()>,
    ) -> Result<PublicationOutcome, FilesystemError> {
        crate::platform::validate_acl(&self.file, FilesystemOperation::Publish)?;
        crate::platform::validate_acl(&self.parent, FilesystemOperation::Publish)?;
        validate_expected(&self.parent, &self.destination, self.expected)?;
        validate_temporary(&self.parent, &self.temporary, self.temporary_identity)?;
        if self.replace {
            self.parent
                .rename(&self.temporary, &self.parent, &self.destination)
                .map_err(|_| {
                    FilesystemError::new(FilesystemOperation::Publish, FilesystemErrorKind::Io)
                })?;
        } else {
            rename_noreplace(&self.parent, &self.temporary, &self.destination)?;
        }
        self.published = true;
        match parent_sync(&self.parent) {
            Ok(()) => Ok(PublicationOutcome::PublishedAndSynced),
            Err(_) => Ok(PublicationOutcome::PublishedButParentUnsynced),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn rename_noreplace(
    parent: &Dir,
    source: &OsStr,
    destination: &OsStr,
) -> Result<(), FilesystemError> {
    use std::os::fd::AsFd as _;

    rustix::fs::renameat_with(
        parent.as_fd(),
        Path::new(source),
        parent.as_fd(),
        Path::new(destination),
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        let kind = match error {
            rustix::io::Errno::EXIST => FilesystemErrorKind::AlreadyExists,
            rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP => {
                FilesystemErrorKind::Unsupported
            }
            _ => FilesystemErrorKind::Io,
        };
        FilesystemError::new(FilesystemOperation::Publish, kind)
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn rename_noreplace(
    _parent: &Dir,
    _source: &OsStr,
    _destination: &OsStr,
) -> Result<(), FilesystemError> {
    Err(FilesystemError::new(
        FilesystemOperation::Publish,
        FilesystemErrorKind::Unsupported,
    ))
}

impl fmt::Debug for PreparedPrivateFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPrivateFile")
            .field("byte_len", &self.byte_len)
            .field("replace", &self.replace)
            .field("contents", &"[REDACTED]")
            .field("destination", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PreparedPrivateFile {
    fn drop(&mut self) {
        if !self.published {
            remove_owned_temporary(&self.parent, &self.temporary, &self.file);
        }
    }
}

pub(crate) fn preview(
    parent: &Dir,
    name: &Path,
) -> Result<PrivateFilePrecondition, FilesystemError> {
    preview_with_visibility(parent, name, FileVisibility::OwnerOnly)
}

pub(crate) fn preview_encrypted_shared_artifact(
    parent: &Dir,
    name: &Path,
) -> Result<PrivateFilePrecondition, FilesystemError> {
    preview_with_visibility(parent, name, FileVisibility::PublicEncryptedArtifact)
}

pub(crate) fn preview_public_in_dir(
    parent: &Dir,
    name: &Path,
) -> Result<PublicFilePrecondition, FilesystemError> {
    preview_with_visibility(parent, name, FileVisibility::PublicEncryptedArtifact)
        .map(|inner| PublicFilePrecondition { inner })
}

/// Retains a bounded public-file destination selected by an absolute direct
/// path. The parent is opened once and the leaf is never followed.
pub fn preview_public_file(path: &Path) -> Result<PublicFilePrecondition, FilesystemError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(FilesystemError::new(
            FilesystemOperation::Preview,
            FilesystemErrorKind::Traversal,
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        FilesystemError::new(FilesystemOperation::Preview, FilesystemErrorKind::Traversal)
    })?;
    let name = path.file_name().ok_or_else(|| {
        FilesystemError::new(FilesystemOperation::Preview, FilesystemErrorKind::Traversal)
    })?;
    let directory = crate::capability::open_absolute_dir(parent, FilesystemOperation::Preview)?;
    preview_with_visibility(
        &directory.dir,
        Path::new(name),
        FileVisibility::PublicEncryptedArtifact,
    )
    .map(|inner| PublicFilePrecondition { inner })
}

fn preview_with_visibility(
    parent: &Dir,
    name: &Path,
    visibility: FileVisibility,
) -> Result<PrivateFilePrecondition, FilesystemError> {
    let destination = single_component(name, FilesystemOperation::Preview)?;
    let state = destination_state(parent, &destination, FilesystemOperation::Preview)?;
    validate_existing_visibility(state, visibility)?;
    Ok(PrivateFilePrecondition {
        parent: parent.try_clone().map_err(|_| {
            FilesystemError::new(FilesystemOperation::Preview, FilesystemErrorKind::Io)
        })?,
        destination,
        state,
        visibility,
    })
}

#[derive(Clone, Copy)]
enum FileVisibility {
    OwnerOnly,
    PublicEncryptedArtifact,
}

#[derive(Clone, Copy)]
enum PreparedContents<'a> {
    Protected(&'a ProtectedMemory),
    Public(&'a [u8]),
}

impl PreparedContents<'_> {
    const fn len(&self) -> usize {
        match self {
            Self::Protected(contents) => contents.len(),
            Self::Public(contents) => contents.len(),
        }
    }
}

fn prepare(
    parent: Dir,
    name: &Path,
    contents: &ProtectedMemory,
    policy: PublicationPolicy,
    visibility: FileVisibility,
) -> Result<PreparedPrivateFile, FilesystemError> {
    let destination = single_component(name, FilesystemOperation::Prepare)?;
    let expected = destination_state(&parent, &destination, FilesystemOperation::Prepare)?;
    validate_existing_visibility(expected, visibility)?;
    let replace = match (policy, expected) {
        (PublicationPolicy::CreateNew, DestinationState::Absent) => false,
        (PublicationPolicy::CreateNew, DestinationState::Existing(_)) => {
            return Err(FilesystemError::new(
                FilesystemOperation::Prepare,
                FilesystemErrorKind::AlreadyExists,
            ));
        }
        (PublicationPolicy::ReplaceExisting, DestinationState::Existing(_)) => true,
        (PublicationPolicy::ReplaceExisting, DestinationState::Absent) => {
            return Err(FilesystemError::new(
                FilesystemOperation::Prepare,
                FilesystemErrorKind::NotFound,
            ));
        }
    };
    write_prepared(
        parent,
        destination,
        PreparedContents::Protected(contents),
        expected,
        replace,
        visibility,
    )
}

fn validate_existing_visibility(
    state: DestinationState,
    visibility: FileVisibility,
) -> Result<(), FilesystemError> {
    let DestinationState::Existing(snapshot) = state else {
        return Ok(());
    };
    #[cfg(not(unix))]
    {
        let _ = (snapshot, visibility);
        return Err(FilesystemError::new(
            FilesystemOperation::Preview,
            FilesystemErrorKind::Unsupported,
        ));
    }
    #[cfg(unix)]
    {
        let invalid_mode = match visibility {
            FileVisibility::OwnerOnly => snapshot.mode() & 0o077 != 0,
            FileVisibility::PublicEncryptedArtifact => snapshot.mode() & 0o022 != 0,
        };
        if invalid_mode || snapshot.owner() != rustix::process::geteuid().as_raw() {
            return Err(FilesystemError::new(
                FilesystemOperation::Preview,
                FilesystemErrorKind::Permission,
            ));
        }
        Ok(())
    }
}

fn destination_state(
    parent: &Dir,
    name: &OsStr,
    operation: FilesystemOperation,
) -> Result<DestinationState, FilesystemError> {
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.is_file() && metadata.nlink() == 1 => {
            #[cfg(unix)]
            {
                let snapshot = RegularFileSnapshot::from_metadata(&metadata);
                validate_destination_acl(parent, name, snapshot, operation)?;
                Ok(DestinationState::Existing(snapshot))
            }
            #[cfg(not(unix))]
            {
                let _ = metadata;
                Err(FilesystemError::new(
                    operation,
                    FilesystemErrorKind::Unsupported,
                ))
            }
        }
        Ok(_) => Err(FilesystemError::new(
            operation,
            FilesystemErrorKind::LinkOrWrongType,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(DestinationState::Absent),
        Err(_) => Err(FilesystemError::new(operation, FilesystemErrorKind::Io)),
    }
}

fn validate_expected(
    parent: &Dir,
    destination: &OsStr,
    expected: DestinationState,
) -> Result<(), FilesystemError> {
    let current = destination_state(parent, destination, FilesystemOperation::Publish)?;
    if current == expected {
        Ok(())
    } else {
        Err(FilesystemError::new(
            FilesystemOperation::Publish,
            FilesystemErrorKind::IdentityChanged,
        ))
    }
}

fn validate_temporary(
    parent: &Dir,
    temporary: &OsStr,
    expected: RegularFileSnapshot,
) -> Result<(), FilesystemError> {
    let metadata = parent.symlink_metadata(temporary).map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::Publish,
            FilesystemErrorKind::IdentityChanged,
        )
    })?;
    if metadata.is_file()
        && metadata.nlink() == 1
        && RegularFileSnapshot::from_metadata(&metadata) == expected
    {
        Ok(())
    } else {
        Err(FilesystemError::new(
            FilesystemOperation::Publish,
            FilesystemErrorKind::IdentityChanged,
        ))
    }
}

fn temporary_name() -> Result<OsString, FilesystemError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| FilesystemError::new(FilesystemOperation::Prepare, FilesystemErrorKind::Io))?;
    let mut name = String::from(".jury-private-");
    for byte in random {
        use std::fmt::Write as _;
        let _ = write!(&mut name, "{byte:02x}");
    }
    name.push_str(".tmp");
    Ok(OsString::from(name))
}

fn sync_parent(parent: &Dir) -> std::io::Result<()> {
    crate::platform::sync_parent(parent)
}

#[cfg(all(test, unix))]
mod tests;

#[cfg(all(test, target_os = "macos"))]
mod macos_tests;

fn validate_destination_acl(
    parent: &Dir,
    name: &OsStr,
    expected: RegularFileSnapshot,
    operation: FilesystemOperation,
) -> Result<(), FilesystemError> {
    #[cfg(target_os = "macos")]
    {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        let mut options = cap_std::fs::OpenOptions::new();
        use cap_std::fs::OpenOptionsExt;
        options
            .read(true)
            .follow(FollowSymlinks::No)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits().cast_signed());
        let file = parent
            .open_with(name, &options)
            .map_err(|_| FilesystemError::new(operation, FilesystemErrorKind::Io))?;
        let observed = file
            .metadata()
            .map_err(|_| FilesystemError::new(operation, FilesystemErrorKind::Io))?;
        if !observed.is_file()
            || observed.nlink() != 1
            || RegularFileSnapshot::from_metadata(&observed) != expected
        {
            return Err(FilesystemError::new(
                operation,
                FilesystemErrorKind::IdentityChanged,
            ));
        }
        crate::platform::validate_acl(&file, operation)?;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (parent, name, expected, operation);
    Ok(())
}

#[cfg(not(unix))]
fn write_prepared(
    _parent: Dir,
    _destination: OsString,
    _contents: PreparedContents<'_>,
    _expected: DestinationState,
    _replace: bool,
    _visibility: FileVisibility,
) -> Result<PreparedPrivateFile, FilesystemError> {
    Err(FilesystemError::new(
        FilesystemOperation::Prepare,
        FilesystemErrorKind::Unsupported,
    ))
}

fn remove_owned_temporary(parent: &Dir, name: &OsStr, file: &cap_std::fs::File) {
    use crate::capability::FileIdentity;
    // Cleanup asks whether we still own this inode, not whether its contents
    // or ACL stayed unchanged. Keep the descriptor alive to prevent inode reuse.
    let (Ok(held), Ok(named)) = (file.metadata(), parent.symlink_metadata(name)) else {
        return;
    };
    if named.is_file() && FileIdentity::from_metadata(&held) == FileIdentity::from_metadata(&named)
    {
        let _ = parent.remove_file(name);
    }
}
