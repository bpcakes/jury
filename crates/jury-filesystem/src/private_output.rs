use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Write;
use std::path::Path;

use cap_fs_ext::{FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{OpenOptionsExt, PermissionsExt};
use jury_protected::ProtectedMemory;

use crate::capability::{FileIdentity, single_component};
use crate::{
    FilesystemError, FilesystemErrorKind, FilesystemOperation, HardenedStateRoot,
    RepositoryLocation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationPolicy {
    CreateNew,
    ReplaceExisting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationOutcome {
    PublishedAndSynced,
    PublishedButParentUnsynced,
    PublishedButTemporaryCleanupFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestinationState {
    Absent,
    Existing(DestinationIdentity),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DestinationIdentity {
    file: FileIdentity,
    byte_len: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl DestinationIdentity {
    #[cfg(unix)]
    fn from_metadata(metadata: &cap_std::fs::Metadata) -> Self {
        Self {
            file: FileIdentity::from_metadata(metadata),
            byte_len: metadata.len(),
            changed_seconds: cap_std::fs::MetadataExt::ctime(metadata),
            changed_nanoseconds: cap_std::fs::MetadataExt::ctime_nsec(metadata),
        }
    }
}

/// Opaque, single-use observation of one destination identity.
pub struct PrivateFilePrecondition {
    parent: Dir,
    destination: OsString,
    state: DestinationState,
    visibility: FileVisibility,
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
    temporary_identity: DestinationIdentity,
    expected: DestinationState,
    replace: bool,
    byte_len: usize,
    published: bool,
}

impl PreparedPrivateFile {
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
            contents,
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
        validate_expected(&self.parent, &self.destination, self.expected)?;
        validate_temporary(&self.parent, &self.temporary, self.temporary_identity)?;
        if self.replace {
            self.parent
                .rename(&self.temporary, &self.parent, &self.destination)
                .map_err(|_| {
                    FilesystemError::new(FilesystemOperation::Publish, FilesystemErrorKind::Io)
                })?;
        } else {
            self.parent
                .hard_link(&self.temporary, &self.parent, &self.destination)
                .map_err(|error| {
                    let kind = if error.kind() == std::io::ErrorKind::AlreadyExists {
                        FilesystemErrorKind::AlreadyExists
                    } else {
                        FilesystemErrorKind::Io
                    };
                    FilesystemError::new(FilesystemOperation::Publish, kind)
                })?;
            self.published = true;
            if self.parent.remove_file(&self.temporary).is_err() {
                let _ = parent_sync(&self.parent);
                return Ok(PublicationOutcome::PublishedButTemporaryCleanupFailed);
            }
        }
        self.published = true;
        match parent_sync(&self.parent) {
            Ok(()) => Ok(PublicationOutcome::PublishedAndSynced),
            Err(_) => Ok(PublicationOutcome::PublishedButParentUnsynced),
        }
    }
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
        if !self.published
            && validate_temporary(&self.parent, &self.temporary, self.temporary_identity).is_ok()
        {
            let _ = self.parent.remove_file(&self.temporary);
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

/// Retains a bounded public-file destination selected by an absolute direct
/// path. The parent is opened once and the leaf is never followed.
pub fn preview_public_file(path: &Path) -> Result<PrivateFilePrecondition, FilesystemError> {
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
}

fn preview_with_visibility(
    parent: &Dir,
    name: &Path,
    visibility: FileVisibility,
) -> Result<PrivateFilePrecondition, FilesystemError> {
    let destination = single_component(name, FilesystemOperation::Preview)?;
    let state = destination_state(parent, &destination, FilesystemOperation::Preview)?;
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

fn prepare(
    parent: Dir,
    name: &Path,
    contents: &ProtectedMemory,
    policy: PublicationPolicy,
    visibility: FileVisibility,
) -> Result<PreparedPrivateFile, FilesystemError> {
    let destination = single_component(name, FilesystemOperation::Prepare)?;
    let expected = destination_state(&parent, &destination, FilesystemOperation::Prepare)?;
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
    write_prepared(parent, destination, contents, expected, replace, visibility)
}

fn write_prepared(
    parent: Dir,
    destination: OsString,
    contents: &ProtectedMemory,
    expected: DestinationState,
    replace: bool,
    visibility: FileVisibility,
) -> Result<PreparedPrivateFile, FilesystemError> {
    #[cfg(not(unix))]
    {
        let _ = (parent, destination, contents, expected, replace, visibility);
        return Err(FilesystemError::new(
            FilesystemOperation::Prepare,
            FilesystemErrorKind::Unsupported,
        ));
    }

    #[cfg(unix)]
    {
        let temporary = temporary_name()?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(match visibility {
                FileVisibility::OwnerOnly => 0o600,
                FileVisibility::PublicEncryptedArtifact => 0o644,
            })
            .follow(FollowSymlinks::No);
        let mut file = parent.open_with(&temporary, &options).map_err(|_| {
            FilesystemError::new(FilesystemOperation::Prepare, FilesystemErrorKind::Io)
        })?;
        let write_result = contents.expose(|bytes| file.write_all(bytes));
        match write_result {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => {
                let _ = parent.remove_file(&temporary);
                return Err(FilesystemError::new(
                    FilesystemOperation::Prepare,
                    FilesystemErrorKind::Io,
                ));
            }
        }
        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                let _ = parent.remove_file(&temporary);
                return Err(FilesystemError::new(
                    FilesystemOperation::Prepare,
                    FilesystemErrorKind::Io,
                ));
            }
        };
        let mode = metadata.permissions().mode();
        let permissions_invalid = match visibility {
            FileVisibility::OwnerOnly => mode & 0o077 != 0,
            FileVisibility::PublicEncryptedArtifact => mode & 0o022 != 0,
        };
        if !metadata.is_file()
            || metadata.nlink() != 1
            || permissions_invalid
            || cap_std::fs::MetadataExt::uid(&metadata) != rustix::process::geteuid().as_raw()
        {
            let _ = parent.remove_file(&temporary);
            return Err(FilesystemError::new(
                FilesystemOperation::Prepare,
                FilesystemErrorKind::Permission,
            ));
        }
        if file.sync_all().is_err() {
            let _ = parent.remove_file(&temporary);
            return Err(FilesystemError::new(
                FilesystemOperation::Prepare,
                FilesystemErrorKind::Io,
            ));
        }
        Ok(PreparedPrivateFile {
            parent,
            destination,
            temporary,
            temporary_identity: DestinationIdentity::from_metadata(&metadata),
            expected,
            replace,
            byte_len: contents.len(),
            published: false,
        })
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
                Ok(DestinationState::Existing(
                    DestinationIdentity::from_metadata(&metadata),
                ))
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
    expected: DestinationIdentity,
) -> Result<(), FilesystemError> {
    let metadata = parent.symlink_metadata(temporary).map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::Publish,
            FilesystemErrorKind::IdentityChanged,
        )
    })?;
    if metadata.is_file()
        && metadata.nlink() == 1
        && DestinationIdentity::from_metadata(&metadata) == expected
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
    parent.open(".")?.sync_all()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use jury_protected::ProtectionPolicy;

    #[test]
    fn reports_publication_when_parent_sync_fails() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state = HardenedStateRoot::open_or_create(&temporary.path().join("state"), &[])?;
        let contents = ProtectedMemory::initialize(16, ProtectionPolicy::Strict, |destination| {
            destination.copy_from_slice(b"ExampleSecret123");
            Ok::<usize, ()>(destination.len())
        })?;
        let prepared = PreparedPrivateFile::prepare_state(
            &state,
            Path::new("value.bin"),
            &contents,
            PublicationPolicy::CreateNew,
        )?;
        let outcome = prepared.publish_with_sync(|_| Err(std::io::Error::other("injected")))?;
        assert_eq!(outcome, PublicationOutcome::PublishedButParentUnsynced);
        assert_eq!(
            std::fs::read(temporary.path().join("state/value.bin"))?,
            b"ExampleSecret123"
        );
        Ok(())
    }
}
