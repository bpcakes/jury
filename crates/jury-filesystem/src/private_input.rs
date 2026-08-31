use std::io::Read as _;
use std::path::Path;

use cap_fs_ext::{FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _};
#[cfg(unix)]
use cap_std::fs::PermissionsExt as _;
use cap_std::fs::{Metadata, OpenOptions};

use crate::capability::{FileIdentity, single_component};
use cap_std::fs::Dir;

use crate::{FilesystemError, FilesystemErrorKind, FilesystemOperation, HardenedStateRoot};

#[derive(Clone, Copy, Eq, PartialEq)]
struct ReadSnapshot {
    identity: FileIdentity,
    byte_len: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl ReadSnapshot {
    #[cfg(unix)]
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            identity: FileIdentity::from_metadata(metadata),
            byte_len: metadata.len(),
            changed_seconds: cap_std::fs::MetadataExt::ctime(metadata),
            changed_nanoseconds: cap_std::fs::MetadataExt::ctime_nsec(metadata),
        }
    }
}

pub(crate) fn read(
    root: &HardenedStateRoot,
    name: &Path,
    maximum_bytes: usize,
) -> Result<Vec<u8>, FilesystemError> {
    read_from_dir(&root.root.dir, name, maximum_bytes)
}

pub(crate) fn read_from_dir(
    directory: &Dir,
    name: &Path,
    maximum_bytes: usize,
) -> Result<Vec<u8>, FilesystemError> {
    read_with_permissions(directory, name, maximum_bytes, PermissionProfile::OwnerOnly)
}

pub(crate) fn read_public_from_dir(
    directory: &Dir,
    name: &Path,
    maximum_bytes: usize,
) -> Result<Vec<u8>, FilesystemError> {
    read_with_permissions(
        directory,
        name,
        maximum_bytes,
        PermissionProfile::PublicReadOnly,
    )
}

#[derive(Clone, Copy)]
enum PermissionProfile {
    OwnerOnly,
    PublicReadOnly,
}

fn read_with_permissions(
    directory: &Dir,
    name: &Path,
    maximum_bytes: usize,
    permissions: PermissionProfile,
) -> Result<Vec<u8>, FilesystemError> {
    #[cfg(not(unix))]
    {
        let _ = (directory, name, maximum_bytes);
        return Err(FilesystemError::new(
            FilesystemOperation::Read,
            FilesystemErrorKind::Unsupported,
        ));
    }

    #[cfg(unix)]
    {
        if maximum_bytes == 0 {
            return Err(FilesystemError::new(
                FilesystemOperation::Read,
                FilesystemErrorKind::HardLinkOrSize,
            ));
        }
        let name = single_component(name, FilesystemOperation::Read)?;
        let before = directory.symlink_metadata(&name).map_err(|error| {
            let kind = if error.kind() == std::io::ErrorKind::NotFound {
                FilesystemErrorKind::NotFound
            } else {
                FilesystemErrorKind::Io
            };
            FilesystemError::new(FilesystemOperation::Read, kind)
        })?;
        validate_metadata(&before, maximum_bytes, permissions)?;
        let expected = ReadSnapshot::from_metadata(&before);

        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let mut file = directory.open_with(&name, &options).map_err(|_| {
            FilesystemError::new(FilesystemOperation::Read, FilesystemErrorKind::Io)
        })?;
        let opened = file.metadata().map_err(|_| {
            FilesystemError::new(FilesystemOperation::Read, FilesystemErrorKind::Io)
        })?;
        validate_metadata(&opened, maximum_bytes, permissions)?;
        if ReadSnapshot::from_metadata(&opened) != expected {
            return Err(FilesystemError::new(
                FilesystemOperation::Read,
                FilesystemErrorKind::IdentityChanged,
            ));
        }

        let capacity = usize::try_from(opened.len()).map_err(|_| {
            FilesystemError::new(
                FilesystemOperation::Read,
                FilesystemErrorKind::HardLinkOrSize,
            )
        })?;
        let mut output = Vec::new();
        output.try_reserve_exact(capacity).map_err(|_| {
            FilesystemError::new(FilesystemOperation::Read, FilesystemErrorKind::Io)
        })?;
        let limit = u64::try_from(maximum_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        (&mut file)
            .take(limit)
            .read_to_end(&mut output)
            .map_err(|_| {
                FilesystemError::new(FilesystemOperation::Read, FilesystemErrorKind::Io)
            })?;
        if output.len() > maximum_bytes {
            return Err(FilesystemError::new(
                FilesystemOperation::Read,
                FilesystemErrorKind::HardLinkOrSize,
            ));
        }
        let after = file.metadata().map_err(|_| {
            FilesystemError::new(FilesystemOperation::Read, FilesystemErrorKind::Io)
        })?;
        if ReadSnapshot::from_metadata(&after) != expected {
            return Err(FilesystemError::new(
                FilesystemOperation::Read,
                FilesystemErrorKind::IdentityChanged,
            ));
        }
        Ok(output)
    }
}

#[cfg(unix)]
fn validate_metadata(
    metadata: &Metadata,
    maximum_bytes: usize,
    permissions: PermissionProfile,
) -> Result<(), FilesystemError> {
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() > u64::try_from(maximum_bytes).unwrap_or(u64::MAX)
    {
        return Err(FilesystemError::new(
            FilesystemOperation::Read,
            FilesystemErrorKind::HardLinkOrSize,
        ));
    }
    let mode = metadata.permissions().mode();
    let permission_invalid = match permissions {
        PermissionProfile::OwnerOnly => mode & 0o077 != 0,
        PermissionProfile::PublicReadOnly => mode & 0o022 != 0,
    };
    if permission_invalid
        || cap_std::fs::MetadataExt::uid(metadata) != rustix::process::geteuid().as_raw()
    {
        return Err(FilesystemError::new(
            FilesystemOperation::Read,
            FilesystemErrorKind::Permission,
        ));
    }
    Ok(())
}
