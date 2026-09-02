use std::io::Read as _;
use std::path::Path;

use cap_fs_ext::{FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _};
#[cfg(unix)]
use cap_std::fs::PermissionsExt as _;
use cap_std::fs::{Metadata, OpenOptions};

use crate::capability::{RegularFileSnapshot, single_component};
use cap_std::fs::Dir;

use crate::{FilesystemError, FilesystemErrorKind, FilesystemOperation, HardenedStateRoot};

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

/// Reads one bounded public regular file selected by an absolute direct path.
/// The leaf must not be a link or hard-link alias and must not be group/world
/// writable. The parent is retained as a capability for the complete read.
pub fn read_public_file(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, FilesystemError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(FilesystemError::new(
            FilesystemOperation::Read,
            FilesystemErrorKind::Traversal,
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        FilesystemError::new(FilesystemOperation::Read, FilesystemErrorKind::Traversal)
    })?;
    let name = path.file_name().ok_or_else(|| {
        FilesystemError::new(FilesystemOperation::Read, FilesystemErrorKind::Traversal)
    })?;
    let directory = crate::capability::open_absolute_dir(parent, FilesystemOperation::Read)?;
    read_public_from_dir(&directory.dir, Path::new(name), maximum_bytes)
}

/// Reads one bounded owner-only regular file selected by an absolute direct
/// path. The leaf must not be a link or hard-link alias, must be owned by the
/// current effective user, and must have no group or world permissions. The
/// parent is retained as a capability for the complete read.
pub fn read_private_file(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, FilesystemError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(FilesystemError::new(
            FilesystemOperation::Read,
            FilesystemErrorKind::Traversal,
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        FilesystemError::new(FilesystemOperation::Read, FilesystemErrorKind::Traversal)
    })?;
    let name = path.file_name().ok_or_else(|| {
        FilesystemError::new(FilesystemOperation::Read, FilesystemErrorKind::Traversal)
    })?;
    let directory = crate::capability::open_absolute_dir(parent, FilesystemOperation::Read)?;
    read_from_dir(&directory.dir, Path::new(name), maximum_bytes)
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
        let expected = RegularFileSnapshot::from_metadata(&before);

        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let mut file = directory.open_with(&name, &options).map_err(|_| {
            FilesystemError::new(FilesystemOperation::Read, FilesystemErrorKind::Io)
        })?;
        let opened = file.metadata().map_err(|_| {
            FilesystemError::new(FilesystemOperation::Read, FilesystemErrorKind::Io)
        })?;
        validate_metadata(&opened, maximum_bytes, permissions)?;
        if RegularFileSnapshot::from_metadata(&opened) != expected {
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
        if RegularFileSnapshot::from_metadata(&after) != expected {
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
