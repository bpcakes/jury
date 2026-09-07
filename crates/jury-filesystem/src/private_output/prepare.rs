use super::*;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{File, OpenOptions, OpenOptionsExt};
use std::io::Write;

pub(super) fn write_prepared(
    parent: Dir,
    destination: OsString,
    contents: PreparedContents<'_>,
    expected: DestinationState,
    replace: bool,
    visibility: FileVisibility,
) -> Result<PreparedPrivateFile, FilesystemError> {
    if matches!(visibility, FileVisibility::OwnerOnly) {
        crate::platform::validate_private_directory(&parent, FilesystemOperation::Prepare)?;
    } else {
        crate::platform::validate_publication_volume(&parent, FilesystemOperation::Prepare)?;
        crate::platform::validate_acl(&parent, FilesystemOperation::Prepare)?;
    }
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
    let mut file = parent
        .open_with(&temporary, &options)
        .map_err(|_| FilesystemError::new(FilesystemOperation::Prepare, FilesystemErrorKind::Io))?;
    let result = validate_and_write(&mut file, visibility, |file| match contents {
        PreparedContents::Protected(contents) => contents
            .expose(|bytes| file.write_all(bytes))
            .map_err(|_| std::io::Error::other("protected exposure failed"))?,
        PreparedContents::Public(contents) => file.write_all(contents),
    });
    match result {
        Ok(temporary_identity) => Ok(PreparedPrivateFile {
            parent,
            destination,
            temporary,
            temporary_identity,
            file,
            expected,
            replace,
            byte_len: contents.len(),
            published: false,
        }),
        Err(error) => {
            remove_owned_temporary(&parent, &temporary, &file);
            Err(error)
        }
    }
}

fn validate_and_write(
    file: &mut File,
    visibility: FileVisibility,
    write: impl FnOnce(&mut File) -> std::io::Result<()>,
) -> Result<RegularFileSnapshot, FilesystemError> {
    validate_and_write_with_sync(file, visibility, write, crate::platform::sync_file)
}

fn validate_and_write_with_sync(
    file: &mut File,
    visibility: FileVisibility,
    write: impl FnOnce(&mut File) -> std::io::Result<()>,
    sync: impl FnOnce(&File) -> std::io::Result<()>,
) -> Result<RegularFileSnapshot, FilesystemError> {
    validate_file(file, visibility)?;
    write(file)
        .map_err(|_| FilesystemError::new(FilesystemOperation::Prepare, FilesystemErrorKind::Io))?;
    let metadata = validate_file(file, visibility)?;
    sync(file)
        .map_err(|error| crate::platform::native_error(FilesystemOperation::Prepare, error))?;
    Ok(RegularFileSnapshot::from_metadata(&metadata))
}

#[cfg(test)]
mod tests;

fn validate_file(
    file: &File,
    visibility: FileVisibility,
) -> Result<cap_std::fs::Metadata, FilesystemError> {
    let metadata = file
        .metadata()
        .map_err(|_| FilesystemError::new(FilesystemOperation::Prepare, FilesystemErrorKind::Io))?;
    let forbidden = match visibility {
        FileVisibility::OwnerOnly => 0o077,
        FileVisibility::PublicEncryptedArtifact => 0o022,
    };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & forbidden != 0
        || cap_std::fs::MetadataExt::uid(&metadata) != rustix::process::geteuid().as_raw()
    {
        return Err(FilesystemError::new(
            FilesystemOperation::Prepare,
            FilesystemErrorKind::Permission,
        ));
    }
    crate::platform::validate_acl(file, FilesystemOperation::Prepare)?;
    Ok(metadata)
}
