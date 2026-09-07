//! Descriptor-only native policy. No ACL principal or path escapes this boundary.

use cap_std::fs::{Dir, File};
use std::io;
#[cfg(unix)]
use std::os::fd::AsFd;

use crate::{FilesystemError, FilesystemErrorKind, FilesystemOperation};

#[cfg(unix)]
pub(crate) fn validate_acl(
    descriptor: &impl AsFd,
    operation: FilesystemOperation,
) -> Result<(), FilesystemError> {
    #[cfg(target_os = "macos")]
    {
        let acl = calcifer_macos_acl::read_acl(descriptor.as_fd())
            .map_err(|error| native_error(operation, error))?;
        // Deliberately reject even harmless entries. No principal lookup,
        // guessed effective-rights calculation, or mutation of existing ACLs.
        if !acl.is_empty() {
            return Err(FilesystemError::new(
                operation,
                FilesystemErrorKind::Permission,
            ));
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (descriptor, operation);
    Ok(())
}

#[cfg(unix)]
pub(crate) fn validate_publication_volume(
    descriptor: &impl AsFd,
    operation: FilesystemOperation,
) -> Result<(), FilesystemError> {
    #[cfg(target_os = "macos")]
    {
        let stat = rustix::fs::fstatfs(descriptor)
            .map_err(|error| native_error(operation, error.into()))?;
        // APFS is a local filesystem; remote protocols report their own type.
        if stat.f_fstypename[..5] != [97, 112, 102, 115, 0] {
            return Err(FilesystemError::new(
                operation,
                FilesystemErrorKind::Unsupported,
            ));
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (descriptor, operation);
    Ok(())
}

#[cfg(unix)]
pub(crate) fn validate_private_directory(
    directory: &Dir,
    operation: FilesystemOperation,
) -> Result<(), FilesystemError> {
    use cap_std::fs::{MetadataExt, PermissionsExt};
    let metadata = directory
        .dir_metadata()
        .map_err(|_| FilesystemError::new(operation, FilesystemErrorKind::Io))?;
    if metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(FilesystemError::new(
            operation,
            FilesystemErrorKind::Permission,
        ));
    }
    validate_publication_volume(directory, operation)?;
    validate_acl(directory, operation)
}

pub(crate) fn sync_file(file: &File) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        rustix::fs::fcntl_fullfsync(file).map_err(Into::into)
    }
    #[cfg(not(target_os = "macos"))]
    {
        file.sync_all()
    }
}

pub(crate) fn sync_parent(parent: &Dir) -> io::Result<()> {
    sync_file(&parent.open(".")?)
}

pub(crate) fn native_error(operation: FilesystemOperation, error: io::Error) -> FilesystemError {
    let kind = match error
        .raw_os_error()
        .map(rustix::io::Errno::from_raw_os_error)
    {
        Some(
            rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP,
        ) => FilesystemErrorKind::Unsupported,
        _ => FilesystemErrorKind::Io,
    };
    FilesystemError::new(operation, kind)
}

#[cfg(not(unix))]
pub(crate) fn validate_acl<T>(
    _: &T,
    operation: FilesystemOperation,
) -> Result<(), FilesystemError> {
    Err(FilesystemError::new(
        operation,
        FilesystemErrorKind::Unsupported,
    ))
}

#[cfg(not(unix))]
pub(crate) fn validate_private_directory(
    _: &Dir,
    operation: FilesystemOperation,
) -> Result<(), FilesystemError> {
    Err(FilesystemError::new(
        operation,
        FilesystemErrorKind::Unsupported,
    ))
}
