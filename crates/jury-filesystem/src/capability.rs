use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{DirExt, MetadataExt};
use cap_std::ambient_authority;
use cap_std::fs::Dir;

use crate::{FilesystemError, FilesystemErrorKind, FilesystemOperation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

impl FileIdentity {
    pub(crate) fn from_metadata(metadata: &cap_std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

pub(crate) struct HardenedDir {
    pub(crate) dir: Dir,
    pub(crate) absolute: PathBuf,
    pub(crate) identity: FileIdentity,
    pub(crate) lineage: Vec<FileIdentity>,
}

pub(crate) fn open_absolute_dir(
    path: &Path,
    operation: FilesystemOperation,
) -> Result<HardenedDir, FilesystemError> {
    let absolute = normalized_absolute(path, operation)?;
    #[cfg(unix)]
    let mut dir = Dir::open_ambient_dir("/", ambient_authority())
        .map_err(|_| FilesystemError::new(operation, FilesystemErrorKind::Io))?;
    #[cfg(windows)]
    let mut dir = {
        let prefix = windows_prefix(&absolute)?;
        Dir::open_ambient_dir(prefix, ambient_authority())
            .map_err(|_| FilesystemError::new(operation, FilesystemErrorKind::Io))?
    };
    let root_metadata = dir
        .dir_metadata()
        .map_err(|_| FilesystemError::new(operation, FilesystemErrorKind::Io))?;
    let mut lineage = vec![FileIdentity::from_metadata(&root_metadata)];

    for component in absolute.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {}
            Component::Normal(name) => {
                reject_nul(name, operation)?;
                dir = dir
                    .open_dir_nofollow(name)
                    .map_err(|error| map_open_error(error, operation))?;
                let metadata = dir
                    .dir_metadata()
                    .map_err(|_| FilesystemError::new(operation, FilesystemErrorKind::Io))?;
                lineage.push(FileIdentity::from_metadata(&metadata));
            }
            Component::CurDir | Component::ParentDir => {
                return Err(FilesystemError::new(
                    operation,
                    FilesystemErrorKind::Traversal,
                ));
            }
        }
    }
    let metadata = dir
        .dir_metadata()
        .map_err(|_| FilesystemError::new(operation, FilesystemErrorKind::Io))?;
    Ok(HardenedDir {
        identity: FileIdentity::from_metadata(&metadata),
        dir,
        absolute,
        lineage,
    })
}

pub(crate) fn normalized_absolute(
    path: &Path,
    operation: FilesystemOperation,
) -> Result<PathBuf, FilesystemError> {
    reject_nul(path.as_os_str(), operation)?;
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| FilesystemError::new(operation, FilesystemErrorKind::Io))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(FilesystemError::new(
                        operation,
                        FilesystemErrorKind::Traversal,
                    ));
                }
            }
            Component::Normal(name) => normalized.push(name),
        }
    }
    resolve_platform_root_alias(normalized, operation)
}

pub(crate) fn is_contained(left: &HardenedDir, right: &HardenedDir) -> bool {
    left.identity == right.identity
        || left.lineage.contains(&right.identity)
        || right.lineage.contains(&left.identity)
        || left.absolute.starts_with(&right.absolute)
        || right.absolute.starts_with(&left.absolute)
}

pub(crate) fn nofollow_directory_child(
    parent: &Dir,
    name: &Path,
    operation: FilesystemOperation,
) -> Result<Dir, FilesystemError> {
    single_component(name, operation)?;
    parent
        .open_dir_nofollow(name)
        .map_err(|error| map_open_error(error, operation))
}

pub(crate) fn single_component(
    name: &Path,
    operation: FilesystemOperation,
) -> Result<OsString, FilesystemError> {
    let mut components = name.components();
    let Some(Component::Normal(value)) = components.next() else {
        return Err(FilesystemError::new(
            operation,
            FilesystemErrorKind::Traversal,
        ));
    };
    if components.next().is_some() {
        return Err(FilesystemError::new(
            operation,
            FilesystemErrorKind::Traversal,
        ));
    }
    reject_nul(value, operation)?;
    Ok(value.to_os_string())
}

fn reject_nul(
    value: &std::ffi::OsStr,
    operation: FilesystemOperation,
) -> Result<(), FilesystemError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if value.as_bytes().contains(&0) {
            return Err(FilesystemError::new(operation, FilesystemErrorKind::Nul));
        }
    }
    #[cfg(not(unix))]
    if value.to_string_lossy().contains('\0') {
        return Err(FilesystemError::new(operation, FilesystemErrorKind::Nul));
    }
    Ok(())
}

fn map_open_error(error: io::Error, operation: FilesystemOperation) -> FilesystemError {
    let kind = if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
        FilesystemErrorKind::LinkOrWrongType
    } else {
        match error.kind() {
            io::ErrorKind::NotFound => FilesystemErrorKind::NotFound,
            io::ErrorKind::NotADirectory | io::ErrorKind::InvalidInput => {
                FilesystemErrorKind::LinkOrWrongType
            }
            io::ErrorKind::PermissionDenied => FilesystemErrorKind::Permission,
            _ => FilesystemErrorKind::Io,
        }
    };
    FilesystemError::new(operation, kind)
}

#[cfg(target_os = "macos")]
fn resolve_platform_root_alias(
    path: PathBuf,
    operation: FilesystemOperation,
) -> Result<PathBuf, FilesystemError> {
    for (alias, expected) in [
        (Path::new("/var"), Path::new("/private/var")),
        (Path::new("/tmp"), Path::new("/private/tmp")),
        (Path::new("/etc"), Path::new("/private/etc")),
    ] {
        let Ok(suffix) = path.strip_prefix(alias) else {
            continue;
        };
        let physical = std::fs::canonicalize(alias)
            .map_err(|_| FilesystemError::new(operation, FilesystemErrorKind::Io))?;
        if physical == alias {
            return Ok(path);
        }
        if physical != expected {
            return Err(FilesystemError::new(operation, FilesystemErrorKind::Alias));
        }
        return Ok(physical.join(suffix));
    }
    Ok(path)
}

#[cfg(not(target_os = "macos"))]
fn resolve_platform_root_alias(
    path: PathBuf,
    _operation: FilesystemOperation,
) -> Result<PathBuf, FilesystemError> {
    Ok(path)
}

#[cfg(windows)]
fn windows_prefix(path: &Path) -> Result<PathBuf, FilesystemError> {
    match path.components().next() {
        Some(Component::Prefix(prefix)) => Ok(PathBuf::from(prefix.as_os_str())),
        _ => Err(FilesystemError::new(
            FilesystemOperation::Open,
            FilesystemErrorKind::Unsupported,
        )),
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;

    #[test]
    fn fixed_system_aliases_resolve_to_verified_physical_roots() -> Result<(), FilesystemError> {
        assert_eq!(
            normalized_absolute(Path::new("/tmp/ExampleVault"), FilesystemOperation::Open)?,
            Path::new("/private/tmp/ExampleVault")
        );
        assert_eq!(
            normalized_absolute(Path::new("/var/ExampleVault"), FilesystemOperation::Open)?,
            Path::new("/private/var/ExampleVault")
        );
        Ok(())
    }
}
