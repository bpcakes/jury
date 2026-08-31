use std::fmt;
use std::path::Path;

use cap_std::fs::{DirBuilder, DirBuilderExt, PermissionsExt};

#[cfg(unix)]
use crate::capability::open_or_create_absolute_dir;
use crate::capability::{
    FileIdentity, HardenedDir, is_contained, nofollow_directory_child, normalized_absolute,
    open_absolute_dir,
};
use crate::{FilesystemError, FilesystemErrorKind, FilesystemOperation, RepositoryLocation};

/// Retained owner-only capability for Jury's private platform state.
pub struct HardenedStateRoot {
    pub(crate) root: HardenedDir,
}

impl HardenedStateRoot {
    /// Opens an existing owner-only directory without changing its mode.
    pub fn open_existing(
        path: &Path,
        repositories: &[&RepositoryLocation],
    ) -> Result<Self, FilesystemError> {
        #[cfg(not(unix))]
        {
            let _ = (path, repositories);
            return Err(FilesystemError::new(
                FilesystemOperation::OpenStateRoot,
                FilesystemErrorKind::Unsupported,
            ));
        }

        #[cfg(unix)]
        {
            let absolute = normalized_absolute(path, FilesystemOperation::OpenStateRoot)?;
            let root = open_absolute_dir(&absolute, FilesystemOperation::OpenStateRoot)?;
            validate_root(&root, repositories, &[])?;
            Ok(Self { root })
        }
    }

    /// Opens or creates one final owner-only directory and proves that it does
    /// not overlap any retained worktree.
    pub fn open_or_create(
        path: &Path,
        repositories: &[&RepositoryLocation],
    ) -> Result<Self, FilesystemError> {
        Self::open_or_create_excluding(path, repositories, &[])
    }

    /// Opens or creates the state root while proving disjointness from both
    /// retained repositories and explicit vault-home paths.
    pub fn open_or_create_excluding(
        path: &Path,
        repositories: &[&RepositoryLocation],
        excluded_paths: &[&Path],
    ) -> Result<Self, FilesystemError> {
        #[cfg(not(unix))]
        {
            let _ = (path, repositories, excluded_paths);
            return Err(FilesystemError::new(
                FilesystemOperation::OpenStateRoot,
                FilesystemErrorKind::Unsupported,
            ));
        }

        #[cfg(unix)]
        {
            let absolute = normalized_absolute(path, FilesystemOperation::OpenStateRoot)?;
            if repositories.iter().any(|repository| {
                absolute.starts_with(&repository.worktree.absolute)
                    || repository.worktree.absolute.starts_with(&absolute)
            }) {
                return Err(FilesystemError::new(
                    FilesystemOperation::OpenStateRoot,
                    FilesystemErrorKind::Containment,
                ));
            }
            for excluded in excluded_paths {
                let excluded = normalized_absolute(excluded, FilesystemOperation::OpenStateRoot)?;
                if absolute.starts_with(&excluded) || excluded.starts_with(&absolute) {
                    return Err(FilesystemError::new(
                        FilesystemOperation::OpenStateRoot,
                        FilesystemErrorKind::Containment,
                    ));
                }
            }
            let root = match open_absolute_dir(&absolute, FilesystemOperation::OpenStateRoot) {
                Ok(root) => root,
                Err(error) if error.kind() == FilesystemErrorKind::NotFound => {
                    open_or_create_absolute_dir(&absolute, FilesystemOperation::OpenStateRoot)?
                }
                Err(error) => return Err(error),
            };
            validate_root(&root, repositories, excluded_paths)?;
            Ok(Self { root })
        }
    }

    /// Opens or creates one owner-only child without following a link.
    pub fn open_or_create_private_child(&self, name: &Path) -> Result<Self, FilesystemError> {
        #[cfg(not(unix))]
        {
            let _ = name;
            return Err(FilesystemError::new(
                FilesystemOperation::OpenStateRoot,
                FilesystemErrorKind::Unsupported,
            ));
        }
        #[cfg(unix)]
        {
            let name =
                crate::capability::single_component(name, FilesystemOperation::OpenStateRoot)?;
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            match self.root.dir.create_dir_with(&name, &builder) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => {
                    return Err(FilesystemError::new(
                        FilesystemOperation::OpenStateRoot,
                        FilesystemErrorKind::Io,
                    ));
                }
            }
            let dir = nofollow_directory_child(
                &self.root.dir,
                Path::new(&name),
                FilesystemOperation::OpenStateRoot,
            )?;
            let metadata = dir.dir_metadata().map_err(|_| {
                FilesystemError::new(FilesystemOperation::OpenStateRoot, FilesystemErrorKind::Io)
            })?;
            let identity = FileIdentity::from_metadata(&metadata);
            let mut lineage = self.root.lineage.clone();
            lineage.push(identity);
            let child = HardenedDir {
                dir,
                absolute: self.root.absolute.join(&name),
                identity,
                lineage,
            };
            validate_root(&child, &[], &[])?;
            Ok(Self { root: child })
        }
    }

    pub fn preview_private_file(
        &self,
        name: &Path,
    ) -> Result<crate::PrivateFilePrecondition, FilesystemError> {
        crate::private_output::preview(&self.root.dir, name)
    }

    /// Reads one bounded owner-only regular file through the retained root.
    pub fn read_private_file(
        &self,
        name: &Path,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, FilesystemError> {
        crate::private_input::read(self, name, maximum_bytes)
    }
}

#[cfg(unix)]
fn validate_root(
    root: &HardenedDir,
    repositories: &[&RepositoryLocation],
    excluded_paths: &[&Path],
) -> Result<(), FilesystemError> {
    let metadata = root.dir.dir_metadata().map_err(|_| {
        FilesystemError::new(FilesystemOperation::OpenStateRoot, FilesystemErrorKind::Io)
    })?;
    if metadata.permissions().mode() & 0o077 != 0
        || cap_std::fs::MetadataExt::uid(&metadata) != rustix::process::geteuid().as_raw()
    {
        return Err(FilesystemError::new(
            FilesystemOperation::OpenStateRoot,
            FilesystemErrorKind::Permission,
        ));
    }
    for repository in repositories {
        if is_contained(root, &repository.worktree) {
            return Err(FilesystemError::new(
                FilesystemOperation::OpenStateRoot,
                FilesystemErrorKind::Containment,
            ));
        }
    }
    for excluded in excluded_paths {
        let excluded = normalized_absolute(excluded, FilesystemOperation::OpenStateRoot)?;
        if root.absolute.starts_with(&excluded) || excluded.starts_with(&root.absolute) {
            return Err(FilesystemError::new(
                FilesystemOperation::OpenStateRoot,
                FilesystemErrorKind::Containment,
            ));
        }
        match open_absolute_dir(&excluded, FilesystemOperation::OpenStateRoot) {
            Ok(excluded) if is_contained(root, &excluded) => {
                return Err(FilesystemError::new(
                    FilesystemOperation::OpenStateRoot,
                    FilesystemErrorKind::Containment,
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == FilesystemErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl fmt::Debug for HardenedStateRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HardenedStateRoot")
            .field("path", &"[REDACTED]")
            .finish()
    }
}
