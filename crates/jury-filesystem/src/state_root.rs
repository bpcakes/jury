use std::fmt;
use std::path::Path;

use cap_std::fs::{DirBuilder, DirBuilderExt, Permissions, PermissionsExt};

use crate::capability::{HardenedDir, is_contained, normalized_absolute, open_absolute_dir};
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
            validate_root(&root, repositories)?;
            Ok(Self { root })
        }
    }

    /// Opens or creates one final owner-only directory and proves that it does
    /// not overlap any retained worktree.
    pub fn open_or_create(
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
            if open_absolute_dir(&absolute, FilesystemOperation::OpenStateRoot).is_err() {
                let parent_path = absolute.parent().ok_or(FilesystemError::new(
                    FilesystemOperation::OpenStateRoot,
                    FilesystemErrorKind::Traversal,
                ))?;
                let name = absolute.file_name().ok_or(FilesystemError::new(
                    FilesystemOperation::OpenStateRoot,
                    FilesystemErrorKind::Traversal,
                ))?;
                let parent = open_absolute_dir(parent_path, FilesystemOperation::OpenStateRoot)?;
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                match parent.dir.create_dir_with(name, &builder) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(_) => {
                        return Err(FilesystemError::new(
                            FilesystemOperation::OpenStateRoot,
                            FilesystemErrorKind::Io,
                        ));
                    }
                }
            }
            let root = open_absolute_dir(&absolute, FilesystemOperation::OpenStateRoot)?;
            root.dir
                .set_permissions(".", Permissions::from_mode(0o700))
                .map_err(|_| {
                    FilesystemError::new(
                        FilesystemOperation::OpenStateRoot,
                        FilesystemErrorKind::Permission,
                    )
                })?;
            validate_root(&root, repositories)?;
            Ok(Self { root })
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
