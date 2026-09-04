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
        Self::open_existing_excluding(path, repositories, &[])
    }

    /// Opens an existing owner-only directory while proving disjointness from
    /// retained repositories and explicit excluded directory paths.
    pub fn open_existing_excluding(
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
            let root = open_absolute_dir(&absolute, FilesystemOperation::OpenStateRoot)?;
            validate_root(&root, repositories, excluded_paths)?;
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

    /// Creates one new owner-only child directory. Any existing directory,
    /// file, or link is preserved and rejected.
    pub fn create_private_child_new(&self, name: &Path) -> Result<Self, FilesystemError> {
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
            self.root
                .dir
                .create_dir_with(&name, &builder)
                .map_err(|error| {
                    let kind = if error.kind() == std::io::ErrorKind::AlreadyExists {
                        FilesystemErrorKind::AlreadyExists
                    } else {
                        FilesystemErrorKind::Io
                    };
                    FilesystemError::new(FilesystemOperation::OpenStateRoot, kind)
                })?;
            self.root
                .dir
                .open(".")
                .and_then(|dir| dir.sync_all())
                .map_err(|_| {
                    FilesystemError::new(FilesystemOperation::SyncParent, FilesystemErrorKind::Io)
                })?;
            self.open_private_child(Path::new(&name))
        }
    }

    /// Reports whether any direct child occupies a name without following it.
    pub fn private_child_exists(&self, name: &Path) -> Result<bool, FilesystemError> {
        let name = crate::capability::single_component(name, FilesystemOperation::Preview)?;
        match self.root.dir.symlink_metadata(&name) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(FilesystemError::new(
                FilesystemOperation::Preview,
                FilesystemErrorKind::Io,
            )),
        }
    }

    /// Opens one existing owner-only child without following a link or
    /// creating filesystem state.
    pub fn open_private_child(&self, name: &Path) -> Result<Self, FilesystemError> {
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

    /// Removes a direct owner-only file only when its bounded contents still
    /// equal the caller's authenticated marker bytes, then syncs the parent.
    pub fn remove_private_file_if_exact(
        &self,
        name: &Path,
        expected: &[u8],
    ) -> Result<(), FilesystemError> {
        let name = crate::capability::single_component(name, FilesystemOperation::Cleanup)?;
        let maximum = expected.len().checked_add(1).ok_or_else(|| {
            FilesystemError::new(
                FilesystemOperation::Cleanup,
                FilesystemErrorKind::HardLinkOrSize,
            )
        })?;
        let observed =
            crate::private_input::read_from_dir(&self.root.dir, Path::new(&name), maximum)?;
        if observed != expected {
            return Err(FilesystemError::new(
                FilesystemOperation::Cleanup,
                FilesystemErrorKind::IdentityChanged,
            ));
        }
        self.root.dir.remove_file(&name).map_err(|_| {
            FilesystemError::new(FilesystemOperation::Cleanup, FilesystemErrorKind::Io)
        })?;
        self.root
            .dir
            .open(".")
            .and_then(|dir| dir.sync_all())
            .map_err(|_| {
                FilesystemError::new(FilesystemOperation::SyncParent, FilesystemErrorKind::Io)
            })
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{PreparedPrivateFile, PublicationPolicy};
    use jury_protected::{ProtectedMemory, ProtectionPolicy};

    #[test]
    fn restore_marker_removal_requires_exact_owner_only_contents()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = HardenedStateRoot::open_or_create(&temporary.path().join("private"), &[])?;
        let marker =
            ProtectedMemory::initialize(15, ProtectionPolicy::EmergencyAllowDegraded, |output| {
                output.copy_from_slice(b"ExampleMarkerV1");
                Ok::<usize, ()>(output.len())
            })?;
        PreparedPrivateFile::prepare_state(
            &root,
            Path::new("marker.json"),
            &marker,
            PublicationPolicy::CreateNew,
        )?
        .publish()?;
        assert!(matches!(
            root.remove_private_file_if_exact(Path::new("marker.json"), b"DifferentMarker"),
            Err(error) if error.kind() == FilesystemErrorKind::IdentityChanged
        ));
        assert!(root.private_child_exists(Path::new("marker.json"))?);
        root.remove_private_file_if_exact(Path::new("marker.json"), b"ExampleMarkerV1")?;
        assert!(!root.private_child_exists(Path::new("marker.json"))?);
        Ok(())
    }

    #[test]
    fn absent_restore_directory_creation_preserves_existing_targets()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(
            temporary.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )?;
        let parent = HardenedStateRoot::open_existing(temporary.path(), &[])?;
        parent.create_private_child_new(Path::new("restore"))?;
        assert!(matches!(
            parent.create_private_child_new(Path::new("restore")),
            Err(error) if error.kind() == FilesystemErrorKind::AlreadyExists
        ));
        assert!(parent.private_child_exists(Path::new("restore"))?);
        Ok(())
    }

    #[test]
    fn existing_state_root_rejects_an_explicit_excluded_tree()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("source");
        let output = source.join("output");
        std::fs::create_dir_all(&output)?;
        for directory in [&source, &output] {
            std::fs::set_permissions(
                directory,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )?;
        }
        assert!(matches!(
            HardenedStateRoot::open_existing_excluding(&output, &[], &[&source]),
            Err(error) if error.kind() == FilesystemErrorKind::Containment
        ));
        Ok(())
    }
}

impl fmt::Debug for HardenedStateRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HardenedStateRoot")
            .field("path", &"[REDACTED]")
            .finish()
    }
}
