use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use cap_fs_ext::{FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};

use crate::capability::{HardenedDir, nofollow_directory_child, open_absolute_dir};
use crate::{FilesystemError, FilesystemErrorKind, FilesystemOperation};

const MAX_GITDIR_MARKER_BYTES: u64 = 4096;

/// Retained capability to the nearest hardened Git worktree.
pub struct RepositoryLocation {
    pub(crate) worktree: HardenedDir,
    _git_dir: HardenedDir,
    jury_dir: Option<Dir>,
}

impl RepositoryLocation {
    /// Discovers the nearest ordinary or linked Git worktree without following
    /// user-controlled path components or marker links.
    pub fn discover(start: &Path) -> Result<Self, FilesystemError> {
        let start =
            crate::capability::normalized_absolute(start, FilesystemOperation::DiscoverRepository)?;
        let mut current = Some(start.as_path());
        while let Some(candidate_path) = current {
            let worktree =
                open_absolute_dir(candidate_path, FilesystemOperation::DiscoverRepository)?;
            match open_git_marker(&worktree) {
                Ok(Some(git_dir)) => {
                    let jury_dir = inspect_jury_directory(&worktree.dir)?;
                    return Ok(Self {
                        worktree,
                        _git_dir: git_dir,
                        jury_dir,
                    });
                }
                Ok(None) => {}
                Err(error) => return Err(error),
            }
            current = candidate_path.parent();
        }
        Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::NotFound,
        ))
    }

    #[must_use]
    pub fn has_jury_directory(&self) -> bool {
        self.jury_dir.is_some()
    }

    /// Explicitly creates the encrypted shared-artifact directory owner-only.
    pub fn create_jury_directory(&mut self) -> Result<(), FilesystemError> {
        if self.jury_dir.is_some() {
            return Ok(());
        }
        #[cfg(not(unix))]
        return Err(FilesystemError::new(
            FilesystemOperation::Open,
            FilesystemErrorKind::Unsupported,
        ));
        #[cfg(unix)]
        {
            use cap_std::fs::{DirBuilder, DirBuilderExt};
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            self.worktree
                .dir
                .create_dir_with(".jury", &builder)
                .map_err(|error| {
                    let kind = if error.kind() == std::io::ErrorKind::AlreadyExists {
                        FilesystemErrorKind::AlreadyExists
                    } else {
                        FilesystemErrorKind::Io
                    };
                    FilesystemError::new(FilesystemOperation::Open, kind)
                })?;
            self.jury_dir = Some(nofollow_directory_child(
                &self.worktree.dir,
                Path::new(".jury"),
                FilesystemOperation::Open,
            )?);
            Ok(())
        }
    }

    pub fn preview_encrypted_shared_artifact(
        &self,
    ) -> Result<crate::PrivateFilePrecondition, FilesystemError> {
        crate::private_output::preview(&self.jury_dir_clone()?, Path::new("vault.json"))
    }

    pub(crate) fn jury_dir_clone(&self) -> Result<Dir, FilesystemError> {
        self.jury_dir
            .as_ref()
            .ok_or(FilesystemError::new(
                FilesystemOperation::Open,
                FilesystemErrorKind::NotFound,
            ))?
            .try_clone()
            .map_err(|_| FilesystemError::new(FilesystemOperation::Open, FilesystemErrorKind::Io))
    }
}

impl fmt::Debug for RepositoryLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryLocation")
            .field("has_jury_directory", &self.has_jury_directory())
            .field("path", &"[REDACTED]")
            .finish()
    }
}

fn open_git_marker(worktree: &HardenedDir) -> Result<Option<HardenedDir>, FilesystemError> {
    match worktree.dir.symlink_metadata(".git") {
        Ok(metadata) if metadata.is_dir() => {
            let dir = nofollow_directory_child(
                &worktree.dir,
                Path::new(".git"),
                FilesystemOperation::DiscoverRepository,
            )?;
            let identity = crate::capability::FileIdentity::from_metadata(
                &dir.dir_metadata().map_err(|_| {
                    FilesystemError::new(
                        FilesystemOperation::DiscoverRepository,
                        FilesystemErrorKind::Io,
                    )
                })?,
            );
            let git_dir = HardenedDir {
                dir,
                absolute: worktree.absolute.join(".git"),
                identity,
                lineage: {
                    let mut lineage = worktree.lineage.clone();
                    lineage.push(identity);
                    lineage
                },
            };
            validate_git_head(&git_dir)?;
            Ok(Some(git_dir))
        }
        Ok(metadata) if metadata.is_file() => {
            let git_dir = linked_git_dir(worktree, metadata)?;
            validate_git_head(&git_dir)?;
            Ok(Some(git_dir))
        }
        Ok(_) => Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::LinkOrWrongType,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::Io,
        )),
    }
}

fn validate_git_head(git_dir: &HardenedDir) -> Result<(), FilesystemError> {
    let metadata = git_dir.dir.symlink_metadata("HEAD").map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        )
    })?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() == 0 || metadata.len() > 1024
    {
        return Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let head = git_dir.dir.open_with("HEAD", &options).map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        )
    })?;
    let opened = head.metadata().map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        )
    })?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() || opened.nlink() != 1 {
        return Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::IdentityChanged,
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    head.take(1025).read_to_end(&mut bytes).map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        )
    })?;
    let value = std::str::from_utf8(&bytes).map(str::trim).map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        )
    })?;
    let detached =
        matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    let symbolic = value
        .strip_prefix("ref: refs/")
        .is_some_and(|name| !name.is_empty() && !name.contains(['\0', '\n', '\r']));
    if detached || symbolic {
        Ok(())
    } else {
        Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        ))
    }
}

fn linked_git_dir(
    worktree: &HardenedDir,
    path_metadata: cap_std::fs::Metadata,
) -> Result<HardenedDir, FilesystemError> {
    if path_metadata.nlink() != 1 || path_metadata.len() > MAX_GITDIR_MARKER_BYTES {
        return Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::HardLinkOrSize,
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let marker = worktree.dir.open_with(".git", &options).map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::LinkOrWrongType,
        )
    })?;
    let opened = marker.metadata().map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::Io,
        )
    })?;
    if opened.dev() != path_metadata.dev()
        || opened.ino() != path_metadata.ino()
        || opened.nlink() != 1
        || opened.len() > MAX_GITDIR_MARKER_BYTES
    {
        return Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::IdentityChanged,
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    marker
        .take(MAX_GITDIR_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            FilesystemError::new(
                FilesystemOperation::DiscoverRepository,
                FilesystemErrorKind::Io,
            )
        })?;
    if bytes.len() as u64 > MAX_GITDIR_MARKER_BYTES {
        return Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::HardLinkOrSize,
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        )
    })?;
    let value = text
        .strip_prefix("gitdir:")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        ))?;
    let path = PathBuf::from(value);
    let resolved = if path.is_absolute() {
        path
    } else {
        worktree.absolute.join(path)
    };
    open_absolute_dir(&resolved, FilesystemOperation::DiscoverRepository)
}

fn inspect_jury_directory(worktree: &Dir) -> Result<Option<Dir>, FilesystemError> {
    match worktree.symlink_metadata(".jury") {
        Ok(metadata) if metadata.is_dir() => nofollow_directory_child(
            worktree,
            Path::new(".jury"),
            FilesystemOperation::DiscoverRepository,
        )
        .map(Some),
        Ok(_) => Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::LinkOrWrongType,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::Io,
        )),
    }
}
