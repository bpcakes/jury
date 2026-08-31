use std::ffi::OsString;
use std::fmt;
use std::path::Path;

use cap_fs_ext::{FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{OpenOptionsExt, PermissionsExt};

use crate::capability::{FileIdentity, single_component};
use crate::{FilesystemErrorKind, FilesystemOperation, HardenedStateRoot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockError {
    Busy,
    InvalidName,
    Unsupported,
    Io,
}

impl fmt::Display for LockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => formatter.write_str("state lock is already held"),
            Self::InvalidName => formatter.write_str("state lock name is invalid"),
            Self::Unsupported => {
                formatter.write_str("state locks are unsupported on this platform")
            }
            Self::Io => formatter.write_str("state lock operation failed"),
        }
    }
}

impl std::error::Error for LockError {}

/// Identity-safe exclusive lock whose file exists only below private state.
pub struct ExclusiveStateLock {
    parent: Dir,
    name: OsString,
    file: cap_std::fs::File,
}

impl ExclusiveStateLock {
    pub fn try_acquire(root: &HardenedStateRoot, public_name: &Path) -> Result<Self, LockError> {
        #[cfg(not(unix))]
        {
            let _ = (root, public_name);
            return Err(LockError::Unsupported);
        }
        #[cfg(unix)]
        {
            let name =
                single_component(public_name, FilesystemOperation::Lock).map_err(|error| {
                    match error.kind() {
                        FilesystemErrorKind::Traversal | FilesystemErrorKind::Nul => {
                            LockError::InvalidName
                        }
                        _ => LockError::Io,
                    }
                })?;
            let parent = root.root.dir.try_clone().map_err(|_| LockError::Io)?;
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .mode(0o600)
                .follow(FollowSymlinks::No);
            let file = parent.open_with(&name, &options).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    LockError::Busy
                } else {
                    LockError::Io
                }
            })?;
            let metadata = file.metadata().map_err(|_| LockError::Io)?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o077 != 0
                || cap_std::fs::MetadataExt::uid(&metadata) != rustix::process::geteuid().as_raw()
            {
                let _ = parent.remove_file(&name);
                return Err(LockError::Io);
            }
            file.sync_all().map_err(|_| LockError::Io)?;
            Ok(Self { parent, name, file })
        }
    }
}

impl fmt::Debug for ExclusiveStateLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExclusiveStateLock")
            .field("name", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ExclusiveStateLock {
    fn drop(&mut self) {
        // Retaining the original descriptor until after this comparison also
        // prevents its inode from being recycled for a replacement path.
        let Ok(original) = self.file.metadata() else {
            return;
        };
        let Ok(metadata) = self.parent.symlink_metadata(&self.name) else {
            return;
        };
        if metadata.is_file()
            && metadata.nlink() == 1
            && FileIdentity::from_metadata(&metadata) == FileIdentity::from_metadata(&original)
        {
            let _ = self.parent.remove_file(&self.name);
        }
    }
}
