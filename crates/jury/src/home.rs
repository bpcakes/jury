//! Native vault and identity home selection.

use std::ffi::OsStr;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use jury_filesystem::{FilesystemError, RepositoryLocation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HomeSource {
    Explicit,
    GlobalFlag,
    Environment,
    Repository,
    PlatformDefault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HomeSelectionError {
    Ambiguous,
    InvalidPath,
    UnsupportedPlatform,
    MissingUserHome,
    Repository,
}

impl fmt::Display for HomeSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ambiguous => "--home and --global cannot be used together",
            Self::InvalidPath => "vault home must be an absolute direct path",
            Self::UnsupportedPlatform => "native vault homes are unsupported on this platform",
            Self::MissingUserHome => "platform vault home has no user home directory",
            Self::Repository => "repository discovery failed",
        })
    }
}

impl std::error::Error for HomeSelectionError {}

pub enum VaultHomeLocation {
    Repository { repository: Box<RepositoryLocation> },
    Detached { path: PathBuf, source: HomeSource },
}

impl VaultHomeLocation {
    #[must_use]
    pub const fn source(&self) -> HomeSource {
        match self {
            Self::Repository { .. } => HomeSource::Repository,
            Self::Detached { source, .. } => *source,
        }
    }

    #[must_use]
    pub fn detached_path(&self) -> Option<&Path> {
        match self {
            Self::Repository { .. } => None,
            Self::Detached { path, .. } => Some(path),
        }
    }

    #[must_use]
    pub const fn repository(&self) -> Option<&RepositoryLocation> {
        match self {
            Self::Repository { repository } => Some(repository),
            Self::Detached { .. } => None,
        }
    }

    pub fn repository_mut(&mut self) -> Option<&mut RepositoryLocation> {
        match self {
            Self::Repository { repository } => Some(repository),
            Self::Detached { .. } => None,
        }
    }
}

impl fmt::Debug for VaultHomeLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultHomeLocation")
            .field("source", &self.source())
            .field("path", &"[REDACTED]")
            .finish()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_vault_home(
    start: &Path,
    explicit_home: Option<PathBuf>,
    global: bool,
    jury_home: Option<&OsStr>,
    xdg_data_home: Option<&OsStr>,
    user_home: Option<&OsStr>,
) -> Result<VaultHomeLocation, HomeSelectionError> {
    if explicit_home.is_some() && global {
        return Err(HomeSelectionError::Ambiguous);
    }
    if let Some(path) = explicit_home {
        validate_absolute_direct(&path)?;
        return Ok(VaultHomeLocation::Detached {
            path,
            source: HomeSource::Explicit,
        });
    }
    if global {
        return Ok(VaultHomeLocation::Detached {
            path: platform_global_vault_home(xdg_data_home, user_home)?,
            source: HomeSource::GlobalFlag,
        });
    }
    if let Some(path) = jury_home.filter(|value| !value.is_empty()) {
        let path = PathBuf::from(path);
        validate_absolute_direct(&path)?;
        return Ok(VaultHomeLocation::Detached {
            path,
            source: HomeSource::Environment,
        });
    }
    match RepositoryLocation::discover(start) {
        Ok(repository) => Ok(VaultHomeLocation::Repository {
            repository: Box::new(repository),
        }),
        Err(error) if error.kind() == jury_filesystem::FilesystemErrorKind::NotFound => {
            Ok(VaultHomeLocation::Detached {
                path: platform_global_vault_home(xdg_data_home, user_home)?,
                source: HomeSource::PlatformDefault,
            })
        }
        Err(_) => Err(HomeSelectionError::Repository),
    }
}

pub fn resolve_identity_root(
    jury_identity_home: Option<&OsStr>,
    xdg_data_home: Option<&OsStr>,
    user_home: Option<&OsStr>,
) -> Result<PathBuf, HomeSelectionError> {
    // Preserve Linux empty-override compatibility. macOS rejects an explicitly
    // empty private root; JURY_HOME separately retains its established selector
    // fallback semantics (it selects a vault, not a private storage root).
    if let Some(path) =
        jury_identity_home.filter(|value| cfg!(target_os = "macos") || !value.is_empty())
    {
        let path = PathBuf::from(path);
        validate_absolute_direct(&path)?;
        return Ok(path);
    }
    platform_data_home(xdg_data_home, user_home).map(|base| base.join("identities"))
}

fn platform_global_vault_home(
    xdg_data_home: Option<&OsStr>,
    user_home: Option<&OsStr>,
) -> Result<PathBuf, HomeSelectionError> {
    platform_data_home(xdg_data_home, user_home).map(|base| base.join("vaults/default"))
}

fn platform_data_home(
    xdg_data_home: Option<&OsStr>,
    user_home: Option<&OsStr>,
) -> Result<PathBuf, HomeSelectionError> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (xdg_data_home, user_home);
        Err(HomeSelectionError::UnsupportedPlatform)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = xdg_data_home;
        let home = user_home
            .filter(|value| !value.is_empty())
            .ok_or(HomeSelectionError::MissingUserHome)?;
        let home = PathBuf::from(home);
        validate_absolute_direct(&home)?;
        Ok(home.join("Library/Application Support/Jury"))
    }
    #[cfg(target_os = "linux")]
    {
        let base = if let Some(xdg) = xdg_data_home.filter(|value| !value.is_empty()) {
            PathBuf::from(xdg)
        } else {
            PathBuf::from(user_home.ok_or(HomeSelectionError::MissingUserHome)?)
                .join(".local/share")
        };
        let path = base.join("jury");
        validate_absolute_direct(&path)?;
        Ok(path)
    }
}

fn validate_absolute_direct(path: &Path) -> Result<(), HomeSelectionError> {
    if path.as_os_str().as_encoded_bytes().contains(&0)
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        Err(HomeSelectionError::InvalidPath)
    } else {
        Ok(())
    }
}

impl From<FilesystemError> for HomeSelectionError {
    fn from(_: FilesystemError) -> Self {
        Self::Repository
    }
}

#[cfg(test)]
#[path = "home_tests.rs"]
mod tests;
