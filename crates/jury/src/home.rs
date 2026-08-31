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
    Repository { repository: RepositoryLocation },
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
            path: linux_global_vault_home(xdg_data_home, user_home)?,
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
        Ok(repository) => Ok(VaultHomeLocation::Repository { repository }),
        Err(error) if error.kind() == jury_filesystem::FilesystemErrorKind::NotFound => {
            Ok(VaultHomeLocation::Detached {
                path: linux_global_vault_home(xdg_data_home, user_home)?,
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
    if let Some(path) = jury_identity_home.filter(|value| !value.is_empty()) {
        let path = PathBuf::from(path);
        validate_absolute_direct(&path)?;
        return Ok(path);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (xdg_data_home, user_home);
        Err(HomeSelectionError::UnsupportedPlatform)
    }
    #[cfg(target_os = "linux")]
    {
        let base = if let Some(xdg) = xdg_data_home.filter(|value| !value.is_empty()) {
            PathBuf::from(xdg)
        } else {
            PathBuf::from(user_home.ok_or(HomeSelectionError::MissingUserHome)?)
                .join(".local/share")
        };
        let path = base.join("jury/identities");
        validate_absolute_direct(&path)?;
        Ok(path)
    }
}

fn linux_global_vault_home(
    xdg_data_home: Option<&OsStr>,
    user_home: Option<&OsStr>,
) -> Result<PathBuf, HomeSelectionError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (xdg_data_home, user_home);
        Err(HomeSelectionError::UnsupportedPlatform)
    }
    #[cfg(target_os = "linux")]
    {
        let base = if let Some(xdg) = xdg_data_home.filter(|value| !value.is_empty()) {
            PathBuf::from(xdg)
        } else {
            PathBuf::from(user_home.ok_or(HomeSelectionError::MissingUserHome)?)
                .join(".local/share")
        };
        let path = base.join("jury/vaults/default");
        validate_absolute_direct(&path)?;
        Ok(path)
    }
}

fn validate_absolute_direct(path: &Path) -> Result<(), HomeSelectionError> {
    if !path.is_absolute()
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
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn precedence_is_explicit_global_environment_repository_default()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let repository = root.path().join("repository");
        fs::create_dir_all(repository.join(".git"))?;
        fs::write(
            repository.join(".git").join("HEAD"),
            [b"ref: refs".as_slice(), b"/heads/main\n"].concat(),
        )?;
        let nested = repository.join("nested");
        fs::create_dir(&nested)?;
        let explicit = root.path().join("explicit");
        let environment = root.path().join("environment");
        let xdg = root.path().join("xdg");

        let selected = resolve_vault_home(
            &nested,
            Some(explicit.clone()),
            false,
            Some(environment.as_os_str()),
            Some(xdg.as_os_str()),
            Some(root.path().as_os_str()),
        )?;
        assert_eq!(selected.source(), HomeSource::Explicit);
        assert_eq!(selected.detached_path(), Some(explicit.as_path()));
        assert!(matches!(
            resolve_vault_home(
                &nested,
                Some(explicit),
                true,
                None,
                Some(xdg.as_os_str()),
                Some(root.path().as_os_str()),
            ),
            Err(HomeSelectionError::Ambiguous)
        ));

        let selected = resolve_vault_home(
            &nested,
            None,
            true,
            Some(environment.as_os_str()),
            Some(xdg.as_os_str()),
            Some(root.path().as_os_str()),
        )?;
        assert_eq!(selected.source(), HomeSource::GlobalFlag);
        assert!(
            selected
                .detached_path()
                .is_some_and(|path| path.ends_with("jury/vaults/default"))
        );

        let selected = resolve_vault_home(
            &nested,
            None,
            false,
            Some(environment.as_os_str()),
            Some(xdg.as_os_str()),
            Some(root.path().as_os_str()),
        )?;
        assert_eq!(selected.source(), HomeSource::Environment);
        let selected = resolve_vault_home(
            &nested,
            None,
            false,
            None,
            Some(xdg.as_os_str()),
            Some(root.path().as_os_str()),
        )?;
        assert_eq!(selected.source(), HomeSource::Repository);

        let outside = root.path().join("outside");
        fs::create_dir(&outside)?;
        let selected = resolve_vault_home(
            &outside,
            None,
            false,
            None,
            Some(xdg.as_os_str()),
            Some(root.path().as_os_str()),
        )?;
        assert_eq!(selected.source(), HomeSource::PlatformDefault);
        Ok(())
    }

    #[test]
    fn relative_and_parent_paths_fail_without_disclosing_them() {
        for path in [PathBuf::from("relative"), PathBuf::from("/tmp/../escape")] {
            let error = resolve_vault_home(
                Path::new("/tmp"),
                Some(path),
                false,
                None,
                None,
                Some(OsStr::new("/tmp")),
            )
            .err();
            assert_eq!(error, Some(HomeSelectionError::InvalidPath));
        }
    }
}
