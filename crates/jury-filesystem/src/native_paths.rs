//! Pure platform state-root selection; no filesystem access or migration.

use std::ffi::OsStr;
use std::fmt;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatePathError {
    Unsupported,
    MissingHome,
    NotAbsolute,
    Nul,
    Traversal,
}

impl fmt::Display for StatePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unsupported => "the platform state root is unsupported",
            Self::MissingHome => "the platform state root has no home directory",
            Self::NotAbsolute => "the platform state root is not absolute",
            Self::Traversal => "the platform state root contains traversal",
            Self::Nul => "the platform state root contains a NUL byte",
        })
    }
}

impl std::error::Error for StatePathError {}

/// Resolves the Linux state-root contract from caller-supplied environment
/// values. This function does not read process-global environment state.
pub fn resolve_linux_state_root(
    jury_state_home: Option<&OsStr>,
    xdg_state_home: Option<&OsStr>,
    user_home: Option<&OsStr>,
) -> Result<PathBuf, StatePathError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (jury_state_home, xdg_state_home, user_home);
        Err(StatePathError::Unsupported)
    }
    #[cfg(target_os = "linux")]
    {
        let path = if let Some(path) = jury_state_home.filter(|value| !value.is_empty()) {
            PathBuf::from(path)
        } else if let Some(path) = xdg_state_home.filter(|value| !value.is_empty()) {
            PathBuf::from(path).join("jury/vaults")
        } else {
            PathBuf::from(user_home.ok_or(StatePathError::MissingHome)?)
                .join(".local/state/jury/vaults")
        };
        validate_resolved_path(path)
    }
}

/// Resolves native CLI state roots without reading environment or touching disk.
/// Linux retains its existing XDG contract; macOS ignores XDG inputs.
pub fn resolve_platform_state_root(
    jury_state_home: Option<&OsStr>,
    xdg_state_home: Option<&OsStr>,
    user_home: Option<&OsStr>,
) -> Result<PathBuf, StatePathError> {
    #[cfg(not(target_os = "macos"))]
    {
        resolve_linux_state_root(jury_state_home, xdg_state_home, user_home)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = xdg_state_home;
        // An explicitly empty private root is invalid on macOS; JURY_HOME is
        // a vault selector whose established empty-value fallback is retained.
        let path = if let Some(path) = jury_state_home {
            PathBuf::from(path)
        } else {
            let home = user_home
                .filter(|value| !value.is_empty())
                .ok_or(StatePathError::MissingHome)?;
            validate_resolved_path(PathBuf::from(home))?
                .join("Library/Application Support/Jury/state/vaults")
        };
        validate_resolved_path(path)
    }
}

/// Reads the state-root inputs once and applies [`resolve_platform_state_root`].
pub fn resolve_state_root_from_environment() -> Result<PathBuf, StatePathError> {
    let jury = std::env::var_os("JURY_STATE_HOME");
    let xdg = std::env::var_os("XDG_STATE_HOME");
    let home = std::env::var_os("HOME");
    resolve_platform_state_root(jury.as_deref(), xdg.as_deref(), home.as_deref())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_resolved_path(path: PathBuf) -> Result<PathBuf, StatePathError> {
    if !path.is_absolute() {
        return Err(StatePathError::NotAbsolute);
    }
    // Absolute Path components normalize interior dots; only parent traversal
    // is rejected here. Filesystem opening enforces its own path constraints.
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(StatePathError::Traversal);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        if path.as_os_str().as_bytes().contains(&0) {
            return Err(StatePathError::Nul);
        }
    }
    #[cfg(not(unix))]
    if path.to_string_lossy().contains('\0') {
        return Err(StatePathError::Nul);
    }
    Ok(path)
}

#[cfg(test)]
#[path = "native_paths_tests.rs"]
mod tests;
