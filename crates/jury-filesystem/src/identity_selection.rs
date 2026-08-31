use std::fmt;
use std::path::{Component, Path, PathBuf};

use jury_protected::ProtectedMemory;

use crate::{
    FilesystemError, HardenedStateRoot, PreparedPrivateFile, PublicationPolicy, RepositoryLocation,
};

pub const MAX_IDENTITY_NAME_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentitySelectionError {
    Ambiguous,
    InvalidName,
    InvalidExplicitPath,
}

impl fmt::Display for IdentitySelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ambiguous => "identity name and explicit file cannot both be selected",
            Self::InvalidName => "identity name is not a canonical portable component",
            Self::InvalidExplicitPath => "explicit identity file path is not absolute and direct",
        })
    }
}

impl std::error::Error for IdentitySelectionError {}

/// A bounded local selector name. It is not a principal identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdentityName(String);

impl IdentityName {
    pub fn parse(value: impl Into<String>) -> Result<Self, IdentitySelectionError> {
        let value = value.into();
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_IDENTITY_NAME_BYTES
            || !value.is_ascii()
            || !bytes[0].is_ascii_alphanumeric()
            || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
            || bytes
                .iter()
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(*byte, b'-' | b'.' | b'_'))
        {
            return Err(IdentitySelectionError::InvalidName);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn filename(&self) -> String {
        format!("{}.identity.json", self.0)
    }
}

impl fmt::Debug for IdentityName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityName(<redacted>)")
    }
}

/// Exactly one selected identity: a named child or one explicit absolute file.
#[derive(Clone, Eq, PartialEq)]
pub enum IdentitySelector {
    Named(IdentityName),
    ExplicitFile(PathBuf),
}

impl IdentitySelector {
    /// Resolves mutually exclusive selection inputs, defaulting to `default`.
    pub fn select(
        name: Option<&str>,
        explicit_file: Option<PathBuf>,
    ) -> Result<Self, IdentitySelectionError> {
        match (name, explicit_file) {
            (Some(_), Some(_)) => Err(IdentitySelectionError::Ambiguous),
            (Some(name), None) => IdentityName::parse(name).map(Self::Named),
            (None, Some(path)) => {
                validate_explicit_path(&path)?;
                Ok(Self::ExplicitFile(path))
            }
            (None, None) => IdentityName::parse("default").map(Self::Named),
        }
    }

    /// Reads only the selected file; it never scans or probes sibling identities.
    pub fn read(
        &self,
        named_root: &HardenedStateRoot,
        repositories: &[&RepositoryLocation],
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, FilesystemError> {
        match self {
            Self::Named(name) => {
                named_root.read_private_file(Path::new(&name.filename()), maximum_bytes)
            }
            Self::ExplicitFile(path) => {
                let (root, name) = explicit_root(path, repositories)?;
                root.read_private_file(Path::new(name), maximum_bytes)
            }
        }
    }

    /// Prepares an atomic owner-only write at exactly the selected destination.
    pub fn prepare(
        &self,
        named_root: &HardenedStateRoot,
        repositories: &[&RepositoryLocation],
        contents: &ProtectedMemory,
        policy: PublicationPolicy,
    ) -> Result<PreparedPrivateFile, FilesystemError> {
        match self {
            Self::Named(name) => PreparedPrivateFile::prepare_state(
                named_root,
                Path::new(&name.filename()),
                contents,
                policy,
            ),
            Self::ExplicitFile(path) => {
                let (root, name) = explicit_root(path, repositories)?;
                PreparedPrivateFile::prepare_state(&root, Path::new(name), contents, policy)
            }
        }
    }
}

impl fmt::Debug for IdentitySelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(_) => formatter.write_str("IdentitySelector::Named(<redacted>)"),
            Self::ExplicitFile(_) => {
                formatter.write_str("IdentitySelector::ExplicitFile(<redacted>)")
            }
        }
    }
}

fn validate_explicit_path(path: &Path) -> Result<(), IdentitySelectionError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.parent().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(IdentitySelectionError::InvalidExplicitPath);
    }
    Ok(())
}

fn explicit_root<'a>(
    path: &'a Path,
    repositories: &[&RepositoryLocation],
) -> Result<(HardenedStateRoot, &'a std::ffi::OsStr), FilesystemError> {
    let parent = path.parent().ok_or_else(|| {
        FilesystemError::new(
            crate::FilesystemOperation::OpenStateRoot,
            crate::FilesystemErrorKind::Traversal,
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        FilesystemError::new(
            crate::FilesystemOperation::OpenStateRoot,
            crate::FilesystemErrorKind::Traversal,
        )
    })?;
    Ok((
        HardenedStateRoot::open_existing(parent, repositories)?,
        name,
    ))
}
