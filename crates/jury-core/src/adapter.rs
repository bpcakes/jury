//! Non-authoritative seams for external reference and storage routing.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use crate::domain::FieldSelector;

/// Maximum encoded byte length accepted for an explicit external vault home.
pub const MAX_EXTERNAL_HOME_BYTES: usize = 4_096;

/// A downstream translator from an external reference into a bounded native
/// selector.
///
/// The return type deliberately contains no vault, principal, or item ID and no
/// grant. Translation can select caller-visible names but cannot replace
/// cryptographic identity or authority.
pub trait ExternalReferenceAdapter {
    type Reference: ?Sized;
    type Error;

    fn translate(&self, reference: &Self::Reference) -> Result<FieldSelector, Self::Error>;
}

/// Routing context used only to locate native storage before domain parsing.
/// This type is intentionally not serializable.
#[derive(Clone, Eq, PartialEq)]
pub enum StorageContext {
    Repository,
    Global,
    Explicit(AbsoluteVaultHome),
}

impl fmt::Debug for StorageContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Repository => formatter.write_str("StorageContext::Repository"),
            Self::Global => formatter.write_str("StorageContext::Global"),
            Self::Explicit(_) => formatter.write_str("StorageContext::Explicit(<redacted-home>)"),
        }
    }
}

/// A validated absolute home for explicit adapter routing.
#[derive(Clone, Eq, PartialEq)]
pub struct AbsoluteVaultHome(PathBuf);

impl AbsoluteVaultHome {
    /// Applies only syntactic bounds to an explicit home without resolving or
    /// publishing it.
    ///
    /// This does not establish filesystem identity or safety across symlinks,
    /// mount changes, or races. The J02 storage adapter must enforce those
    /// properties while opening the location.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, StorageContextError> {
        let path = path.into();
        let encoded = path.as_os_str().as_encoded_bytes();

        if encoded.is_empty() {
            return Err(StorageContextError::Empty);
        }
        if encoded.len() > MAX_EXTERNAL_HOME_BYTES {
            return Err(StorageContextError::TooLong {
                maximum: MAX_EXTERNAL_HOME_BYTES,
                actual: encoded.len(),
            });
        }
        if encoded.contains(&0) {
            return Err(StorageContextError::Nul);
        }
        if !path.is_absolute() {
            return Err(StorageContextError::NotAbsolute);
        }
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(StorageContextError::Traversal);
        }

        Ok(Self(path))
    }

    /// Exposes the path only to the storage adapter that must open it.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl fmt::Debug for AbsoluteVaultHome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AbsoluteVaultHome(<redacted>)")
    }
}

/// Non-sensitive reason an external storage location was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageContextError {
    Empty,
    TooLong { maximum: usize, actual: usize },
    Nul,
    NotAbsolute,
    Traversal,
}

impl fmt::Display for StorageContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("explicit vault home cannot be empty"),
            Self::TooLong { maximum, actual } => {
                write!(
                    formatter,
                    "explicit vault home exceeds {maximum} bytes (got {actual})"
                )
            }
            Self::Nul => formatter.write_str("explicit vault home contains a NUL byte"),
            Self::NotAbsolute => formatter.write_str("explicit vault home must be absolute"),
            Self::Traversal => {
                formatter.write_str("explicit vault home cannot contain relative traversal")
            }
        }
    }
}

impl std::error::Error for StorageContextError {}
