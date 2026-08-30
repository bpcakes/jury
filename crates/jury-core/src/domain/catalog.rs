use std::collections::BTreeSet;
use std::fmt;

use super::{
    ConfirmedFieldName, ConfirmedItemName, FieldName, FieldNameInput, ItemId, ItemName,
    ItemSelector, Role,
};

/// Maximum number of active plus tombstoned items in a vault.
pub const MAX_ACCESSIBLE_CATALOG_ITEMS: usize = 1_024;

/// An item name is either resolved through the decrypted accessible catalog or
/// uniformly unavailable. The error has no name or existence detail.
pub type LookupResult<T> = Result<T, ItemUnavailable>;

/// Uniform result for a nonexistent or inaccessible caller-supplied name.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ItemUnavailable;

impl fmt::Display for ItemUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("requested item is unavailable")
    }
}

impl std::error::Error for ItemUnavailable {}

/// Failure to construct a bounded, unambiguous accessible catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogError {
    TooManyEntries { maximum: usize, actual: usize },
    DuplicateItemId,
    DuplicateItemName,
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyEntries { maximum, actual } => {
                write!(
                    formatter,
                    "accessible catalog exceeds {maximum} entries (got {actual})"
                )
            }
            Self::DuplicateItemId => {
                formatter.write_str("accessible catalog has a duplicate item ID")
            }
            Self::DuplicateItemName => {
                formatter.write_str("accessible catalog has a duplicate canonical item name")
            }
        }
    }
}

impl std::error::Error for CatalogError {}

/// One decrypted item descriptor known to be accessible to the active
/// principal. Its name is safe to display to that caller.
#[derive(Clone, Eq, PartialEq)]
pub struct AccessibleCatalogEntry {
    item_id: ItemId,
    name: ConfirmedItemName,
    role: Role,
}

impl AccessibleCatalogEntry {
    /// Creates an entry from an already decrypted accessible descriptor.
    #[must_use]
    pub fn from_decrypted(item_id: ItemId, name: ItemName, role: Role) -> Self {
        Self {
            item_id,
            name: ConfirmedItemName::from_accessible_name(name),
            role,
        }
    }

    /// Returns the public opaque item ID.
    #[must_use]
    pub const fn item_id(&self) -> ItemId {
        self.item_id
    }

    /// Returns the catalog-confirmed, caller-safe display name.
    #[must_use]
    pub const fn name(&self) -> &ConfirmedItemName {
        &self.name
    }

    /// Returns the active principal's effective role for this item.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }
}

impl fmt::Debug for AccessibleCatalogEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessibleCatalogEntry")
            .field("item_id", &self.item_id)
            .field("name", &"<redacted-confirmed-name>")
            .field("role", &self.role)
            .finish()
    }
}

/// The bounded catalog of descriptors decrypted for one active principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessibleCatalog {
    entries: Vec<AccessibleCatalogEntry>,
}

impl AccessibleCatalog {
    /// Validates bounds and rejects ambiguity before exposing lookup.
    pub fn try_new(entries: Vec<AccessibleCatalogEntry>) -> Result<Self, CatalogError> {
        if entries.len() > MAX_ACCESSIBLE_CATALOG_ITEMS {
            return Err(CatalogError::TooManyEntries {
                maximum: MAX_ACCESSIBLE_CATALOG_ITEMS,
                actual: entries.len(),
            });
        }

        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        for entry in &entries {
            if !ids.insert(entry.item_id) {
                return Err(CatalogError::DuplicateItemId);
            }
            if !names.insert(entry.name.as_name().as_str()) {
                return Err(CatalogError::DuplicateItemName);
            }
        }

        Ok(Self { entries })
    }

    /// Resolves only against decrypted accessible names. An absent entry gives
    /// the same result whether it is nonexistent or merely inaccessible.
    pub fn resolve(&self, selector: &ItemSelector) -> LookupResult<&AccessibleCatalogEntry> {
        self.entries
            .iter()
            .find(|entry| entry.name.as_name() == selector.input().as_name())
            .ok_or(ItemUnavailable)
    }

    /// Returns only already-confirmed accessible entries.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = &AccessibleCatalogEntry> {
        self.entries.iter()
    }
}

/// A field name confirmed only after decrypting an accessible item body.
#[derive(Clone, Eq, PartialEq)]
pub struct AccessibleField {
    name: ConfirmedFieldName,
}

impl AccessibleField {
    /// Creates a display projection from an already decrypted accessible body.
    #[must_use]
    pub fn from_decrypted(name: FieldName) -> Self {
        Self {
            name: ConfirmedFieldName::from_accessible_name(name),
        }
    }

    /// Returns the caller-safe confirmed field name.
    #[must_use]
    pub const fn name(&self) -> &ConfirmedFieldName {
        &self.name
    }

    /// Compares validated caller input without exposing the decrypted name.
    #[must_use]
    pub fn matches(&self, input: &FieldNameInput) -> bool {
        self.name.as_name() == input.as_name()
    }
}

impl fmt::Debug for AccessibleField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccessibleField(<redacted-confirmed-name>)")
    }
}
