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
///
/// External callers cannot manufacture the confirmed projection:
///
/// ```compile_fail
/// use jury_core::domain::{AccessibleCatalogEntry, ItemId, ItemName, Role};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let item_id = ItemId::from_bytes([1; 32])?;
/// let name = ItemName::parse("ExampleItem")?;
/// let _entry = AccessibleCatalogEntry::from_decrypted(item_id, name, Role::Reader);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct AccessibleCatalogEntry {
    item_id: ItemId,
    name: ConfirmedItemName,
    role: Role,
}

impl AccessibleCatalogEntry {
    /// Creates an entry from an already decrypted accessible descriptor.
    #[must_use]
    pub(crate) fn from_decrypted(item_id: ItemId, name: ItemName, role: Role) -> Self {
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

    /// Overwrites decrypted accessible names and empties the catalog.
    pub(crate) fn clear_sensitive(&mut self) {
        for entry in &mut self.entries {
            entry.name.clear_sensitive();
        }
        self.entries.clear();
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
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "J04 decryptors are the first production callers of this crate-private seam"
        )
    )]
    pub(crate) fn from_decrypted(name: FieldName) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inaccessible_and_nonexistent_names_have_one_result() -> Result<(), Box<dyn std::error::Error>>
    {
        let visible = AccessibleCatalogEntry::from_decrypted(
            ItemId::from_bytes([0x41; 32])?,
            ItemName::parse("ExampleVisible")?,
            Role::Reader,
        );
        let catalog = AccessibleCatalog::try_new(vec![visible])?;

        let inaccessible = catalog.resolve(&ItemSelector::parse("ExampleHidden")?);
        let nonexistent = catalog.resolve(&ItemSelector::parse("ExampleMissing")?);
        assert_eq!(inaccessible, Err(ItemUnavailable));
        assert_eq!(nonexistent, Err(ItemUnavailable));
        assert_eq!(inaccessible.map(|_| ()), nonexistent.map(|_| ()));
        assert_eq!(ItemUnavailable.to_string(), "requested item is unavailable");

        let found = catalog.resolve(&ItemSelector::parse("ExampleVisible")?)?;
        assert_eq!(found.item_id(), ItemId::from_bytes([0x41; 32])?);
        assert_eq!(found.name().to_string(), "ExampleVisible");
        assert_eq!(found.role(), Role::Reader);
        assert!(!format!("{found:?}").contains("ExampleVisible"));
        Ok(())
    }

    #[test]
    fn accessible_catalog_rejects_duplicate_ids_and_names() -> Result<(), Box<dyn std::error::Error>>
    {
        let item_id = ItemId::from_bytes([0x51; 32])?;
        let first = AccessibleCatalogEntry::from_decrypted(
            item_id,
            ItemName::parse("ExampleItem")?,
            Role::Reader,
        );
        let duplicate_id = AccessibleCatalogEntry::from_decrypted(
            item_id,
            ItemName::parse("ExampleOther")?,
            Role::Writer,
        );
        assert_eq!(
            AccessibleCatalog::try_new(vec![first.clone(), duplicate_id]),
            Err(CatalogError::DuplicateItemId)
        );

        let duplicate_name = AccessibleCatalogEntry::from_decrypted(
            ItemId::from_bytes([0x52; 32])?,
            ItemName::parse("ExampleItem")?,
            Role::Writer,
        );
        assert_eq!(
            AccessibleCatalog::try_new(vec![first, duplicate_name]),
            Err(CatalogError::DuplicateItemName)
        );
        Ok(())
    }

    #[test]
    fn accessible_catalog_enforces_its_entry_bound() -> Result<(), Box<dyn std::error::Error>> {
        let entry = AccessibleCatalogEntry::from_decrypted(
            ItemId::from_bytes([0x53; 32])?,
            ItemName::parse("ExampleItem")?,
            Role::Reader,
        );
        let actual = MAX_ACCESSIBLE_CATALOG_ITEMS + 1;

        assert_eq!(
            AccessibleCatalog::try_new(vec![entry; actual]),
            Err(CatalogError::TooManyEntries {
                maximum: MAX_ACCESSIBLE_CATALOG_ITEMS,
                actual,
            })
        );
        Ok(())
    }

    #[test]
    fn field_display_requires_a_decrypted_accessible_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        let field = AccessibleField::from_decrypted(FieldName::parse("EXAMPLE_FIELD")?);
        assert_eq!(field.name().to_string(), "EXAMPLE_FIELD");
        assert!(field.matches(&FieldNameInput::parse("EXAMPLE_FIELD")?));
        assert!(!field.matches(&FieldNameInput::parse("EXAMPLE_OTHER")?));
        assert!(!format!("{field:?}").contains("EXAMPLE_FIELD"));
        Ok(())
    }

    #[test]
    fn confirmed_name_debug_is_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let entry = AccessibleCatalogEntry::from_decrypted(
            ItemId::from_bytes([0x54; 32])?,
            ItemName::parse("ExampleSensitiveItem")?,
            Role::Reader,
        );
        let field = AccessibleField::from_decrypted(FieldName::parse("EXAMPLE_SENSITIVE_FIELD")?);

        assert_eq!(format!("{:?}", entry.name()), "<redacted-item-name>");
        assert_eq!(format!("{:?}", field.name()), "<redacted-field-name>");
        assert!(!format!("{:?}", entry.name()).contains("ExampleSensitiveItem"));
        assert!(!format!("{:?}", field.name()).contains("EXAMPLE_SENSITIVE_FIELD"));
        Ok(())
    }
}
