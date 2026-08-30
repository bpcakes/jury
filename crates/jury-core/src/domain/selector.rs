use std::fmt;

use serde::{Deserialize, Serialize};

use super::{FieldNameInput, ItemNameInput, NameError};

/// Unconfirmed caller selection of one item by canonical name.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemSelector {
    item: ItemNameInput,
}

impl ItemSelector {
    /// Validates an item argument without confirming catalog membership.
    pub fn parse(item: impl Into<String>) -> Result<Self, NameError> {
        Ok(Self {
            item: ItemNameInput::parse(item)?,
        })
    }

    /// Constructs a selector from separately validated caller input.
    #[must_use]
    pub const fn from_input(item: ItemNameInput) -> Self {
        Self { item }
    }

    /// Returns the still-unconfirmed item-name input.
    #[must_use]
    pub const fn input(&self) -> &ItemNameInput {
        &self.item
    }
}

impl fmt::Debug for ItemSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ItemSelector(<unconfirmed>)")
    }
}

/// Unconfirmed caller selection of one field within one item.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSelector {
    item: ItemNameInput,
    field: FieldNameInput,
}

impl FieldSelector {
    /// Validates separate item and field arguments. Combined URI or path syntax
    /// is intentionally not accepted here.
    pub fn parse(item: impl Into<String>, field: impl Into<String>) -> Result<Self, NameError> {
        Ok(Self {
            item: ItemNameInput::parse(item)?,
            field: FieldNameInput::parse(field)?,
        })
    }

    /// Constructs a selector from separately validated caller inputs.
    #[must_use]
    pub const fn from_inputs(item: ItemNameInput, field: FieldNameInput) -> Self {
        Self { item, field }
    }

    /// Returns the item-only portion without confirming catalog membership.
    #[must_use]
    pub fn item_selector(&self) -> ItemSelector {
        ItemSelector::from_input(self.item.clone())
    }

    /// Returns the still-unconfirmed item-name input.
    #[must_use]
    pub const fn item_input(&self) -> &ItemNameInput {
        &self.item
    }

    /// Returns the still-unconfirmed field-name input.
    #[must_use]
    pub const fn field_input(&self) -> &FieldNameInput {
        &self.field
    }
}

impl fmt::Debug for FieldSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FieldSelector(<unconfirmed>)")
    }
}
