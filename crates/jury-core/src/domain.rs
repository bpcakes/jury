//! Bounded, Jury-native domain values.
//!
//! Names use a small version-independent ASCII profile. External routing,
//! filesystem locations, and source-control metadata belong to adapters and
//! cannot be represented by these types.
//!
//! Serde representations in this module are semantic transport forms, not
//! canonical signed preimages. The protocol layer owns the versioned binary
//! preimages introduced by J05. Serialized item and field names belong only in
//! encrypted descriptor or body plaintext; public state identifies objects by
//! opaque identifiers.

mod access;
mod catalog;
mod id;
mod name;
mod revision;
mod selector;

pub use access::{Capability, Grant, ItemRole, Role};
pub use catalog::{
    AccessibleCatalog, AccessibleCatalogEntry, AccessibleField, CatalogError, ItemUnavailable,
    LookupResult, MAX_ACCESSIBLE_CATALOG_ITEMS,
};
pub use id::{
    IDENTIFIER_BYTES, IDENTIFIER_COLLISION_RETRY_ATTEMPTS, IDENTIFIER_HEX_LENGTH,
    IDENTIFIER_ZERO_RETRY_ATTEMPTS, IdentifierError, IdentifierGenerationError, ItemId,
    NativeIdGenerator, PrincipalId, VaultId,
};
pub use name::{
    ConfirmedFieldName, ConfirmedItemName, FieldName, FieldNameInput, ItemName, ItemNameInput,
    MAX_FIELD_NAME_BYTES, MAX_ITEM_NAME_BYTES, NameError,
};
pub use revision::{ItemRevision, KeyEpoch, PolicyRevision, RevisionError};
pub use selector::{FieldSelector, ItemSelector};
