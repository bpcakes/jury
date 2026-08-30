use serde::{Deserialize, Serialize};

use super::{ItemId, PrincipalId};

/// An operation class checked against an effective role.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Read,
    Write,
    Administer,
}

/// Effective authority after applying the vault-owner rule and item grants.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Reader,
    Writer,
    Owner,
}

impl Role {
    /// Returns whether this role permits the requested operation class.
    #[must_use]
    pub const fn permits(self, capability: Capability) -> bool {
        matches!(
            (self, capability),
            (Self::Reader, Capability::Read)
                | (Self::Writer, Capability::Read | Capability::Write)
                | (Self::Owner, _)
        )
    }
}

/// Item-scoped authority. Owner authority is vault-scoped and cannot be
/// represented as an item grant.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemRole {
    Reader,
    Writer,
}

impl From<ItemRole> for Role {
    fn from(role: ItemRole) -> Self {
        match role {
            ItemRole::Reader => Self::Reader,
            ItemRole::Writer => Self::Writer,
        }
    }
}

/// A normalized vault-wide owner grant or item-scoped read/write grant.
///
/// The enum shape makes invalid combinations such as an item-scoped owner or a
/// vault-wide reader unrepresentable. This Serde form is a semantic transport
/// representation; J05 defines the separate, versioned binary preimage used
/// for signatures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum Grant {
    VaultOwner {
        principal_id: PrincipalId,
    },
    Item {
        principal_id: PrincipalId,
        item_id: ItemId,
        role: ItemRole,
    },
}

impl Grant {
    /// Returns the principal receiving this authority.
    #[must_use]
    pub const fn principal_id(self) -> PrincipalId {
        match self {
            Self::VaultOwner { principal_id } | Self::Item { principal_id, .. } => principal_id,
        }
    }

    /// Returns the effective role represented by this grant.
    #[must_use]
    pub const fn role(self) -> Role {
        match self {
            Self::VaultOwner { .. } => Role::Owner,
            Self::Item { role, .. } => match role {
                ItemRole::Reader => Role::Reader,
                ItemRole::Writer => Role::Writer,
            },
        }
    }
}
