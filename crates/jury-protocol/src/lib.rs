//! Versioned public wire formats for Jury vaults and witnesses.

#![forbid(unsafe_code)]

mod artifact;
mod canonical;
pub mod identity_v1;
pub mod transfer_v1;
pub mod vault_v1;
pub mod witness_v1;

/// Stable protocol family name reserved by the scaffold.
pub const PROTOCOL_FAMILY: &str = "jury";

/// No complete interoperable runtime protocol version has shipped.
pub const IMPLEMENTED_PROTOCOL_VERSION: Option<u16> = None;
