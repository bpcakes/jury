//! Versioned protocol boundary for Jury witnesses.
//!
//! Message schemas and cryptographic encodings are deliberately absent until
//! the threat model and protocol specification are reviewed.

#![forbid(unsafe_code)]

/// Stable protocol family name reserved by the scaffold.
pub const PROTOCOL_FAMILY: &str = "jury";

/// Indicates that no interoperable protocol version has shipped.
pub const IMPLEMENTED_PROTOCOL_VERSION: Option<u16> = None;
