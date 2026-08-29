//! Domain boundary for Jury.
//!
//! This crate intentionally contains no cryptographic implementation yet.

#![forbid(unsafe_code)]

/// Human-readable product name.
pub const PRODUCT_NAME: &str = "Jury";

/// Short product positioning used by the initial command-line interface.
pub const PRODUCT_TAGLINE: &str = "Portable secrets with configurable distributed authority.";

/// Current implementation maturity.
pub const MATURITY: &str = "pre-alpha scaffold; do not use with real secrets";
