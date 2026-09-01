//! Domain boundary for Jury.
//!
//! Cryptographic providers stay private behind typed Jury operations.

#![forbid(unsafe_code)]

pub mod access_provider;
pub mod adapter;
mod canonical;
mod crypto;
pub mod domain;
pub mod entropy;
pub mod identity;
pub mod item;
pub mod local_state;
pub mod mutation;
pub mod policy;
pub mod registration;
#[cfg(test)]
mod registration_tests;
pub mod session;
pub mod transfer;
pub mod witness_engine;

/// Human-readable product name.
pub const PRODUCT_NAME: &str = "Jury";

/// Short product positioning used by the initial command-line interface.
pub const PRODUCT_TAGLINE: &str = "Portable secrets with configurable distributed authority.";

/// Current implementation maturity.
pub const MATURITY: &str = "pre-alpha; do not use with real secrets";
