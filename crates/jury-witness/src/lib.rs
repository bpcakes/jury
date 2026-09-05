//! Self-hostable transport and persistence adapters for the Jury witness engine.
//!
//! Jury is pre-alpha and must not be used with real secrets.

#![forbid(unsafe_code)]

pub mod anchor;
pub mod config;
pub mod identity_provider;
pub mod persistence;
pub mod policy_material;
pub mod runtime;
pub mod server;

mod credentials;
mod error;
mod state_worker;

pub use error::{AdapterError, AdapterErrorKind};
