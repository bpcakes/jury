#![no_std]
#![deny(unsafe_code)]

//! Optional crypto crate interop helpers for `sanitization`.
//!
//! The core `sanitization` crate clears memory it owns. It cannot clear private
//! buffers inside third-party hash implementations unless those crates expose
//! their own zeroization hooks. This crate provides small feature-gated helpers
//! for those cases while keeping the core crate dependency-free.

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "blake3")]
pub mod blake3;
#[cfg(feature = "hmac-sha2")]
pub mod hmac_sha2;
#[cfg(feature = "sha2")]
pub mod sha2;
