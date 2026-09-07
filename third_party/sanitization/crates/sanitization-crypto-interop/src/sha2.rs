//! SHA-2 helpers with upstream hasher zeroization enabled.
//!
//! The `sha2` dependency is compiled with its `zeroize` feature. SHA-2 hasher
//! state is then cleared by the upstream implementation when the hasher is
//! dropped or consumed during finalization.

use sanitization::SecureSanitize;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

/// Compute a SHA-224 digest.
///
/// The returned array is ordinary caller-owned memory. If the digest is
/// sensitive, clear it with `sanitization::wipe::bytes` after use or move it
/// directly into a secret container.
#[must_use]
#[inline]
pub fn sha224_digest(preimage: &[u8]) -> [u8; 28] {
    let mut hasher = Sha224::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

/// Compute a SHA-256 digest.
///
/// The returned array is ordinary caller-owned memory. If the digest is
/// sensitive, clear it with `sanitization::wipe::bytes` after use or move it
/// directly into a secret container.
#[must_use]
#[inline]
pub fn sha256_digest(preimage: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

/// Compute a SHA-384 digest.
///
/// The returned array is ordinary caller-owned memory. If the digest is
/// sensitive, clear it with `sanitization::wipe::bytes` after use or move it
/// directly into a secret container.
#[must_use]
#[inline]
pub fn sha384_digest(preimage: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

/// Compute a SHA-512 digest.
///
/// The returned array is ordinary caller-owned memory. If the digest is
/// sensitive, clear it with `sanitization::wipe::bytes` after use or move it
/// directly into a secret container.
#[must_use]
#[inline]
pub fn sha512_digest(preimage: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

/// Compute a SHA-512/224 digest.
///
/// The returned array is ordinary caller-owned memory. If the digest is
/// sensitive, clear it with `sanitization::wipe::bytes` after use or move it
/// directly into a secret container.
#[must_use]
#[inline]
pub fn sha512_224_digest(preimage: &[u8]) -> [u8; 28] {
    let mut hasher = Sha512_224::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

/// Compute a SHA-512/256 digest.
///
/// The returned array is ordinary caller-owned memory. If the digest is
/// sensitive, clear it with `sanitization::wipe::bytes` after use or move it
/// directly into a secret container.
#[must_use]
#[inline]
pub fn sha512_256_digest(preimage: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

/// Clear-on-drop wrapper around [`sha2::Sha256`].
///
/// This is useful when an application needs incremental hashing but wants the
/// dependency features that make the upstream hasher clear its internal state
/// on drop.
pub struct SanitizedSha256 {
    inner: Sha256,
}

impl SanitizedSha256 {
    /// Create a new hasher.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Feed bytes into the hasher.
    #[inline]
    pub fn update(&mut self, input: &[u8]) {
        self.inner.update(input);
    }

    /// Finalize and return the digest.
    #[must_use]
    #[inline]
    pub fn finalize(mut self) -> [u8; 32] {
        let hasher = core::mem::replace(&mut self.inner, Sha256::new());
        hasher.finalize().into()
    }
}

impl Default for SanitizedSha256 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl SecureSanitize for SanitizedSha256 {
    #[inline]
    fn secure_sanitize(&mut self) {
        // `sha2` exposes `ZeroizeOnDrop`, not direct `Zeroize`, for hashers.
        // Assignment drops the old hasher before installing the fresh one.
        self.inner = Sha256::new();
    }
}

impl Drop for SanitizedSha256 {
    #[inline]
    fn drop(&mut self) {
        // Make the clear-on-drop boundary visible at this wrapper layer. The
        // old hasher is zeroized through upstream `ZeroizeOnDrop`.
        self.inner = Sha256::new();
    }
}

/// Clear-on-drop wrapper around [`sha2::Sha384`].
pub struct SanitizedSha384 {
    inner: Sha384,
}

impl SanitizedSha384 {
    /// Create a new hasher.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Sha384::new(),
        }
    }

    /// Feed bytes into the hasher.
    #[inline]
    pub fn update(&mut self, input: &[u8]) {
        self.inner.update(input);
    }

    /// Finalize and return the digest.
    #[must_use]
    #[inline]
    pub fn finalize(mut self) -> [u8; 48] {
        let hasher = core::mem::replace(&mut self.inner, Sha384::new());
        hasher.finalize().into()
    }
}

impl Default for SanitizedSha384 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl SecureSanitize for SanitizedSha384 {
    #[inline]
    fn secure_sanitize(&mut self) {
        // `sha2` exposes `ZeroizeOnDrop`, not direct `Zeroize`, for hashers.
        // Assignment drops the old hasher before installing the fresh one.
        self.inner = Sha384::new();
    }
}

impl Drop for SanitizedSha384 {
    #[inline]
    fn drop(&mut self) {
        // Make the clear-on-drop boundary visible at this wrapper layer. The
        // old hasher is zeroized through upstream `ZeroizeOnDrop`.
        self.inner = Sha384::new();
    }
}

/// Clear-on-drop wrapper around [`sha2::Sha512`].
pub struct SanitizedSha512 {
    inner: Sha512,
}

impl SanitizedSha512 {
    /// Create a new hasher.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Sha512::new(),
        }
    }

    /// Feed bytes into the hasher.
    #[inline]
    pub fn update(&mut self, input: &[u8]) {
        self.inner.update(input);
    }

    /// Finalize and return the digest.
    #[must_use]
    #[inline]
    pub fn finalize(mut self) -> [u8; 64] {
        let hasher = core::mem::replace(&mut self.inner, Sha512::new());
        hasher.finalize().into()
    }
}

impl Default for SanitizedSha512 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl SecureSanitize for SanitizedSha512 {
    #[inline]
    fn secure_sanitize(&mut self) {
        // `sha2` exposes `ZeroizeOnDrop`, not direct `Zeroize`, for hashers.
        // Assignment drops the old hasher before installing the fresh one.
        self.inner = Sha512::new();
    }
}

impl Drop for SanitizedSha512 {
    #[inline]
    fn drop(&mut self) {
        // Make the clear-on-drop boundary visible at this wrapper layer. The
        // old hasher is zeroized through upstream `ZeroizeOnDrop`.
        self.inner = Sha512::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn sha2_hashers_expose_zeroize_on_drop() {
        assert_zeroize_on_drop::<Sha224>();
        assert_zeroize_on_drop::<Sha256>();
        assert_zeroize_on_drop::<Sha384>();
        assert_zeroize_on_drop::<Sha512>();
        assert_zeroize_on_drop::<Sha512_224>();
        assert_zeroize_on_drop::<Sha512_256>();
    }

    #[test]
    fn sha512_helper_matches_known_empty_digest() {
        let digest = sha512_digest(b"");
        assert_eq!(
            digest,
            [
                0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
                0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
                0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
                0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
            ]
        );
    }

    #[test]
    fn wrapper_hashes_incrementally() {
        let mut hasher = SanitizedSha256::new();
        hasher.update(b"hel");
        hasher.update(b"lo");

        assert_eq!(hasher.finalize(), sha256_digest(b"hello"));
    }

    #[test]
    fn wrappers_implement_secure_sanitize() {
        let mut hasher = SanitizedSha512::new();
        hasher.update(b"secret");
        hasher.secure_sanitize();

        assert_eq!(hasher.finalize(), sha512_digest(b""));
    }
}
