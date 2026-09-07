//! BLAKE3 helpers with explicit hasher and XOF reader cleanup.

use sanitization::{ct, wipe, SecureSanitize};
use zeroize::Zeroize;

/// Compute a 32-byte BLAKE3 digest.
///
/// Use [`blake3_digest_verify`] instead of comparing this returned digest with
/// `==` when checking an expected digest.
///
/// The returned array is ordinary caller-owned memory. If the digest is
/// sensitive, clear it with `sanitization::wipe::bytes` after use or move it
/// directly into a secret container.
#[must_use]
#[inline]
pub fn blake3_digest(preimage: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(preimage);
    let digest = *hasher.finalize().as_bytes();
    hasher.zeroize();
    digest
}

/// Verify a 32-byte BLAKE3 digest without short-circuiting on the first mismatch.
#[must_use]
#[inline]
pub fn blake3_digest_verify(preimage: &[u8], digest: &[u8; 32]) -> bool {
    let mut actual = blake3_digest(preimage);
    let matches =
        ct::eq_fixed(&actual, digest).declassify("BLAKE3 digest verification result is public");
    wipe::bytes(&mut actual);
    matches
}

/// Compute a keyed 32-byte BLAKE3 digest.
///
/// Use [`blake3_keyed_digest_verify`] instead of comparing this returned tag
/// with `==` when checking an expected keyed digest.
///
/// The caller remains responsible for clearing `key` if it is stored outside a
/// `sanitization` secret container.
/// The returned array is ordinary caller-owned memory. If the digest is
/// sensitive, clear it with `sanitization::wipe::bytes` after use or move it
/// directly into a secret container.
#[must_use]
#[inline]
pub fn blake3_keyed_digest(key: &[u8; 32], preimage: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(preimage);
    let digest = *hasher.finalize().as_bytes();
    hasher.zeroize();
    digest
}

/// Verify a keyed 32-byte BLAKE3 digest without short-circuiting on the first mismatch.
#[must_use]
#[inline]
pub fn blake3_keyed_digest_verify(key: &[u8; 32], preimage: &[u8], digest: &[u8; 32]) -> bool {
    let mut actual = blake3_keyed_digest(key, preimage);
    let matches =
        ct::eq_fixed(&actual, digest).declassify("keyed BLAKE3 verification result is public");
    wipe::bytes(&mut actual);
    matches
}

/// Compute 64 bytes of BLAKE3 XOF output.
///
/// Use [`blake3_xof_64_verify`] instead of comparing this returned digest with
/// `==` when checking an expected fixed XOF output.
///
/// Both the BLAKE3 hasher and XOF reader are explicitly zeroized after the
/// output bytes are copied into the returned array.
/// The returned array is ordinary caller-owned memory. If the digest is
/// sensitive, clear it with `sanitization::wipe::bytes` after use or move it
/// directly into a secret container.
#[must_use]
#[inline]
pub fn blake3_xof_64(preimage: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(preimage);
    let mut digest = [0u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut digest);
    reader.zeroize();
    hasher.zeroize();
    digest
}

/// Verify 64 bytes of BLAKE3 XOF output without short-circuiting on mismatch.
#[must_use]
#[inline]
pub fn blake3_xof_64_verify(preimage: &[u8], digest: &[u8; 64]) -> bool {
    let mut actual = blake3_xof_64(preimage);
    let matches =
        ct::eq_fixed(&actual, digest).declassify("BLAKE3 XOF verification result is public");
    wipe::bytes(&mut actual);
    matches
}

/// Compute 64 bytes of keyed BLAKE3 XOF output.
///
/// Use [`blake3_keyed_xof_64_verify`] instead of comparing this returned tag
/// with `==` when checking an expected fixed keyed XOF output.
///
/// The caller remains responsible for clearing `key` if it is stored outside a
/// `sanitization` secret container.
/// The returned array is ordinary caller-owned memory. If the digest is
/// sensitive, clear it with `sanitization::wipe::bytes` after use or move it
/// directly into a secret container.
#[must_use]
#[inline]
pub fn blake3_keyed_xof_64(key: &[u8; 32], preimage: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(preimage);
    let mut digest = [0u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut digest);
    reader.zeroize();
    hasher.zeroize();
    digest
}

/// Verify 64 bytes of keyed BLAKE3 XOF output without short-circuiting on mismatch.
#[must_use]
#[inline]
pub fn blake3_keyed_xof_64_verify(key: &[u8; 32], preimage: &[u8], digest: &[u8; 64]) -> bool {
    let mut actual = blake3_keyed_xof_64(key, preimage);
    let matches =
        ct::eq_fixed(&actual, digest).declassify("keyed BLAKE3 XOF verification result is public");
    wipe::bytes(&mut actual);
    matches
}

/// Fill caller-provided output with BLAKE3 XOF bytes.
///
/// This supports callers that need output lengths other than 32 or 64 bytes
/// while still clearing both the hasher and XOF reader state before returning.
#[inline]
pub fn blake3_xof_fill(preimage: &[u8], output: &mut [u8]) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(preimage);
    let mut reader = hasher.finalize_xof();
    reader.fill(output);
    reader.zeroize();
    hasher.zeroize();
}

/// Fill caller-provided output with keyed BLAKE3 XOF bytes.
///
/// The caller remains responsible for clearing `key` if it is stored outside a
/// `sanitization` secret container.
#[inline]
pub fn blake3_keyed_xof_fill(key: &[u8; 32], preimage: &[u8], output: &mut [u8]) {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(preimage);
    let mut reader = hasher.finalize_xof();
    reader.fill(output);
    reader.zeroize();
    hasher.zeroize();
}

/// Clear-on-drop wrapper around [`blake3::Hasher`].
pub struct SanitizedBlake3 {
    inner: blake3::Hasher,
}

impl SanitizedBlake3 {
    /// Create a new BLAKE3 hasher.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }

    /// Create a new keyed BLAKE3 hasher.
    ///
    /// The caller remains responsible for clearing `key` if it is stored
    /// outside a `sanitization` secret container.
    #[must_use]
    #[inline]
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Self {
            inner: blake3::Hasher::new_keyed(key),
        }
    }

    /// Feed bytes into the hasher.
    #[inline]
    pub fn update(&mut self, input: &[u8]) {
        self.inner.update(input);
    }

    /// Finalize to a 32-byte digest, clearing the hasher state first.
    #[must_use]
    #[inline]
    pub fn finalize(mut self) -> [u8; 32] {
        let digest = *self.inner.finalize().as_bytes();
        self.inner.zeroize();
        digest
    }

    /// Finalize to 64 bytes of XOF output, clearing the reader and hasher.
    #[must_use]
    #[inline]
    pub fn finalize_xof_64(mut self) -> [u8; 64] {
        let mut digest = [0u8; 64];
        let mut reader = self.inner.finalize_xof();
        reader.fill(&mut digest);
        reader.zeroize();
        self.inner.zeroize();
        digest
    }

    /// Fill caller-provided XOF output, clearing the reader and hasher.
    #[inline]
    pub fn finalize_xof_fill(mut self, output: &mut [u8]) {
        let mut reader = self.inner.finalize_xof();
        reader.fill(output);
        reader.zeroize();
        self.inner.zeroize();
    }
}

impl Default for SanitizedBlake3 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl SecureSanitize for SanitizedBlake3 {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.inner.zeroize();
        self.inner = blake3::Hasher::new();
    }
}

impl Drop for SanitizedBlake3 {
    #[inline]
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_digest_matches_upstream() {
        assert_eq!(blake3_digest(b"hello"), *blake3::hash(b"hello").as_bytes());
    }

    #[test]
    fn blake3_xof_fill_matches_fixed_helper() {
        let mut output = [0u8; 64];
        blake3_xof_fill(b"hello", &mut output);

        assert_eq!(output, blake3_xof_64(b"hello"));
    }

    #[test]
    fn keyed_helpers_match_upstream() {
        let key = [7u8; 32];
        let mut expected = blake3::Hasher::new_keyed(&key);
        expected.update(b"hello");

        assert_eq!(
            blake3_keyed_digest(&key, b"hello"),
            *expected.finalize().as_bytes()
        );

        let mut fill = [0u8; 64];
        blake3_keyed_xof_fill(&key, b"hello", &mut fill);
        assert_eq!(fill, blake3_keyed_xof_64(&key, b"hello"));
    }

    #[test]
    fn verify_helpers_accept_and_reject_outputs() {
        let key = [7u8; 32];
        let digest = blake3_digest(b"hello");
        let keyed_digest = blake3_keyed_digest(&key, b"hello");
        let xof = blake3_xof_64(b"hello");
        let keyed_xof = blake3_keyed_xof_64(&key, b"hello");

        assert!(blake3_digest_verify(b"hello", &digest));
        assert!(blake3_keyed_digest_verify(&key, b"hello", &keyed_digest));
        assert!(blake3_xof_64_verify(b"hello", &xof));
        assert!(blake3_keyed_xof_64_verify(&key, b"hello", &keyed_xof));

        let mut bad_digest = digest;
        let mut bad_keyed_digest = keyed_digest;
        let mut bad_xof = xof;
        let mut bad_keyed_xof = keyed_xof;
        bad_digest[0] ^= 1;
        bad_keyed_digest[0] ^= 1;
        bad_xof[0] ^= 1;
        bad_keyed_xof[0] ^= 1;

        assert!(!blake3_digest_verify(b"hello", &bad_digest));
        assert!(!blake3_keyed_digest_verify(
            &key,
            b"hello",
            &bad_keyed_digest
        ));
        assert!(!blake3_xof_64_verify(b"hello", &bad_xof));
        assert!(!blake3_keyed_xof_64_verify(&key, b"hello", &bad_keyed_xof));
    }

    #[test]
    fn wrapper_hashes_incrementally() {
        let mut hasher = SanitizedBlake3::new();
        hasher.update(b"hel");
        hasher.update(b"lo");

        assert_eq!(hasher.finalize(), blake3_digest(b"hello"));
    }

    #[test]
    fn wrapper_implements_secure_sanitize() {
        let mut hasher = SanitizedBlake3::new();
        hasher.update(b"secret");
        hasher.secure_sanitize();

        assert_eq!(hasher.finalize(), blake3_digest(b""));
    }
}
