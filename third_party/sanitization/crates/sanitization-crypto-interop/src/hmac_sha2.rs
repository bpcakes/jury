//! HMAC-SHA2 helpers with explicit scratch-buffer sanitization.
//!
//! Prefer these helpers over manually hashing `key || message` with raw SHA-2.
//! Raw SHA-2 keyed constructions are vulnerable to length-extension and other
//! misuse patterns. HMAC is the standard MAC construction for SHA-2.

use sanitization::{ct, wipe};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::sha2::{sha256_digest, sha384_digest, sha512_digest};

const SHA256_BLOCK: usize = 64;
const SHA384_BLOCK: usize = 128;
const SHA512_BLOCK: usize = 128;

// RFC 2104 section 2.
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

struct Scratch<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Scratch<N> {
    #[inline]
    const fn zeroed() -> Self {
        Self { bytes: [0; N] }
    }

    #[inline]
    const fn filled(byte: u8) -> Self {
        Self { bytes: [byte; N] }
    }

    #[inline]
    fn from_array(mut bytes: [u8; N]) -> Self {
        let mut scratch = Self::zeroed();
        scratch.bytes.copy_from_slice(&bytes);
        wipe::bytes(&mut bytes);
        scratch
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl<const N: usize> Drop for Scratch<N> {
    #[inline]
    fn drop(&mut self) {
        wipe::bytes(&mut self.bytes);
    }
}

/// Compute HMAC-SHA256.
///
/// Use [`hmac_sha256_verify`] instead of comparing this returned tag with `==`
/// when checking an expected tag.
///
/// The caller remains responsible for clearing `key` after use if it is stored
/// outside a `sanitization` secret container.
///
/// The returned tag is ordinary caller-owned memory. If the tag is sensitive,
/// clear it with `sanitization::wipe::bytes` after use or move it directly
/// into a secret container.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let key_block = normalize_key::<SHA256_BLOCK, 32>(key, sha256_digest);
    let mut inner_pad = Scratch::<SHA256_BLOCK>::filled(IPAD);
    let mut outer_pad = Scratch::<SHA256_BLOCK>::filled(OPAD);
    xor_key_block(
        key_block.as_slice(),
        inner_pad.as_mut_slice(),
        outer_pad.as_mut_slice(),
    );

    let mut inner = Sha256::new();
    inner.update(inner_pad.as_slice());
    inner.update(message);
    let inner_hash = Scratch::<32>::from_array(inner.finalize().into());

    let mut outer = Sha256::new();
    outer.update(outer_pad.as_slice());
    outer.update(inner_hash.as_slice());
    outer.finalize().into()
}

/// Verify an HMAC-SHA256 tag without short-circuiting on the first mismatch.
#[must_use]
pub fn hmac_sha256_verify(key: &[u8], message: &[u8], tag: &[u8; 32]) -> bool {
    let mut actual = hmac_sha256(key, message);
    let matches =
        ct::eq_fixed(&actual, tag).declassify("HMAC-SHA256 verification result is public");
    wipe::bytes(&mut actual);
    matches
}

/// Compute HMAC-SHA384.
///
/// Use [`hmac_sha384_verify`] instead of comparing this returned tag with `==`
/// when checking an expected tag.
///
/// The caller remains responsible for clearing `key` after use if it is stored
/// outside a `sanitization` secret container.
///
/// The returned tag is ordinary caller-owned memory. If the tag is sensitive,
/// clear it with `sanitization::wipe::bytes` after use or move it directly
/// into a secret container.
#[must_use]
pub fn hmac_sha384(key: &[u8], message: &[u8]) -> [u8; 48] {
    let key_block = normalize_key::<SHA384_BLOCK, 48>(key, sha384_digest);
    let mut inner_pad = Scratch::<SHA384_BLOCK>::filled(IPAD);
    let mut outer_pad = Scratch::<SHA384_BLOCK>::filled(OPAD);
    xor_key_block(
        key_block.as_slice(),
        inner_pad.as_mut_slice(),
        outer_pad.as_mut_slice(),
    );

    let mut inner = Sha384::new();
    inner.update(inner_pad.as_slice());
    inner.update(message);
    let inner_hash = Scratch::<48>::from_array(inner.finalize().into());

    let mut outer = Sha384::new();
    outer.update(outer_pad.as_slice());
    outer.update(inner_hash.as_slice());
    outer.finalize().into()
}

/// Verify an HMAC-SHA384 tag without short-circuiting on the first mismatch.
#[must_use]
pub fn hmac_sha384_verify(key: &[u8], message: &[u8], tag: &[u8; 48]) -> bool {
    let mut actual = hmac_sha384(key, message);
    let matches =
        ct::eq_fixed(&actual, tag).declassify("HMAC-SHA384 verification result is public");
    wipe::bytes(&mut actual);
    matches
}

/// Compute HMAC-SHA512.
///
/// Use [`hmac_sha512_verify`] instead of comparing this returned tag with `==`
/// when checking an expected tag.
///
/// The caller remains responsible for clearing `key` after use if it is stored
/// outside a `sanitization` secret container.
///
/// The returned tag is ordinary caller-owned memory. If the tag is sensitive,
/// clear it with `sanitization::wipe::bytes` after use or move it directly
/// into a secret container.
#[must_use]
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let key_block = normalize_key::<SHA512_BLOCK, 64>(key, sha512_digest);
    let mut inner_pad = Scratch::<SHA512_BLOCK>::filled(IPAD);
    let mut outer_pad = Scratch::<SHA512_BLOCK>::filled(OPAD);
    xor_key_block(
        key_block.as_slice(),
        inner_pad.as_mut_slice(),
        outer_pad.as_mut_slice(),
    );

    let mut inner = Sha512::new();
    inner.update(inner_pad.as_slice());
    inner.update(message);
    let inner_hash = Scratch::<64>::from_array(inner.finalize().into());

    let mut outer = Sha512::new();
    outer.update(outer_pad.as_slice());
    outer.update(inner_hash.as_slice());
    outer.finalize().into()
}

/// Verify an HMAC-SHA512 tag without short-circuiting on the first mismatch.
#[must_use]
pub fn hmac_sha512_verify(key: &[u8], message: &[u8], tag: &[u8; 64]) -> bool {
    let mut actual = hmac_sha512(key, message);
    let matches =
        ct::eq_fixed(&actual, tag).declassify("HMAC-SHA512 verification result is public");
    wipe::bytes(&mut actual);
    matches
}

#[inline]
fn normalize_key<const BLOCK: usize, const OUT: usize>(
    key: &[u8],
    digest_key: impl FnOnce(&[u8]) -> [u8; OUT],
) -> Scratch<BLOCK> {
    let mut key_block = Scratch::<BLOCK>::zeroed();
    if key.len() > BLOCK {
        let hashed_key = Scratch::<OUT>::from_array(digest_key(key));
        key_block.as_mut_slice()[..OUT].copy_from_slice(hashed_key.as_slice());
    } else {
        key_block.as_mut_slice()[..key.len()].copy_from_slice(key);
    }
    key_block
}

#[inline]
fn xor_key_block(key_block: &[u8], inner_pad: &mut [u8], outer_pad: &mut [u8]) {
    let mut index = 0;
    while index < key_block.len() {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_1() {
        let tag = hmac_sha256(&[0x0b; 20], b"Hi There");

        assert_eq!(
            tag,
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ]
        );
    }

    #[test]
    fn hmac_sha384_matches_rfc_4231_case_1() {
        let tag = hmac_sha384(&[0x0b; 20], b"Hi There");

        assert_eq!(
            tag,
            [
                0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46,
                0x90, 0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6, 0x82, 0xaa, 0x03, 0x4c,
                0x7c, 0xeb, 0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1,
                0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6,
            ]
        );
    }

    #[test]
    fn hmac_sha512_matches_rfc_4231_case_1() {
        let tag = hmac_sha512(&[0x0b; 20], b"Hi There");

        assert_eq!(
            tag,
            [
                0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d,
                0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05,
                0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b,
                0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
                0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54,
            ]
        );
    }

    #[test]
    fn hmac_sha384_matches_rfc_4231_long_key_case_6() {
        let tag = hmac_sha384(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );

        assert_eq!(
            tag,
            [
                0x4e, 0xce, 0x08, 0x44, 0x85, 0x81, 0x3e, 0x90, 0x88, 0xd2, 0xc6, 0x3a, 0x04, 0x1b,
                0xc5, 0xb4, 0x4f, 0x9e, 0xf1, 0x01, 0x2a, 0x2b, 0x58, 0x8f, 0x3c, 0xd1, 0x1f, 0x05,
                0x03, 0x3a, 0xc4, 0xc6, 0x0c, 0x2e, 0xf6, 0xab, 0x40, 0x30, 0xfe, 0x82, 0x96, 0x24,
                0x8d, 0xf1, 0x63, 0xf4, 0x49, 0x52,
            ]
        );
    }

    #[test]
    fn hmac_sha512_matches_rfc_4231_long_key_case_6() {
        let tag = hmac_sha512(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );

        assert_eq!(
            tag,
            [
                0x80, 0xb2, 0x42, 0x63, 0xc7, 0xc1, 0xa3, 0xeb, 0xb7, 0x14, 0x93, 0xc1, 0xdd, 0x7b,
                0xe8, 0xb4, 0x9b, 0x46, 0xd1, 0xf4, 0x1b, 0x4a, 0xee, 0xc1, 0x12, 0x1b, 0x01, 0x37,
                0x83, 0xf8, 0xf3, 0x52, 0x6b, 0x56, 0xd0, 0x37, 0xe0, 0x5f, 0x25, 0x98, 0xbd, 0x0f,
                0xd2, 0x21, 0x5d, 0x6a, 0x1e, 0x52, 0x95, 0xe6, 0x4f, 0x73, 0xf6, 0x3f, 0x0a, 0xec,
                0x8b, 0x91, 0x5a, 0x98, 0x5d, 0x78, 0x65, 0x98,
            ]
        );
    }

    #[test]
    fn hmac_verify_helpers_accept_and_reject_tags() {
        let tag256 = hmac_sha256(b"key", b"message");
        let tag384 = hmac_sha384(b"key", b"message");
        let tag512 = hmac_sha512(b"key", b"message");

        assert!(hmac_sha256_verify(b"key", b"message", &tag256));
        assert!(hmac_sha384_verify(b"key", b"message", &tag384));
        assert!(hmac_sha512_verify(b"key", b"message", &tag512));

        let mut bad256 = tag256;
        let mut bad384 = tag384;
        let mut bad512 = tag512;
        bad256[0] ^= 1;
        bad384[0] ^= 1;
        bad512[0] ^= 1;

        assert!(!hmac_sha256_verify(b"key", b"message", &bad256));
        assert!(!hmac_sha384_verify(b"key", b"message", &bad384));
        assert!(!hmac_sha512_verify(b"key", b"message", &bad512));
    }
}
