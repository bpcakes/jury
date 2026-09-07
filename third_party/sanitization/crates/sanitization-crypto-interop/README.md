<p align="center">
  <b>Crypto hasher and MAC cleanup helpers for sanitization.</b><br>
  Targeted SHA-2, BLAKE3, and HMAC-SHA2 interop without changing the core crate defaults.
</p>

<div align="center">
  <a href="https://crates.io/crates/sanitization">sanitization crate</a>
  |
  <a href="https://docs.rs/sanitization-crypto-interop">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/docs/SAFETY.md">Safety</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/docs/MIGRATION_2.0.md">2.0 Migration</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/sanitization">
    <img src="https://raw.githubusercontent.com/valkyoth/sanitization/main/.github/images/sanitization.webp" alt="sanitization Rust crate overview">
  </a>
</p>

# sanitization-crypto-interop

Optional crypto crate integration helpers for
[`sanitization`](https://crates.io/crates/sanitization).

This crate exists for projects migrating from direct `zeroize` usage to
`sanitization` while still depending on third-party hash implementations whose
internal state is only clearable through those crates' own `zeroize` features.

The core `sanitization` crate remains dependency-free by default. This sister
crate is explicitly opt-in and feature-gated per backend.
The optional `std` feature forwards to `sanitization/std` for callers that want
the same feature profile across both crates; it is disabled by default.
The dependency-free `asm-compare` feature is enabled by default and forwards to
`sanitization/asm-compare`, so fixed-length verification uses the reviewed
x86_64/AArch64 equality backend. Disable default features only when the
portable fallback is deliberately required.
The optional `strict-compare` feature forwards to
`sanitization/strict-compare`, making all fixed-length HMAC and BLAKE3 verify
helpers use the reviewed native assembly equality backend on x86_64 and
AArch64 and fail closed on unsupported non-Miri targets.

```toml
[dependencies]
sanitization-crypto-interop = { version = "2.0.4", features = ["sha2", "blake3", "hmac-sha2", "strict-compare"] }
```

## SHA-2

The `sha2` feature enables `sha2`'s own `zeroize` support so hasher state is
cleared by the upstream implementation when the hasher is dropped.
The incremental wrapper types also implement `sanitization::SecureSanitize`.

The digest helper functions return ordinary arrays. If a digest is sensitive,
clear it after use with `sanitization::wipe::bytes` or move it directly into
a `sanitization` secret container.

```rust
use sanitization_crypto_interop::sha2::sha512_digest;

let digest = sha512_digest(b"input");
```

## BLAKE3

The `blake3` feature enables `blake3`'s own `zeroize` support and explicitly
clears both the `Hasher` and XOF `OutputReader` after digest extraction.
The incremental wrapper type also implements `sanitization::SecureSanitize`.

```rust
use sanitization_crypto_interop::blake3::{blake3_xof_64, blake3_xof_64_verify};

let digest = blake3_xof_64(b"input");
assert!(blake3_xof_64_verify(b"input", &digest));
```

Keyed BLAKE3 helpers are also available:

```rust
use sanitization_crypto_interop::blake3::{
    blake3_keyed_digest_verify, blake3_keyed_xof_64,
};

let key = [7u8; 32];
let digest = blake3_keyed_xof_64(&key, b"input");
let expected_tag = sanitization_crypto_interop::blake3::blake3_keyed_digest(&key, b"input");
assert!(blake3_keyed_digest_verify(&key, b"input", &expected_tag));
```

The caller remains responsible for clearing key material stored outside a
`sanitization` secret container.

## HMAC-SHA2

The `hmac-sha2` feature enables HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512
helpers built directly on SHA-2 with RAII sanitization of key-block, pad, and
inner-digest scratch buffers, including panic-unwind cleanup.
Prefer these helpers over manually building keyed SHA-2 by hashing
`key || message`.
Because this is a local RFC 2104 implementation, keep this module in audit
scope for high-assurance deployments.

```toml
[dependencies]
sanitization-crypto-interop = { version = "2.0.4", features = ["hmac-sha2"] }
```

```rust
use sanitization_crypto_interop::hmac_sha2::{hmac_sha256, hmac_sha256_verify};

let tag = hmac_sha256(b"key", b"message");
assert!(hmac_sha256_verify(b"key", b"message", &tag));
```

Like digest helpers, returned tags are ordinary arrays and remain the caller's
responsibility to clear if treated as sensitive.
Use the `*_verify` helpers for MAC or tag checks; ordinary `==` on arrays
short-circuits and can leak the mismatch position through timing.
The caller also remains responsible for clearing HMAC key bytes held outside a
`sanitization` secret container.

## HKDF

HKDF helpers are intentionally not exposed yet. The current upstream `hkdf`
crate stores PRK/HMAC state internally, and this crate will only wrap it after
the cleanup path can be made explicit and tested the same way as the SHA-2,
BLAKE3, and HMAC helpers.

## Scope

This crate does not implement clearing for arbitrary opaque crypto types. It
only wraps third-party crates that expose their own clearing hooks or provides
purpose-built helpers where scratch buffers are owned and cleared locally. If a
crypto crate does not expose a zeroization API or feature, this crate cannot
safely clear that crate's private internal buffers.
