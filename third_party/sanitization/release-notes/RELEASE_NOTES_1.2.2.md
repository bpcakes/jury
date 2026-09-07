# Release 1.2.2

- Added the optional `sanitization-crypto-interop` sister crate for targeted
  third-party crypto hasher cleanup and HMAC-SHA2 helpers during migrations
  from direct `zeroize` usage.
- Added feature-gated SHA-2 helpers and wrappers that compile `sha2` with its
  upstream `zeroize` support enabled.
- Added feature-gated BLAKE3 helpers and wrappers that explicitly clear
  `blake3::Hasher` and XOF reader state after digest extraction.
- Added feature-gated HMAC-SHA2 helpers implemented over SHA-2 with explicit
  RAII sanitization of key-block, pad, and inner-digest scratch buffers.
- Added RFC 4231 HMAC-SHA384/SHA512 short-key and long-key test-vector
  coverage for the local HMAC-SHA2 helper implementation.
- Clarified that free digest/MAC helpers return ordinary caller-owned arrays
  and that HKDF wrappers are deferred until internal PRK cleanup can be made
  explicit.
- Updated release checks and publishing order to include the new crypto
  interop crate.
