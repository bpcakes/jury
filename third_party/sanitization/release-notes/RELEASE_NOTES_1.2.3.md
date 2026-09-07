# Release 1.2.3

- Fixed `ct::CtOrdering::new` so hidden `Choice` inputs are normalized without
  secret-dependent branches.
- Added constant-time verification helpers for HMAC-SHA256, HMAC-SHA384,
  HMAC-SHA512, BLAKE3 digest, keyed BLAKE3 digest, and fixed 64-byte BLAKE3
  XOF outputs in `sanitization-crypto-interop`.
- Clamped serde sequence preallocation for `SecretVec` so untrusted
  `size_hint` values cannot trigger attacker-sized initial allocations.
- Hardened native `SecretPool` by storing the construction-validated slot
  stride and removing a destructor-path overflow `expect`.
- Surfaced native mapping unmap failures during setup-error cleanup instead of
  silently discarding them.
- Added dependency-advisory auditing to CI and opportunistic local checks.
- Switched the pinned/default release toolchain to Rust `1.96.1` while keeping
  `rust-version = "1.90"` and adding a compatibility check gate for Rust
  `1.90.0` through `1.96.1`.
- Updated crates.io-facing version references for the 1.2.3 patch release.
