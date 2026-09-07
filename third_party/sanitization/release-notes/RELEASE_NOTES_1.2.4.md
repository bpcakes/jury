# Release 1.2.4

- Switched the pinned/default toolchain to Rust `1.97.0` while retaining Rust
  `1.90.0` as the minimum supported version.
- Verified the complete all-features workspace across every supported stable
  compiler from Rust `1.90.0` through Rust `1.97.0`.
- Refreshed compatible dependency locks, including `zeroize 1.9.0`,
  `arrayvec 0.7.8`, `bytes 1.12.1`, `quote 1.0.46`, and `syn 2.0.118`.
- Pinned every GitHub Action to the immutable commit for its documented release,
  added Dependabot maintenance, and added a check that rejects mutable action
  references.
- Updated fallible secret constructors for Rust 1.97 Clippy without changing
  their clear-on-error RAII behavior.
- Surfaced guard-page setup cleanup failures consistently with locked mappings
  and documented that unmap errors take precedence when setup and cleanup both
  fail.
- Bounded Linux AArch64 auxiliary-vector read retries before falling back to the
  conservative page granule.
- Added `SecretArrayVec::push_or_sanitize` with a payload-free error for secure
  rejection while preserving conventional `push` behavior and its unchanged
  recoverable `CapacityError<T>` value.
- Added unwind-safe eager clearing guards to `ReadOnceSecret::consume` and
  `consume_mut`, including when another shared owner keeps the wrapper alive.
- Added `BoundedSecretVec<MAX>` for application-defined dynamic secret limits,
  including strict bounded serde handling for borrowed bytes, owned buffers,
  and sequences.
- Added a 1 MiB default ceiling to ordinary `SecretVec` deserialization so
  existing serde call sites are no longer unbounded by default.
- Pinned CI installation of `cargo-audit` to version `0.22.2`.
- Added reproducible deployment guidance for locked, frozen, vendored final
  application dependency graphs.
- Updated all workspace crates and crates.io-facing version references for the
  `1.2.4` patch release.
