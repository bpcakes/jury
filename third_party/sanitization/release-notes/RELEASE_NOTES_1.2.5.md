# Release 1.2.5

- Added `BoundedSecretString<MAX>` for UTF-8 secrets with an application-defined
  public byte limit across construction, append, replacement, and serde
  ingestion.
- Added a 1 MiB default serde byte ceiling for ordinary `SecretString`, matching
  the existing bounded-by-default `SecretVec` ingestion policy.
- Added allocation-preserving conversions between `SecretVec` and
  `SecretString`; invalid UTF-8 inputs are cleared before returning an error.
- Added `LockedSecretString`, a UTF-8-safe wrapper over `LockedSecretVec` that
  preserves memory locking, dump/fork policy, canaries, clearing, and mapped
  storage without introducing a second mapping.
- Added `GuardedSecretString`, a UTF-8-safe wrapper over `GuardedSecretVec` that
  preserves guard pages, optional memory locking, canaries, and clearing.
- Added checked locked/guarded text exposure through
  `SecretTextIntegrityError`, distinguishing canary corruption from invalid
  UTF-8.
- Added owned `String` ingestion helpers that clear the original global
  allocator storage after copying into locked or guarded mappings.
- Extended native constant-time traits and optional `zeroize`/`subtle`
  interoperability to the new text containers.
- Updated README guidance for direct secret-aware JSON ingestion, including the
  remaining limits around parser input and scratch-buffer copies.
- Clarified that UTF-8 validation and length rejection are not data-oblivious,
  that serde limits begin at visitor control, and that Miri/Kani do not provide
  native syscall or real-concurrency coverage.
- Updated all workspace crates and crates.io-facing version references for the
  `1.2.5` patch release.
