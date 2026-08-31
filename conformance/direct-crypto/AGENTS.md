# Direct-crypto conformance crate

## Purpose

Exercise the exact J01B provider set against the frozen J01A corpus without
linking cryptographic providers into a Jury product crate.

## Key entrypoints

- `src/lib.rs` contains provider and cross-implementation conformance tests.
- `Cargo.toml` and `Cargo.lock` pin the isolated test dependency graph.

## Edit here for X

Update this crate only when J01A vectors or the J01B provider selection is
explicitly reopened. Product cryptographic wrappers belong in `jury-core`.

## Invariants

- This crate remains a standalone workspace and never becomes a root-workspace
  member or a runtime dependency.
- Provider features remain exact; no default, getrandom, legacy, PEM, PKCS8, or
  general hazmat API is enabled.
- Test values are public generic fixtures only.

## Common commands

- `cargo test --manifest-path conformance/direct-crypto/Cargo.toml --locked`
