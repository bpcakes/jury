# Suite-2 conformance

## Purpose

Test J18's AES-256-GCM HPKE composition using pinned real providers.
This standalone crate is not a runtime dependency. Its inputs are bound by
`docs/security/jury-v2-crypto-gate.toml`; the crate alone does not satisfy that gate.

## Key entrypoints

- `src/bin/primitives.rs`: public primitive corpus producer/consumer.
- `alternate/boringssl_runner.cc`: pinned alternate-provider consumer.
- `primitive-vectors.json` and `primitive-alternate.json`: retained outputs.
- `contexts.py`, `src/bin/contexts.rs` and `context-vectors.json`: canonical
  production-context conformance.

## Edit here for X

Update canonical contexts and provider checks through the exact-input gate.
Production cryptographic adapters belong in `jury-core` after input acceptance.

## Invariants

- Keep this crate outside the root workspace and runtime dependency graph.
- Keep exact provider pins and resolved zeroization features.
- Use public generic fixtures only; never overwrite retained vectors to pass.
- Cross-provider agreement is interoperability evidence, not independent review.

## Common commands

- `cargo run --manifest-path conformance/suite-2/Cargo.toml --locked --bin primitives -- verify conformance/suite-2/primitive-alternate.json`
