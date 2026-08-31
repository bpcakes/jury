# Rust Workspace Guidelines

## Purpose

The `crates` tree owns Jury's Rust implementation. It is a pre-alpha
implementation and must not be used for real secrets.

## Key entrypoints

- `jury/src/main.rs`: `jury` CLI process entrypoint
- `jury-core/src/lib.rs`: vault-domain and cryptographic orchestration boundary
- `jury-protocol/src/lib.rs`: versioned public protocol boundary
- `jury-tui/src/lib.rs`: terminal UI boundary
- `jury-witness/src/main.rs`: `juryd` process entrypoint

## Edit here for X

- Put domain invariants and use cases in `jury-core`.
- Put canonical wire types and compatibility logic in `jury-protocol`.
- Keep argument parsing and terminal output in `jury`.
- Keep rendering and input concerns in `jury-tui`.
- Keep HTTP/RPC, persistence, and process lifecycle adapters in `jury-witness`.

## Invariants

- Jury must not depend on Jig at runtime.
- Keep the core independent of transport, terminal, database, and hosted-service
  implementations.
- Do not expose raw private-key access to adapters.
- Do not log or snapshot secrets, private keys, decrypted payloads, or
  passphrases.
- Do not add production cryptography before the threat-model and protocol gate
  in `docs/architecture.md` is satisfied.
- Fixtures must use unmistakably generic names such as `ExampleVault`,
  `ExamplePrincipal`, and `ExampleSecret`.

## Common commands

- `scripts/jig check fmt`
- `scripts/jig check clippy`
- `scripts/jig check test`
- `cargo run -p jury -- --help`
- `cargo run -p jury-witness --bin juryd -- --help`
