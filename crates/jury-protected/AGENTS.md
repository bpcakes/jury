## Purpose

Own Jury's generic protected-memory, entropy, bounded-redaction, and
pre-capture process-protection boundary.

## Key entrypoints

- `src/lib.rs`: intentionally narrow public API
- `src/memory.rs`: page-dedicated protected allocations and status
- `src/randomness.rs`: fallible caller-owned entropy seam
- `src/process_protection.rs`: core-dump suppression before private callbacks

## Edit here for X

- Add generic secret lifetime controls here, never vault-domain behavior.
- Add encoded or streaming redaction forms in the redaction modules.

## Invariants

- Keep `unsafe_code = "forbid"`; native memory operations belong to the pinned
  reviewed provider.
- Compact protected secrets never fall back to ordinary Jury-owned heap bytes.
- Errors, `Debug`, JSON status, and tests never expose secret values.
- Strict protection fails closed. The sole emergency policy reports every
  unavailable control and remains visible to callers.
- This crate contains no cryptographic algorithms and no Jig dependency.

## Common commands

- `cargo test -p jury-protected --all-targets`
- `scripts/jig check clippy`
