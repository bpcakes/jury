## Purpose

Own Jury's neutral child-process containment, bounded capture, and
streaming-redaction boundary. Linux is the active `0.x` platform. The macOS
backend is provisional, deferred, and not release-supported. This crate
contains no vault-domain policy.

## Key entrypoints

- `src/lib.rs`: supported public process contract
- `src/process.rs`: spawn, observe, signal, timeout, cleanup, and capture flow
- `src/process/output.rs`: bounded nonblocking pipe drains and redaction
- `src/unix.rs`: safe-provider Unix process-group and membership operations

## Edit here for X

- Add process lifecycle behavior in `src/process.rs`.
- Add output bounds or redaction behavior in `src/process/output.rs`.
- Keep platform-specific membership proofs in `src/unix.rs`.

## Invariants

- Keep `unsafe_code = "forbid"`; native calls belong to maintained safe
  dependencies.
- Never signal a numeric PID or process group after its direct-child wait
  status has been consumed or lost.
- Terminate and prove the complete group quiescent before reaping its leader.
- Bound every wait, drain, retry, scan, and retained output allocation.
- When redaction is configured, observers and returned captures receive only
  post-redaction bytes; secret-bearing commands must configure it.
- Unsupported containment guarantees fail explicitly before spawn.
- This crate has no Jig dependency and no vault-domain types.

## Common commands

- `cargo test -p jury-process --all-targets`
- `scripts/jig check clippy`
