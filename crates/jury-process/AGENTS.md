## Purpose

Own Jury's neutral child-process containment, bounded capture, and
streaming-redaction boundary. Linux is the active `0.x` platform. The macOS
backend is provisional and not release-supported; M04 native containment
validation passed on supported Apple Silicon macOS versions. This crate
also supplies running-image identity snapshots on Linux and macOS. It
contains no vault-domain policy.

## Key entrypoints

- `src/lib.rs`: supported public process contract
- `src/process.rs`: spawn, observe, signal, timeout, cleanup, and capture flow
- `src/process/error.rs`: primary-operation and cleanup failure classification
- `src/process/output.rs`: bounded nonblocking pipe drains and redaction
- `src/unix.rs`: safe-provider Unix process-group and membership operations
- `src/running_image.rs`: kernel-backed current executable identity evidence

## Edit here for X

- Add process lifecycle behavior in `src/process.rs`.
- Add output bounds or redaction behavior in `src/process/output.rs`.
- Keep platform-specific membership proofs in `src/unix.rs`.
- Keep running-image evidence separate from pathname discovery and launch authority.

## Invariants

- Keep `unsafe_code = "forbid"`; native calls belong to maintained safe
  dependencies.
- Never signal a numeric PID or process group after its direct-child wait
  status has been consumed or lost. A failed native wait operation that does
  not revoke ownership still permits best-effort direct-child cleanup.
- Terminate and prove the complete group quiescent before reaping its leader.
- Bound waits, drains, retries and retained allocations with absolute deadlines.
  Reject native query results arriving after the deadline; synchronous kernel
  calls themselves are not preemptible.
- Keep the primary operation error when cleanup also fails. Compound cleanup
  failure must not be classified as ordinary cancellation.
- When redaction is configured, observers and returned captures receive only
  post-redaction bytes; secret-bearing commands must configure it.
- Unsupported containment guarantees fail explicitly before spawn.
- This crate has no Jig dependency and no vault-domain types.

## Common commands

- `cargo test -p jury-process --all-targets`
- `scripts/jig check clippy`
