# Loom Concurrency Models

This unpublished tool models:

- the atomic claim and cleanup ordering used by
  `sanitization::ConsumeOnceSecret<T>`; and
- fixed-slot `SecretPool` allocation, clear-before-release, generation reuse,
  and failed-setup rollback.

Run it with:

```text
cargo test --release --manifest-path tools/consume-once-loom/Cargo.toml
```

The models verify that racing consumers cannot both enter a consume-once value,
racing allocators cannot overlap one pool slot, reuse observes a cleared slot
with a new generation, and failed setup releases its claim exactly once. Panic,
application-error, native mapping, and canary behavior are tested against the
production types in the main crate's test suite.

These are hand-maintained models of the production atomic transitions, not the
production types compiled under `loom`. Any production ordering change must be
reviewed against and copied into this tool. `SealedSecretBytes` access reentry is
instead prevented by `&mut self` and the lifetime-bound access guard; that
compile-time property is intentionally outside this atomics-only model.
