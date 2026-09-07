# sanitization 2.0.3

This patch release closes the policy-ordering gap for runtime-length secret
decoders and generators.

## Protection before materialization

`LockedSecretVec` and `GuardedSecretVec` now provide policy-aware in-place
constructors for exact-length and capacity-bounded output. Every control marked
`Required` is established before the fill callback runs. This lets decoders,
RNGs, KDFs, and protocol implementations write directly into final protected
storage without first materializing plaintext under a degraded mapping.

Explicit `try_from_capacity_bounded_with_protection` constructors reject
untrusted decoder capacities above an application maximum before mapping or
callback execution. The unbounded variants are documented for trusted,
already-limited capacities only.

For applications that need the maximum to remain enforced after construction,
this release also adds const-generic bounded mapped owners:

- `BoundedLockedSecretVec<MAX>` and `BoundedLockedSecretString<MAX>`;
- `BoundedGuardedSecretVec<MAX>` and `BoundedGuardedSecretString<MAX>`.

These wrappers keep the underlying growable owner private and reject every
oversized construction, append, or replacement before allocation or generator
execution. `BoundedMappedSecretError<E>` keeps limit, arithmetic-overflow,
integrity, and platform-operation failures distinct. The existing bounded
constructors remain useful as one-shot admission controls when later growth is
intentionally permitted.

The callback receives exactly the requested public capacity. This remains true
when guard-page allocation rounds its internal writable payload to a larger
page boundary. Success clears the entire unreported tail; callback failure and
excessive reported lengths clear the mapping before returning.

`LockedSecretString` and `GuardedSecretString` expose matching constructors.
They validate the initialized prefix as UTF-8 without reallocating and clear
invalid payloads before returning an error.

## Typed integrity boundary

`ProtectedSecretFillError<E>` distinguishes required-protection setup,
callback, canary-integrity, capacity-limit, and reported-length failures.
`ProtectedSecretTextFillError<E>` adds UTF-8 validation failure.

When canaries are enabled, the suffix canary is placed at the caller-visible
capacity boundary while the fill callback runs and verified immediately after
it returns. This catches an unsafe external decoder writing past its advertised
destination before the canary is moved to the final initialized length.
Before that relocation, the constructor erases the initial length-zero suffix
canary and the full caller-visible payload. Initialization callbacks therefore
receive zeroed storage and cannot observe the mapping's expected canary value.

Mapped native and `subtle` comparison traits fail closed before scanning the
payload when an integrity check reports corruption. Their data-oblivious
comparison claim is therefore conditioned on intact canaries; applications
requiring typed incident handling should use the checked comparison methods.

Native regression tests inject corruption from the full mapping owner directly
after fill callbacks return, proving that the temporary canary at the requested
capacity boundary is verified without relying on one-past-slice pointer
arithmetic.

Controls marked `Preferred` retain their documented degraded-success semantics.
Applications that require a control before any plaintext is written must mark
that control `Required`.

The primary high-assurance example requires memory locking, dump exclusion,
fork exclusion, and canaries before decoding. It does not use the portable
profile's explicitly degraded dump/fork policy.

All five workspace crates are released together at `2.0.3`, with the derive
crate exact-pinned to the matching runtime version.
