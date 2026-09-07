# Advanced Usage

This guide is level 3 of the user journey. Start with the ordinary containers
and recommended locked constructors in the project README. Use the facilities
below only when a threat model or deployment policy requires them.

Read [`GUARANTEES.md`](GUARANTEES.md),
[`NON_GUARANTEES.md`](NON_GUARANTEES.md), and
[`THREAT_MODEL.md`](THREAT_MODEL.md) before selecting platform hardening.

## Custom Protection Policy

Cargo features compile capabilities. `ProtectionRequest` declares policy, and
`ProtectionReport` records the achieved runtime outcome.

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::{
    ForkProtectionRequest, LockedSecretBytes, ProtectionRequest, Requirement,
};

let request = ProtectionRequest {
    memory_lock: Requirement::Required,
    dump_exclusion: Requirement::Preferred,
    fork: ForkProtectionRequest::exclude(Requirement::Preferred),
    guard_pages: Requirement::NotRequested,
    canary: Requirement::Preferred,
    cache_policy: Requirement::NotRequested,
};

let key = LockedSecretBytes::<32>::zeroed_with_protection(request)?;
if !key.protection_report().satisfies(request) {
    return Err("deployment protection policy was not achieved".into());
}
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

When the secret is generated or decoded after policy selection, fill that same
mapping directly:

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::{LockedSecretBytes, ProtectionRequest};

let request = ProtectionRequest::profile_hardened_native();
let key = LockedSecretBytes::<32>::zeroed_with_protection(request)?
    .try_init_with(|output| {
        output.fill(0x42);
        Ok::<(), std::io::Error>(())
    })?;

assert_eq!(key.try_constant_time_eq(&[0x42; 32]), Ok(true));
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

`try_init_with` runs the configured integrity check before and after the
initializer; with `canary-check`, both canary regions are verified. A callback
error clears partial output before teardown. Prefer this path, `try_from_fill`,
or `try_from_fn` over constructing an unlocked array and moving it into the
mapping. Avoid cloning, formatting, and `to_vec` on secrets; place unavoidable
scratch storage under clear-on-drop ownership and minimize exposure scope.

For a decoder whose exact output length is known only after writing, establish
the policy before decoding and return the initialized prefix length:

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::{
    BoundedLockedSecretVec, ForkProtectionRequest, ProtectionRequest, Requirement,
};

const MAX_DECODED_SECRET_BYTES: usize = 4096;
let decoder_capacity = 4096; // Derived from validated public input.
let request = ProtectionRequest {
    memory_lock: Requirement::Required,
    dump_exclusion: Requirement::Required,
    fork: ForkProtectionRequest::exclude(Requirement::Required),
    guard_pages: Requirement::NotRequested,
    canary: Requirement::Required,
    cache_policy: Requirement::NotRequested,
};
let decoded = BoundedLockedSecretVec::<MAX_DECODED_SECRET_BYTES>::try_from_capacity_with_protection(
    decoder_capacity,
    request,
    |output| {
        output[..5].copy_from_slice(b"token");
        Ok::<usize, std::io::Error>(5)
    },
)?;
assert_eq!(decoded.try_constant_time_eq(b"token"), Ok(true));
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

The callback receives exactly the requested capacity even when a guarded
mapping owns a larger page-rounded payload. Required protection failure prevents
the callback from running. The constructor verifies canaries at the advertised
capacity boundary, rejects over-reported lengths, and clears every unreported
tail byte. `GuardedSecretVec` exposes the same API. The locked and guarded
string wrappers additionally validate UTF-8 and clear invalid payloads.

Use unbounded policy-aware constructors only when the capacity has already been
limited by trusted application logic. A `*_bounded_with_protection` constructor
rejects oversized initial input but returns an ordinary growable mapped owner.
The const-generic bounded mapped types shown above also enforce `MAX` on every
safe append and replacement for their full lifetime. Their underlying growable
owner is private and cannot be extracted. The request above is deliberately
stricter than `profile_hardened_native()`: that portable profile treats dump
and fork exclusion as preferred and can therefore return a degraded mapping.

Use named profile constructors when their policy matches the deployment. Use a
custom request only when required/preferred controls genuinely differ. See
[`PROTECTION_REPORT.md`](PROTECTION_REPORT.md) and
[`ERROR_HANDLING.md`](ERROR_HANDLING.md).

## Guard Pages

`GuardedSecretVec` and `GuardedSecretString` place inaccessible pages around a
private native mapping. Guard pages detect accesses crossing the mapped data
region; they do not detect every in-capacity overwrite or protect copies made
outside the container.

```rust,no_run
# #[cfg(feature = "profile-guarded-native")]
# {
use sanitization::GuardedSecretVec;

let mut token = GuardedSecretVec::with_capacity_guarded_native(4096)?;
token.try_extend_from_slice(b"session-key")?;
assert_eq!(token.try_constant_time_eq(b"session-key"), Ok(true));

if token.protection_report().is_degraded() {
    return Err("guarded deployment policy was not achieved".into());
}
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

Enable `canary-check` or `random-canary` when in-region prefix/suffix overwrite
detection is also required.

## Page-Sealed Fixed Secrets

`SealedSecretBytes<N>` is a review-candidate mapping whose data pages are
inaccessible between scoped accesses. Every access is fallible and requires
`&mut self`; failures may retire or poison the value.

```rust,no_run
# #[cfg(feature = "page-seal")]
# {
use sanitization::SealedSecretBytes;

let mut key = SealedSecretBytes::<32>::from_array([7; 32])?;
let first = key.try_with_secret(|bytes| bytes[0])?;
assert_eq!(first, 7);
assert!(key.is_sealed());
key.try_close()?;
assert!(key.is_retired());
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

`try_close()` makes final cleanup observable. Its `CleanupReport` records page
normalization, memory unlock, and unmap outcomes using only public operation
names and platform error codes. Cleanup erases and reseals each page immediately
after making it writable. If any page transition fails, no unlock or unmap is
attempted; successfully processed pages are already erased, while the value
remains poisoned, retains any established lock, and may retry `try_close()`.
After confirmed erasure, a failed unmap remains retryable and cleanup may unlock
the erased mapping. Applications may record
`CleanupError::operation()` and `errno()`, but must not add secret bytes,
mapping addresses, or canary values to telemetry. `Drop` calls the same cleanup
path as a final best-effort fallback and cannot report its result.

Fork policy, partial protection transitions, signal handlers, process abort,
and privileged remapping require particular review. See
[`SAFETY.md`](SAFETY.md) and [`TARGETS.md`](TARGETS.md).

## Secret CT Ownership

Use `PublicCtOption` and `PublicCtResult` only for public backing values. Use
`SecretValue`, `SecretCtOption`, and `SecretCtResult` when dummy or unselected
backing values are secret and must be cleared before declassification.

```rust
use sanitization::ct::{Choice, SecretCtOption, SecretValue};

let state = SecretCtOption::secret([7u8; 32], Choice::TRUE);
let selected = state.declassify("authenticated key selection is public");
assert_eq!(selected, Some([7u8; 32]));
```

Reason strings are searchable review labels, not runtime authorization. Run
`scripts/lint-declassification-reasons.py` in high-assurance downstream CI.

## Cache And Register Controls

`cache-flush` adds checked x86_64 cache-line eviction after volatile clearing.
It reduces post-use residency; it does not stop an attacker who can observe
cache timing while the secret is live.

`register-scrub` clears a documented architecture-specific subset of vector
registers and returns a `RegisterScrubReport`. It cannot clear compiler spills,
all callee-saved state, interrupt frames, other threads, or every AVX-512 state
component.

See [`BARRIERS.md`](BARRIERS.md) for the exact scope and
[`LEAKAGE_TESTS.md`](LEAKAGE_TESTS.md) for target timing evidence.

## Other Specialized APIs

Pool allocation is always checked. `Ok(None)` means only that all usable slots
are occupied; setup, random-canary, length, generator, and integrity failures
remain typed errors.

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::SecretPool;

let pool = SecretPool::<32, 64>::new()?;
let Some(key) = pool.try_allocate_from_array([7; 32])? else {
    return Err("locked secret pool exhausted".into());
};

if pool.quarantined_slots() != 0 {
    return Err("a pool slot failed integrity verification".into());
}

drop(key);
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

Treat quarantine counts as public operational telemetry. Never log secret
bytes, mapping addresses, or canary values.

| Requirement | API |
| --- | --- |
| Many same-size locked values under one lock quota | `SecretPool<N, SLOTS>` |
| One successful scoped access | `ConsumeOnceSecret<T>` |
| no-std expiry from application ticks | `MonotonicExpiringSecretBytes<N, C>` |
| std wall-clock-style expiry | `ExpiringSecretBytes<N>` |
| N-of-N XOR shares | `SplitSecretBytes<N, SHARES>` |
| External HSM/TEE/enclave integration | `hardware-secrets` provider traits |
| Existing RustCrypto bounds | `zeroize-interop` and `subtle-interop` |

These facilities solve different threat-model problems. Combining features is
not automatically stronger; the request/report result and target evidence must
match the deployment's actual requirements.
