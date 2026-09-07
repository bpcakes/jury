# Migrating From 1.x To 2.0

Version 2.0 makes security boundaries explicit even where that requires source
changes. The volatile clearing backend remains the default, but generic
exposure, data-oblivious declassification, mapped integrity, platform reports,
and derives now fail closed.

This guide covers the intentional 1.2.5-to-2.0 source changes. Migrate one
category at a time and run the downstream verification command shown at the
end.

## Generic Secret Storage

`Secret<T>` still owns and clears every `T: SecureSanitize`. Scoped access now
requires a storage-stability attestation:

```rust
use sanitization::{Secret, SecretBytes};

let secret = Secret::new(SecretBytes::<32>::from_array([7; 32]));
let first = secret.with_secret(|bytes| {
    bytes.export_byte("application returns public key identifier byte", 0)
});
assert_eq!(first, Some(7));
```

- `with_secret` requires `T: StableSharedSecretStorage`.
- `with_secret_mut` requires `T: StableMutableSecretStorage`.
- `Vec<T>`, `String`, and arbitrary interior-mutable allocators do not satisfy
  those contracts merely because they implement `SecureSanitize`.

Replace `Secret<Vec<u8>>` with `SecretVec`, `Secret<String>` with
`SecretString`, or use fixed/bounded/mapped containers. Implement a storage
contract manually only after reviewing every safe operation described in
`docs/STORAGE_CONTRACTS.md`.

For a closed assurance profile, define a private or crate-visible exact-type
policy with `define_secret_storage_policy!` and use
`AllowlistedSecret<T, Policy>`. This adds a central compiler-enforced allow-list
without pretending that a field-only derive can prove storage stability. Each
entry requires a non-empty review rationale that is not solely ASCII
whitespace, and exposure still requires the appropriate stability marker.

## Fixed Secret Exposure

Direct borrowing and temporary-copy exposure now have distinct names:

| 1.x | 2.0 | Migration |
| --- | --- | --- |
| `SecretBytes::expose_secret` | same name | Closure now borrows the owned array directly. |
| `SecretBytes::expose_secret_volatile` | `export_secret_copy(reason, ...)` | Explicitly creates and clears a reason-bearing stack copy. |
| `SecretBytes::copy_to_slice` | `export_to_slice(reason, destination)` | Export now requires an audit reason and leaves destination cleanup to the caller. |
| `SecretBytes::read_byte` | `export_byte(reason, index)` | Scalar export now requires an audit reason. |
| `ExpiringSecretBytes::try_expose_secret_volatile` | `try_export_secret_copy(reason, ...)` | Expiration-checked temporary copy. |
| `ExpiringSecretBytes::try_copy_to_slice` | `try_export_to_slice(reason, destination)` | Expiration-checked reason-bearing export. |
| `MonotonicExpiringSecretBytes::try_expose_secret_volatile` | `try_export_secret_copy(reason, ...)` | Counter-checked temporary copy. |
| `MonotonicExpiringSecretBytes::try_copy_to_slice` | `try_export_to_slice(reason, destination)` | Counter-checked reason-bearing export. |
| `LockedSecretBytes::with_secret` | `try_expose_secret` | Checked direct protected-storage exposure. |
| `SecretPoolSlot::with_secret` | `try_expose_secret` | Checked direct pooled-storage exposure. |

Prefer direct exposure:

```rust
use sanitization::SecretBytes;

let key = SecretBytes::<32>::from_array([7; 32]);
let marker = key.expose_secret(|bytes| bytes[0]);
assert_eq!(marker, 7);
```

For core fixed storage, use `SecretBytes::export_secret_copy` only when an
external API requires independent storage. Expiring fixed containers use
`try_export_secret_copy` because expiration checks are fallible. Mapped fixed
containers instead use `try_expose_secret_copy` because their integrity check
is fallible. Split-secret storage cannot expose contiguous owned plaintext and
therefore retains only explicit reconstruction/copy APIs.

## Data-Oblivious APIs

Declassification is now reason-bearing and searchable:

```rust
use sanitization::ct::{Choice, ConstantTimeEq};

let choice = [1u8; 4].ct_eq(&[1u8; 4]);
assert!(choice.declassify("authentication result is public"));
assert_eq!(Choice::TRUE.declassify_u8("wire flag is public"), 1);

let accepted = sanitization::ct::declassified_eq_fixed(
    &[1u8; 4],
    &[1u8; 4],
    "authentication result is public",
);
assert!(accepted);
```

Do not use generic labels such as `"todo"`, `"reason"`, or `"result is
public"`. The repository's `scripts/lint-declassification-reasons.py` command
can be added to downstream CI to require reviewable literal reasons. It catches
common placeholder abuse but does not replace review of whether each public
boundary is actually authorized.

Use the `declassified_*` convenience functions for final equality or ordering
decisions. Use `eq_fixed`, `cmp_fixed`, and `eq_public_len` when the result must
remain a `Choice` or `CtOrdering` for further data-oblivious composition.

The following ordinary extraction or comparison paths were removed:

| 1.x | 2.0 replacement |
| --- | --- |
| `Choice::unwrap_u8()` | `Choice::declassify_u8(reason)` |
| ordinary `Choice` equality | Choice algebra, then explicit declassification |
| ordinary `CtOrdering` equality | `is_less`, `is_equal`, `is_greater`, or `declassify(reason)` |
| `Mask::expose()` | `Mask::declassify(reason)` |
| `ct::Public<T>` | `ct::PublicValue<T>` |
| generic copyable `ct::Secret<T>` index | `ct::SecretIndex` |
| generic copyable `ct::Secret<T>` scalar | `ct::SecretScalar<T>` |
| public backing in `CtOption`/`CtResult` | `PublicCtOption`/`PublicCtResult` |
| secret backing in `CtOption`/`CtResult` | `SecretValue<T>`, `SecretCtOption`, `SecretCtResult` |

`SecretIndex`, `SecretScalar`, and secret CT backing values are redacted,
non-`Copy`, clear-on-drop owners. Consuming declassification clears remaining
secret state while transferring only the selected value.

`PublicCtOption<T>` and `PublicCtResult<T, E>` are explicitly classified for
public/non-secret backing. Do not put secrets in them. Use the classified secret
variants so dummy and unselected owned values are also cleared.

The feature `strict-ct` was renamed to `strict-compare`. Its scope is
equal-length byte equality on reviewed assembly backends. It does not strengthen
ordering, lookup, selection, allocation, text validation, or caller code.

```toml
sanitization = { version = "2", features = ["strict-compare"] }
```

The default feature set now enables the dependency-free `asm-compare` backend.
On x86_64 and AArch64, ordinary equal-length equality therefore uses reviewed
target assembly. Use `default-features = false` only when the portable fallback
is deliberately required; the 2.0 evidence does not make an AArch64 Linux
timing claim for that fallback.

`Choice`, `Mask`, and `CtOrdering` no longer implement ordinary `Eq` or
`PartialEq`. This is intentional: comparing secret-derived control values must
stay inside their data-oblivious algebra until a reason-bearing public
declassification boundary.

## Derive Macros

`SecureSanitize` and `SecureSanitizeOnDrop` enum derives are rejected because
ordinary variant assignment can leave inactive bytes in the enum allocation.
Final-drop sanitization cannot repair history from earlier transitions. Replace
secret-bearing enums with a struct whose secret storage has a stable layout and
whose public state is a separate tag. If an enum is unavoidable, implement its
sanitization and drop policy manually and use
`secure_replace(&mut value, replacement)` before every transition.

Skipped fields now require a reason:

```rust
#[derive(SecureSanitize)]
struct Record {
    key: [u8; 32],
    #[sanitization(skip, reason = "public algorithm identifier")]
    algorithm: u16,
}
```

Constant-time derives reject enums and unions. `ConditionallySelectable`
rejects skipped fields because every output field must be constructed. The old
`strict-enum-derive` feature was removed because fail-closed diagnostics are now
unconditional. Generic `SecureSanitizeOnDrop` structs still need sanitizable
and `Unpin` type bounds on the struct declaration. The generated destructor
requires the complete struct to implement `DropSafeSanitize + Unpin` and calls
its complete sanitizer. `#[derive(SecureSanitize)]` provides the drop-safe
marker automatically. Types with manual aggregate sanitizers must implement
`DropSafeSanitize` explicitly after reviewing external cleanup, ordering, and
non-recursive behavior. Address-sensitive `!Unpin` types need a reviewed
pin-aware manual implementation.

## Wipe API

Volatile clearing is the canonical default and is grouped under `wipe`:

| 1.x | 2.0 |
| --- | --- |
| `sanitize_bytes*` | `wipe::bytes` or `wipe::bytes_multi_pass` |
| `volatile_sanitize_array*` | `wipe::array` or `wipe::array_multi_pass` |
| `volatile_sanitize_vec*` | `wipe::vec` or `wipe::vec_multi_pass` |
| `volatile_sanitize_string*` | `wipe::string` or `wipe::string_multi_pass` |
| `unsafe_wipe::VolatileSanitize` | `wipe::Wipe` |
| `unsafe_wipe::VolatileOnDrop` | `wipe::WipeOnDrop` |

The public `unsafe_wipe` module and `unsafe-wipe` feature were removed. Normal
`SecretVec` and `SecretString` constructors now always use the canonical wipe
path, so the `*_volatile` constructor aliases were removed.

`WipeOnDrop` is intentionally sealed to audited built-in plain-data types. It
is not a generic representation wipe for arbitrary user-defined values.
Downstream `Wipe` implementations fail to compile; custom structured values
must use `SecureSanitize`, `Secret<T>`, or the derive/macro clear-on-drop paths.

```rust
use sanitization::wipe::{self, Wipe};

let mut bytes = [7u8; 32];
bytes.wipe();
wipe::bytes(&mut bytes);
assert_eq!(bytes, [0; 32]);
```

The old `sanitize_bytes_best_effort` name has no weaker 2.0 replacement.
`wipe::bytes` is the canonical optimizer-resistant path. Every
`volatile_sanitize_*_multi_pass` helper maps to the corresponding
`wipe::*_multi_pass` helper.

## Dynamic Allocation Errors

Fallible dynamic generation now includes allocation and capacity errors rather
than only forwarding the caller's generator error:

| 1.x signature | 2.0 signature |
| --- | --- |
| `SecretVec::try_from_fn(...) -> Result<Self, E>` | `Result<Self, SecretGenerateError<E>>` |
| `SecretVec::try_replace_from_fn(...) -> Result<(), E>` | `Result<(), SecretGenerateError<E>>` |
| `SecretString::try_from_chars(...) -> Result<Self, E>` | `Result<Self, SecretGenerateError<E>>` |
| `SecretString::try_replace_from_chars(...) -> Result<(), E>` | `Result<(), SecretGenerateError<E>>` |

Use `try_with_capacity` when only fallible reservation is needed; it returns
`SecretAllocationError`. Use `try_from_slice_bounded`,
`try_from_secret_str_bounded`, `try_from_fn_bounded`, or
`try_from_chars_bounded` when a public input length must be rejected against an
application maximum before allocation and callback execution.

`SecretString::try_from_chars_bounded` takes a maximum UTF-8 byte capacity, not
a maximum scalar count. It checks `char_count * 4` with checked arithmetic
before allocation or generator execution. Existing infallible constructors
remain appropriate only for trusted, already-bounded sizes.

## ArrayVec Companion

`SecretArrayVec::from_arrayvec` is no longer `const`. Construction now clears
historical bytes in the incoming inline spare region. Move any const call site
to runtime initialization:

```rust
use arrayvec::ArrayVec;
use sanitization_arrayvec::SecretArrayVec;

let source = ArrayVec::<u8, 16>::from_iter([1, 2, 3]);
let secret = SecretArrayVec::from_arrayvec(source);
assert_eq!(secret.len(), 3);
```

Pop, truncate, clear, and drop also clear the complete resulting spare inline
storage. Rejected `push` values remain the caller's responsibility; use
`push_or_sanitize` to consume and clear them on capacity failure.

## Consume-Once Secrets

`ReadOnceSecret<T>` is now `ConsumeOnceSecret<T>` because the operation claims
one scoped access rather than moving out the value.

| 1.x | 2.0 |
| --- | --- |
| `ReadOnceSecret<T>` | `ConsumeOnceSecret<T>` |
| `is_consumed()` | `is_claimed()` |
| `consume_mut(...)` | no direct replacement |

Perform required mutation before wrapping. `consume` provides one shared
exposure and requires stable shared storage. Its cleanup guard clears on normal
return, application error, and panic unwinding; process abort remains outside
the guarantee.

```rust
use sanitization::{ConsumeOnceSecret, SecretBytes};

let token = ConsumeOnceSecret::new(SecretBytes::<4>::from_array([1, 2, 3, 4]));
let length = token.consume(|bytes| bytes.len()).unwrap();
assert_eq!(length, 4);
assert!(token.consume(|_| ()).is_err());
```

## Cache And Register Operations

Cache flushing and register scrubbing now report target-specific outcomes:

- `flush_cache_lines`, `cache_flush_sanitize_*`, container `*_and_flush`
  helpers, and `CacheFlushOnDrop::into_cleared` return
  `Result<CacheFlushReport, CacheFlushError>`;
- sanitizing helpers clear before returning a cache-flush error;
- register scrub functions return `RegisterScrubReport`.

Handle the report instead of assuming an instruction ran:

```rust
#[cfg(feature = "register-scrub")]
{
    let report = sanitization::scrub_simd_registers();
    assert!(report.instructions_executed() || !report.instructions_executed());
}
```

These APIs do not claim complete cache or register erasure. See
`docs/BARRIERS.md` and `docs/NON_GUARANTEES.md`.

## Mapped Storage And Integrity

Mapped operations that can observe canary corruption now return checked
results even when the feature combination makes the check a no-op. This keeps
one API shape across feature profiles. The change covers exposure, mutation,
copying, replacement, and comparison on locked bytes/vectors/strings, pool
slots, and guarded bytes/strings.

| Type | Operations changed to checked results |
| --- | --- |
| `LockedSecretBytes<N>` | copying, replacement, exposure, mutation, comparison, and clear-and-flush |
| `LockedSecretVec` | exposure, mutation, extension, replacement, comparison, and clear-and-flush |
| `LockedSecretString` | exposure, mutation, append, replacement, comparison, and clear-and-flush |
| `SecretPoolSlot<'_, N, SLOTS>` | copying, replacement, exposure, mutation, comparison, and cache flushing |
| `GuardedSecretVec` | exposure, mutation, extension, replacement, comparison, and clear-and-flush |
| `GuardedSecretString` | exposure, mutation, append, replacement, comparison, and clear-and-flush |

All checked mapped operations now begin with `try_`; for example,
`expose_secret` becomes `try_expose_secret`, `constant_time_eq` becomes
`try_constant_time_eq`, and `clear_secret_and_flush` becomes
`try_clear_secret_and_flush`. The redundant `*_checked` aliases were removed.
Where the supplied generator or fill callback can itself fail, use the
`try_replace_from_fallible_*` family. Explicit `*_or_panic` helpers remain for
applications that intentionally choose fail-stop behavior.

The exact error depends on whether the operation can also fail for a length,
capacity, UTF-8, mapping, or cache-flush reason. Propagate the returned
`Result`, or match `SecretIntegrityError::Canary` separately from
`SecretIntegrityError::Operation` when the response policy differs.

Handle `CanaryCorruptedError` or `SecretIntegrityError<E>` explicitly. Use an
`*_or_panic` helper only when aborting the current control flow is an intentional
deployment policy.

Mapped initialization now uses operation-specific `LockedSecretInitError`,
`PoolInitError`, and `SecretPoolGenerateError<E>` types. In particular,
`LockedSecretBytes::from_array` and the `SecretPool::try_allocate_from_*`
helpers do not suppress canary or CSPRNG failure. For pool initialization,
`Ok(None)` means only that every usable slot is occupied.

The lossy 1.x `SecretPool::allocate`, `allocate_from_array`, and
`allocate_from_fn` methods were removed. Use `try_allocate`,
`try_allocate_from_array`, or `try_allocate_from_fn` and propagate the setup
error. Canary corruption clears and quarantines the affected slot; use
`quarantined_slots()` or `arena_report().quarantined_slots` for public
application telemetry.

When an exposure closure is itself fallible, import
`SecretIntegrityResultExt` and call `flatten_secret_integrity()` to convert
`Result<Result<T, E>, CanaryCorruptedError>` into the concise
`MappedResult<T, E>` alias. Use `IntegrityResult<T>` for operations that can
fail only because canaries are corrupted. `SecretIntegrityResult<T, E>` remains
an equivalent descriptive alias. Common crate operation errors support `?`;
custom errors can use `SecretIntegrityError::Operation`, `map_err`, or
`map_operation`. This preserves the integrity/operation distinction without
nested matching. See `docs/ERROR_HANDLING.md` for mapped text and
application-error patterns.

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::LockedSecretBytes;

let mut key = LockedSecretBytes::<4>::zeroed()?;
key.try_copy_from_slice(&[1, 2, 3, 4])?;
let first = key.try_expose_secret(|bytes| bytes[0])?;
assert_eq!(first, 1);
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

`LockedSecretBytesCheckedCopyError` changed from a dedicated enum to the type
alias `SecretIntegrityError<LengthError>`. Match `SecretIntegrityError::Canary`
and `SecretIntegrityError::Operation` instead of the old enum representation.

`MemoryLockOperation` and `GuardPageOperation` gained `WipeOnFork`. These enums
remain exhaustive, so downstream matches must add the new variant. Their
implicit numeric discriminants after the insertion changed; 1.x numeric casts
must not be used as a stable wire or persistence format.

Runtime hardening is now modeled by:

- `ProtectionRequest`: required, preferred, or omitted controls;
- `ProtectionReport`: achieved outcomes; and
- `ProtectionError`: failed required control plus partial rollback report.

Cargo profiles describe compiled capability, never successful runtime
protection. Read `docs/PROTECTION_REPORT.md` before migrating locked or guarded
constructors. `Required` controls fail construction; for requests containing
`Preferred` controls, `ProtectionReport::satisfies` provides a concise strict
check after construction. The longer
`all_requested_controls_established` spelling remains equivalent.

## Added 2.0 Facilities

These additions do not replace a 1.x name but may simplify migrations:

- `SecretBoxBytes` for fixed-length heap storage without growth;
- `BoundedSecretVec` and `BoundedSecretString` for explicit dynamic limits;
- `SecretPool` generation IDs and capacity/lock-efficiency reports;
- `SealedSecretBytes` for opt-in page-sealed access windows;
- named native feature profiles and structured protection policies;
- native CT ownership types and oblivious memory primitives; and
- conservative `ZeroValidPlainData` support for reviewed plain-data erasure.

## Verification

The repository exercises representative downstream use without workspace
feature unification:

```bash
scripts/verify-downstream-migration.py
scripts/verify-secret-exposure-failures.sh
scripts/verify-derive-failures.sh
scripts/verify-feature-profiles.py
```

The machine-readable inventory in `docs/migration-2.0.json` maps every known
removed or behaviorally changed 1.x API to an anchor in this guide.
`scripts/verify-migration-2.0.py` fails if that inventory or its guide links
become incomplete.
