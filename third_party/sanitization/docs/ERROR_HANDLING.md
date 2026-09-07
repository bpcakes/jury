# Checked Error Handling

Mapped secret APIs keep one checked shape across feature combinations. An
integrity check may compile to a no-op when canaries are disabled, but exposure,
mutation, replacement, comparison, and cache operations still return `Result`.
This prevents enabling a hardening feature from changing downstream function
signatures.

These checked operations use a `try_*` prefix. Explicit `*_or_panic` helpers
encode a deliberate fail-stop application policy; libraries should normally
propagate or map the checked result. Constructors retain conventional Rust
names such as `from_slice` and `zeroed` even though platform setup can fail.

The crate deliberately does not combine integrity, capacity, UTF-8, generator,
mapping, and cache failures into one global error enum. Those errors have
different recovery policies and not every application enables every facility.
Libraries should normally map them into their own domain error at the boundary.

## Dynamic Allocation And Generation

`SecretVec::try_with_capacity` and `SecretString::try_with_capacity` use
`Vec::try_reserve_exact`, so capacity overflow and allocator refusal are
returned as `SecretAllocationError::Allocation`. The same error type reports
`TooLong` and explicit checked-arithmetic `CapacityOverflow` failures. Their
`try_from_fn` and `try_from_chars` constructors return
`SecretGenerateError<E>`, separating `Build(SecretAllocationError)` from
`Generate(E)`.

Use `try_from_slice_bounded`, `try_from_secret_str_bounded`,
`try_from_fn_bounded`, or `try_from_chars_bounded` when a length can cross a
trust boundary. The byte limit is checked before allocation and before invoking
a generator. String generation calculates worst-case UTF-8 byte capacity with
checked multiplication and compares that capacity with `maximum_bytes`.

The infallible `with_capacity`, `from_fn`, and `from_chars` constructors remain
available for trusted, already-bounded public sizes. Like standard allocation
APIs, they can panic on capacity overflow or invoke the allocation error
handler when memory cannot be obtained.

## Mapped Initialization

Mapped initialization uses operation-specific errors without impossible
variants:

- `LockedSecretInitError` distinguishes allocation or OS-CSPRNG setup from
  fixed-secret integrity failure;
- `LockedSecretBytesFillError<E>` distinguishes allocation or OS-CSPRNG setup,
  fixed-secret integrity failure, and a fallible whole-buffer initializer;
- `LockedSecretInitializeError<E>` distinguishes integrity failure from a
  callback error when initializing an already-created mapping;
- `PoolInitError` distinguishes public length, allocation or OS-CSPRNG setup,
  and integrity failure; and
- `SecretPoolGenerateError<E>` additionally preserves a caller generator
  failure.

`LockedSecretBytes::from_array`, `LockedSecretBytes::from_fill`,
`LockedSecretBytes::try_from_fill`, `LockedSecretBytes::try_init_with`,
`SecretPool::try_allocate_from_slice`,
`SecretPool::try_allocate_from_array`, and
`SecretPool::try_allocate_from_fn` preserve these classifications. `Ok(None)`
means only that every usable pool slot is occupied. Pool allocation has no
lossy non-`try` convenience path.

Canary corruption clears and permanently quarantines the affected slot for the
pool's lifetime before returning `Integrity`. Applications can inspect
`SecretPool::quarantined_slots()` or `arena_report().quarantined_slots` as
public security telemetry, then reject service or terminate according to their
deployment policy. Do not log secret bytes, mapping addresses, or canary
values.

## Fallible Exposure Closures

A mapped byte exposure whose closure also returns `Result<T, E>` would normally
produce `Result<Result<T, E>, CanaryCorruptedError>`. Import
`SecretIntegrityResultExt` to flatten it while preserving both error classes:

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::{
    LockedSecretBytes, MappedResult, SecretIntegrityError,
    SecretIntegrityResultExt,
};

fn parse_key(bytes: &[u8; 32]) -> Result<u8, &'static str> {
    bytes.first().copied().ok_or("empty key")
}

fn read_key(
    key: &LockedSecretBytes<32>,
) -> MappedResult<u8, &'static str> {
    key.try_expose_secret(parse_key).flatten_secret_integrity()
}

let key = LockedSecretBytes::<32>::from_array([7; 32])?;
match read_key(&key) {
    Ok(value) => assert_eq!(value, 7),
    Err(SecretIntegrityError::Canary(_)) => {
        // Fail closed: the mapped value has been cleared or retired.
    }
    Err(SecretIntegrityError::Operation(error)) => {
        // Apply the parser's ordinary error policy.
        eprintln!("{error}");
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

Use `IntegrityResult<T>` for operations whose only failure is
`CanaryCorruptedError`. Use `MappedResult<T, E>` when a mapped operation also
has an operation-specific error. `SecretIntegrityResult<T, E>` is retained as
an equivalent descriptive alias.

`CanaryCorruptedError`, `LengthError`, `MemoryLockError`, and `GuardPageError`
support ordinary `?` propagation into their corresponding `MappedResult`.
Rust's coherence rules prevent a blanket `From<E>` implementation because it
would overlap the canary conversion when `E = CanaryCorruptedError`. Convert
other application errors explicitly with `SecretIntegrityError::Operation`,
`map_err`, or `flatten_secret_integrity()`.

`SecretIntegrityError::map_operation` maps only the operation error into an
application error while preserving canary corruption. `is_canary`,
`is_operation`, and `operation` support policy checks without nested matches.

Mapped text exposure has an outer `SecretTextIntegrityError`, because invalid
UTF-8 is an integrity condition specific to text. Map the two layers explicitly
at the application boundary:

```rust,ignore
let parsed = text
    .try_with_secret(parse_text)
    .map_err(AppError::SecretText)?
    .map_err(AppError::Parse)?;
```

This is intentionally explicit: an invalid mapped string and a parser rejection
should not silently become the same failure.

## Protection Reports

Use `Requirement::Required` for controls that must exist. Constructors then
fail instead of returning reduced-protection storage, so the report does not
need to be revalidated at every operation.

When a named profile matches deployment policy, use its associated constructor
instead of manually coordinating the feature and request. For example,
`LockedSecretBytes::zeroed_hardened_native()` and
`GuardedSecretVec::with_capacity_guarded_native()` select the policy compiled
by their respective profile features. Explicit `*_with_protection`
constructors remain the custom-policy path.

When a request contains `Preferred` controls, inspect the report after
construction and retain the resulting application state. Growth and staged
replacement preserve that accepted state: a preferred control that was
established for the current nonempty mapping, or accepted as not applicable
for empty storage, is required while constructing replacement storage. If it
cannot be re-established, the operation returns an error and leaves the old
value, request, and report unchanged. The successful replacement retains the
caller's original request for future policy evaluation. The convenience
method `ProtectionReport::satisfies(request)` returns `false` for failed,
unsupported, or compatibility-only requested controls and treats empty-storage
`NotApplicable` outcomes as fulfilled. `is_degraded()` provides a request-free
operational summary, while `failed_or_unsupported_controls()` identifies the
affected controls without allocation. For nonempty retired or unlocked
storage, `NotApplicable` is degraded and never satisfies the original request.

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::{LockedSecretBytes, ProtectionRequest};

let request = ProtectionRequest::locked();
let key = LockedSecretBytes::<32>::zeroed_with_protection(request)?;
if !key
    .protection_report()
    .satisfies(request)
{
    return Err("a preferred runtime protection was unavailable".into());
}
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

Applications that permit reduced protection should inspect the individual
public report fields once and record the accepted deployment mode. Cargo
features only describe compiled capability; they do not replace this runtime
decision.

## Protected Dynamic Filling

`ProtectedSecretFillError<E>` keeps dynamic initialization failures separate:

- `CapacityLimit` means an application maximum rejected the requested public
  capacity before mapping or callback execution;
- `Protection` means a required control failed before the callback ran and
  retains the partial report and rollback outcome;
- `Fill` preserves the decoder, RNG, KDF, or protocol error;
- `Integrity` means a canary changed while the callback held the destination;
- `Length` means the callback reported more initialized bytes than requested.

Use bounded fills whenever capacity comes from a protocol field, decoder
estimate, file, or other untrusted source. The unbounded variants accept only
trusted, already-limited capacities; fallible mapping is not itself a resource
limit on overcommitting operating systems.

`BoundedMappedSecretError<E>` is used by permanently bounded mapped owners. It
distinguishes an ordinary `CapacityLimit`, `CapacityOverflow`, integrity-canary
failure, and the underlying platform operation. Limit and overflow failures
occur before allocation, mutation, or a caller-provided generator runs. The
existing `try_from_capacity_bounded_with_protection` methods enforce only the
initial admission decision; use a `Bounded*SecretVec<MAX>` or
`Bounded*SecretString<MAX>` when later growth must obey the same policy.

`ProtectedSecretTextFillError<E>` adds `Utf8`; invalid initialized bytes are
cleared before that error is returned. These types intentionally do not collapse
corruption into an ordinary decoder failure. An application can treat
`Integrity` as security telemetry or a fail-stop event without logging bytes,
addresses, or canary material.

For controls marked `Preferred`, construction can still succeed with a degraded
report. Mark every control that must exist before plaintext is written as
`Required`.

## Fail-Stop Helpers

Explicitly named `*_or_panic` methods remain available for binaries with a
reviewed fail-stop policy. Reusable libraries should propagate checked errors
instead. A panic can abort the current control flow, but it is not a substitute
for a process-level response policy, crash-dump controls, or monitoring.

Cache-flush errors remain separate from integrity errors because cache eviction
is an optional post-use mitigation with target-specific availability. Do not
erase that distinction merely to shorten a call site.

## Explicit Page-Sealed Cleanup

`Drop` cannot report page normalization, unlock, or unmap failures.
`SealedSecretBytes::try_close()` is the checked finalization boundary for
applications that require observable cleanup. It returns `CleanupError` with a
`CleanupReport`; the report contains only operation classifications and
platform error codes.

A page-transition failure leaves the value poisoned, retains the mapping and
any established memory lock, reports `unlock` and `unmap` as `NotNeeded`, and
permits another `try_close()` attempt. Cleanup continues page by page: each page
successfully made writable is erased and resealed immediately, while any failed
page remains uncertain. It never releases a mapping containing an uncertain
page. After all pages are confirmed erased, an unmap failure remains retryable;
cleanup may then unlock the erased mapping and updates the retained
`ProtectionReport` accordingly. Successful unmap retires the value and
implicitly releases any remaining lock.
Applications can treat any error as a security event or invoke a reviewed
fail-stop policy. `Drop` still invokes the same cleanup path when explicit
close was omitted or failed.
