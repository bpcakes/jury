# Release 2.0.0

Version 2.0.0 is a security-model release. It preserves the dependency-free,
`no_std` default and canonical volatile wipe backend while making generic
storage, exposure, data-oblivious control state, derive behavior, and native
protection outcomes more explicit and fail-closed.

Protection reports now accept `NotApplicable` as satisfying a requested control
only when the requested secret length is zero. Retired nonempty mappings and
wiped mappings left live but unlocked after release failure are degraded and
cannot satisfy their original protection request. Release evidence also keeps
the original CP-21 source snapshot immutable under a pinned digest while using
a separately named current-source inventory for the evolving release candidate.
The standalone freeze verifier now validates every field of that current
inventory, including source and manifest hashes, feature definitions, package
metadata, and dependency inventories. It resolves supplied paths once and
performs the comparison in-process through the same snapshot implementation as
the capture CLI.

Page-sealed cleanup now attempts mapping release while an unwiped payload is
still locked. If both page normalization and release fail, the poisoned mapping
remains locked for a later cleanup retry, and its protection report continues
to reflect the live lock. Successful release retires the mapping and clears its
current protection-state accounting.

The dependency-free default now enables `asm-compare`. Reviewed x86_64 and
AArch64 targets therefore use the assembly-backed equal-length equality path
without requiring an opt-in feature. Repeated independent AArch64 Linux
leakage runs rejected the portable fallback as release timing evidence;
`default-features = false` still exposes that fallback, but 2.0 makes no
AArch64 timing claim for it. `sanitization-crypto-interop` forwards the same
dependency-free default for its HMAC and BLAKE3 verification helpers.

`wipe::maybe_uninit` now clears non-live `MaybeUninit<T>` storage without
constructing references to uninitialized byte values. The
`sanitization-arrayvec` companion uses this typed path for complete inline
spare-capacity cleanup.

The `sanitization-bytes` companion now requires patched `bytes 1.11.1` or
newer, preventing fresh downstream lockfiles from resolving versions affected
by `RUSTSEC-2026-0007`.

`SecureSanitizeOnDrop` and `secure_drop_struct!` now require
`DropSafeSanitize + Unpin` owners and invoke the complete sanitizer. Generated
field-wise sanitizers receive the drop-safe marker automatically, while manual
aggregate sanitizers must explicitly attest that destructor-path cleanup is
complete and non-recursive.

The runtime now exact-pins `sanitization-derive` to the matching release, and
release gates enforce that lockstep so generated runtime trait references
cannot be paired with an older core crate.

Wrapping an existing `bytes::BytesMut` now immediately volatile-clears its
spare capacity so historical bytes from pre-wrap truncation do not survive.

CI now enforces a source, license, wildcard, and duplicate-version policy with
`cargo-deny 0.20.2` across every Cargo graph. The rustup fallback installer is
versioned and SHA-256 pinned instead of executing a downloaded shell script.

The release also refreshes the derive stack to `syn 3.0.0`,
`proc-macro2 1.0.107`, and `quote 1.0.47`, updates serde to `1.0.229`, and pins
release-evidence uploads to `actions/upload-artifact v7.0.1`.

Linux-specific CSPRNG and page-lifecycle fault-injection helpers are now
compiled only with the Linux tests that exercise them. Supported non-Linux
all-target test builds therefore remain warning-free without suppressing
production lints.

The multi-seed leakage collector now normalizes Unicode formatting whitespace
around command-line arguments, avoiding false "required argument" errors when
commands are copied from rendered documentation or chat clients.

## Ownership And Exposure

- Renamed checked mapped-container operations to `try_*`, removed redundant
  `*_checked` aliases, and kept `*_or_panic` only for deliberate fail-stop
  application policy. Fallible generator callbacks use explicit
  `try_replace_from_fallible_*` names.
- Added `StableSharedSecretStorage` and `StableMutableSecretStorage` contracts.
  Generic `Secret<T>` exposure now requires an explicit storage-stability
  attestation covering safe shared access, interior mutation, mutable access,
  callbacks, guards, trait methods, and destruction.
- Fixed-size containers now expose their owned storage directly. Core APIs that
  create temporary copies are reason-bearing `export_*` boundaries so the
  extra secret lifetime is visible and searchable.
- Added `SecretBoxBytes` for fixed-allocation runtime-length secret bytes that
  never grow, reallocate, or expose their private backing allocation.
- Made dynamic `SecretVec` and `SecretString` generation genuinely fallible for
  capacity arithmetic and allocation. Added bounded generator constructors
  that reject application-defined public maxima before allocation or callback
  execution.
- Added shared `SecretAllocationError` and `SecretGenerateError<E>`
  classifications plus bounded slice and UTF-8 string copy constructors.
  Bounded character generation now checks worst-case UTF-8 bytes with checked
  arithmetic against an explicit byte ceiling.
- Renamed `ReadOnceSecret<T>` to `ConsumeOnceSecret<T>`. Its single scoped
  shared access is claimed atomically and cleared on normal return, returned
  errors, and panic unwinding.

## Data-Oblivious State

- Unified equal-length equality dispatch so `ct::eq_fixed`, native
  secret-container CT traits, and crypto-interop HMAC/BLAKE3 verification use
  the strict assembly backend when enabled. Path-specific LLVM IR checks now
  prove those representative call paths reach that backend.
- Made `Choice`, masks, and `CtOrdering` declassification reason-bearing and
  removed ordinary equality or raw extraction paths that bypassed the review
  boundary.
- Replaced the generic copyable CT marker with redacted, non-`Copy`,
  clear-on-drop `SecretIndex` and `SecretScalar<T>` owners.
- Added `PublicValue<T>`, `SecretValue<T>`, `SecretCtOption`, and
  `SecretCtResult` so dummy, unselected, mapped, and panic-path secret values
  receive explicit cleanup.
- Renamed `strict-ct` to `strict-compare` to state its actual scope:
  assembly-backed equal-length byte equality on reviewed native targets.
- Expanded Kani, codegen, leakage, panic-unwind, ownership-transition, and
  zero-sized/drop-bearing test coverage for the native CT API.

## Derives And Companion Crates

- Rejected enum `SecureSanitize` and `SecureSanitizeOnDrop` derives because
  generated safe code cannot clear inactive variant storage and final-drop
  cleanup cannot repair prior transitions. Reviewed manual enums must use
  `secure_replace` before every transition; stable-layout structs are preferred.
- Required every skipped derive field to include a non-empty reason and
  rejected duplicate, malformed, empty, or misplaced helper attributes.
- Kept constant-time derives struct-only and field-wise; enums, unions, and
  unsafe selection skips remain compile failures.
- Corrected `sanitization-arrayvec` so live values are sanitized and dropped
  before the complete inline backing region, including historical spare bytes,
  is volatile-cleared.
- Added secure ArrayVec `pop` and `truncate` handling with valid destructor
  ordering and stale-slot cleanup.

## Wiping And Native Hardening

- Pool-slot Drop now verifies canaries before clearing can rewrite them, making
  corruption quarantine unconditional even when no checked accessor follows
  the corruption. Random expected canaries are non-`Copy`, borrowed in place,
  and clear on ordinary, pooled, and page-sealed teardown.
- Consolidated clearing behind the canonical safe `sanitization::wipe` API and
  private sealed `wipe_backend`; removed misleading best-effort and
  `unsafe-wipe` compatibility surfaces.
- Added `wipe::WipeOnDrop<T>` for the audited built-in plain-data set. Public
  downstream representation-erasure implementations remain intentionally
  unsupported.
- Added `ProtectionRequest`, required/preferred policy, structured
  `ProtectionReport` outcomes, and partial setup reports so compiled features
  are not confused with achieved runtime protection.
- Made fork inheritance, dump exclusion, memory locking, guard pages, and
  canary integrity explicit per-container policy outcomes.
- Hardened `SecretPool` with checked fixed-layout accounting, generation-bound
  canaries, failure quarantine, and efficiency reporting.
- Preserved CSPRNG, mapping, canary-integrity, length, and caller-generator
  failures through operation-specific `LockedSecretInitError`, `PoolInitError`,
  and `SecretPoolGenerateError<E>` types. Pool initialization reserves
  `Ok(None)` exclusively for exhaustion and removes lossy allocation helpers.
- Added checked direct initialization of final locked fixed-size storage.
  `try_init_with` supports custom protection requests, while `from_fill` and
  `try_from_fill` use the same configured pre/post integrity checks and clear
  partial output on callback failure. `LockedSecretBytesFillError<E>` and
  `LockedSecretInitializeError<E>` preserve those error classes. Filled
  replacements are verified before swap.
- Made pool integrity failure clear and permanently quarantine the affected
  slot. Added aggregate quarantine telemetry without exposing addresses,
  canary values, or secret bytes.
- Added pre/post integrity verification around normal mapped exposure and
  persistent poison state for standalone locked and guarded owners. Clearing
  physical canary words no longer makes a corrupted owner reusable.
- Added opt-in `SealedSecretBytes<N>` with guard pages, fallible page sealing,
  poisoning/retirement after unsafe transition failures, and multi-page fault
  recovery tests. This remains a reviewed optional facility with documented
  platform limits, not an infallible secrecy guarantee.
- Added `SealedSecretBytes::try_close()` with structured page-normalization,
  unlock, and unmap outcomes. Failed mapping release remains poisoned and
  retryable, and retains its memory lock when erasure was not confirmed;
  `Drop` uses the same path as a final best-effort fallback.
- Reworked cache eviction and SIMD/vector scrubbing to report supported,
  executed, limited, and unsupported outcomes instead of implying universal
  hardware coverage.
- Added named hardened-native, guarded-native, and Linux hardening profiles;
  runtime requests and reports remain authoritative over feature selection.
- Added profile-matched type constructors such as
  `LockedSecretBytes::zeroed_hardened_native()` and
  `GuardedSecretVec::with_capacity_guarded_native()`. Custom deployments retain
  the explicit `*_with_protection` policy path.
- Added `ProtectionReport::satisfies`, `is_degraded`, common-control status
  helpers, and a zero-allocation unavailable-control iterator while preserving
  every detailed report field.
- Added a dependency-free downstream storage-policy lint and compile-checked
  private-policy example. Sensitive roots can reject direct `Secret<T>`,
  marker impls outside approved files, public policy types, and destructor
  bypass through `mem::forget`, `Box::leak`, or `ManuallyDrop` in CI.

## Verification And Release Evidence

- Added path-specific LLVM IR and assembly checks across optimization, LTO,
  panic, and codegen-unit profiles.
- Added lifecycle allocation-quarantine probes, Loom concurrency models,
  sanitizer jobs, fail-closed negative fixtures, Miri/Kani coverage, and
  downstream migration builds.
- Added repeated multi-seed dudect-style leakage runs and relative performance
  baselines for x86_64 Linux, AArch64 Linux, and Apple Silicon.
- Recorded native and compile-only target tiers, exact accepted workflow URLs,
  and GitHub artifact SHA-256 digests in the 2.0 release evidence record.
- Added semantic public-API snapshots and semver review for all five
  publishable crates, freezing the CP-21 API before final release metadata.
- Added complete migration, storage-contract, protection-report, scope,
  guarantees, non-guarantees, target, evidence, and verification-tooling docs.
- Updated package archive validation and publication tooling for all five
  `2.0.0` crates in dependency order.
- Updated dependency-audit detection to use Cargo's subcommand registry and
  scan every committed workspace, fuzz, and tooling lockfile.
- Added a CI declassification-reason lint with fail-closed fixtures. Consumer
  call sites must use meaningful direct literals rather than dynamic or
  placeholder labels; human review remains authoritative.
- Added a fail-closed initialization lint that rejects discarded `try_*`
  results through explicit `drop`, `.ok()`, or unhandled underscore bindings,
  plus lossy pool allocation in production source. Negative fixtures cover
  each suppression form while checked propagation and fail-stop handling remain
  accepted.
- Added a deployment-hardening responsibility matrix covering abort behavior,
  private policy gates, native protection reports, privileged attackers, WASM,
  canary response, swap/hibernation, and explicit cleanup.
- Added reason-bearing high-level CT helpers for final fixed equality, fixed
  ordering, and public-length equality decisions while retaining low-level
  `Choice` and `CtOrdering` composition APIs.
- Replaced the monolithic README with a three-level user journey, a concise
  type-selection table, small recipes, and separate feature/advanced guides.
- Sealed `wipe::Wipe` to its audited built-in implementations and added a
  downstream compile-fail guard against no-op `WipeOnDrop<T>` implementations.
- Added concise checked-error composition through `IntegrityResult`,
  `MappedResult`, the descriptive `SecretIntegrityResult` alias,
  `SecretIntegrityResultExt`, common `?` conversions, operation-error mapping
  helpers, and one-shot requested-protection report validation.
- Documented recommended library propagation, mapped text, fail-stop, and
  application error-boundary patterns without collapsing distinct failures
  into one global error enum.
- Added `AllowlistedSecret<T, P>` and a rationale-bearing policy macro so
  closed deployments can centrally approve exact storage types while retaining
  the independent shared/mutable stability bounds.
- Rejected empty and ASCII-whitespace-only storage-policy rationales at compile
  time so policy approvals cannot carry blank review metadata.
- Kept storage contracts deliberately non-derived: field inspection cannot
  prove method behavior, interior mutation, guard cleanup, callbacks, or
  deferred allocation release.

## Migration

This release contains intentional source-breaking changes. Read
[`docs/MIGRATION_2.0.md`](https://github.com/valkyoth/sanitization/blob/main/docs/MIGRATION_2.0.md)
before upgrading from `1.2.5`. The migration guide covers generic storage
bounds, direct versus copied exposure, CT declassification, derives, wipe API
renames, fallible dynamic allocation, ArrayVec behavior, consume-once
ownership, mapped initialization errors, native protection policy, feature
profiles, and deferred experimental facilities.
