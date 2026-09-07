# Guarantees

This document defines the security claims this repository is willing to make.
It should be read together with `docs/NON_GUARANTEES.md`, `docs/THREAT_MODEL.md`,
`docs/SAFETY.md`, `docs/BARRIERS.md`, `docs/TARGETS.md`,
`docs/ERASURE_BACKENDS.md`, `docs/REPRODUCIBLE_BUILDS.md`, and
`docs/EVIDENCE.md`. Generic ownership contracts are normative in
`docs/STORAGE_CONTRACTS.md`; mapped runtime policy and outcome semantics are
normative in `docs/PROTECTION_REPORT.md`.

The short version: `sanitization` provides dependency-free secret ownership,
optimizer-resistant clearing, and data-oblivious primitives under documented
target and feature conditions. It does not claim identical wall-clock timing or
complete protection against every process, OS, hardware, compiler, or runtime
side channel.

## Secret Ownership

For crate-owned secret containers, the crate guarantees:

- secret-owning containers do not implement `Copy`;
- secret-owning containers do not expose raw secret references through `Debug`;
- container `Debug` output is redacted;
- ordinary equality for secret containers is avoided in favor of explicit
  comparison APIs;
- public exposure goes through narrow closure-based APIs where practical;
- drop-time clearing is installed for the crate-owned secret containers.

These guarantees apply to bytes owned by the crate. They do not revoke copies
that were already created by caller code, external libraries, deserializers,
formatters, syscalls, kernels, runtimes, debuggers, or hardware.

## Clearing

All default clearing paths bottom out in volatile byte writes through the
audited wipe boundary. This is the crate's primary clearing guarantee:

- clearing stores are emitted as volatile operations on native targets;
- compiler fences and hardware fences are used around the wipe boundary;
- heap containers wipe initialized bytes and spare capacity that the crate can
  reach before releasing the allocation;
- replacement helpers clear the old value before installing the new value where
  the API can do so safely;
- explicit volatile helper functions are available for ordinary byte buffers.
- `BoundedSecretVec<MAX>` checks its public maximum before construction,
  append, replacement, and every supported serde visitor input form.
- Ordinary `SecretVec` serde rejects inputs larger than the documented 1 MiB
  default ceiling rather than allocating without a crate-level bound.
- `BoundedSecretString<MAX>` checks its public UTF-8 byte maximum before
  construction, append, replacement, and supported serde string inputs.
- Const-generic bounded locked and guarded byte/text wrappers enforce their
  public maximum before initial mapping, append, and replacement. They do not
  expose the underlying growable mapped owner.
- Ordinary `SecretString` serde rejects inputs larger than the documented
  1 MiB byte ceiling.
- Consuming `SecretVec`/`SecretString` conversions transfer the existing heap
  allocation after UTF-8 validation. Invalid byte input is cleared before the
  conversion error is returned.

The guarantee is about bytes reachable through the current allocation or
container. It does not cover allocator metadata, stale copies from earlier
Rust moves, prior stack frames, external buffers, or allocations already freed
before they entered a crate-owned type.

`LockedSecretBytes::try_from_fn`, `try_from_fill`, and `try_init_with` let
callers generate or decode directly into final mapped storage. They avoid an
API-required intermediate array and clear partial output on a returned
initializer error. This is copy reduction, not proof that the compiler, ABI,
or cryptographic implementation never placed secret values in registers or
historical stack locations.

`AllowlistedSecret<T, P>` adds an application-owned exact-type policy before
construction or exposure. It does not replace or prove the storage-stability
contract: shared and mutable exposure still require the corresponding marker,
and the guarantee remains conditional on both the marker implementation and
the policy review being correct. Keeping `P` private or `pub(crate)` prevents
dependencies from naming that deployment policy.

`scripts/lint-storage-policies.py` can enforce this application boundary over
declared sensitive roots. It is a CI source-policy check, not part of the Rust
type-system guarantee and not a proof that an approved marker is correct.

Primitive scalar representation wiping is closed over a reviewed internal set:
integer primitives, `bool`, `char`, `f32`, and `f64`. The crate does not offer
a blanket representation wipe for user-defined types or a public
target-provided erasure callback.

## Locked And Guarded Storage

When `memory-lock` is enabled on supported native targets, locked containers
attempt to keep their owned secret storage out of swap/pagefile paths using the
platform's memory-locking facility. On Linux-family targets, supported
constructors also request `MADV_DONTDUMP`, and when available they request
`MADV_DONTFORK` unless the platform-specific backend documents otherwise.

Cargo features describe compiled capability. Runtime success is represented by
`ProtectionReport`, retained by mapped byte and text containers. Explicit
`ProtectionRequest` values make each control required, preferred, or not
requested. A required failure returns a structured `ProtectionError` and no
container; a preferred failure can succeed only with a reduced state recorded
in the report.

Named profiles have an exact policy mapping documented in
`docs/FEATURE_PROFILES.md`. Their guarantee is limited to compiling the listed
capabilities and exposing the matching request policy. Runtime establishment
is guaranteed only when the report records `Established`; required failures
return an error instead of a reduced container.

The stronger native storage types guarantee:

- locked mappings are cleared before unlock/unmap on drop;
- `LockedSecretString` delegates its storage lifecycle to `LockedSecretVec`
  while restricting safe exposure to valid UTF-8;
- failed constructors do not intentionally leak successfully created mappings;
- canary-enabled mappings verify prefix/suffix integrity before exposure,
  mutation, replacement, copying, and comparison; scoped exposure verifies
  again after normal closure return. Corruption clears storage, permanently
  poisons standalone owners or quarantines pool slots, and returns a structured
  error from ordinary APIs;
- guarded dynamic storage places inaccessible guard pages around the writable
  region on supported native targets.
- `GuardedSecretString` delegates its storage lifecycle to
  `GuardedSecretVec` while restricting safe exposure to valid UTF-8.
- protection reports contain only public operational metadata and never
  addresses, canary values, or secret-derived contents.

When `require-fork-exclusion` is enabled, native locked constructors fail
closed on platforms where fork-inheritance exclusion is unavailable.
Explicit Linux policies can alternatively allow inheritance or request
`MADV_WIPEONFORK`; the retained report records the requested policy and actual
outcome.

On WASM, `memory-lock` is available only with `wasm-compat` and is an
API-compatibility backend. It guarantees owned WASM storage and drop-time
clearing, not host OS memory locking.

## Data-Oblivious Primitives

The native `sanitization::ct` module is designed around this claim:

> No secret-dependent control flow or secret-dependent memory access inside
> the provided primitives, under the documented compiler, target, feature, and
> release-profile conditions.

The data-oblivious guarantees apply to the crate's own primitives:

- `ct::Choice` and masks normalize secret-derived boolean-like values;
- fixed-size equality and ordering scan every public element;
- public-length equality treats length as public metadata and rejects length
  mismatch without claiming the length is secret;
- `ct::PublicCtOption` and `ct::PublicCtResult` keep success/failure state inside the CT
  domain until explicit declassification for public or non-secret backing
  values;
- `ct::SecretIndex` and `ct::SecretScalar<T>` are non-copying, redacted,
  clear-on-drop owners with consuming reason-bearing declassification;
- `ct::SecretCtOption` and `ct::SecretCtResult` clear dummy and unselected
  `ct::SecretValue<T>` backing values before transferring a selected value;
- `ct::oblivious_lookup` scans the full public table length instead of indexing
  directly by a secret index;
- conditional copy, swap, and slice selection operate over public lengths.

Turning a secret-derived value into normal control flow must happen through an
explicit `declassify(reason)` method or reason-bearing `declassified_*`
boundary. The high-level fixed equality, fixed ordering, and public-length
equality helpers perform only this final conversion; their lower-level forms
remain available for composition. The reason string is not a runtime security
mechanism; it exists to make public-branch decisions searchable and reviewable.
Repository CI additionally runs
`scripts/lint-declassification-reasons.py`, which requires direct call-site
literals and rejects known placeholder or generic wording. The lint cannot
decide whether a well-written sentence represents an authorized policy; that
remains a human review obligation.

## Consume-Once Ownership

`ConsumeOnceSecret<T>` permits exactly one successful scoped shared exposure:

- racing callers claim access with one atomic transition;
- the successful closure receives `&T`, not ownership or mutable access;
- later callers are rejected;
- the wrapped value is cleared after normal return, application-level error,
  or panic unwinding;
- a never-consumed value is cleared on drop; and
- shared exposure requires `T: StableSharedSecretStorage`.

This guarantee covers access through the wrapper. The winning closure can
deliberately copy or export data, and process abort, compiler-created
temporaries, Rust move history, and register residue remain outside it.

## Fixed Secure Arenas

`SecretPool<N, SLOTS>` provides a bounded fixed-size arena:

- one atomic bitmap claim prevents overlapping safe handles for a slot;
- every successful claim receives a new non-zero generation;
- lifetime-bound handles prevent pool drop or mutable pool clearing while live;
- slot drop clears before release;
- the next acquire observes release after cleanup;
- native pools amortize mapping and lock overhead across all slots; and
- `arena_report()` exposes capacity and lock-efficiency metadata without
  exposing secret contents.

Generations are diagnostic reuse identifiers. Rust lifetimes and the atomic
claim are the stale-handle defense.

## Page-Sealed Review Candidate

With the opt-in `page-seal` feature, `SealedSecretBytes<N>` keeps its data pages
inaccessible between scoped mutable-borrow access windows. Normal return and
panic unwinding both attempt to restore no-access protection. A detected
normal-return transition failure initiates cleanup. Cleanup makes each page
writable, immediately clears it, and restores no-access before advancing. It
continues after individual failures, so successfully transitioned pages are
erased and resealed even when another page remains uncertain. If any transition
fails, cleanup does not unlock or unmap the poisoned mapping. The mapping and
any established memory lock remain retryable instead of returning uncertain
physical pages to the operating system.

Default page-sealed constructors require Linux `MADV_WIPEONFORK`. A child
created while an unrelated thread has opened an access window therefore
receives zero-filled data pages instead of a permanently exposed copy. Windows
process creation does not clone the address space. Fork-capable targets without
a reviewed equivalent fail default construction; an explicit
`ProtectionRequest` is required to acknowledge a lower-assurance fork policy.

This remains a conditional 2.0 guarantee pending the CP-16 unsafe review and
native target evidence. Existing locked and guarded guarantees do not depend on
its acceptance.

Page-sealed cleanup is explicitly fallible. `SealedSecretBytes<N>` provides
`try_secure_sanitize()` and `try_close()` but does not implement
`SecureSanitize`, zeroize interop traits, or stable-storage marker traits
because an operating-system failure may prevent an inaccessible page from
becoming writable. Explicit close reports normalization, unlock, and unmap
outcomes. A mapping with any uncertain page remains poisoned and locked after a
failed transition and can retry; pages successfully processed during that
attempt are already erased and resealed. A confirmed-wiped mapping may be
unlocked after failed release; successful release retires it and implicitly
disposes of its lock.

## Evidence

The repository carries release evidence in two forms:

- human-readable evidence in `docs/EVIDENCE.md`;
- machine-readable evidence in `docs/ct-evidence.json`, validated by
  `scripts/verify-evidence.py`.

The current evidence includes unit tests, release codegen checks, Miri where
available, and bounded Kani proof harnesses for selected wipe, comparison,
ordering, selection, and allocation-arithmetic properties. These are evidence
for specific claims, not blanket proof of all timing behavior on all targets.
