# Sanitization 2.0.0 Architecture And Hardening Plan

## Purpose

Version 2.0.0 is the opportunity to correct security boundaries that cannot be
fixed cleanly while preserving the complete 1.x API.

The central wipe primitive is already sound for live, reachable native memory:
the crate uses non-inlined volatile byte stores, compiler ordering barriers, and
an explicit unsafe boundary. The largest remaining gains are now in ownership,
copy avoidance, storage stability, data-oblivious API discipline, strict derive
behavior, platform reporting, and stronger release evidence.

This document is an implementation plan based on the post-1.2.5 gap analysis.
It is not a claim that the work is complete.

## Release Strategy

The project should maintain the 1.2.x line only for security fixes, correctness
fixes, documentation corrections, and narrowly additive interoperability work.
The redesign should be developed through the reviewed commit checkpoints in
[`IMPLEMENTATION_PLAN_2.0.0.md`](IMPLEMENTATION_PLAN_2.0.0.md). Intermediate
work receives no alpha, beta, or release-candidate tags. Only the completed
release is versioned and tagged as `v2.0.0`.

The following known corrections are intentionally semver-breaking:

- direct scoped borrowing becomes the normal fixed-secret exposure path;
- unrestricted generic `Secret<T>` shared and mutable exposure is removed;
- shared and mutable exposure require their corresponding explicit
  storage-stability contracts;
- `Choice` loses ordinary equality and raw extraction;
- `CtOrdering` and `Mask<T>` lose declassification bypasses;
- the misleading generic `ct::Secret<T>` marker is replaced;
- secret-bearing CT option/result state becomes clear-on-drop and redacted;
- enum derives are rejected because inactive storage is unreachable;
- every skipped derive field requires a reason;
- `strict-ct` is replaced by the accurately scoped `strict-compare`;
- ambiguous `unsafe_wipe` and best-effort compatibility names are removed;
- checked canary APIs become the normal API;
- infallible cache-flush APIs become checked;
- `ReadOnceSecret<T>` is replaced by the more precise
  `ConsumeOnceSecret<T>`;
- `sanitization-arrayvec` covers historical inline storage rather than only live
  elements.

These changes should ship together so users migrate once to one coherent
security model.

## Non-Negotiable Constraints

Version 2.0 must retain:

- `no_std` by default;
- zero external runtime dependencies in the default core crate;
- no default allocator requirement;
- isolated and documented unsafe code;
- no proc-macro implementation inside the core crate;
- redacted secret-owning types;
- optimizer-resistant native clearing;
- honest WASM and platform non-guarantees;
- optional ecosystem interop rather than mandatory third-party dependencies;
- MSRV compatibility back to Rust 1.90 unless a reviewed implementation
  requirement justifies changing it.

No 2.0 feature may claim identical wall-clock timing, complete process-memory
secrecy, or protection from privileged, physical, DMA, firmware, debugger, or
hypervisor attackers.

## Security Model

The 2.0 architecture should distinguish four separate properties:

1. **Sanitizable value:** the currently owned value can clear the storage it can
   reach.
2. **Stable secret storage:** no safe operation exposed by the type releases,
   replaces, or transfers secret-bearing historical storage without clearing
   it first.
3. **Protected native storage:** the platform established requested controls
   such as locking, dump exclusion, fork policy, guard pages, or canaries.
4. **Data-oblivious operation:** the provided primitive avoids
   secret-dependent control flow and secret-dependent memory access under a
   documented compiler, target, feature, and release profile.

These properties must not be collapsed into one trait or one marketing claim.

## Workstream 0: Behavior-Preserving Module Split

Before changing public behavior, split the current large implementation into
auditable internal modules:

- `wipe_backend`;
- `owned`;
- `ct`;
- `mapped`;
- `platform`;
- `canary`;
- `interop`.

Platform code should be divided further by target family where that reduces
cfg duplication without hiding ABI details.

The split must be behavior-preserving:

- no public API or feature change;
- no intentional codegen change;
- no unsafe invariant change;
- no target support change;
- no versioned release claim change.

Capture before-and-after:

- public API snapshots;
- test and feature-matrix results;
- LLVM IR and assembly for the current wipe and CT harnesses;
- package file lists;
- unsafe-block inventory.

This may remain one published core crate. File and module separation is
mandatory; a published-crate split is not.

## Workstream 1: Core Contracts

### 1.1 `SecureSanitize` implementer contract

Make the trait contract normative in rustdoc and `docs/SAFETY.md`.

Every implementation must:

- be idempotent;
- avoid panicking where reasonably possible;
- allocate no new storage during cleanup;
- leave the value valid to drop after sanitization;
- clear all currently owned secret elements and reachable capacity;
- clear storage before releasing or replacing ownership;
- document external allocations, shared storage, historical copies, padding,
  allocator metadata, or platform copies it cannot reach.

The trait means "can clear the currently reachable owned value." It does not
mean that arbitrary mutation is storage-stable.

Add a downstream implementation checklist and negative examples for:

- references;
- `Rc` and `Arc`;
- `NonZero*`;
- `MaybeUninit<T>`;
- unions;
- third-party containers that can reallocate internally;
- types whose all-zero representation is invalid.

Do not blanket-implement `SecureSanitize` for those categories.

### 1.2 Shared and mutable storage stability

Use two contracts rather than treating `&T` as inherently read-only:

```rust
pub trait StableSharedSecretStorage: SecureSanitize {}

pub trait StableMutableSecretStorage: StableSharedSecretStorage {}
```

`StableSharedSecretStorage` means:

> No safe operation reachable through `&self` may release, transfer, replace,
> or schedule later release of secret-bearing storage without clearing it
> first.

`StableMutableSecretStorage` extends that guarantee to safe operations reachable
through `&mut self`.

Both contracts explicitly cover:

- inherent methods;
- trait methods implemented by the type;
- interior mutation through `Cell`, `RefCell`, mutexes, atomics, custom
  allocators, or other `UnsafeCell`-based mechanisms;
- destructors and guard values returned by safe methods;
- storage release or replacement initiated through callbacks invoked by those
  methods;
- deferred cleanup work scheduled by a safe operation.

The contracts also require that the type:

- does not silently transfer a secret-bearing allocation to another owner;
- preserves a valid later sanitization and drop path;
- documents external, shared, deferred, and historical storage it cannot
  reach.

These remain normal traits rather than unsafe traits because false
implementations violate a security promise but must not be relied on for Rust
memory safety. The generic guarantees are conditional on downstream
implementations being correct.

The core crate should provide the traits primarily through audited built-in
implementations. Manual implementations require an explicit contract comment
and documentation example. Add compile-pass examples and negative rustdoc tests
covering interior-mutable and reallocating types.

An optional conservative derive may be added only if it is presented as an
explicit assertion by the type author, not as proof. It must require every field
to implement the corresponding stability trait and must reject syntactically
obvious interior-mutability types. Because a derive cannot inspect arbitrary
inherent or trait methods, manual review remains required.

Initial built-in implementations:

- integer, boolean, character, and floating-point scalars already supported by
  `SecureSanitize`;
- fixed arrays whose element type has the corresponding stability contract;
- tuples whose fields have the corresponding stability contract;
- crate-owned fixed-size and fixed-allocation secret containers.

Do not implement either trait for:

- `Vec<T>`;
- `String`;
- replaceable `Box<T>` ownership patterns;
- references or shared ownership;
- `Cell`, `RefCell`, mutex, or lock wrappers without a dedicated reviewed
  implementation;
- arbitrary third-party containers.

The closure passed to an exposure API remains a caller-responsibility boundary.
Rust cannot prevent deliberate copying, logging, `mem::replace`, or calls to
external code inside the closure. The stability traits prevent hidden storage
release by operations that the wrapped type exposes; they do not make hostile
closure code safe.

### 1.3 Generic `Secret<T>` redesign

Keep generic ownership for every `T: SecureSanitize`:

```rust
pub struct Secret<T: SecureSanitize> {
    inner: T,
}
```

Shared scoped access requires shared stability because an `&T` may mutate
through interior mutability:

```rust
impl<T> Secret<T>
where
    T: SecureSanitize + StableSharedSecretStorage,
{
    pub fn with_secret<R>(&self, inspect: impl FnOnce(&T) -> R) -> R;
}
```

Mutable scoped access exists only when storage is stable:

```rust
impl<T> Secret<T>
where
    T: SecureSanitize + StableMutableSecretStorage,
{
    pub fn with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut T) -> R,
    ) -> R;
}
```

Remove unrestricted 1.x shared and mutable exposure. `Secret<Vec<_>>` and
`Secret<String>` may still be owned and cleared, but cannot receive generic
exposure because shared interior mutation or mutable growth may release
uncleared historical allocations.

Route byte and UTF-8 users to:

- `SecretBytes<N>`;
- `SecretBoxBytes`;
- `SecretVec` and `BoundedSecretVec<MAX>`;
- `SecretString` and `BoundedSecretString<MAX>`;
- locked and guarded variants where platform protection is required.

Acceptance criteria:

- compile-fail tests reject shared exposure for an interior-mutable
  reallocating type;
- compile-fail tests reject `Secret<Vec<_>>::with_secret_mut`;
- shared-stable and mutable-stable user-defined structs can opt in explicitly;
- no `Deref`, `DerefMut`, `AsRef`, `AsMut`, `Clone`, `Copy`, ordinary equality,
  or value-printing `Debug` is introduced.

## Workstream 2: Exposure And Copy Reduction

### 2.1 Direct fixed-size exposure

Change `SecretBytes<N>::expose_secret` to borrow the owned array directly:

```rust
pub fn expose_secret<R>(
    &self,
    inspect: impl FnOnce(&[u8; N]) -> R,
) -> R;
```

The implementation must not construct an additional `[u8; N]` stack array.
This reduces stack remanence, stack use, abort exposure, register spills, and
compiler-generated scratch copies.

Retain temporary-copy behavior only through an explicitly named API:

```rust
pub fn expose_secret_copy<R>(
    &self,
    inspect: impl FnOnce(&[u8; N]) -> R,
) -> R;
```

The copy method must eagerly volatile-clear the temporary on normal return and
use a guard during unwinding. It cannot clear after process abort.

Apply the same naming and direct-borrow policy consistently to fixed-size
locked, pooled, expiring, split, and guarded wrappers where the storage and
integrity model permit it.

Acceptance criteria:

- downstream codegen harnesses show no full-size temporary in direct exposure;
- compile-fail tests prove the borrow cannot escape the closure;
- copy-based APIs are visibly named as copies;
- all abort and caller-closure limits remain documented.

### 2.2 Fixed-allocation dynamic bytes

Add:

```rust
pub struct SecretBoxBytes {
    // Private fixed-capacity backing. No safe growth or extraction API.
    inner: Vec<u8>,
}
```

This type serves dynamic lengths that are fixed after construction. The
private vector permits stable-Rust fallible reservation; its safe API preserves
length and capacity and clears the full capacity before release.

Required API:

- `zeroed(len)`;
- bounded, genuinely fallible allocation constructors;
- `from_boxed_slice`;
- `from_fn(len, ...)`;
- `try_from_fn(len, ...)`;
- copying `from_slice`;
- direct read and mutable scoped exposure;
- staged replacement;
- clear, drop, and consuming clear;
- public-length CT equality;
- optional serde and interop implementations.

Required properties:

- allocation length cannot change after construction;
- mutable exposure cannot reallocate;
- replacement creates a new clear-on-drop value before clearing and swapping
  the old value;
- complete allocation is cleared before release;
- untrusted lengths can be rejected before allocation and reserve failure can
  be returned without entering an infallible allocation path;
- `Debug` is redacted;
- no ordinary equality, `Deref`, `AsRef`, `Clone`, or `Copy`.

### 2.3 Stable UTF-8 and byte guidance

Keep `SecretVec` and `SecretString` as managed-growth containers because their
growth paths stage a replacement allocation and clear the old allocation before
release.

Document three distinct dynamic choices:

- `SecretBoxBytes`: fixed runtime length, no growth;
- `SecretVec`/`SecretString`: managed secure growth;
- locked/guarded mapped containers: platform protection and explicit mapping
  behavior.

Do not suggest generic `Secret<Vec<u8>>` or `Secret<String>` for mutable secret
storage.

## Workstream 3: Aggregate And Representation Coverage

### 3.1 Tuple implementations

Implement `SecureSanitize`, `StableSharedSecretStorage`, and
`StableMutableSecretStorage` for tuples up to a documented arity, preferably
12 or 16.

Each field is sanitized in deterministic order. Document that field-wise
cleanup does not clear padding.

### 3.2 Byte-specialized guidance

Keep generic arrays, slices, boxes, and vectors for current-value sanitization,
but route byte workloads to byte-specialized containers.

The generic `Vec<T>` implementation must explicitly state:

- it sanitizes every live `T`;
- it clears the current allocation capacity before release;
- it cannot recover allocations already released by earlier caller-controlled
  reallocation;
- `SecretVec` is the optimized and storage-aware byte path.

Add performance tests that catch repeated per-byte fences when callers
accidentally select generic byte aggregates.

### 3.3 Full-representation wiping

Do not clear arbitrary Rust object representations.

An experimental feature may introduce:

```rust
pub unsafe trait ZeroValidPlainData: Copy { }
```

Stabilization requirements:

- `Copy`;
- no `Drop`;
- no references, raw pointers, function pointers, or provenance-bearing
  fields;
- no interior ownership, allocation handles, or interior mutability;
- all-zero is a valid representation;
- raw representation clearing cannot violate a later operation or destructor;
- exact validity and padding contract;
- no blanket implementations for references, `NonZero*`, shared ownership,
  enums, unions, `MaybeUninit`, trait objects, or unknown representations;
- built-in implementations only for the first stable release;
- Miri coverage for every built-in implementation;
- external unsafe-code review;
- demonstrated value beyond ordinary field-wise sanitization.

This trait is optional for 2.0 stable. If its review is incomplete, defer it
without delaying the mandatory architecture corrections.

CP-17 resolves this by keeping `ZeroValidPlainData` private and built-in-only.
It constrains the primitive scalar representation wipes already present
without creating a downstream implementation surface. A public marker remains
deferred.

## Workstream 4: Data-Oblivious API Redesign

### 4.1 Security claim

The `ct` module must use the precise claim:

> No secret-dependent control flow or secret-dependent memory access inside the
> provided primitives, under the documented compiler, target, feature, and
> release-profile conditions.

Do not use "constant time" to mean exact equal wall-clock duration.

### 4.2 `Choice`

Redesign `Choice` so declassification is explicit:

- remove `Eq` and `PartialEq`;
- remove `unwrap_u8`;
- retain normalized hidden 0/1 storage;
- retain branchless boolean composition;
- expose `declassify(reason) -> bool`;
- expose `declassify_u8(reason) -> u8` only when raw public bits are needed;
- keep `Debug` redacted;
- retain `Copy` only if codegen review confirms it remains useful and does not
  undermine the intended boundary.

Repository checks must reject new raw-choice extraction outside the audited
implementation.

### 4.3 `CtOrdering` and masks

For `CtOrdering`:

- remove ordinary equality;
- keep hidden `is_less`, `is_equal`, and `is_greater` choices;
- retain only reason-bearing conversion to public `Ordering`;
- keep invariant validation in constructors and debug assertions.

For `Mask<T>`:

- make raw mask extraction private where possible;
- remove unclassified `expose`;
- if a public raw mask is required, require a reason-bearing declassification
  method;
- keep mask construction and use inside audited CT helpers.

### 4.4 Replace `ct::Secret<T>`

Remove the generic marker that currently permits copying, equality, and raw
borrowing.

Add purpose-specific types:

```rust
pub struct SecretIndex(usize);
pub struct SecretScalar<T: SecureSanitize>(T);
```

`SecretIndex`:

- implements `SecureSanitize` and clears on drop;
- does not implement `Copy`, `Clone`, ordinary equality, or value-printing
  `Debug`;
- has no normal index getter;
- is accepted directly by full-scan lookup APIs;
- can be converted to a public index only with a consuming reason-bearing
  declassification method;
- clears the wrapper's remaining storage during consuming declassification.

`SecretScalar<T>`:

- implements `SecureSanitize` and clears on drop;
- does not implement `Copy`, `Clone`, ordinary equality, or value-printing
  `Debug`;
- exposes reviewed CT operations based on trait bounds;
- does not provide a generic `&T` getter that allows normal comparison or
  indexing;
- permits explicit declassification only through a reason-bearing consuming
  method when the use case requires a public value;
- transfers responsibility for the returned value to the caller and clears any
  wrapper-owned storage that remains after the move.

Both types must document that Rust moves, compiler-generated temporaries,
registers, and caller-created copies remain outside their clearing guarantee.

Use an initialized ownership state such as `Option<T>` so consuming
declassification can move the value out, leave the wrapper empty, and avoid a
second cleanup in `Drop`. Do not introduce unsafe field extraction merely to
work around the presence of a destructor.

The type system cannot make arbitrary caller closures data-oblivious. Avoid
generic exposure closures that would only recreate the original bypass.

### 4.5 Secret-bearing CT option and result

Redesign `PublicCtOption` and `PublicCtResult` into two clearly separated categories:

1. lightweight control containers for public or non-secret backing values;
2. clear-on-drop secret-bearing containers.

Classify backing values explicitly:

```rust
pub struct PublicValue<T>(T);
pub struct SecretValue<T: SecureSanitize>(T);

pub struct SecretCtOption<V> { ... }
pub struct SecretCtResult<V, E> { ... }
```

Required behavior:

- redacted `Debug`;
- no `Copy`, `Clone`, ordinary equality, or raw backing getters;
- every `SecretValue<T>` backing value is sanitized on drop;
- `PublicValue<T>` is treated as explicitly public metadata and does not require
  `SecureSanitize`;
- absent `SecretCtOption<SecretValue<T>>` sanitizes its dummy value during
  declassification;
- `SecretCtResult` sanitizes every unselected secret-classified success or error
  backing value before returning the selected value;
- mapping and conditional selection preserve clear-on-drop ownership;
- panic-unwind and partial-construction paths clear initialized values;
- no secret-dependent branch occurs before explicit declassification.

Use initialized ownership states such as `Option<T>` fields or another reviewed
strategy so values can be moved out safely without introducing unnecessary
unsafe extraction.

Acceptance criteria:

- a panic while sanitizing an unselected value unwinds without double-drop,
  invalid ownership, or returning a partially declassified result;
- a panic inside a mapping closure clears every still-owned secret backing
  value;
- conditional selection may create a third owned value while both inputs remain
  live without aliasing or suppressing later cleanup;
- zero-sized types and drop-bearing types behave correctly;
- the returned selected value is not cleaned a second time by the wrapper it was
  moved out of;
- Miri and panic-probe tests cover each ownership transition.

### 4.6 CT feature naming

Remove `strict-ct`.

Add:

```toml
strict-compare = ["asm-compare"]
```

The documentation must state that this feature hardens equal-length byte
comparison only. Ordering, selection, lookup, and other portable Rust
primitives keep their own target-tier claims.

Do not expose a whole-module "strict CT" profile until every included primitive
has an audited target-specific backend and matching evidence.

## Workstream 5: Strict Derive Behavior

### 5.1 Enums fail closed

Enum `SecureSanitize` and `SecureSanitizeOnDrop` derives must reject
unconditionally. A manual `SecureSanitize` implementation does not make a drop
derive acceptable because final-drop cleanup cannot repair inactive bytes
retained by earlier variant transitions.

The diagnostic must explain:

- only the active variant is reachable safely;
- bytes from a previously active larger variant may remain;
- reviewed manual implementations must sanitize before replacement with
  `secure_replace`;
- struct-based state machines are preferred for high-assurance secret state.

There is no acknowledgement attribute or feature flag that weakens this rule.

### 5.2 Skip reasons

Require:

```rust
#[sanitization(skip, reason = "public algorithm identifier")]
```

Rules:

- `skip` without a non-empty reason is rejected;
- `reason` without `skip` is rejected;
- duplicate `skip`, `reason`, `bound`, or container options are rejected;
- reason text appears in generated documentation or diagnostics where useful;
- CT selection derives continue to reject skipped fields when every output field
  must be constructed.

### 5.3 Derive test matrix

Add compile-pass and compile-fail coverage for:

- named, tuple, and unit structs;
- generics and struct-level `Drop` bounds;
- `SecureSanitizeOnDrop` rejection for `!Unpin` structs;
- automatic `DropSafeSanitize` for generated field-wise sanitizers;
- explicit `DropSafeSanitize` approval and complete aggregate dispatch for
  reviewed manual sanitizers;
- rejection of unapproved manual whole-value sanitizers;
- `PhantomData`;
- crate-path override;
- enum rejection for every derive, including `SecureSanitizeOnDrop` paired with
  a manual `SecureSanitize` implementation;
- missing and empty skip reasons;
- duplicate and malformed attributes;
- unions;
- CT derives and padding-safe field-wise behavior.

The derive crate remains optional. Its compile-time dependencies do not become
runtime dependencies of the core crate.

## Workstream 6: Correct `sanitization-arrayvec`

The 1.x assumption that spare storage has never held a `T` is invalid for an
arbitrary incoming `ArrayVec`. Popped, truncated, or cleared elements may leave
historical bytes in inline spare capacity.

The 2.0 implementation should:

1. sanitize every live element;
2. clear the `ArrayVec` so live values are dropped in a valid state;
3. obtain the now-complete spare capacity as `MaybeUninit<T>`;
4. volatile-clear `CAP * size_of::<T>()` bytes through one audited unsafe
   helper;
5. handle zero-sized types and overflow explicitly.

The unsafe helper belongs in the sister crate and must document:

- why no live `T` remains;
- why the complete spare region is writable;
- why byte writes to `MaybeUninit<T>` storage are valid;
- why the `ArrayVec` remains valid after the wipe.

If the supported `arrayvec` API cannot expose the complete post-clear spare
capacity with a stable contract, remove generic ownership-taking conversion and
provide:

- direct secret-aware construction;
- a byte-specialized `SecretByteArrayVec<CAP>`;
- no claim that arbitrary historical generic inline storage is covered.

Acceptance criteria:

- tests cover push, pop, truncate, clear, reuse, and wrapping an `ArrayVec` with
  historical spare bytes;
- a test probe confirms the entire inline backing region is overwritten;
- Miri passes;
- no live value is raw-zeroed before its destructor runs.

## Workstream 7: Wipe Backend Architecture

### 7.1 Public naming

Expose safe public helpers under a canonical safe module such as:

```rust
sanitization::wipe
```

Rename the private implementation module to `wipe_backend`.

Remove:

- the public `unsafe_wipe` name;
- the no-op `unsafe-wipe` feature;
- `sanitize_bytes_best_effort`;
- duplicate "volatile" aliases whose behavior is now identical.

Only the private backend contains unsafe code. Public wipe helpers remain safe.

### 7.2 Fence policy

Benchmark and separate:

- compiler ordering needed to retain erasure and constrain compiler movement;
- hardware ordering needed for device handoff, DMA, persistent memory, cache
  maintenance, or explicit cross-agent visibility.

Evaluate replacing the unconditional hardware `SeqCst` fence on ordinary RAM
wipes with:

- volatile stores plus compiler fences for normal RAM;
- an explicit hardware-ordered wipe policy for platform/device handoff;
- architecture-specific completion instructions where a target requires them.

No fence reduction may ship based on benchmarks alone. It requires:

- LLVM and assembly inspection;
- target documentation;
- native tests;
- performance evidence;
- external review.

If the evidence is inconclusive, retain the 1.x fence behavior.

### 7.3 Internal erasure backend

Introduce a sealed internal abstraction:

```rust
trait ErasureBackend {
    fn erase(ptr: *mut u8, len: usize);
}
```

Internal implementations may cover:

- ordinary volatile RAM;
- hardware-ordered RAM;
- x86 cache-cleaned RAM;
- target-specific embedded cache maintenance;
- test instrumentation and fault injection.

Do not stabilize a public generic backend trait until concrete DMA, MMIO,
NVRAM, or persistent-memory prototypes establish precise safety contracts.

### 7.4 Target-provided backend path

Design an experimental, feature-gated integration path for bare-metal systems
that require cache cleaning or device coherency beyond ordinary CPU stores.

The design must distinguish:

- normal coherent RAM;
- non-coherent cacheable RAM;
- DMA/shared buffers;
- persistent memory;
- MMIO/device memory;
- hardware keystore or enclave handles.

Do not pretend one generic fence or volatile loop is sufficient for every
category. If a public extension trait is eventually exposed, it must be unsafe,
target-specific, and externally reviewed.

CP-17 defers the public target-provided backend from 2.0. The category
contracts and requirements for a future companion or unsafe API are recorded
in `ERASURE_BACKENDS.md`.

Multi-pass overwrite remains a compliance option, not a claim of stronger
security for volatile RAM.

## Workstream 8: Cache And Register Hardening

### 8.1 Checked x86 cache flushing

Replace hard-coded assumptions:

- check CPUID `CLFSH`;
- obtain and validate the reported cache-line flush size;
- preserve overflow-safe range arithmetic;
- return structured unsupported or platform errors;
- perform the volatile wipe even when eviction is unavailable;
- use the correct completion fence after flushes.

Existing infallible cache-flush methods should become checked in 2.0.

Document that cache flushing:

- reduces post-use cache residency;
- does not prevent cache timing attacks during the secret's lifetime;
- does not guarantee eviction from every platform-private buffer;
- can itself be observable.

### 8.2 Register scrubbing

Keep register scrubbing explicitly best effort.

Document remaining limits:

- compiler spills;
- general-purpose registers;
- callee-saved state;
- AVX-512 mask and extended register state where not covered;
- AArch64 preserved vector halves where inline assembly cannot express a safe
  partial clobber;
- interrupt, signal, context-switch, and kernel save areas.

Add codegen and native tests for every claimed architecture-specific register.
Do not make register scrubbing implicit on every drop.

## Workstream 9: Native Memory Protection

### 9.1 Protection request, policy, and result

Separate requested policy from achieved runtime protection:

```rust
pub enum Requirement {
    Required,
    Preferred,
    NotRequested,
}

pub struct ProtectionRequest {
    pub memory_lock: Requirement,
    pub dump_exclusion: Requirement,
    pub fork: ForkProtectionRequest,
    pub guard_pages: Requirement,
    pub canary: Requirement,
    pub cache_policy: Requirement,
}
```

`ProtectionRequest` is public policy. Cargo features and named profiles control
which implementations are compiled; they do not prove that a runtime control
was established.

Add a structured report of actual outcomes:

```rust
pub struct ProtectionReport {
    pub memory_lock: ProtectionState,
    pub dump_exclusion: ProtectionState,
    pub fork: ForkProtectionReport,
    pub guard_pages: ProtectionState,
    pub canary: ProtectionState,
    pub cache_policy: ProtectionState,
}
```

States must distinguish:

- established;
- not requested;
- unsupported;
- preferred but unavailable or failed;
- compatibility-only, such as WASM.

Reports for mapped storage should also include public operational metadata such
as requested bytes, mapped bytes, locked bytes, page granule, and whether a
failure is consistent with a platform lock quota. This helps deployments detect
`RLIMIT_MEMLOCK` or `VirtualLock` pressure without exposing secret contents.

Rules:

- failure or unavailability of a `Required` control returns an error and rolls
  back every established control;
- failure or unavailability of a `Preferred` control may return the container
  with a report describing the reduced result;
- `NotRequested` controls are not attempted;
- strict profile constructors translate their promised controls into
  `Required`;
- flexible constructors accept an explicit `ProtectionRequest`;
- errors carry a partial report describing controls established before rollback
  and the rollback outcome;
- successful constructors return or retain the final `ProtectionReport`.

The error type must distinguish failure to establish a control from failure to
roll it back. A rollback failure is a separate high-severity platform condition
and must not be hidden behind the original error.

The report must not imply protection from privileged reads, hibernation,
snapshots, DMA, firmware, or all crash-dump mechanisms.

### 9.2 Explicit fork policy

Add:

```rust
pub enum ForkPolicy {
    Inherit,
    Exclude,
    WipeChild,
}
```

`ForkProtectionRequest` must combine the desired fork behavior with its
`Requirement`.

On Linux:

- `Exclude` uses `MADV_DONTFORK`;
- `WipeChild` uses `MADV_WIPEONFORK` where supported;
- strict constructors fail if the requested policy cannot be established.

Other platforms report their exact supported state rather than claiming a
Linux-equivalent policy.

### 9.3 Checked integrity access

Make checked canary APIs the normal API:

- unqualified exposure, mutation, copy, replacement, and comparison return a
  structured integrity error when canaries are enabled;
- panic behavior is available only through explicitly named `*_or_panic`
  helpers, if retained at all;
- corruption clears the untrusted secret before returning;
- error messages and timing do not reveal partial canary information;
- deterministic canaries remain documented as corruption detectors, not
  authentication;
- random canaries continue to use OS CSPRNG sources and fail closed on setup
  failure.

### 9.4 Page-sealed fixed secrets

Add a reviewed fixed-size mapped type:

```rust
pub struct SealedSecretBytes<const N: usize> { ... }
```

The data pages remain `PROT_NONE` or `PAGE_NOACCESS` between accesses.

A scoped access method:

1. changes the data region to readable or read/write;
2. verifies integrity;
3. invokes the closure;
4. restores no-access protection through an unwind guard.

Constraints:

- access requires `&mut self`;
- the type is not `Sync`;
- drop restores write access, clears, unlocks, and unmaps;
- every protection transition is fallible and structured;
- explicit sanitization remains fallible and the type does not implement
  infallible sanitization or zeroize traits;
- process abort, signals, privileged remapping, and external copies remain out
  of scope.

The `page-seal` review candidate implements this design without changing the
existing guarded containers. It is a 2.0 target only if native Linux, macOS,
Windows, and AArch64 evidence plus external review are complete. Otherwise
defer it without blocking the mandatory core redesign.

### 9.5 Secure arena evolution

Build on `SecretPool` with a reviewed arena design for applications that need
many protected secrets under lock quotas.

Desired properties:

- wipe-before-slot-release;
- generation counters or equivalent stale-handle defense where applicable;
- fixed-size pools as the first stable implementation;
- optional memory lock, dump exclusion, guard pages, canaries, and fork policy;
- allocation quarantine hooks for tests;
- `ProtectionReport` integration;
- no pool drop while slots are borrowed;
- Loom coverage of slot allocation and release ordering.

The 2.0 stable arena remains fixed-size. Variable-size arena allocation is
deferred because fragmentation, metadata secrecy, stale-offset behavior, and
bounded wipe-before-reuse invariants have not been reviewed sufficiently.

## Workstream 10: One-Access Secrets

Rename `ReadOnceSecret<T>` to:

```rust
pub struct ConsumeOnceSecret<T: SecureSanitize> { ... }
```

The name reflects the real guarantee:

- exactly one scoped shared accessor wins through this API;
- the accessor receives `&T`, requires `T: StableSharedSecretStorage`, and
  cannot request `&mut T` through this wrapper;
- the value is cleared when that access returns or unwinds;
- later access is rejected;
- a never-consumed value is cleared on drop.

It does not prove that the value was never copied before construction or by the
successful closure.

Required verification:

- the standalone `tools/consume-once-loom` model for competing accessors and
  cleanup ordering;
- panic-unwind cleanup tests;
- Miri coverage;
- explicit `panic = "abort"` non-guarantee;
- review of `Send` and `Sync` unsafe impls.

Remove the older ambiguous name in 2.0.

## Workstream 11: Feature And Crate Architecture

### 11.1 Named profiles

Add accurately scoped profile features:

```toml
strict-compare = ["asm-compare"]
profile-hardened-native = [
    "memory-lock",
    "random-canary",
    "strict-canary-check",
    "strict-compare",
]
profile-guarded-native = [
    "profile-hardened-native",
    "guard-pages",
]
profile-hardened-linux = [
    "profile-hardened-native",
    "require-fork-exclusion",
]
```

Profiles request controls. `ProtectionReport` states what was established.
Strict profiles convert their controls to `Required`; flexible profiles use
`Preferred` where documented. Known-incompatible strict target/profile
combinations fail to compile rather than silently reducing guarantees.
`wasm-compat` remains an explicitly reduced-guarantee profile and reports
compatibility-only outcomes.

### 11.2 Companion crates

Retain the existing pattern:

- `sanitization-derive`;
- `sanitization-arrayvec`;
- `sanitization-bytes`;
- `sanitization-crypto-interop`.

Evaluate additional companion crates only when they isolate a real optional
dependency or platform SDK. Do not move core clearing or ownership guarantees
behind mandatory companion dependencies.

Vendor TEE, HSM, TPM, SGX, Nitro, or platform-keystore integrations should use
provider traits and separate crates rather than adding vendor SDK dependencies
to the core.

## Workstream 12: Verification And Release Evidence

### 12.1 Path-specific codegen verification

Replace broad artifact greps with downstream exported harnesses for:

- ordinary byte slices;
- `SecretBytes<N>` direct exposure and clear;
- copy exposure and temporary cleanup;
- `SecretBoxBytes`;
- `SecretVec` and `SecretString` full-capacity clearing;
- locked, guarded, pooled, and sealed mappings;
- derive-generated struct cleanup and reviewed manual enum cleanup;
- tuple cleanup;
- `sanitization-arrayvec` complete backing cleanup;
- CT equality, ordering, selection, conditional copy/swap, and oblivious lookup.

For each harness, structurally verify:

- the public path reaches the intended wipe backend;
- volatile stores occur in a length-controlled loop;
- forbidden `memcmp`/`bcmp` substitutions are absent;
- direct exposure does not create a full-size temporary;
- assembly backends are selected only on supported targets.

Build matrix:

- optimization levels 2, 3, `s`, and `z`;
- ThinLTO and FatLTO;
- codegen units 1 and many;
- unwind and `panic = "abort"`;
- Rust 1.90, repository default stable, beta, and nightly warnings;
- x86_64 Linux;
- AArch64 Linux;
- AArch64 macOS;
- x86_64 Windows;
- embedded Thumb;
- embedded RISC-V when available;
- WASM output inspection with Tier C claims only.

### 12.2 Minimum stable target evidence matrix

Define the minimum release matrix now rather than leaving "native evidence"
open-ended:

| Tier | Required targets | Minimum 2.0 evidence |
|---|---|---|
| Tier A | `x86_64-unknown-linux-gnu` | Full native functional tests, platform protection tests, release codegen matrix, Miri/Kani where applicable, sanitizer coverage, and full leakage evidence for claimed CT primitives. |
| Tier B native | `aarch64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `aarch64-apple-darwin` | Native functional tests for supported platform controls, release codegen for touched primitives, feature matrix, and target-specific non-guarantees. A CT primitive receives a timing claim only when native leakage evidence exists for that target. |
| Tier B compile-only | supported BSD, Android, iOS, embedded ARM, and embedded RISC-V targets listed in `docs/TARGETS.md` | Cross-compilation, cfg/feature validation, package checks, and source/codegen review where available. No native runtime or timing claim. |
| Tier C | WASM compatibility targets | Build and API compatibility evidence only, with explicit JIT, memory-lock, page-protection, and volatile-semantics limits. |
| Experimental | every other target | No stable guarantee beyond what its documentation explicitly states. |

The target table in `docs/TARGETS.md` must list every supported triple, tier,
tested feature set, compiler version, runner type, and date of the latest
evidence. A target must be downgraded when required evidence becomes stale.

### 12.3 Lifecycle failure testing

Add unpublished tooling for:

- a quarantining allocator that delays reuse and inspects released allocations;
- fuzzing growth, replacement, conversions, serde limits, enum transitions,
  canary corruption, and syscall failures;
- fault injection for map, lock, protect, random, fork-policy, and flush
  failures;
- ASan, TSan, and UBSan jobs for platform unsafe modules;
- child-process tests for `DONTFORK` and `WIPEONFORK`;
- crash/core-dump marker searches where CI permissions permit;
- native runners for Linux, macOS, Windows, BSD, Android, AArch64 Linux, and an
  iOS simulator or device environment where available.

Test-only dependencies belong in unpublished tools or harnesses and must not
become default runtime dependencies.

### 12.4 Concurrency verification

Add Loom models for:

- `ConsumeOnceSecret`;
- `SecretPool` slot allocation, clear, and release;
- arena generation/reuse logic;
- any new atomic protection state.

Kani remains useful for bounded functional properties but is not evidence of
real concurrent scheduling.

### 12.5 Timing evidence

Promote the leakage harness from smoke evidence to release evidence:

- multiple randomized seeds;
- full dudect-style fixed-vs-random and class-separated experiments where the
  primitive permits them;
- default comparison and `strict-compare` runs;
- CPU affinity and frequency controls where available;
- x86_64 Linux, AArch64 Linux, and AArch64 macOS native runs;
- per-case environment metadata and Welch t-test results;
- evidence regeneration after compiler, profile, backend, or CT changes;
- no strong CT claim for browser or Node WASM JIT execution.

### 12.6 Performance gates

Add baselines and regression thresholds for:

- wipe throughput by length;
- compiler-fence and hardware-fence overhead;
- generic aggregate cleanup;
- full-capacity heap clearing;
- locked, guarded, pooled, and sealed construction/drop;
- CT primitives;
- cache flushing.

Performance gates exist to catch accidental repeated fences and pathological
regressions. They must not justify weakening a security boundary without
separate review.

### 12.7 Formal and unsafe-code evidence

Expand Kani proofs for:

- wipe loop bounds;
- capacity arithmetic;
- CT functional equivalence;
- stable replacement state machines;
- pool slot index arithmetic;
- protection-report state transitions.

Run Miri for all platform-independent unsafe paths. Native syscall, page-table,
locking, and guard-page behavior still requires native tests.

Every new unsafe block requires:

- a local `SAFETY` explanation;
- a matching invariant in `docs/SAFETY.md`;
- a test or proof exercising the boundary;
- external review before stable release.

## Workstream 13: Documentation

Update:

- `README.md`;
- `docs/GUARANTEES.md`;
- `docs/NON_GUARANTEES.md`;
- `docs/THREAT_MODEL.md`;
- `docs/SAFETY.md`;
- `docs/BARRIERS.md`;
- `docs/TARGETS.md`;
- `docs/EVIDENCE.md`;
- `docs/LEAKAGE_TESTS.md`;
- `SECURITY.md`.

Add:

- `docs/MIGRATION_2.0.md`;
- `docs/STORAGE_CONTRACTS.md`;
- `docs/PROTECTION_REPORT.md` if the protection request/report model is
  included;
- target-specific evidence manifests for the release candidates.

The README's concise decision table, together with `docs/FEATURES.md` and
`docs/ADVANCED_USAGE.md`, must distinguish:

- current-value sanitization;
- stable shared and stable mutable storage;
- fixed-size and fixed-allocation storage;
- managed-growth byte/text storage;
- locked, guarded, pooled, and sealed storage;
- data-oblivious control values;
- optional third-party interoperability.

The migration guide must cover every removed 1.x API and provide a concrete 2.0
replacement.

## 2.0 Stable Scope

### Security-model release blockers

These correct known misleading or incomplete boundaries and cannot be deferred:

1. Behavior-preserving internal module split and unsafe-inventory baseline.
2. Normative `SecureSanitize` implementer contract.
3. `StableSharedSecretStorage` and `StableMutableSecretStorage`.
4. Restricted generic `Secret<T>` shared and mutable exposure.
5. Direct fixed-secret exposure and explicitly named copy exposure.
6. CT declassification repair for `Choice`, `CtOrdering`, and masks.
7. Replacement of generic `ct::Secret<T>` with clear-on-drop,
   purpose-specific secret owners.
8. Redacted, ownership-correct secret CT option/result types with explicit
   public/secret backing classification.
9. Strict enum derive and mandatory skip reasons.
10. Correct historical `ArrayVec` backing cleanup or removal of the unsupported
    generic guarantee.
11. Accurate `strict-compare` naming.
12. Canonical safe wipe naming and removal of obsolete aliases.
13. Checked canary access as the normal API.
14. Accurate documentation for generic aggregates, interior mutability, enum
    transitions, WASM, abort behavior, and platform limits.

If the x86 cache-flush feature remains in 2.0, capability detection and checked
failure handling are also release blockers. The alternative is to remove or
defer that feature rather than ship the known hard-coded assumption.

### Production-readiness release blockers

These establish that the corrected model is credible in production:

1. Path-specific release codegen across the documented optimization profiles.
2. Miri for platform-independent unsafe paths.
3. Kani for selected functional and arithmetic invariants.
4. Loom for retained concurrent types and unsafe `Send`/`Sync` claims.
5. The exact minimum target evidence matrix.
6. Current leakage evidence for every target and primitive receiving a timing
   claim.
7. Complete migration, safety, guarantees, non-guarantees, target, and evidence
   documentation.
8. Downstream migration builds using real cryptographic consumers.
9. Independent review with no unresolved finding that contradicts a guarantee.
10. Packaging, release-script, report-only commit, and signed-tag gates.

### Additive features that may be deferred

These are valuable but must not delay correction of known security boundaries:

- `SecretBoxBytes`;
- `ConsumeOnceSecret<T>` rename or redesign;
- `ProtectionRequest` and `ProtectionReport`, provided existing constructors do
  not make ambiguous claims;
- expanded cache-flush APIs if the 1.x feature is removed from 2.0 until ready;
- secure arena generation counters and variable-size allocation;
- `SealedSecretBytes<N>`;
- `ZeroValidPlainData`;
- public target-provided erasure backends;
- expanded non-x86 cache maintenance;
- additional register-state coverage;
- native BSD, Android, and iOS runners beyond the minimum compile-only tier.

Any additive feature included before API freeze must satisfy its own tests,
documentation, target evidence, and external review requirements.

## 1.2.x Backport Policy

Users should not wait for 2.0 to receive non-breaking corrections.

The active disposition and branch-integration process are maintained in
[`BACKPORTS_1.2.x.md`](BACKPORTS_1.2.x.md).

Backport candidates:

- correct the inaccurate `sanitization-arrayvec` spare-storage documentation;
- implement complete historical inline-storage clearing in 1.2.x if it can be
  done without breaking the public API and passes unsafe review;
- keep `PublicCtOption` and `PublicCtResult` `Debug` implementations redacted so backing
  values are not printed;
- strengthen documentation around `ct::Secret<T>`, raw `Choice` extraction,
  enum transitions, interior mutability, and `Secret<Vec<T>>`;
- direct new examples toward dedicated byte/text containers and checked canary
  APIs;
- add non-breaking checked helpers and warnings where they do not create
  downstream `deny(warnings)` failures;
- deprecate misleading names only after checking the practical effect on
  downstream builds.

Do not backport API removals, changed generic bounds, or derive-default changes
to 1.2.x.

## Explicit Non-Goals

Version 2.0 will not claim or attempt:

- soundly scrubbing arbitrary old Rust stack frames;
- preventing intentional copies by caller closures;
- native-equivalent volatile guarantees in WASM JIT runtimes;
- complete general-purpose or kernel-saved register clearing;
- protection against privileged process, kernel, hypervisor, firmware, DMA, or
  physical attackers;
- one generic erasure strategy for RAM, MMIO, DMA, and persistent memory;
- automatic vendor SDK dependencies in the core crate;
- threshold secret sharing unless separately designed and audited;
- multi-pass RAM clearing as a stronger technical security guarantee.

## Commit-Gated 2.0.0 Execution

The complete implementation order is defined in
[`IMPLEMENTATION_PLAN_2.0.0.md`](IMPLEMENTATION_PLAN_2.0.0.md).

Development uses symbolic commit checkpoints `CP-00` through `CP-23`. These are
commit-message and temporary review identifiers, not versions or tags.

For every checkpoint:

- record the current branch tip as the checkpoint base;
- implement one bounded security concern;
- stop at the implementation commit;
- review the complete Git range from the checkpoint base;
- apply checkpoint-scoped remediation commits when required;
- retest the complete range;
- delete the ignored root `PENTEST.md` after the review is accepted;
- wait for clean CI and project-owner confirmation before starting later
  implementation.

Development findings are temporary and are not committed. The detailed plan
contains a roadmap coverage matrix so every workstream has an implementation
checkpoint or an explicit reviewed defer/reject decision.

The frozen pre-2.0 comparison state is documented in
[`baselines/2.0/BASELINE_1.2.5.md`](baselines/2.0/BASELINE_1.2.5.md).

No alpha, beta, or release-candidate packages are planned. Workspace versions
remain unchanged during implementation. The coordinated `2.0.0` version bump,
package review, and release-script dry run happen only in `CP-23`.

The final release requires:

- clean acceptance of every checkpoint;
- an independent full-range close-out review at `CP-22`;
- no open critical, high, or medium finding;
- no unresolved low finding that contradicts a guarantee;
- all security-model and production-readiness blockers complete;
- every additive feature complete or explicitly deferred;
- current migration, target, codegen, formal, concurrency, timing, and
  performance evidence;
- a final `security/pentest/v2.0.0.md` report-only commit;
- a clean release-readiness gate;
- a signed `v2.0.0` tag pointing to that final report commit.

## Definition Of Done

Version 2.0.0 is ready only when:

- the public API reflects the four-property security model;
- known misleading 1.x boundaries have been removed rather than aliased;
- direct secret exposure avoids unnecessary copies;
- shared or mutable generic exposure cannot reach a storage-releasing operation
  unless the corresponding downstream stability contract is implemented;
- secret-derived CT state cannot bypass explicit declassification;
- derives fail closed by default;
- historical inline storage is covered;
- platform controls are reported accurately;
- default `no_std` and zero-external-dependency behavior remains intact;
- all new unsafe code is isolated, documented, tested, and externally reviewed;
- native, codegen, formal, concurrency, timing, and performance evidence is
  current;
- all workspace packages, release artifacts, pentest reports, and signed-tag
  gates pass.
