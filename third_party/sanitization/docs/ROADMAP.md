# Roadmap

This crate is stable in the `1.x` line. The roadmap tracks high-assurance
features that fit the crate's core model: dependency-free-by-default secret
ownership, explicit unsafe boundaries, and documented platform limits.

The detailed architecture and hardening plan for the next major release is in
[`ROADMAP_2.0.0.md`](ROADMAP_2.0.0.md). Version 2.0 is intended to correct
security boundaries that cannot be changed cleanly while retaining the full
1.x API.

The commit-by-commit execution order, verification stops, and pentest handoff
process are defined in
[`IMPLEMENTATION_PLAN_2.0.0.md`](IMPLEMENTATION_PLAN_2.0.0.md). Development
uses reviewed commits rather than alpha, beta, or release-candidate tags.

The goal is not to be a drop-in replacement for `zeroize`. The goal is to be a
zero-dependency secret lifecycle crate for new projects: redacted containers,
narrow exposure APIs, constant-time equality for crate-owned secrets, and one
audited memory clearing path.

## Ecosystem Position

`zeroize` is deliberately minimal: one trait, one optimizer-resistant clearing
primitive, and an optional derive macro. That design is valuable because it
keeps the crate focused. The broader Rust secret-handling ecosystem usually
combines multiple crates to cover lifecycle concerns:

- `zeroize` for memory clearing;
- `secrecy` for controlled secret exposure;
- `subtle` for constant-time equality;
- older or less-maintained crates for memory locking, guard pages, and platform
  memory protection.

This crate should not clone every `zeroize` capability. Its stronger position is
to be a dependency-free secret lifecycle crate: storage, controlled exposure,
comparison, and destruction under one coherent threat model.

The opportunity is to keep that lifecycle scope while adding the high-assurance
pieces that are currently hard to get from maintained, dependency-light Rust
crates.

## Non-Negotiables

- Keep zero external runtime dependencies.
- Keep `no_std` as the default.
- Keep proc macros out of the core crate.
- Prefer small, explicit unsafe internals over broad safe APIs with weaker
  security properties.
- Document limits instead of implying complete process-memory secrecy.

## 1.x Architecture Direction

### Implemented: 1.2.0 Native Data-Oblivious API

Status: implemented in the 1.2 release line. The alpha tags were GitHub-only
checkpoints; the stable `v1.2.0` release carried the native `ct` API, memory
helpers, secret-container integrations, verification/evidence work, and
conservative native `ct` derive support.

The `1.2.0` line added a first-class dependency-free data-oblivious
primitive module:

```rust
sanitization::ct
```

The module name should stay short and familiar, but the documented security
claim should be precise: no secret-dependent control flow or secret-dependent
memory access under documented compiler, target, feature, and release-profile
conditions. It should not claim identical wall-clock timing or universal
microarchitectural protection.

This is not intended to replace the optional `subtle-interop` feature. The
native module gives this crate its own no-dependency data-oblivious primitives,
while `subtle-interop` remains the compatibility bridge for RustCrypto and other
ecosystem APIs that already require `subtle` traits.

Historical release checkpoints:

- `v1.2.0-alpha.1`: public API skeleton.
  Exit gate: `ct` module exists with documented `Choice`,
  `ConstantTimeEq`, conditional select/assign traits, `PublicCtOption`, and explicit
  non-guarantees. Existing crate APIs and feature builds still compile.
- `v1.2.0-alpha.2`: primitive implementations.
  Exit gate: unsigned/signed integer, fixed-array, and public-length slice
  equality/select implementations are complete, tested, and routed through one
  documented portable backend.
- `v1.2.0-alpha.3`: oblivious memory operations.
  Exit gate: oblivious lookup, conditional copy, conditional swap, slice select,
  fixed equality, and public-length equality helpers are implemented with tests
  that cover edge cases and length/publicness behavior.
- `v1.2.0-alpha.4`: secret-container integrations.
  Exit gate: `SecretBytes<N>`, `SecretVec`, `SecretString`,
  `LockedSecretBytes<N>`, `LockedSecretVec`, `SecretPoolSlot<N, SLOTS>`, and
  `GuardedSecretVec` use or expose the native `ct` traits where their feature
  gates are enabled. Existing `constant_time_eq` APIs remain source-compatible.
- `v1.2.0-alpha.5`: verification and evidence.
  Exit gate: Kani harnesses, release-codegen checks, Miri coverage, and the
  first `docs/EVIDENCE.md` or `docs/ct-evidence.json` draft describe exactly which
  targets, features, rustc versions, and claims are covered.
- `v1.2.0-rc.1`: documentation-complete release candidate.
  Exit gate: README, SAFETY, THREAT_MODEL, roadmap, examples, rustdoc, target
  tier table, barrier notes, WASM notes, and non-guarantees are complete. Full
  CI is green. This is the tag to hand to external reviewers/pentest.
- `v1.2.0-rc.2`: pentest close-out candidate, only if needed.
  Exit gate: every pentest finding is fixed, explicitly accepted as documented
  residual risk, or moved out of scope with rationale. The temporary pentest
  report file is removed, relevant lessons are reflected in permanent docs, and
  full CI is green again.
- `v1.2.0`: stable crates.io release.
  Exit gate: the latest RC has clean CI, clean docs, clean release checks, no
  open high/medium pentest findings, and no known API changes pending for the
  1.2 line.

The alpha and RC tags are GitHub-only save points unless explicitly published.
Only the stable `v1.2.0` tag is intended for crates.io publication. If a
checkpoint is not actually complete, do not tag it; either continue work or add
the next alpha tag with a clear reason in the release notes.

Initial API shape:

- `ct::Choice`: normalized opaque 0/1 constant-time boolean;
- `ct::Choice::declassify(reason)`: explicit conversion from a secret-derived
  choice into a public boolean, so reviews can search for every branch boundary;
- `ct::ConstantTimeEq`: native equality trait for public-length,
  secret-content comparisons;
- `ct::ConstantTimeOrd`: native ordering trait for primitive integers and
  fixed byte arrays where ordering must not reveal the first differing byte;
- `ct::CtOrdering`: less/equal/greater bits that require explicit
  `declassify(reason)` before normal branching;
- `ct::ConditionallySelectable`: branchless selection between two values;
- `ct::ConditionallyAssignable`: branchless assignment under a `Choice`;
- `ct::PublicCtOption<T>`: optional value controlled by a `Choice` instead of a
  secret-dependent branch, with explicit `declassify(reason)` when converting
  to normal `Option<T>`;
- `ct::PublicCtResult<T, E>`: result-like value where success/failure can remain
  hidden until explicit `declassify(reason)`, plus branchless success-value
  selection through `unwrap_or`;
- `ct::Mask<T>`: all-zero/all-one mask values used by branchless operations;
- `ct::Public<T>` and `ct::Secret<T>` marker wrappers for APIs that need to
  distinguish public parameters from secret-controlled values.

Initial memory-access primitives:

- `ct::oblivious_lookup(table, secret_index)`, implemented as a full-table scan;
- `ct::conditional_copy(dst, src, choice)`;
- `ct::conditional_swap(left, right, choice)`;
- `ct::select_slice(left, right, choice)`;
- `ct::eq_fixed(left, right)` for fixed-size arrays;
- `ct::cmp_fixed(left, right)` for fixed-size byte-array ordering;
- `ct::eq_public_len(left, right)` for slices where length is explicitly public.
- reason-bearing `ct::declassified_*` final-decision helpers corresponding to
  those equality and ordering operations.

Initial implementation targets:

- unsigned integers: `u8`, `u16`, `u32`, `u64`, `u128`, `usize`;
- signed integers through byte-equivalent logic where appropriate;
- fixed byte arrays `[u8; N]`;
- byte slices `[u8]`, with length treated as public;
- existing secret containers: `SecretBytes<N>`, `SecretVec`, `SecretString`,
  `LockedSecretBytes<N>`, `LockedSecretVec`, `SecretPoolSlot<N, SLOTS>`, and
  `GuardedSecretVec` where their feature gates are enabled.
- optional `derive` feature support for conservative field-wise
  `ConstantTimeEq` and `ConditionallySelectable` struct derives.

Design rules:

- keep the portable core `no_std` and dependency-free;
- do not make `black_box` the sole security argument;
- document that `core::hint::black_box` is a best-effort optimization boundary,
  not a formal hardware timing guarantee;
- keep the optional `asm-compare` backend as the stronger x86_64/AArch64
  equal-length byte-comparison path;
- avoid secret-dependent branching and secret-dependent memory access inside
  the native constant-time operations;
- treat slice length, allocation behavior, page faults, panics, scheduling, and
  platform faults as public/non-constant-time effects;
- make declassification explicit and searchable;
- make secret-dependent indexing impossible through the safe `Secret<T>` wrapper
  APIs; callers should use oblivious lookup helpers instead;
- do not derive or implement raw struct-byte comparisons that could read padding
  or representation details;
- document forbidden or target-sensitive operations for secret values:
  branching, indexing, early return, secret-dependent allocation sizes,
  floating point, formatting/logging, panics, and division/modulo unless a
  target-specific review covers them.

Barrier strategy:

- portable branchless arithmetic and bitwise operations are the baseline;
- `core::hint::black_box` may be used as a best-effort optimizer boundary, but
  never as the only proof argument;
- optional inline assembly remains the stronger backend on reviewed targets;
- external-symbol or function-pointer barriers can be considered only if they
  improve release-codegen evidence without adding dependencies;
- each target tier should document which barrier strategy is active.

Target evidence tiers:

- Tier A: checked in CI with release-codegen inspection and available proof or
  leakage-test evidence;
- Tier B: source-level discipline and tests, but no target-specific timing
  evidence;
- Tier C: API available, no strong data-oblivious timing claim;
- Forbidden: known-bad target or feature combinations.

Expected initial target stance:

- x86_64 Linux with release profile and reviewed feature set: target Tier A;
- aarch64 Linux with release profile and reviewed feature set: target Tier A or
  Tier B depending on available assembly/timing evidence;
- embedded ARM/RISC-V without hardware timing tests: Tier B;
- browser/Node WASM JIT targets: Tier C because LLVM output can be optimized
  again by the runtime.

Verification work for `1.2.0`:

- tests for `Choice` normalization and boolean algebra;
- tests for primitive, array, slice, and secret-container equality;
- tests for conditional select, conditional assign, and `PublicCtOption`;
- Kani proofs that selected equality implementations match normal equality;
- Kani proofs that `Choice` remains normalized;
- Kani or code-structure checks that equal-length byte comparisons visit every
  element;
- release-codegen checks updated where the `ct` module reuses or extends the
  existing comparison backends;
- a `docs/EVIDENCE.md` or machine-readable `docs/ct-evidence.json` draft that lists the
  exact targets, rustc versions, features, checks, and claims covered by the
  release;
- documentation pages for guarantees, non-guarantees, barriers, target tiers,
  WASM limits, and leakage-test expectations. Initial guarantee,
  non-guarantee, barrier, target-tier, and leakage-test pages now exist as
  `docs/GUARANTEES.md`, `docs/NON_GUARANTEES.md`, `docs/BARRIERS.md`, `docs/TARGETS.md`, and
  `docs/LEAKAGE_TESTS.md`.

The stable `1.2.0` release should not claim complete hardware-level
constant-time behavior across all targets. The claim should be narrower:
branchless/data-oblivious, dependency-free primitives with documented compiler
and platform limits, stronger optional assembly paths where available, explicit
declassification boundaries, target evidence, and bounded formal verification
for selected invariants.

### Implemented: 1.1.0 High-Assurance Additions

Status: implemented for the 1.1.0 development line.

Implemented in 1.1.0:

- `LockedSecretVec` for native dynamic-length memory-locked byte storage
  without guard-page overhead.
- `register-scrub` best-effort SIMD/vector register clearing on x86_64 and
  AArch64.
- `hardware-secrets` provider traits so SGX, Nitro, HSM, TPM, platform-keystore,
  or enclave integration crates can plug in without adding dependencies to the
  main crate.
- `split-secret` N-of-N XOR split storage through
  `SplitSecretBytes<N, SHARES>`.
- separate `sanitization-arrayvec` and `sanitization-bytes` wrapper crates for
  users that already depend on those ecosystems.

Still intentionally out of scope for the core crate:

- direct vendor SDK integrations;
- threshold secret sharing;
- pretending WASM can provide host memory locking or guard pages;
- broad dependencies in the default crate.

### 1. Make Volatile Wiping the Default Clear Path

Status: implemented in `1.0.0`.

Earlier release candidates had two clearing tiers:

- default safe best-effort clearing;
- opt-in volatile clearing.

That split was honest, but it was easy for users to miss. The crate now uses
optimizer-resistant volatile clearing as the normal clear path for secret-owned
memory and ordinary byte-slice sanitization.

Expected shape:

- The volatile wipe backend lives in one small internal module.
- Unsafe code remains isolated and audited.
- Byte-slice, heap-capacity, and temporary-copy clearing route through that
  backend where applicable.
- Version 2 removes the obsolete `unsafe-wipe` compatibility feature and
  exposes direct wiping through the canonical safe `sanitization::wipe`
  module.

### 2. Simplify `SecretBytes<N>` Storage

Status: implemented in `1.0.0`.

Earlier release candidates used atomic byte storage on targets with 8-bit
atomics and fell back on non-atomic storage elsewhere. That was defensible, but
surprising and target-dependent.

Implemented direction:

- Fixed-size bytes are stored as `[u8; N]`.
- Mutation remains behind `&mut self`.
- Clearing uses the same internal volatile wipe path as other byte buffers.
- `Sync` follows from plain byte storage instead of interior mutability.

This should make behavior easier to audit and more consistent across embedded
and server targets.

### 3. Keep Secret Lifecycle APIs

The crate should keep focusing on lifecycle management rather than becoming a
large blanket trait implementation crate.

Keep and harden:

- `SecretBytes<N>`;
- `SecretVec`;
- `SecretString`;
- `BoundedSecretVec<MAX>`;
- `BoundedSecretString<MAX>`;
- `LockedSecretString`;
- `GuardedSecretString`;
- `Secret<T>` including `Default` when `T: SecureSanitize + Default`;
- closure-based exposure;
- redacted `Debug`;
- dependency-free struct macros.

Implemented dynamic rotation helpers:

- `SecretBytes::try_from_fn`;
- `SecretBytes::replace_from_array`;
- `SecretBytes::replace_from_fn`;
- `SecretBytes::try_replace_from_fn`;
- `SecretBytes::into_cleared`;
- `LockedSecretBytes::try_from_fn`;
- `LockedSecretBytes::from_fill` and `try_from_fill`;
- `LockedSecretBytes::try_init_with` for direct initialization after custom
  protection-policy construction;
- `LockedSecretBytes::try_replace_from_array`;
- `LockedSecretBytes::try_replace_from_slice`;
- `LockedSecretBytes::try_replace_from_fill`;
- `LockedSecretBytes::try_replace_from_fn`;
- `LockedSecretBytes::into_cleared`;
- `SecretVec::default`;
- `SecretVec::from_vec`;
- `SecretVec::from_fn`;
- `SecretVec::try_from_fn`;
- `SecretVec::try_with_capacity`, `try_from_slice_bounded`, and
  `try_from_fn_bounded`;
- `SecretVec::replace_from_vec`;
- `SecretVec::replace_from_slice`;
- `SecretVec::replace_from_fn`;
- `SecretVec::try_replace_from_fn`;
- `ExpiringSecretBytes::try_from_fn`;
- `ExpiringSecretBytes::replace_from_array`;
- `ExpiringSecretBytes::replace_from_fn`;
- `ExpiringSecretBytes::try_replace_from_fn`;
- `ExpiringSecretBytes::into_cleared`;
- `GuardedSecretVec::try_from_fn`;
- `GuardedSecretVec::locked_try_from_fn`;
- `GuardedSecretVec::try_replace_from_fn`;
- `GuardedSecretVec::try_replace_from_fn`;
- `GuardedSecretVec::into_cleared`;
- `SecretString::default`;
- `SecretString::from_string`;
- `SecretString::from_chars`;
- `SecretString::try_from_chars`;
- `SecretString::try_with_capacity`, `try_from_secret_str_bounded`, and
  `try_from_chars_bounded`;
- `SecretString::try_with_secret_mut`;
- `SecretString::replace_from_string`;
- `SecretString::replace_from_secret_str`;
- `SecretString::replace_from_chars`;
- `SecretString::try_replace_from_chars`;
- allocation-preserving `SecretVec`/`SecretString` conversions;
- UTF-8-validating `LockedSecretVec`/`LockedSecretString` conversions;
- UTF-8-validating `GuardedSecretVec`/`GuardedSecretString` conversions.
- explicit `SealedSecretBytes::try_close` cleanup reports and retry semantics;
- downstream high-assurance storage-policy linting with fail-closed fixtures;

Continue avoiding:

- broad blanket impls for every primitive and container;
- proc-macro derives in the core crate;
- compatibility layers that make the security model harder to explain.

### 4. Add Stronger Verification

Status: implemented in `1.0.0`, with external review still recommended for
high-assurance deployments.

Implemented now:

- `scripts/checks.sh` runs the feature matrix, clippy, release codegen
  verification, machine-readable evidence validation, local release-evidence
  smoke reporting, bounded Kani harnesses when available, rustdoc, and package
  listing.
- `scripts/verify-codegen.sh` builds release LLVM IR and checks that the wipe
  backend contains volatile byte-zero stores. It also checks native `ct` helper
  symbols, optimizer-barrier and mask-generation patterns, and absence of
  `memcmp`/`bcmp`; on x86_64 it checks release assembly for optional
  comparison and cache-flush instruction paths.
- `scripts/verify-kani.sh` runs bounded Kani proof harnesses when `cargo-kani`
  is installed, covering selected fixed-size wipe, equality, ordering,
  selection, `PublicCtOption`/`PublicCtResult`, oblivious memory helper, and capacity
  arithmetic properties.
- `scripts/evidence-report.py` captures local commit, dirty-state, rustc,
  target, Kani, and Miri metadata for alpha, RC, and pentest handoffs.
- `scripts/verify-miri.sh` runs default, `alloc`, and all-features tests under
  Miri when a nightly toolchain with Miri is available.
- `.github/workflows/miri.yml` runs the Miri verification script on pull
  requests, `main` pushes, and manual dispatch.
- `.github/workflows/kani.yml` runs bounded Kani harnesses on pull requests,
  `main` pushes, and manual dispatch.

Remaining verification work:

- external review focused on unsafe clearing, drop behavior, and API misuse;
- optional property-based or timing-distribution tests if the project accepts
  dev-only dependencies or keeps them in an unpublished test harness.

Property-based or timing-distribution tests can live outside the published crate
if keeping dev dependencies out of the repository remains preferred.

### 5. Memory Locking as a High-Assurance Feature

Status: implemented for fixed-size secrets and pooled fixed-size slots behind
the `memory-lock` feature on supported Linux, Android, macOS, iOS, Windows, and
BSD targets, and for guarded dynamic secrets when `memory-lock` and
`guard-pages` are both enabled. WASM targets expose `LockedSecretBytes<N>` and
`SecretPool<N, SLOTS>` as volatile-only compatibility containers, not as memory
locked storage.

`mlock`, `VirtualLock`, guard pages, and platform-specific memory policies are
important for high-assurance deployments. Memory locking is the biggest
ecosystem gap because it prevents secret pages from being swapped to disk,
pagefiles, or hibernation images.

Current implementation:

- `LockedSecretBytes<N>` is available on supported Linux, Android, macOS, iOS,
  Windows, and BSD targets when the `memory-lock` feature is enabled.
- `SecretPool<N, SLOTS>` is available on the same memory-lock targets for
  applications that need many same-size fixed secrets under one locked mapping.
- On `wasm32`, `LockedSecretBytes<N>` and `SecretPool<N, SLOTS>` are available
  for API portability with inline WASM-owned storage and volatile clearing, but
  no `mlock`, dump exclusion, fork exclusion, or page-table policy is applied.
- Secret bytes live in a private platform mapping rather than the Rust global
  allocator on native memory-lock backends.
- Linux uses raw `mmap`/`madvise`/`mlock` syscalls on `x86_64` and `aarch64`.
- Android, macOS, iOS, and BSD use system `mmap`/`mlock` ABI calls without
  adding a Rust `libc` crate dependency.
- Windows uses `VirtualAlloc`/`VirtualLock` without adding Windows binding
  dependencies.
- The mapping is volatile-cleared in full on drop, then unlocked and released
  with the platform backend.
- Moving the Rust value copies only pointer metadata, not the secret byte
  allocation.
- `SecretPool<N, SLOTS>` checks `N * SLOTS`, rounds the mapping length to the
  platform page granule, tracks slot ownership with an atomic bitmap, and
  volatile-clears slots before reuse.
- `canary-check` adds opt-in prefix/suffix integrity words for non-empty
  `LockedSecretBytes<N>` mappings, `SecretPool<N, SLOTS>` slots, and
  `GuardedSecretVec` writable mappings, then fails closed before exposing,
  mutating, replacing, or comparing corrupted secrets.
- `random-canary` optionally backs those integrity words with direct OS CSPRNG
  calls without adding external dependencies. WASI preview1 uses `random_get`;
  other currently supported WASM cfgs fail random-canary setup explicitly.
- `GuardedSecretVec` is available on supported Linux, Android, macOS, iOS,
  Windows, and BSD targets with `guard-pages`. It can also lock its writable
  data pages when both `guard-pages` and `memory-lock` are enabled. Growth and
  whole-value replacement preserve the lock state.
- `guard-pages` is intentionally unavailable on WASM because WASM linear memory
  has no module-level page protection API.

Remaining stance:

- Keep memory locking out of the default API.
- Continue target-specific review and CI coverage expansion for non-Linux
  targets.
- Pair every lock operation with automatic unlock on drop.
- Document OS limits clearly: resource limits, privileges, page alignment,
  partial failures, dump policy, hibernation policy, and platform differences.

Implemented API shape:

```rust
let key = LockedSecretBytes::<32>::zeroed()?;
let pool = SecretPool::<32, 64>::new()?;
```

This must continue to be reviewed carefully. Non-Linux backends currently lock
resident memory and provide guard pages, but do not apply Linux-equivalent
crate-level dump or fork exclusion. Exact target CI coverage, richer Android,
BSD, iOS, and macOS core-dump policies, pooled locked-arena runtime behavior,
and any future allocator-sensitive dynamic containers all need
platform-specific tests and review.

Follow-up maintenance target: consolidate the native and WASM memory-lock
compatibility modules so shared error types, size arithmetic, canary handling,
and pool invariants live behind one internal abstraction. The current split is
cfg-exclusive and tested, but reducing duplicated backend scaffolding lowers
the chance that a future low-level fix lands in only one backend.

## Candidate Differentiators

These are not promises for the first stable release. They are candidate
directions that could make the crate meaningfully stronger than a clearing-only
crate once the core architecture is solid.

### 1. Memory Locking

Priority: highest high-assurance feature.

Goal:

- prevent secret allocations from reaching swap or pagefiles where the platform
  supports it;
- keep the implementation dependency-free;
- make failures explicit;
- unlock automatically on drop.

Constraints:

- Linux, Android, macOS, iOS, Windows, BSD, and embedded targets need different
  implementations;
- direct syscalls avoid a `libc` dependency but increase audit burden;
- `mlock` does not protect against hibernation, crash dumps, privileged reads,
  DMA, or firmware compromise by itself.

### 2. Formal Verification

Status: partially implemented with bounded Kani harnesses.

Priority: high trust signal.

Kani is used for bounded model-checking of properties regular tests cannot
prove exhaustively:

- wipe loops visit every byte;
- comparison loops execute the expected number of iterations for equal-length
  inputs;
- length mismatch behavior stays explicit and public;
- capacity-growth arithmetic does not overflow into unsound behavior.

Current implementation:

- proof harnesses live behind `#[cfg(kani)]`, so normal builds and published
  dependency resolution are unaffected;
- `Cargo.toml` explicitly allows `cfg(kani)` for check-cfg hygiene;
- `scripts/verify-kani.sh` verifies no-default, `alloc`, and `std` builds when
  `cargo-kani` is available, and otherwise skips cleanly.
- `.github/workflows/kani.yml` runs the same bounded harnesses with the official
  Kani GitHub Action on pull requests and `main` pushes.

Kani itself does not become a crate dependency. These harnesses are bounded
proofs for selected properties, not a complete formal audit of every feature.

### 3. Architecture-Specific Cache Eviction

Status: checked x86_64 implementation behind the `cache-flush` feature;
unsupported targets retain wipe-first APIs with structured errors.

Priority: optional, target-specific hardening.

After memory is zeroed, old values can still exist transiently in CPU caches.
Some targets provide cache-line flush instructions such as x86/x86_64 `clflush`.

This is available as an explicit feature because:

- instructions and guarantees differ by architecture;
- cache-line size detection matters: x86_64 support validates the CPUID-reported
  `clflush` line size;
- the operation is not universally available: unsupported targets return a
  structured result rather than executing an instruction;
- cache eviction does not solve all side channels: documented;
- it can be expensive and surprising as a default: it remains explicit.

Current implementation:

- `cache-flush` exposes checked helpers on every target.
- Sanitizing helpers clear with the crate's volatile wipe backend before any
  capability or range failure can be returned.
- The x86_64 backend checks CPUID `CLFSH`, validates the reported line size,
  issues `clflush` over an overflow-checked covered range, and completes with
  `mfence`.
- Unsupported CPUs, architectures, and Miri return a structured error without
  skipping the wipe performed by sanitizing helpers.
- `SecretBytes<N>`, `SecretVec`, `SecretString`, and `LockedSecretBytes<N>`
  have explicit clear-and-flush methods when the feature is available.
- `GuardedSecretVec` also has `try_clear_secret_and_flush` when both
  `guard-pages` and `cache-flush` are enabled.

Remaining work:

- evaluate additional non-x86_64/AArch64 support separately;
- review platform-specific cache-maintenance semantics during future target
  expansion;
- keep guard-page allocation as a separate design.

### 4. Assembly-Backed Constant-Time Comparison

Status: implemented for x86_64 and AArch64 behind the `asm-compare` feature.

Priority: optional hardening for major targets.

The current Rust comparison path remains the portable fallback. A target-specific
assembly implementation provides a stronger compiler boundary for equal-length
comparisons on x86_64 and AArch64 when the `asm-compare` feature is enabled.

Design requirements:

- safe public API: implemented with no API change;
- strict fallback to the portable implementation on unsupported targets:
  implemented;
- independent review of inline assembly constraints: still recommended for
  high-assurance deployments;
- tests that prove fallback and target paths agree: implemented for x86_64;
- documentation that length remains public metadata: implemented.

### 5. Secret Lifetime Enforcement

Status: implemented for fixed-size secrets through both a no-`std`
caller-provided monotonic clock wrapper and the `std` convenience wrapper.

Priority: policy feature.

Some systems need secrets to expire after a fixed time or tick count. The
default no-`std` API provides `MonotonicExpiringSecretBytes<N, C>`, which uses
a caller-provided `MonotonicClock`. The `std` feature provides
`ExpiringSecretBytes<N>`, which tracks creation time with `std::time::Instant`
and rejects fallible access after a configured maximum age.

Implemented API shape:

```rust
let key = MonotonicExpiringSecretBytes::<32, _>::from_array([0; 32], clock, max_age_ticks);
let key = ExpiringSecretBytes::<32>::from_array([0; 32], duration);
```

Design constraints:

- keep `no_std` defaults untouched: implemented without requiring `std`;
- avoid hidden background work: expiration is checked only on method calls;
- decide whether expiration clears immediately or only prevents exposure:
  expired access clears before returning `SecretExpiredError`;
- account for clock behavior and testability: no-`std` callers provide a
  monotonic tick source; `std` callers can use `std::time::Instant`; review
  clock assumptions for each deployment.
- fallible generated replacement preserves a still-live old value on generator
  error, but clears an already-expired old value before returning the error.

### 6. Guard-Page Heap Allocations

Status: implemented for dynamic byte secrets behind the `guard-pages` feature
on supported Linux, Android, macOS, iOS, Windows, and BSD targets.

Priority: complex, post-core.

Guard pages around heap secrets can turn some overreads and overwrites into
immediate faults. This is potentially valuable for high-assurance builds but is
platform-specific and allocator-sensitive.

Current implementation:

- `GuardedSecretVec` is available on supported Linux, Android, macOS, iOS,
  Windows, and BSD targets when the `guard-pages` feature is enabled.
- Secret bytes live in a private anonymous mapping rather than the Rust global
  allocator.
- The leading and trailing pages remain inaccessible.
- Guard layout uses a dependency-free Linux page granule: 4 KiB on `x86_64`
  and runtime `AT_PAGESZ` detection from `/proc/self/auxv` on `aarch64`, with
  a conservative 64 KiB fallback. Android, macOS, iOS, BSD, and Windows use
  runtime page-size discovery through their platform ABI.
- When `memory-lock` is also enabled, `locked_with_capacity` and
  `locked_from_slice` lock the writable data pages before secret bytes are
  copied into them. Linux also applies `MADV_DONTDUMP` and `MADV_DONTFORK`.
- `from_fn` and `locked_from_fn` can generate dynamic secret bytes directly
  inside guarded storage, reducing ordinary intermediate copies when callers
  can produce bytes by index.
- `try_from_fn` and `locked_try_from_fn` support fallible direct generation and
  clear partial guarded output on generator errors.
- `replace_from_slice` supports whole-value rotation while preserving lock
  state and avoiding old-byte copying when a larger guarded mapping is needed.
- `replace_from_fn` and `try_replace_from_fn` support generated whole-value
  rotation; the fallible path leaves the old guarded value unchanged on
  generator errors.
- The writable data region is volatile-cleared in full before unmapping.
- Growth moves initialized bytes into a new guarded mapping, then clears and
  unmaps the old one. Locked guarded vectors grow into locked replacement
  mappings.

Limits:

- guard pages catch crossings outside the mapped data pages, not logical
  overreads that stay inside writable capacity;
- locked guarded mappings inherit all memory-lock limits: resource caps, OS
  policy, hibernation, nonstandard dump paths, privileged reads, DMA, and
  external copies remain out of scope;
- Linux aarch64 page-size detection depends on `/proc/self/auxv`; if auxv is
  unavailable or malformed, the implementation falls back to 64 KiB.

## Priority Order

If resources are limited, remaining 1.x hardening work should be ordered as:

1. Get external review of the volatile wipe, platform memory mappings, inline
   assembly, drop behavior, and secret lifecycle APIs.
2. Run downstream integration tests in real consumers before expanding the
   stable API surface.
3. Decide whether optional property-based or timing-distribution tests should
   live in-tree, outside the published crate, or in a separate audit harness.
4. Keep richer non-Linux dump/fork policy hardening, non-x86_64 cache eviction,
   and further Linux aarch64 page-size detection hardening as target-specific
   work unless review finds a release-blocking issue.

## Release Readiness Bar

Do not tag a new `1.x` release until:

- README, SAFETY, SECURITY, and THREAT_MODEL match the final design;
- the local check matrix passes;
- package metadata and publish order are clear for every workspace crate;
- new unsafe boundaries have tests, documentation, and a concise invariant
  description;
- dependency-bearing functionality remains outside the main crate unless there
  is a deliberate security reason to change that boundary;
- external review or downstream testing has not found API friction that would
  require an immediate patch release.
