# Changelog

## 2.0.4

- Pin release development to Rust `1.98.1` while retaining Rust `1.90.0` as
  the minimum supported Rust version and extending the compatibility matrix
  through the new stable release.
- Update `syn` to `3.0.4`, BLAKE3 to `1.8.7`, and refresh all workspace and
  standalone-tool lockfiles to current compatible dependency releases.
- Update the pinned `Swatinem/rust-cache` GitHub Action to `2.9.2`; confirm
  checkout, artifact upload, and Kani actions remain current and SHA-pinned.
- Pin `rust-cache` to the signed commit referenced by the annotated `v2.9.2`
  tag rather than the tag object's SHA.
- Preserve established preferred protection controls across mapped growth and
  staged replacement. A replacement now fails before committing secret bytes
  if a previously accepted control cannot be re-established.
- Retain isolated leakage-test excursions and require two fresh same-seed
  confirmations to pass without increasing the Welch threshold. Any repeated
  excursion remains release-blocking evidence.
- Stop emitting full performance-baseline reports to CI stdout. Structured
  benchmark evidence remains in the requested JSON artifact, while console
  output is restricted to a fixed pass/fail status message.
- Coordinate all five workspace crates and the exact runtime/derive dependency
  at version `2.0.4`.

## 2.0.3

- Add policy-aware, in-place runtime-length constructors for
  `LockedSecretVec` and `GuardedSecretVec`, ensuring every required runtime
  control is established before a decoder, RNG, KDF, or protocol callback can
  materialize secret bytes.
- Add matching protected fill constructors for `LockedSecretString` and
  `GuardedSecretString`, with clear-on-error UTF-8 validation.
- Introduce `ProtectedSecretFillError<E>` and
  `ProtectedSecretTextFillError<E>` so protection, callback, integrity, length,
  and UTF-8 failures remain distinguishable.
- Add bounded policy-aware constructors for locked and guarded byte and UTF-8
  storage. Oversized untrusted capacities are rejected before mapping or fill
  callback execution through a distinct `CapacityLimit` error.
- Add `BoundedLockedSecretVec<MAX>`, `BoundedGuardedSecretVec<MAX>`,
  `BoundedLockedSecretString<MAX>`, and `BoundedGuardedSecretString<MAX>` for a
  permanent lifetime bound rather than constructor-only admission. Their inner
  growable owners cannot be extracted, and every safe append or replacement is
  checked before allocation or generator execution.
- Add `BoundedMappedSecretError<E>` to distinguish permanent-limit rejection,
  length overflow, canary corruption, and backend operation failure.
- Restrict fill callbacks to the requested public capacity even when a guarded
  mapping has a larger page-rounded payload, and clear the complete unreported
  tail before returning success.
- Place and verify the suffix canary at the advertised capacity boundary while
  a callback runs, detecting an unsafe decoder write past that boundary before
  moving the canary to the initialized length.
- Erase the initial length-zero suffix canary and the caller-visible payload
  before relocating the canary and invoking protected dynamic fill callbacks,
  preventing disclosure of canary material to decoder or generator code.
- Clarify that mapped native and `subtle` comparison timing is conditioned on
  intact canaries; corruption is a public operational failure that returns a
  false choice before the payload comparison.
- Exercise temporary capacity-boundary canary verification through
  allocation-provenance-safe fault injection immediately after protected fill
  callbacks return.
- Add native and Miri-model regression coverage for policy ordering, degraded
  setup rejection, typed failures, tail handling, UTF-8 rejection, and canary
  corruption.
- Make canary and tail-erasure regressions deterministic without depending on
  the host's memory-lock quota, and make the high-assurance decoder example
  require dump and fork exclusion before materialization.
- Coordinate all five workspace crates and the exact runtime/derive dependency
  at version `2.0.3`.

## 2.0.2

- Add a `cfg(all(miri, test))` aligned-allocation backend for native
  `LockedSecretBytes`, `LockedSecretVec`, `LockedSecretString`, and
  `SecretPool` lifecycle tests so core Miri coverage can exercise those state
  transitions without executing unsupported inline assembly.
- Model random-canary generation under Miri without making a randomness claim,
  and cover construction, replacement, dynamic growth, pool reuse, canary
  quarantine, rollback, and drop paths.
- Enforce complete mapping clearing immediately before native unlock and unmap;
  the Miri backend asserts clear-before-release for every simulated mapping.
- Preserve a poisoned page-sealed mapping and any established memory lock when
  a page transition fails. Cleanup now erases and reseals each successfully
  transitioned page immediately, continues across the range, and defers unmap
  until a checked cleanup retry confirms every page was erased.
- Add native fault-injection coverage proving cleanup continues after a
  first-page failure and that cleanup reseal failure retains an erased mapping
  for a successful checked retry.
- Make mapped native and `subtle` equality traits return a false choice on
  integrity failure instead of panicking, while checked comparison retains the
  typed corruption error.
- Compile and exercise locked dynamic and UTF-8 zeroize/subtle interop under
  the Miri lifecycle model.
- Clarify throughout the evidence, safety, and threat-model documentation that
  Miri protection-report outcomes are simulated and do not prove `mlock`,
  mapping, dump/fork policy, CSPRNG, page protection, or guard-page behavior.
- Restrict every Miri mapping and canary simulator to the crate's own unit-test
  build. A normal build supplied with `--cfg miri` continues through the real
  native backend instead of silently reporting simulated protections.
- Reject release builds that forge both `cfg(miri)` and `cfg(test)`, reject
  ambient Rust flags in the release helper, and record both Rust flag channels
  in release evidence. Compiler invocation remains a trusted input.
- Select portable comparison code whenever Miri is active, including downstream
  builds, while retaining unit-test-only gates for OS-protection simulators.
- Split Miri verification between the all-feature core unit-test model and
  portable derive/companion integration runs, avoiding unsupported native
  assembly without exposing a production simulator.
- Scope the exact `libfuzzer-sys 0.4.13` NCSA license exception to the fuzz
  dependency graph so other cargo-deny graphs do not carry a stale exception.
- Coordinate all five workspace crates and the exact runtime/derive dependency
  at version `2.0.2`.

## 2.0.1

- Fix every repository-document link in the core crate README to use an
  absolute GitHub URL so crates.io and other package renderers resolve the 2.0
  migration guide, feature documentation, threat model, evidence, and security
  policy correctly.
- Add package-archive validation that rejects relative README links to
  repository-only documentation paths.
- Coordinate all five workspace crates and their internal dependency
  requirements at version `2.0.1`.

## 2.0.0

- Make the standalone 2.0 API-freeze verifier validate the complete supplied
  current-source inventory in-process through a shared snapshot implementation,
  with caller-relative paths resolved once before use.
- Make protection-policy evaluation reject `NotApplicable` for nonempty
  retired or unlocked storage while preserving the empty-storage exception,
  and split immutable CP-21 API evidence from the rolling current inventory.
- Preserve the operating-system memory lock when page-sealed cleanup cannot
  erase or release a mapping, and keep the retained protection report aligned
  with actual lock and mapping state across failure and retry.
- Enabled the dependency-free `asm-compare` backend by default on x86_64 and
  AArch64 after repeated independent AArch64 Linux leakage runs rejected the
  portable fallback for release timing claims. Builds using
  `default-features = false` retain that portable fallback without an AArch64
  timing guarantee. `sanitization-crypto-interop` forwards the same default for
  its fixed-length verification helpers.
- Scoped Linux-only fault-injection helpers to the Linux tests that exercise
  them, keeping supported non-Linux all-target test builds warning-free.
- Made the multi-seed leakage collector tolerate Unicode formatting whitespace
  introduced when documented commands are copied from rendered text.
- Restricted `SecureSanitizeOnDrop` and `secure_drop_struct!` to
  `DropSafeSanitize + Unpin`. Generated destructors invoke the complete
  sanitizer, preserving reviewed aggregate cleanup, while manual sanitizers
  require an explicit non-recursive destructor-path contract.
- Exact-pinned the optional `sanitization-derive` dependency to the matching
  runtime version and enforced that lockstep in repository and release gates,
  preventing proc-macro/runtime version-skew build failures.
- Raised the `sanitization-bytes` dependency floor to patched `bytes 1.11.1`
  and added a release-policy check that prevents broadening the published
  requirement back to advisory-affected versions.
- Added `wipe::maybe_uninit` for canonical volatile clearing of non-live
  `MaybeUninit<T>` storage without constructing references to uninitialized
  byte values.
- Corrected `sanitization-arrayvec` spare-capacity clearing to use the typed
  uninitialized-storage wipe API, closing an invalid-reference boundary.
- Verify pool-slot canaries during `Drop` before clearing can rewrite them, so
  corruption is cleared and quarantined even when no later accessor runs.
- Store random expected canaries in private non-`Copy`, clear-on-drop owners,
  borrow them during verification and writes, and explicitly clear them across
  pool and page-sealed custom teardown.
- Route the native `ct` equality family, secret-container CT traits, and HMAC
  and BLAKE3 verification through the strict assembly comparison backend, with
  path-specific LLVM IR evidence for each representative API.
- Added an enforced `cargo-deny 0.20.2` policy across all independent Cargo
  graphs and replaced the CI `curl | sh` rustup fallback with versioned,
  SHA-256-pinned installer binaries.
- Clear historical spare-capacity bytes when wrapping an existing
  `bytes::BytesMut`, cover every independent Cargo lockfile with Dependabot,
  and align the security and Loom documentation with the actual guarantees.
- Updated the derive stack to `syn 3.0.0`, `proc-macro2 1.0.107`, and
  `quote 1.0.47`; updated serde to `1.0.229` and the evidence workflow to
  `actions/upload-artifact v7.0.1`.
- Reworked the README into progressive essential, protected, and advanced
  levels, with separate feature and advanced-usage references.
- Added reason-bearing `declassified_eq_fixed`, `declassified_cmp_fixed`, and
  `declassified_eq_public_len` final-decision helpers, with fail-closed reason
  lint coverage.
- Added `IntegrityResult<T>` and `MappedResult<T, E>` aliases plus ordinary
  `?` conversions for common mapped operation errors while preserving the
  integrity/operation distinction.
- Added zero-allocation `ProtectionReport` summaries for policy satisfaction,
  degraded state, memory locking, guard pages, and unavailable controls.
- Added type-associated hardened-native, guarded-native, and hardened-Linux
  constructors for locked, guarded, text, and pooled storage while retaining
  explicit `*_with_protection` constructors for custom deployment policy.
- Renamed checked mapped-container operations to a consistent `try_*` surface,
  removed redundant `*_checked` aliases, and reserved `*_or_panic` for explicit
  fail-stop policy.
- Distinguished infallible generation callbacks from fallible callbacks with
  `try_replace_from_*` and `try_replace_from_fallible_*` operation families.
- Renamed public-backing CT state to `PublicCtOption` and `PublicCtResult` so
  copyable/unredacted backing data carries an explicit public classification.
- Rejected all `SecureSanitize` and `SecureSanitizeOnDrop` enum derives;
  inactive variant bytes cannot be reached by generated safe code, and
  final-drop cleanup cannot repair history from earlier transitions.
- Replaced fixed `SecretBytes` byte and temporary-copy helpers with
  reason-bearing `export_*` boundaries covered by the repository reason lint.
- Added `sanitize_then_abort` for deliberate `std` fatal paths while retaining
  the explicit non-guarantee for arbitrary aborts and signals.
- Replaced the generic copyable `ct::Secret<T>` control marker with
  clear-on-drop `SecretIndex` and `SecretScalar<T>` owners.
- Added explicit `PublicValue<T>` and clear-on-drop `SecretValue<T>`
  classification for secret-derived CT state.
- Added redacted, non-copying `SecretCtOption` and `SecretCtResult` containers
  that sanitize dummy and unselected secret values before declassification.
- Added panic-unwind and ownership-transition tests for mapping, selection,
  consuming declassification, zero-sized values, and sanitizer failures.
- Made `SecureSanitize` enum derives fail closed unconditionally.
- Required a non-empty reason for every skipped derive field and rejected
  duplicate, malformed, empty, or misplaced helper options.
- Expanded derive pass/fail coverage for unit and tuple structs, renamed crate
  paths, generics, struct-level drop bounds, enums, unions, and diagnostics.
- Updated `sanitization-arrayvec` to sanitize and drop live elements before
  volatile-clearing the complete inline `MaybeUninit<T>` backing region.
- Added secure `pop` and `truncate` paths that clear stale inline slots and
  preserve valid destructor ordering for removed values.
- Added coverage for historical spare bytes, wrapping, reuse, zero-sized
  drop-bearing values, and complete post-clear backing cleanup.
- Added the canonical safe `sanitization::wipe` module and explicit
  `WipeOnDrop<T>` wrapper for ordinary supported buffers.
- Consolidated all clearing through a private sealed `wipe_backend` and
  retained the reviewed 1.x compiler and hardware fence policy.
- Removed best-effort, volatile-alias, volatile-constructor, and misleading
  `unsafe_wipe` compatibility APIs, including the no-op `unsafe-wipe` feature.
- Rotated deterministic `SecretPool` canaries on every slot allocation by
  mixing a per-slot atomic generation into the address-derived value.
- Replaced infallible, fixed-64-byte cache eviction with checked CPUID `CLFSH`
  capability detection, validated runtime line sizes, overflow-checked ranges,
  structured reports/errors, and wipe-before-error semantics.
- Made register scrubbing report the exact x86_64 or AArch64 architectural
  subset executed, including explicit unsupported and Miri outcomes.
- Extended release codegen checks to cover x86 SSE/AVX and AArch64 vector
  register-zeroing instructions.
- Documented locked-mapping resource exhaustion policy and warned against
  placing secret-bearing values in public-backing `PublicCtOption`/`PublicCtResult`.
- Added `StableSharedSecretStorage` and `StableMutableSecretStorage` contracts,
  and restricted generic `Secret<T>` exposure to storage whose safe shared or
  mutable operations cannot release uncleared secret-bearing storage.
- Changed fixed-size exposure to borrow container-owned storage directly and
  renamed temporary-copy paths so stack copies are explicit at call sites.
- Added fixed-allocation `SecretBoxBytes` for runtime-length secrets that must
  never grow, reallocate, or expose their backing allocation.
- Reworked native data-oblivious declassification around reason-bearing
  boundaries and removed ordinary equality/extraction paths from `Choice`,
  `Mask`, and `CtOrdering`.
- Replaced the generic copyable CT marker with redacted, non-`Copy`,
  clear-on-drop `SecretIndex`, `SecretScalar`, `SecretValue`,
  `SecretCtOption`, and `SecretCtResult` ownership types.
- Renamed `ReadOnceSecret<T>` to `ConsumeOnceSecret<T>` and made its single
  scoped access clear on normal return, application error, and unwind.
- Added `ProtectionRequest`, required/preferred policy, structured
  `ProtectionReport` outcomes, partial setup reports, and explicit integrity
  and fork-inheritance policy for native mapped containers.
- Hardened `SecretPool` with checked fixed-layout accounting, generation-bound
  canaries, failure quarantine, and public efficiency reporting.
- Added the opt-in `SealedSecretBytes<N>` review-candidate mapping with guard
  pages, fallible page-protection transitions, poisoning/retirement, and
  failure-recovery evidence.
- Kept representation erasure private to audited built-in plain-data types and
  deferred public erasure backends and variable-size secure arenas rather than
  weakening their contracts.
- Added named hardened-native, guarded-native, and Linux hardening feature
  profiles while keeping compiled capability separate from achieved runtime
  protection.
- Expanded release verification with path-specific codegen matrices,
  lifecycle allocation probes, Loom models, sanitizer runs, fail-closed
  fixtures, semantic API snapshots, migration consumers, and package checks.
- Added multi-seed dudect-style leakage evidence and relative performance
  baselines on native x86_64 Linux, AArch64 Linux, and Apple Silicon, with
  compile-only evidence for the documented cross targets.
- Added complete 1.2.5-to-2.0 migration, storage-contract, protection-report,
  scope-freeze, target-tier, evidence, and reproducible-build documentation.
- Recorded the intentional 2.0 semver break set and froze all five publishable
  crate APIs against the reviewed CP-21 semantic snapshots.
- Updated all workspace crates, internal dependency requirements, examples,
  package archives, release tooling, and crates.io-facing documentation for
  `2.0.0`.
- Made dependency-audit detection use Cargo's subcommand lookup and audited
  every committed tooling lockfile from one already-fetched advisory database.
- Added a fail-closed CT declassification-reason lint and negative fixtures to
  reject dynamic, short, generic, and placeholder audit labels in CI.
- Sealed `wipe::Wipe` to the audited byte slice, byte array, `Vec<u8>`, and
  `String` implementations so `WipeOnDrop<T>` cannot wrap a downstream no-op.
- Added `MappedResult`, its descriptive `SecretIntegrityResult` alias,
  `SecretIntegrityResultExt`, and classification helpers so fallible mapped
  exposure composes without nested results or loss of the canary/operation
  distinction.
- Added concise protection-report validation and documented library,
  application-error, mapped-text, and fail-stop handling patterns.
- Added `AllowlistedSecret<T, P>`, `SecretStoragePolicy<T>`, and
  `define_secret_storage_policy!` so controlled deployments can enforce one
  centralized exact-type storage allow-list with required review rationales.
- Rejected empty and ASCII-whitespace-only storage-policy rationales at compile
  time so every allow-list entry carries reviewable text.
- Documented why storage stability cannot be safely inferred by a field-only
  derive and added negative tests for unapproved types and empty rationales.

## 1.2.5

- Added `BoundedSecretString<MAX>` with byte-length enforcement for
  construction, mutation, conversion, and serde ingestion.
- Added a 1 MiB default serde ceiling for ordinary `SecretString`.
- Added zero-reallocation conversions between `SecretVec` and `SecretString`
  with clear-on-invalid-UTF-8 failure behavior.
- Added `LockedSecretString` over `LockedSecretVec` and
  `GuardedSecretString` over `GuardedSecretVec`.
- Added checked canary and UTF-8 exposure errors for mapped text containers.
- Extended native constant-time traits and optional `zeroize`/`subtle`
  interoperability to the new text types.
- Documented direct JSON-to-secret ingestion and the remaining parser/input
  copy limitations.
- Clarified serde visitor boundaries, validation timing, and the native syscall
  and concurrency limits of Miri/Kani evidence.

## 1.2.4

- Switched the pinned/default toolchain to Rust `1.97.0` while retaining Rust
  `1.90.0` as the minimum supported version and checking every supported stable
  compiler from `1.90.0` through `1.97.0`.
- Refreshed compatible dependency locks, including `zeroize 1.9.0`,
  `arrayvec 0.7.8`, `bytes 1.12.1`, `quote 1.0.46`, and `syn 2.0.118`.
- Pinned every GitHub Action to the immutable commit for its documented release,
  added Dependabot maintenance, and added a check that rejects mutable action
  references.
- Updated fallible secret constructors for Rust 1.97 Clippy without changing
  their clear-on-error RAII behavior.
- Surfaced guard-page setup cleanup failures consistently with locked mappings
  and documented that unmap errors take precedence when setup and cleanup both
  fail.
- Bounded Linux AArch64 auxiliary-vector read retries before falling back to the
  conservative page granule.
- Added `SecretArrayVec::push_or_sanitize` with a payload-free error for secure
  rejection while preserving conventional `push` behavior and its unchanged
  recoverable `CapacityError<T>` value.
- Added unwind-safe eager clearing guards to `ReadOnceSecret::consume` and
  `consume_mut`, including when another shared owner keeps the wrapper alive.
- Added `BoundedSecretVec<MAX>` for application-defined dynamic secret limits,
  including strict bounded serde handling for borrowed bytes, owned buffers,
  and sequences.
- Added a 1 MiB default ceiling to ordinary `SecretVec` deserialization so
  existing serde call sites are no longer unbounded by default.
- Pinned CI installation of `cargo-audit` to version `0.22.2`.
- Documented locked, frozen, vendored application builds for deployments that
  require a reproducibly constrained complete dependency graph.

## 1.2.3

- Fixed `ct::CtOrdering::new` so hidden `Choice` inputs are normalized without
  secret-dependent branches.
- Added constant-time verification helpers for HMAC-SHA256, HMAC-SHA384,
  HMAC-SHA512, BLAKE3 digest, keyed BLAKE3 digest, and fixed 64-byte BLAKE3
  XOF outputs in `sanitization-crypto-interop`.
- Clamped serde sequence preallocation for `SecretVec` so untrusted
  `size_hint` values cannot trigger attacker-sized initial allocations.
- Hardened native `SecretPool` by storing the construction-validated slot
  stride and removing a destructor-path overflow `expect`.
- Surfaced native mapping unmap failures during setup-error cleanup instead of
  silently discarding them.
- Added dependency-advisory auditing to CI and opportunistic local checks.
- Switched the pinned/default release toolchain to Rust `1.96.1` while keeping
  `rust-version = "1.90"` and adding a compatibility check gate for Rust
  `1.90.0` through `1.96.1`.
- Updated crates.io-facing version references for the 1.2.3 patch release.

## 1.2.2

- Added the optional `sanitization-crypto-interop` sister crate for targeted
  third-party crypto hasher cleanup and HMAC-SHA2 helpers during migrations
  from direct `zeroize` usage.
- Added feature-gated SHA-2 helpers and wrappers that compile `sha2` with its
  upstream `zeroize` support enabled.
- Added feature-gated BLAKE3 helpers and wrappers that explicitly clear
  `blake3::Hasher` and XOF reader state after digest extraction.
- Added feature-gated HMAC-SHA2 helpers implemented over SHA-2 with explicit
  RAII sanitization of key-block, pad, and inner-digest scratch buffers.
- Added RFC 4231 HMAC-SHA384/SHA512 short-key and long-key test-vector
  coverage for the local HMAC-SHA2 helper implementation.
- Clarified that free digest/MAC helpers return ordinary caller-owned arrays
  and that HKDF wrappers are deferred until internal PRK cleanup can be made
  explicit.
- Updated release checks and publishing order to include the new crypto
  interop crate.

## 1.2.1

- Added in-place locked fill constructors and replacement APIs for
  `LockedSecretBytes<N>` and `LockedSecretVec`, allowing decoders, KDFs, RNGs,
  and protocol parsers to write directly into OS-locked memory without staging
  plaintext in an unlocked `Vec`.
- Added capacity-based `LockedSecretVec` fill APIs for decoders that know a
  maximum output size before decoding and return the actual initialized length
  afterwards. Over-reported lengths fail closed and clear the temporary locked
  mapping; spare payload bytes beyond the reported initialized length are
  volatile-cleared before exposure.
- Added `LockedSecretVecFillError<E>` for distinguishing memory-lock setup
  failures, fill closure failures, and invalid reported output lengths.
- Hardened locked fill error paths with explicit pre-return clearing, pre-fill
  compiler fences, canary integrity checks before fixed-size locked
  replacements, and release-build capacity assertions for dynamic locked and
  guarded storage initialization.

## 1.2.0

- Added the initial native `sanitization::ct` data-oblivious API skeleton with
  `Choice`, explicit `Choice::declassify`, native equality/select traits,
  `PublicCtOption`, `PublicCtResult`, public/secret marker wrappers, masks, and fixed or
  public-length byte equality helpers.
- Added `secure_replace` for sanitizing a value before replacement, documented
  enum derive inactive-variant byte limits, and added `strict-enum-derive` for
  opt-in compile-time acknowledgment of enum derive risk.
- Hardened split-secret construction by returning `SplitSecretError::TrivialMask`
  for trivially constant mask shares in all build profiles, added a consuming
  split constructor that clears the source `SecretBytes`, and aligned
  `ExpiringSecretBytes::replace_from_slice` with the build-clear-install
  replacement path.
- Aligned `ExpiringSecretBytes::replace_from_array` and the monotonic expiring
  slice/array replacement methods with the same build-clear-install path.
- Added high-assurance strict profiles: `strict-ct` for fail-closed
  assembly-backed comparisons on supported targets, `strict-canary-check` for
  OS-random canary-only integrity checks, and `require-fork-exclusion` for
  locked constructors that must reject platforms without fork-inheritance
  exclusion. The `asm-compare` backend now supports AArch64 in addition to
  x86_64.
- Added native `ct` memory-access helpers: `oblivious_lookup`,
  `conditional_copy`, `conditional_swap`, and `select_slice`, with public
  length-mismatch errors and full public-length scans where applicable.
- Added native `ct::ConstantTimeEq` integrations for secret containers and
  `ct::ConditionallySelectable` for fixed-size `SecretBytes<N>`, while keeping
  existing `constant_time_eq` methods source-compatible.
- Added `docs/EVIDENCE.md` and expanded bounded Kani harness coverage for native
  `ct` choice normalization, fixed equality, public-length mismatch,
  conditional copy, and slice selection behavior.
- Addressed alpha pentest findings by adding stronger optimizer barriers to
  `ct` memory helpers, hardening split-secret mask misuse checks, caching AVX
  OS-support detection, retrying Linux `getrandom` on `EAGAIN`, and removing
  consumed-state disclosure from `ReadOnceSecret` debug output.
- Clarified the benign AVX feature-detection cache race and made the
  split-secret dual mask-quality check explicitly non-short-circuiting.
- Added explicit `PublicCtOption::declassify` and `PublicCtResult::declassify` public
  branch boundaries, plus `PublicCtResult::unwrap_or` for branchless success-value
  selection.
- Added `ct::CtOrdering`, `ct::ConstantTimeOrd`, and `ct::cmp_fixed` for
  dependency-free data-oblivious ordering of primitive integers and fixed byte
  arrays.
- Added bounded Kani proof coverage for native `ct` ordering primitives,
  including fixed byte arrays plus signed and unsigned integer ordering.
- Expanded `ct::PublicCtOption` and `ct::PublicCtResult` with CT-domain map/select
  combinators so callers can keep hidden presence/success state out of normal
  control flow longer.
- Added bounded Kani proof coverage for the new `PublicCtOption` and `PublicCtResult`
  combinator semantics.
- Added bounded Kani proof coverage for `Choice` boolean algebra,
  `ct::oblivious_lookup`, and `ct::conditional_swap`.
- Expanded release codegen verification to cover native `ct` helper symbols,
  optimizer-barrier/mask patterns, and absence of `memcmp`/`bcmp` calls.
- Updated machine-readable evidence validation so native `ct` codegen coverage
  cannot silently drift out of `docs/ct-evidence.json`.
- Added `scripts/evidence-report.py` to capture local release-evidence metadata
  for alpha, RC, and pentest handoffs.
- Wired the evidence-report script into `scripts/checks.sh` as a smoke check.
- Updated `scripts/release_crates.py` to write
  `target/release-evidence-<version>.json` during preflight before publishing.
- Tightened `scripts/checks.sh` to exercise `strict-enum-derive`, workspace
  all-feature tests/clippy, and package listings for all published crates.
- Added `scripts/verify-derive-failures.sh` so release checks assert the
  security-sensitive derive rejection paths remain compile failures.
- Changed permanent documentation links in the crates.io-facing README to
  GitHub URLs so threat-model, guarantees, safety, and roadmap links resolve
  outside the repository checkout.
- Added the unpublished `tools/ct-leakage` dudect-style Welch t-test harness
  plus `scripts/verify-leakage-smoke.sh` for release-evidence collection on
  x86_64, Apple Silicon, and AArch64 machines.
- Tightened native `ct::cmp_fixed` internals to keep raw normalized masks in
  the lexicographic loop and construct `CtOrdering` only at the output boundary,
  reducing barrier noise in AArch64 leakage evidence runs.
- Addressed final 1.2 pentest feedback by normalizing invalid `CtOrdering`
  construction, restoring accumulator barriers in ordering comparison loops,
  deriving deterministic pool canaries from slot addresses, bounding
  `getrandom` retry loops, making `SecretPool::allocate` fail closed on
  random-canary setup failure, and adding `ct::oblivious_lookup_secret`.
- Added a checked `ct_primitives` example covering native equality, ordering,
  selection, `PublicCtOption`, `PublicCtResult`, oblivious lookup, slice selection, and
  conditional swap.
- Added optional `derive` support for conservative field-wise
  `ConstantTimeEq` and `ConditionallySelectable` struct derives.
- Added a draft machine-readable `docs/ct-evidence.json` describing 1.2 target
  tiers, claims, non-claims, proof harnesses, and release-candidate evidence
  requirements.
- Added `scripts/verify-evidence.py` and wired it into `scripts/checks.sh` so
  the machine-readable evidence draft is schema-checked and kept in sync with
  Kani proof harness names.
- Added explicit 1.2 evidence documentation pages for guarantees,
  non-guarantees, barrier strategy, and target tiers.
- Added `docs/LEAKAGE_TESTS.md` to define the scope, metadata, and release policy
  for future dudect-style timing/leakage evidence.

## 1.1.1

- Updated crate metadata, README links, and package examples after the GitHub
  repository rename to `valkyoth/sanitization`.
- No runtime API or security-behavior changes.

## 1.1.0

- Added `LockedSecretVec` for native dynamic-length memory-locked byte storage
  without guard-page overhead.
- Added `register-scrub` for explicit best-effort SIMD/vector register
  scrubbing on x86_64 and AArch64.
- Added `hardware-secrets` provider traits for external HSM, TEE, enclave,
  platform-keystore, or other backend integration crates without adding vendor
  dependencies to the main crate.
- Added `split-secret` with `SplitSecretBytes<N, SHARES>` for dependency-free
  N-of-N XOR split storage.
- Added separate optional `sanitization-arrayvec` and `sanitization-bytes`
  wrapper crates, keeping the main `sanitization` crate dependency-free by
  default.
- Hardened `register-scrub` after review: x86_64 now uses AVX runtime/OS
  detection, uses `vzeroall` on non-Windows AVX targets, uses ABI-safe
  `vzeroupper` on Windows AVX targets, and documents AVX-512/AArch64 residual
  register gaps.
- Changed `sanitization-bytes::SecretBytesMut::extend_from_slice` to return a
  capacity error instead of reallocating, preventing old secret-bearing
  allocations from being freed before they can be wiped.
- Added split-secret misuse guardrails and documentation for deterministic or
  low-entropy mask generators.
- Documented the cache-timing limits of the optional `cache-flush` feature.
- Updated README, safety notes, threat model, and roadmap for the 1.1.0
  feature set.

## 1.0.1

- Fixed a `SecretPool::try_allocate` error path in both native and WASM
  backends so random-canary initialization failure releases the slot bitmap
  exactly once through `SecretPoolSlot::drop`.
- Fixed random-canary failure handling in native `LockedSecretBytes<N>` and
  `GuardedSecretVec` constructors by generating canaries before creating locked
  or guarded mappings, preventing mapping and lock-quota leaks on CSPRNG
  failure.
- Documented deterministic canary disclosure limits more explicitly and steered
  canary-disclosure threat models toward `random-canary`.
- Added explicit safety comments for canary-failure clear paths that mutate
  owned secret storage through `&self` and rely on the types remaining `!Sync`.

## 1.0.0

- Promoted the crate family from release candidate to stable `1.0.0`.
- Documented the Rust `Drop` limitation for
  `#[derive(SecureSanitizeOnDrop)]` on generic structs: sanitizable generic
  parameters must carry their `T: SecureSanitize` bounds on the struct
  declaration itself.
- Simplified `SecureSanitizeOnDrop` code generation by using Rust's standard
  split generics rather than a custom generic reconstruction helper.
- Added derive regression coverage for tuple structs,
  `#[sanitization(crate = "...")]`, and observable drop-time sanitization.
- Fixed `SecretPoolSlot::secure_clear()` in both native and WASM memory-lock
  backends so canary words are reinitialized after clearing. Live pooled slots
  now remain canary-valid, zeroed, and reusable after explicit clears or failed
  fallible replacement.

## 1.0.0-rc.6

- Added optional `sanitization-derive` proc-macro sister crate.
- Added the `derive` feature to re-export
  `#[derive(SecureSanitize)]` and `#[derive(SecureSanitizeOnDrop)]`.
- Added derive support for structs, tuple structs, enums, skipped fields, and
  explicit custom bounds or crate paths through `#[sanitization(...)]`.
- Added `SecureSanitize` for `core::marker::PhantomData<T>` so generic marker
  fields do not force unnecessary `T: SecureSanitize` bounds.
- Kept default `sanitization` builds dependency-free; proc-macro dependencies
  are pulled in only when `derive` is explicitly enabled.
- Moved the repository to a two-crate workspace layout under
  `crates/sanitization` and `crates/sanitization-derive`.

## 1.0.0-rc.5

- Made volatile clearing the default clear path through one internal audited
  unsafe backend.
- Simplified `SecretBytes<N>` storage from atomic/`Cell` byte storage to plain
  `[u8; N]` with volatile clearing on drop.
- Changed `SecretVec`, `SecretString`, `Secret<T>`, byte slices, and byte arrays
  to use volatile clearing by default.
- Added `SecureSanitize` implementations for scalar primitives, generic arrays
  and slices, `Option<T>`, `Result<T, E>`, and, with `alloc`, `Box<T>`,
  `Vec<T>`, and `String`.
- Added `SecretVec::replace_from_slice` and
  `SecretString::replace_from_secret_str` for whole-value rotation without
  copying previous dynamic secrets during growth.
- Added `SecretVec::from_fn` and `SecretVec::replace_from_fn` for direct
  dynamic byte generation into clear-on-drop storage.
- Added `SecretBytes::try_from_fn`, `SecretVec::try_from_fn`, and
  `SecretVec::try_replace_from_fn` for fallible direct byte generation with
  partial-output clearing on error.
- Added `SecretBytes::transform`, `try_transform`, `derive`, and `try_derive`
  for in-container fixed-size mutation and derivation without an
  `expose_secret` stack copy.
- Added `ReadOnceSecret<T>` for atomic shared-reference one-time access
  followed by immediate clearing.
- Added the optional `multi-pass-clear` feature with explicit three-pass
  volatile overwrite helpers for policy or audit compatibility.
- Added `MonotonicClock` and `MonotonicExpiringSecretBytes<N, C>` for no-`std`
  fixed-size secret lifetime enforcement with caller-defined ticks.
- Added CI and local check coverage for mapped memory backends across Linux,
  Android, macOS, iOS, Windows, BSD, WASM, and embedded no-`std` target builds.
- Added a `memory-lock` WASM compatibility backend for
  `LockedSecretBytes<N>` and `SecretPool<N, SLOTS>` using volatile-only
  WASM-owned storage, with documentation that no actual host memory lock is
  applied.
- Added explicit `guard-pages` compile-time rejection on WASM targets because
  WASM linear memory has no module-level page protection.
- Added WASI preview1 `random_get` support for `random-canary`, while keeping
  unsupported WASM random backends as explicit `Random` operation failures.
- Added a WASM-specific volatile clear call boundary to reduce runtime
  optimizer visibility, documented as best-effort rather than equivalent to
  native volatile semantics.
- Added full raw allocation wiping for generic `Vec<T>: SecureSanitize`,
  dependency-free errno capture for Unix C ABI mapped backends, and FreeBSD
  `MADV_NOCORE` core-dump exclusion.
- Added `LockedSecretBytes::try_from_fn`, `GuardedSecretVec::try_from_fn`, and
  `GuardedSecretVec::locked_try_from_fn` for fallible high-assurance direct
  byte generation.
- Expanded `LockedSecretBytes<N>` and `GuardedSecretVec` platform availability
  beyond Linux to supported Android, macOS, iOS, Windows, FreeBSD, OpenBSD,
  NetBSD, and DragonFly BSD targets.
- Added `SecretPool<N, SLOTS>` for pooled same-size fixed secrets inside one
  locked platform mapping, reducing page-granule memory-lock quota overhead
  when many secrets are live at once.
- Added the optional `canary-check` feature for non-empty
  `LockedSecretBytes<N>` mappings, `SecretPool<N, SLOTS>` slots, and
  `GuardedSecretVec` writable mappings, with prefix/suffix canary verification,
  checked access APIs, and fail-closed clearing on corruption.
- Added the optional `random-canary` feature to generate those canary words
  from OS CSPRNG backends without adding external dependencies.
- Added `GuardedSecretVec::replace_from_fn` and
  `GuardedSecretVec::try_replace_from_fn` for generated guarded whole-value
  rotation while preserving lock state.
- Added `ExpiringSecretBytes::try_from_fn`, `replace_from_fn`, and
  `try_replace_from_fn` for fallible generation and generated rotation with
  lifetime-window restart semantics.
- Added `SecretString::from_chars`, `try_from_chars`, `replace_from_chars`, and
  `try_replace_from_chars` for UTF-8-safe generated secret text.
- Added `LockedSecretBytes::replace_from_slice`, `replace_from_fn`, and
  `try_replace_from_fn` for staged whole-value rotation inside locked storage.
- Added `SecretBytes::replace_from_fn` and `try_replace_from_fn` for staged
  generated fixed-size rotation.
- Added `SecretBytes::replace_from_array`,
  `ExpiringSecretBytes::replace_from_array`, and
  `LockedSecretBytes::replace_from_array` for owned-array rotation with input
  clearing.
- Added `SecretVec::replace_from_vec` and
  `SecretString::replace_from_string` for owned heap-allocation rotation without
  copying the new value.
- Added `SecretVec::from_vec` and `SecretString::from_string` as explicit
  ownership-taking constructors for existing heap allocations.
- Added a dedicated GitHub Actions Miri workflow for nightly interpreter
  verification of default, `alloc`, and all-features builds.
- Added `ExpiringSecretBytes::try_expose_secret_volatile` for fallible
  volatile-named temporary exposure with lifetime enforcement.
- Added `SecretString::try_with_secret_mut` for closure-scoped mutable `&mut str`
  access without exposing mutable raw bytes.
- Added `Default` for `SecretVec` and `SecretString`, producing empty
  clear-on-drop heap secret containers.
- Added `Default` for `Secret<T>` when `T: SecureSanitize + Default`.
- Added `SecretVec::capacity` and `SecretString::capacity` for heap allocation
  metadata.
- Added `SecretBytes::into_cleared` for consuming fixed-size secrets after an
  explicit clear.
- Added `ExpiringSecretBytes::into_cleared` for consuming lifetime-enforced
  fixed-size secrets after an explicit clear.
- Added `into_cleared` consume helpers for `LockedSecretBytes<N>` and
  `GuardedSecretVec`.
- Added `Display` for `LengthError` and `std::error::Error::source` chaining
  for wrapper errors when `std` is enabled.
- Configured docs.rs to build documentation with all crate features enabled.
- Documented the current `secure_sanitize_struct!` and `secure_drop_struct!`
  macro syntax limits.
- Clarified README unsafe-policy wording for optional feature-gated hardening
  modules.
- Documented portable comparison timing limits and fixed-size exposure stack
  usage.
- Fixed a guarded mapping cleanup path so theoretical address-computation
  errors unmap before returning.
- Added explicit `Send` implementations for Linux mapped secret containers while
  keeping them intentionally non-`Sync`.
- Kept the `unsafe-wipe` feature as a no-op compatibility flag for older
  release-candidate dependency declarations.
- Kept `unsafe_wipe` public helper APIs available for explicit ordinary-buffer
  wiping.
- Added a release LLVM IR codegen check for volatile byte-zero stores.
- Expanded release codegen checks to verify x86_64 assembly comparison and
  cache-flush instruction paths.
- Added optional bounded Kani proof harnesses for selected fixed-size clearing,
  equality, and capacity properties.
- Added a dedicated GitHub workflow for the bounded Kani harness matrix.
- Added an optional Miri verification script for the wipe boundary and feature
  matrix.
- Added the optional Linux `memory-lock` feature with `LockedSecretBytes<N>` for
  fixed-size secrets backed by private `mmap` storage and `mlock`.
- Added `MADV_DONTDUMP` setup for Linux memory-locked secret mappings.
- Added `MADV_DONTFORK` setup for Linux memory-locked secret mappings.
- Added `LockedSecretBytes::from_slice` for direct runtime-buffer loading.
- Added `LockedSecretBytes::from_fn` for direct byte generation inside locked
  storage.
- Added the optional x86_64 `asm-compare` feature for assembly-backed
  equal-length byte comparison with portable fallback elsewhere.
- Added the optional x86_64 `cache-flush` feature for explicit volatile-clear
  plus `clflush`/`mfence` cache-line eviction helpers.
- Added `std`-only `ExpiringSecretBytes<N>` for fixed-size secret lifetime
  enforcement.
- Added the optional Linux `guard-pages` feature with `GuardedSecretVec` for
  dynamic byte secrets stored between inaccessible pages.
- Added `GuardedSecretVec` locked constructors when both `guard-pages` and
  `memory-lock` are enabled.
- Added `GuardedSecretVec::from_fn` and `GuardedSecretVec::locked_from_fn` for
  direct byte generation inside guarded mappings.
- Added `GuardedSecretVec::replace_from_slice` for whole-value rotation without
  copying the previous guarded bytes during growth.
- Added `GuardedSecretVec::clear_secret_and_flush` and `CacheFlushSanitize`
  support when both `guard-pages` and x86_64 `cache-flush` are enabled.
- Changed Linux `aarch64` mapping length rounding to detect `AT_PAGESZ` from
  `/proc/self/auxv` with raw syscalls, falling back to 64 KiB when detection is
  unavailable.
- Expanded the local check matrix and examples for optional high-assurance
  features.
- Updated README, safety notes, and threat model for the new clearing model.

## 1.0.0-rc.4

- Hardened equal-length comparison accumulators against optimizer-introduced
  short-circuiting.
- Added `SecretBytes::expose_secret_volatile` behind `unsafe-wipe` for volatile
  clearing of temporary stack copies on normal and unwind paths.
- Switched `SecretVec` and `SecretString` growth to exponential capacity
  growth to avoid repeated exact reallocations.
- Updated safety, threat model, and README documentation for volatile string
  wiping, best-effort clearing limits, and abort behavior.

## 1.0.0-rc.3

- Added crates.io homepage and repository metadata for the GitHub project.
- Updated README installation examples to `1.0.0-rc.3`.

## 1.0.0-rc.2

- Updated crates.io-facing README installation examples and release status.

## 1.0.0-rc.1

- Release candidate for downstream integration testing.
- Added dependency-free `secure_sanitize_struct!` and `secure_drop_struct!`
  macros.
- Hardened equal-length constant-time comparisons by removing short-input
  per-index branches.
- Aligned best-effort and volatile heap clearing to wipe allocation capacity
  where available.
- Expanded README examples, Rust version support notes, GitHub CI defaults, and
  crate packaging metadata.

## 0.1.0

- Initial unpublished crate layout.
- Added safe `no_std` fixed-size `SecretBytes<N>`.
- Added `alloc` heap containers `SecretVec` and `SecretString`.
- Added explicit `unsafe-wipe` volatile backend and `VolatileOnDrop<T>`.
- Added threat model, unsafe audit notes, CI, and local check script.
