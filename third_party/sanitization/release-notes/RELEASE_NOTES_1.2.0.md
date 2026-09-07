# Release 1.2.0

- Added the initial native `sanitization::ct` data-oblivious API skeleton with
  `Choice`, explicit `Choice::declassify`, native equality/select traits,
  `CtOption`, `CtResult`, public/secret marker wrappers, masks, and fixed or
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
- Added explicit `CtOption::declassify` and `CtResult::declassify` public
  branch boundaries, plus `CtResult::unwrap_or` for branchless success-value
  selection.
- Added `ct::CtOrdering`, `ct::ConstantTimeOrd`, and `ct::cmp_fixed` for
  dependency-free data-oblivious ordering of primitive integers and fixed byte
  arrays.
- Added bounded Kani proof coverage for native `ct` ordering primitives,
  including fixed byte arrays plus signed and unsigned integer ordering.
- Expanded `ct::CtOption` and `ct::CtResult` with CT-domain map/select
  combinators so callers can keep hidden presence/success state out of normal
  control flow longer.
- Added bounded Kani proof coverage for the new `CtOption` and `CtResult`
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
  selection, `CtOption`, `CtResult`, oblivious lookup, slice selection, and
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
