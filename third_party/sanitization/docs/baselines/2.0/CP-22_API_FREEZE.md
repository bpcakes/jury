# CP-22 API Freeze Review

CP-22 freezes the semantic public API accepted at CP-21 and records the
intentional compatibility boundary from `v1.2.5` to `2.0.0`.

## Reviewed Candidate

- 1.x baseline: `v1.2.5` (`d41204551c840e086b2a7d53c83514633e604e82`)
- 2.0 candidate: CP-21 (`082d1e19fb5473e565b31c24e1c743f4c88d7470`)
- compiler: Rust 1.97.1
- `cargo-semver-checks`: 0.49.0
- `cargo-public-api`: 0.52.0

The original CP-22 checkpoint pinned `syn` 2.0.119 for the derive crate without
changing generated or runtime API behavior. Later finding remediation and
reviewed 2.0 ergonomics work explicitly reopened this freeze. The semantic
snapshots were recaptured through the source inventory recorded in
`public-api/metadata.json`. That metadata references the rolling
`current-source-api.json` inventory. The original `cp21-public-api.json` remains
byte-for-byte historical and is protected by a pinned SHA-256. Subsequent
derive diagnostics and policy-rationale validation do not change the rustdoc
API surface and are covered by dedicated compile-failure gates.

Before the final main-branch review, the derive dependency stack was refreshed
to `syn 3.0.0`, `proc-macro2 1.0.107`, and `quote 1.0.47`. This major proc-macro
parser update requires the complete derive pass/fail matrix and downstream
migration tests to pass; it does not replace the final external review.

## Semver Results

Every normal library target was checked against `v1.2.5` under both an assumed
major release and an assumed minor release.

| Package | Major comparison | Minor comparison |
| --- | --- | --- |
| `sanitization` | Pass | Expected failure: 11 major lint classes |
| `sanitization-arrayvec` | Pass | Expected failure: `inherent_method_const_removed` |
| `sanitization-bytes` | Pass | Pass |
| `sanitization-crypto-interop` | Pass | Pass |
| `sanitization-derive` | Not applicable: proc-macro-only target | Not applicable: proc-macro-only target |

The core break classes are recorded in `cp22-semver-review.json`. Each class
has an explicit destination in `docs/MIGRATION_2.0.md` and a machine-readable
entry in `docs/migration-2.0.json`.

The derive crate is verified by its rustdoc-derived macro snapshot, compile-pass
tests, and compile-fail tests. `cargo-semver-checks` intentionally skips
proc-macro-only targets because they do not expose a normal library API.

## Semantic API Freeze

`scripts/capture-2.0-public-api.py` captures rustdoc-derived API output for all
five publishable packages. The committed files under `public-api/` are the
current reviewed 2.0 candidate. Normal verification compares the current tree
to those files and fails on additions, removals, or signature changes.

The snapshots deliberately include feature-gated APIs by using
`--all-features`. The rolling source-level inventory provides an independent
current declaration and source-hash check; the older CP-21 inventory remains
immutable historical evidence.

## Reproduction

```bash
scripts/verify-2.0-api-freeze.py --run-semver-tools
scripts/capture-2.0-public-api.py
scripts/verify-migration-2.0.py
scripts/verify-derive-failures.sh
```

The standalone freeze verifier resolves supplied artifact paths once and uses
the same import-safe current-source snapshot implementation as the capture CLI.
It compares the already-parsed artifact in-process, including source hashes,
manifests, workspace package metadata, features, and dependency inventories.
The declaration comparison remains an independent additional check.

The exact per-package semver commands and accepted results are stored in
`cp22-semver-review.json`.

## Scope Disposition

`docs/SCOPE_2.0.0.md` identifies the concepts frozen into 2.0 and the additive
ideas deferred beyond 2.0. No deferred item is required to satisfy a 2.0
security guarantee. New major concepts remain prohibited after CP-21; only
finding remediation, documentation corrections, tests, and release metadata
may change before the final release.

The original pre-release review found that `Wipe` was documented as sealed
while its declaration remained downstream-implementable. The release candidate
added the intended private sealed supertrait and refreshed both API snapshots.
Later review findings and approved ergonomics corrections also reopened the
freeze. Each public API change required a matching snapshot refresh; behavioral
derive and macro-policy restrictions required compile-failure regression tests.
The latest finding remediation adds allocation-aware dynamic constructors,
operation-specific mapped-initialization errors, checked-only pool allocation,
production slot quarantine telemetry, shared dynamic allocation/generation
errors, bounded byte/text copy constructors, and observable page-sealed cleanup
with retry after failed mapping release. It also adds downstream
high-assurance storage-policy linting. The reopened candidate now also exposes
checked direct initialization for an already-created locked fixed-size mapping,
with pre/post canary verification and typed callback failure. These are
corrections to unreleased fallibility and integrity guarantees, and both source
and semantic snapshots must be refreshed before the next freeze review.
The latest close-out hardening adds normal-return post-exposure canary checks,
persistent poison state for standalone mapped owners, destructor-bypass and
discarded-result source gates, and a deployment responsibility matrix. These
changes do not replace the required fresh full-range review.
These changes refine unreleased 2.0 contracts rather than silently modifying a
published API.

## Independent Close-Out

This document records the reproducible API and semver portion of the original
CP-22 checkpoint. Its independent review covered the CP-00 through CP-22 range,
but it is not the final 2.0 security report after the freeze was reopened. The
final candidate must receive a fresh full-range close-out review. The permanent
`security/pentest/v2.0.0.md` must be committed alone, name its immediate parent
as `Reviewed-Commit`, and remain unchanged by later source or documentation
commits before tagging.
