# Repair reviewed configuration and distribution boundaries

Consumer: Jury maintainer preparing Linux 0.0.1. This plan gates safe daemon
configuration loading, accurate overwrite help, and container supported-use
documentation. Observed defects: serde Display text reflects rejected values;
one-value parsing omits end-of-document validation; the image omits canonical
warning documents; overwrite help implies content equality. Close/supersede this
plan after the fixes, regressions, native checks, and repository gates pass.

Baseline: a91220ab136461ccdc22d0ea327bf488314bb685, with pre-existing staged work.
Tracker: jury-qv4.6.6. Preserve protocols, persisted formats, the maintainer's
runtime banner removal, and unrelated changes. No commit or publication is part
of this work.

## Progress

- [x] Research metadata consumers and the recorded warning policy.
- [x] Extract config/document.rs without behavior changes; four original tests pass.
- [x] Reproduce both parser defects with failing regression tests.
- [x] Replace text scraping with typed diagnostics and known schema names; require end of input.
- [x] Correct three overwrite help descriptions and package canonical image documents.
- [x] Seven configuration unit tests and two real daemon CLI tests pass.
- [x] Full Linux diagnostics scenario passes against rebuilt native binaries.
- [x] Dockerfile builds successfully; twelve release-helper tests pass, including actual image document reads.
- [x] Full default workspace tests, format, Clippy, contract, and file-budget checks pass.
- [x] Refresh Jig gate records after staging the checked versions; finish with scripts/jig check test.

## Surprises & Discoveries

Jig's target checks passed, but legacy gate records cannot attest partial staging.
The first full workspace run took 1080 seconds. Repeat verification uses
CARGO_PROFILE_TEST_OPT_LEVEL=1 with debug assertions and overflow checks enabled;
test selection and assertions are unchanged. This is additional verification
after the default test build passed, not a substitute for a failing default run.

Serde reports an invalid tagged identity provider at identity.provider; the test
asserts that precise safe path. Duplicate JSON fields must still be rejected,
so parsing into a normalizing map is not used for accepted configurations.

## Decision Log

The leak is a structural trust-boundary error: human-readable dependency errors
are not a safe metadata API. A private JsonDiagnostic retains only a static
category and numeric location. Structured paths are restricted to known schema
names; new or unknown names fall back to a known parent. This deliberately
replaces expected-type text extraction with a stable schema-category diagnostic,
the location, and an examples reference. No raw serde message is retained.

The missing end check is an API-integration omission, now owned by the private
complete-document loader. Help and packaging were contract omissions, requiring
accurate wording and copies of existing canonical documents, not new frameworks.
Scanner suggestions for DTO encapsulation and unrelated server cleanup have no
demonstrated connection to these defects and are not pursued.

GitHub release API returned no releases on 2026-09-08. In-repository references
to the removed JSON metadata are negative assertions; private consumers cannot
be enumerated. Existing release documents explicitly describe an unreleased
cutover. Human configuration diagnostic paths are not a machine-readable API.
The SBOM tool already validates its selected lock against the pinned version;
the hardcoded lock path is not an additional present defect.

## Outcomes & Retrospective

Implementation and validation are complete. All six required Jig gates are
passed and fresh after staging. The final scripts/jig check test run passed
with optimization level 1, debug assertions and overflow checks enabled; the
full default test build also passed before the staging correction. The issue
is closed. Required gate recording did not require any application changes or
weaker checks. No unresolved review finding or input decision remains in scope.
