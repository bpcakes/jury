# M03 native non-child CLI

Consumer: M03 implementer and reviewer. Feature: native strict non-child CLI.
Observed defects: Linux-only imports, dispatcher and roots. Supersede this
active plan when M03 acceptance is complete; retain minimal baseline and test
provenance for recovery. Baseline: 9c48e9610a1584696196afe76da1f15050baacd1.
The full task contract is docs/macos-support-plan.md M03, A09, and A10.

## Progress

- [x] Activate jury-2bg.3 after verifying M01/M02 closure.
- [x] Separate Linux execution and route all CLI state-root callers through native selection.
- [x] Add pure path tests and strict native CLI lifecycle/preflight tests.
- [x] Complete native and Linux tests, required Jig gates, and diff review.
- [x] M03 acceptance is established; close task and finish work record.

## Surprises & Discoveries

The native workspace compile passes after excluding Linux execution internals.
Existing backup fault tests were Linux-gated while their helpers compiled on
macOS; enable the owning tests on Darwin rather than suppressing warnings.
The first full native run passed CLI/core/filesystem/process/protected/protocol
tests but failed ten witness SQLite fixtures because their temporary roots
used Darwin system aliases. The same 28 witness tests passed with a physical
TMPDIR, establishing the fixture defect. Canonicalize only owned fixture
roots; keep production SQLite NOFOLLOW and every test assertion unchanged.
All 28 now pass under the ordinary native environment.

## Decision Log

The operator activated only M03 on 2026-09-08. No changes to cryptography,
wire artifacts, Linux release scope, or M04-M10. The explicit Linux state
resolver preserves its old behavior; the new native wrapper selects Darwin.
macOS rejects empty identity/state overrides and ignores XDG. Empty JURY_HOME
retains the specified fallback. No migration is attempted. Linux execution
remains in its existing owner; unsupported macOS child preflight runs before
environment capture. This is unfinished M07, not full platform support.

## Outcomes & Retrospective

Strict M03 lifecycle passes on native macOS 26.6.2 arm64 (Rust 1.98.1) and
Linux arm64 (Rust 1.97.0, init-equipped Debian container, 64 MiB MEMLOCK).
Native CLI unit tests pass 68 cases and witness tests pass 28 cases. Final
stable workspace gates passed after fixture fixes (receipt below).

## Implementation and acceptance

Owners: crates/jury/src/home.rs and home_tests.rs; CLI dispatch and all state
callers; crates/jury-filesystem/src/native_paths.rs and its tests. Existing
witnessed output naming stays in cli/output_path.rs unchanged.

Run cargo test --workspace --locked --no-run natively; the native_basic_cli
integration target must prove strict default identity/vault, read/inject,
transfer/import and absent-target backup restore. Preflight holds stdin open,
observes a real loopback listener, and compares created artifacts and child
markers. Run owning resolver/output/backup tests, native fmt/Clippy/contract,
and scripts/jig check test; run Linux regression with the same source using
an owned init-equipped container and 64 MiB MEMLOCK. No real secrets.
Use scripts/jig work check/evidence/gates/finish for this plan. Run configured
changed-input checks without changing their assertions or applicability.
On failure fix the owning implementation/test fixture and rerun affected
checks; never close the task with required behavior unverified. CLI tests own
and delete only synthetic temporary roots. No commit or push is requested.

Final native gate repeat uses CARGO_PROFILE_TEST_OPT_LEVEL=1 to reduce crypto
fixture runtime. Test selection, assertions and debug assertions remain enabled;
the strict lifecycle and owning native tests also passed at the default profile.

Completion evidence: final native work check returned ok=true and all six
required gates report passed/fresh. Full Linux workspace Clippy and tests
returned exit 0; final changed home/state/witness owners passed separately.
Direct and witness gate verifiers passed; the witness verifier also ran its
isolated conformance corpus. No accepted cryptographic inputs were changed.
Native workspace --no-run passed. Existing Linux-only lifecycle targets remain
M08; the new M03 strict lifecycle runs on both operating systems. Default
native witness tests pass all 28 cases. No independent review is claimed.

Stable native gate receipt: receipt_01M20HTC8ZKAFRXWCK6VBCYPMV. Final
standalone CARGO_PROFILE_TEST_OPT_LEVEL=1 scripts/jig check test passed in
22.8 seconds after the final workspace --no-run command.
