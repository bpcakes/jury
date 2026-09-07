# Maintain sanitization inside Jury

Consumer: provider maintainers and the Linux release builder. Feature: local
provider development and reproducible source packaging. Observed defect class:
path dependencies are omitted by cargo vendor and its notice collector. This
minimal migration record may be deleted after acceptance if recovery is no
longer needed. HEAD baseline: 9323a5562e11be5e7af86ea202d2fc038561e516;
pre-existing staged M01 changes are preserved. Tracker: jury-ij3.

## Progress

- [x] Import exact owned fork 3f0a72c5640b4919dec93799725c7573b2878a8c.
- [x] Switch production and fuzz graphs to the local provider workspace.
- [x] Preserve licenses and add local-provider notice packaging and regression test.
- [x] Establish local ownership and explicit Linux/macOS provider CI.
- [x] Finish native macOS, offline, release input, and repository checks.
- [x] Full Linux ARM64 Jury workspace: 446 passed, 0 failed, 2 existing ignored.
- [x] Complete separate Linux provider selected-profile and default-workspace suites.
- [x] Operator authorized excluding the provider tree from file-size checks; wrapper implemented and boundary-checked.

## Surprises & Discoveries

An isolated staged import check found 12 unchanged provider files above Jig's
800/1000-line limits. The operator explicitly chose to exclude this tree from file-size checks.
The repo wrapper now applies that exclusion while preserving other violations
and checker errors. Provider format, Clippy, compilation, and tests remain active.
Existing full macOS CLI checks fail on Linux-only memfd imports. Jig evidence
also refuses the pre-existing mixed index/worktree state.

The original provider is a multi-crate workspace with standalone tooling and
fuzz targets. Preserve it whole. Root workspace tests do not run its tests.
The release-input test's temporary root used macOS's /var alias; canonicalize
that fixture root so its existing containment assertion remains meaningful.

## Decision Log

The operator authorized local maintenance on 2026-09-07. Keep the provider a
separate workspace under third_party/sanitization so Jury's license and unsafe
policy do not replace the provider's. Preserve runtime Rust bytes exactly;
change only dependency wiring, package publication/ancestry metadata, guides,
CI, and release integration. Advisory checking remains an explicitly documented
provider-maintenance requirement; migration does not establish registry coverage.

## Outcomes & Retrospective

Native macOS selected-provider suite: 112 unit tests and 16 doctests passed.
Default provider workspace: 112 tests/doctests passed, 2 existing ignored.
Jury protected-memory integration: 42 passed. Release input tests: 10 passed.
Provider formatting/Clippy passed. Production and fuzz metadata resolve exactly
one local provider. All 42 imported Rust files match the fork byte-for-byte.
The selected provider suite also passed without any Git cache. Linux ARM64 Jury workspace passed 446 tests/doctests with 2 existing ignored.
The separate Linux provider selected-profile and default-workspace suites passed. Actual release notice collection
covered 340 external packages plus the local provider. An empty Cargo cache
and vendored dependencies also built and passed all 42 native integration tests. No commits or pushes are authorized.

## Execution and recovery

Use the imported workspace's AGENTS.md commands for its default workspace and
Jury-selected native profile. Run cargo test -p jury-protected --locked,
python3 scripts/test-linux-release.py, and scripts/jig check test. Verify root
and fuzz lockfiles contain a source-less sanitization path package and that the
root member list excludes provider packages. Verify source archive inclusion
and native builds without a provider Git cache. Existing full macOS CLI support
is separate work; report any resulting unrelated compilation failures.
Provider source bytes must match the import revision. On interruption retain
this checkout and resume checks; do not reset the user's pre-existing index.


## File-size policy acceptance (2026-09-07)

The operator explicitly authorized excluding `third_party/sanitization/` from
file-size checks. `scripts/check-rust-file-loc.py` applies that scope to the
pinned Jig report and fails closed on malformed or unsuccessful checker output.
The `.sh` entrypoint, CI, and configured Jig command share it. Real isolated Git
checks cover provider-only success, oversized application and similarly named
sibling failures, and invalid-baseline failure. Existing staged Jury files still
fail their size checks. Contract validation passes. The migration task is
complete; harness closure still cannot claim all pre-existing repository gates
pass. The earlier recorded native and offline tests remain applicable because
this policy change does not change Rust code or Cargo configuration.
