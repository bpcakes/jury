# Inspect and plan native macOS support

Consumer: implementers of native macOS Jury CLI support. Feature: direct and
witnessed macOS CLI workflows. Observed defects: native compilation failure,
strict allocation failure, Linux-only roots/publication, and unproven native
execution delivery. This planning record closes after the plan and Beads graph
are complete and required harness gates permit closure. The implementation
plan is superseded after supported native artifacts and tests exist.

Baseline: `48946faa10f7c0ae16f00c9a4d654d24a37fdb12`.
The durable implementation specification is
[macos-support-plan.md](../../docs/macos-support-plan.md).

## Progress

- [x] Inspect source, release graph, pinned providers, and platform docs.
- [x] Run native compilation and focused boundary tests.
- [x] Write the implementation plan.
- [x] Complete four planning review rounds and Beads conversion.
- [x] Review final diff and harness gate outcomes.
- [x] Audit the plan and Beads after J25/licensing landed at `c5e40d1`.

## Surprises & Discoveries

Native process and protocol suites pass; strict protected memory and filesystem
tests fail. The CLI has unguarded Linux memfd imports and cannot compile on
macOS. The baseline defects are inputs to the plan, not regressions from it.

## Decision Log

Only planning/tracker files change. Preserve the Linux release scope and J12M
deferral; new macOS tasks are deferred follow-on inventory. Do not change
required gates or source code to make a planning session appear green.

## Outcomes & Retrospective

The first `scripts/jig work check` ran its required verify profile and failed
at native Clippy and workspace tests. Format, contract, and source-size checks
passed in that run. The Rust path-specific gates recorded not-applicable for
the docs-only scope, but the unconditional verify profile still fails on the
existing unsupported macOS baseline. `work evidence` and `work gates` report
blocked. Planning delivery can be complete while this harness closure remains
blocked; no successful full-workspace validation is claimed.

Planning deliverables are complete: `docs/macos-support-plan.md`, deferred
epic `jury-2bg`, nine new implementation tasks, and reused J12M. All 18
prerequisite edges match the plan; Beads reports no cycles, and conversion
reruns reuse the same IDs. J12M history and J25/J26 requirements are preserved.
The four actual planning reviews reached steady state in round 4.
An additional review of 24 concrete native acceptance recipes corrected two
local test oracles. The recipes are included in the plan and in their owning
Beads descriptions; the task graph and implementation scope did not change.

On 2026-09-05, audited the merged source at
`c5e40d166763b74c12d2434948b04e857bed3a21` against the original baseline.
Refreshed the epic and all ten task descriptions; M02/M03 retain landed Git
and output-path behavior, M08/M09 include J25 regression/measurement checks,
and M10 includes distribution license texts/notices. J25 is closed and J26
ready. All macOS statuses remain deferred; prerequisites, J12M history, and
J25/J26 requirements are unchanged. No application source changed.

Fresh native protocol tests pass 35 cases. Filesystem unit tests pass 5/fail 5;
the separately executed hardened-boundary binary passes 20/fails 13, with
strict protection/publication failures. The new Git hardening cases pass.
The repeated Jig check passes format, contract, and source-size checks, but
Clippy and workspace tests still fail on existing Darwin resolver diagnostics
and Linux memfd imports. Harness closure remains blocked by native failures;
the source audit and tracker updates are complete.
Jig also reports unknown contract/source-size gate scope because the merged
index differs from this session's original baseline and the tracker export
has local edits. Git has no staged changes. Command passes are not presented
as successful gate attestation; no index manipulation or baseline rewrite was
used to force closure.
