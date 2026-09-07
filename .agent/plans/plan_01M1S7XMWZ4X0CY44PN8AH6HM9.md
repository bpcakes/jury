# M01 — strict Darwin protected memory

Consumer: M01 implementer and downstream memory users. Gated feature: strict
Darwin allocation. Observed defects: provider reports fork unsupported; Jury
lacks verified pre-allocation core suppression. Supersede this plan when M01's
implementation and native/regression acceptance are complete. Full requirements
remain docs/macos-support-plan.md, M01; no scope reduction is authorized.

## Progress

- [x] Audit all constructor/random call sites and status consumers. Public
  compact/large/supported/random paths still converge on initialize_bounded.
- [x] Fork authorized; M01 activated ahead of J26 with operator approval.
- [x] Provider implementation, private fault injection, child mapping oracle,
  cleanup observations, and boundary measurements; local macOS suite passes.
- [x] Jury strict pre-provider core set/read verification, truthful platform
  predicate, shared CLI check, subprocess tests, immutable pin, and docs.
- [x] Complete exact native minimum/current and Linux lanes at final inputs.
- [x] Review final diff, record evidence and remove temporary workflow.
- [x] Finish the passing gates and close M01.

## Surprises & Discoveries

Upstream v2.0.4 still lacked Darwin exclusion. Its changes since the audited
v2.0.3 revision prevent established preferred controls from degrading during
replacement; mapping setup and cleanup were otherwise unchanged. New tests
found guarded Drop clears bytes then rewrites live canaries. A final volatile
wipe now clears those bytes too. Darwin mincore returns residency for holes;
Mach VM-region queries supply the absence oracle, with a present zero-mapping
negative control. Linux retains its per-page mincore ENOMEM oracle.

## Decision Log

- Jury baseline: c5e40d166763b74c12d2434948b04e857bed3a21. Preserve unrelated
  existing planning/tracker edits in the primary worktree.
- Provider base before edits: 0f95eec55aa16562be9dc3a08ee60a043d7a0da8,
  upstream v2.0.4, compared to ffcb211cd931c6966b2e767ce5edffa4b47c4f07.
- Provider pin: 3f0a72c5640b4919dec93799725c7573b2878a8c in the authorized
  featherenvy/sanitization fork. MIT OR Apache-2.0 notices retained.
- macOS SDK declares minherit(void *, size_t, int); VM_INHERIT_NONE is 2.
  Apply to complete writable data region before lock and caller fill.
- Dump Unsupported plus verified process core suppression is the Darwin
  contract. Linux still requires established per-mapping dump exclusion.
- Isolated CI worktree /tmp/jury-m01-ci, branch m01-darwin-validation, owns
  a temporary workflow. Delete that workflow after bounded results are retained.
  Provider checkout: /tmp/jury-m01-sanitization. No Jury unsafe code added.

## Outcomes & Retrospective

Implemented at provider 3f0a72c5640b4919dec93799725c7573b2878a8c.
Required native suites pass: provider/Jury 112/36 on macOS 15.7.9 build
24G830 arm64 and x86_64 with Rust 1.90; 112/36 on current macOS 26.6.2
build 25G83 arm64 with Rust 1.98.1. All have zero failed/ignored tests.
Linux Ubuntu 24.04.4 x86_64 Rust 1.90 passes provider 164, Jury 35, and
secret_input 3 tests, with zero failed/ignored. Exact versions, revisions,
boundary requested/mapped/locked accounting and cleanup outcomes are retained
in jury-2bg.1 notes, with native CI job links from run 33982020261.

Full Linux workspace fmt/Clippy/contract/LOC/tests pass in the Debian 12
arm64 container on Rust 1.97. Stable configured-gate batch receipt:
receipt_01M1SBYTXXE4KZT4B7H7WDR9QT. This passing batch preceded the final native test-harness repair; closure
requires refreshed final evidence after that repair. Final Linux verification
uses CARGO_PROFILE_TEST_OPT_LEVEL=1 to shorten cryptographic fixtures; test
selection, assertions and debug assertions remain enabled.
The two existing special-run workspace fixtures remain ignored; none of the
M01 tests are ignored. Hosted full-workspace CI still fails the unchanged
transfer.rs:515 write-free snapshot assertion; that same test passes locally.
Its cause remains unresolved and the hosted full-workspace step is not claimed
green. Provider supplemental checks.sh also remains incomplete because of
cargo-audit index/tool-version availability, as recorded in task notes.

A verification repeat exposed BrokenPipe in the native test writer after
correct early CLI rejection. The helper now reaps the child before checking
write errors, accepts only BrokenPipe with a failed child, and preserves
response assertions. The rejection fixture exceeds pipe capacity to force
that path; its focused native test passes. Validation branch 351e1a6 contains
this test-only repair, leaving all protected-memory inputs unchanged.

The temporary native workflow was removed after retaining bounded evidence,
in validation branch commit f2837d7. The primary implementation remains
uncommitted; unrelated planning edits were preserved. J26 remains open, full
macOS CLI work remains separate, and no independent review is claimed.

## Validation and recovery

Run exact provider selected-feature suite and locked jury-protected all-targets
suite on macOS 15 arm64, macOS 15 Intel (Rust 1.90), current macOS arm64, and
Linux. Linux additionally runs jury --lib secret_input and required Jig
fmt/clippy/contract/test checks. Record exact OS, architecture, Rust, source
revisions, pass/fail/ignored counts, and boundary accounting in task notes.
Private provider failures must prevent fill and observe actual cleanup;
Jury set/readback failures must prevent provider entry. Fork oracle must prove
absent mapping, not copied/cleared bytes. Keep 1 MiB and 16 MiB public limits.

Use scripts/jig work check/evidence/gates/finish with plan id
plan_01M1S7XMWZ4X0CY44PN8AH6HM9. No historical cryptographic or release-gate
hashes are changed. Revert a failed provider pin and Jury integration together.
Irreversibly reduced core/lock limits stay confined to reaped subprocesses.

Final closure: all required gates fresh and passing after the test-harness
repair, batch receipt_01M1SCSTZP2ZEX49Y6MC4ZF6HW. Work finish succeeded
with receipt_01M1SCX99A77QRVJV5HYCD0SCZ. M01 closed Completed under the
operator-authorized early activation; J26 remains open.
