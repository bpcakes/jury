# Automate the next Linux release

This plan follows .agent/PLANS.md. Consumer: the maintainer preparing 0.0.2. Feature: repeatable source-bound release preparation and publication. Observed defects: transient test fixtures discovered late, repeated full verification caused by bookkeeping and duplicate gate paths, rejected targeted retry receipts, a slow CI test job, and manual reconstruction of signing/upload/download steps. Retire this recovery record when a successor replaces this release procedure.

## Progress

- [x] Inspect release scripts, actual 0.0.1 failures, repository gates and available upstream Jig worktrees.
- [x] Claim jury-24w and isolate upstream investigation without changing existing work.
- [x] Run a complete-suite baseline/optimized benchmark on one GitHub runner and compare identical test inventories and outcomes.
- [x] Implement a resumable release CLI around the existing reproducible builder and packaged QA scripts.
- [x] Fix or integrate verified Jig plan/receipt/input behavior, remove overlapping Jury gates without dropping unique checks, and retain source/document invalidation.
- [x] Isolate release CI from ordinary pushes and exercise the workflow on an exact candidate commit.
- [x] Validate real local preparation, safe retries and artifact tampering, documentation, required gates and final workspace tests; commit and close only completed work.

## Surprises & Discoveries

The current Jig action digest includes the whole worktree even where inputs are declared; bookkeeping therefore invalidates unrelated commands. Jury config also runs the same commands through both legacy check gates and the verify profile. Upstream has unfinished work for targeted retry selection and an in-progress design for canonical input authority; inspect and integrate verified behavior in isolation rather than overwrite those checkouts.

## Decision Log

Preserve the existing pinned two-build recipe, synthetic fixtures, exact public signer identity and OIDC issuer, and explicit publication approval. Implement a local runner with minimal on-disk recovery state read by the runner, rather than another human-only certificate. A checkpoint records source commit, input identity, stage outcomes, checksums and remote identifiers; changed inputs invalidate reuse. Failed or interrupted steps remain incomplete. Publishing requires an explicit command naming the authenticated manifest digest and rechecks current CI, signature, draft body/assets and exact tag target.

Keep source immutable by preparing in a detached worktree at an explicit committed revision. Run fixture/preflight checks before expensive packaging. Release validation runs on a candidate ref in a separate concurrency group; ordinary pushes retain normal cancellation behavior. Do not publish a new release or alter v0.0.1 when testing the automation.

## Context and Orientation

scripts/build-linux-release builds two native binaries in pinned offline containers, packages source/vendor archives and dependency reports, and checks source/artifact hashes. Existing scripts/check-linux-* cover ten user journeys plus TLS. Current docs/linux-release.md describes manual signing and verification. .github/workflows/rust-tests.yml owns complete Rust coverage; .jig.toml and .agent/jig-contract.json declare harness gates. Upstream Jig is in sibling checkouts; use /home/aa/Documents/jig-release-verification for isolated work and obey its guides, including generic fixtures and a rebuilt development binary.

## Implementation and validation

First add a workflow and driver that run the identical locked CLI test selection at opt-level 0 and 1 on the same runner. Explicitly enable debug assertions and overflow checks in both. Record compile and execution time separately, test inventory and all failures; adopt optimization only after comparable complete passes. The denominator is all tests selected by cargo test --locked -p jury; countermetrics are omitted/failed tests, assertion/overflow settings, and compile time. No cross-machine speedup claim is allowed.

Add checked-in release commands for preparation, status, CI dispatch/wait, signing, draft upload, publication and public-download verification. Reuse existing scripts, never interpret a stage flag alone as proof: verify source identity and artifacts before reuse. Unit/integration fixtures must cover fresh preparation, unchanged resume, latest failure, source/artifact drift, partial uploads, signature identity mismatch, non-success CI, immutable tag conflicts and post-publication verification. Local API doubles prove orchestration behavior only; distinguish them from live GitHub and packaged-binary checks.

Expose existing workflows as reusable validation and call them from a release workflow whose concurrency is tied to source revision, isolated from push/PR groups. Keep all currently required jobs and test cases. Validate workflow syntax and action pins, then dispatch an actual candidate run. The release runner must require that exact source and release workflow before publication.

For Jig, reproduce plan attachment and input invalidation in generic temporary repositories, compare behavior before/after, and retain negative tests for relevant source, config, runner and document changes. Do not erase historical receipts, accept stale evidence, or bypass plan identity. Run upstream required checks with a rebuilt JIG_DEV_BIN. Pin the verified upstream revision used by Jury rather than silently depend on an uncommitted runtime.

Finish Jury with its required work gates and scripts/jig check test. For executable release helpers run filesystem/CLI integration tests; use a real unsigned candidate to demonstrate the positive prepare/QA path and existing public v0.0.1 assets for download/signature verification. Do not claim mocked publication as live release proof.

## Idempotence and recovery

Use a private recovery directory outside the committed source and lock it against concurrent invocations. Atomic checkpoint replacement preserves the previous valid state on failure. Resume from the first incomplete step only when its inputs still match; query GitHub after uncertain upload/publication outcomes. Existing matching remote objects can be reused; mismatching ones stop with a concrete diagnostic. No implicit tag replacement or asset clobbering is allowed. The v0.0.1 release remains immutable throughout implementation.

## Outcomes & Retrospective

Implemented `scripts/release-linux` with locked atomic recovery state, immutable source preparation, CI dispatch/wait, exact signature and source checks, resumable uploads, explicit publication approval, and public-download verification. All 23 orchestration/recovery tests passed. A real unsigned candidate at d82c74a completed all 24 preparation stages: two reproducible container builds, ten packaged journeys plus TLS, 29 native integration cases and 93 help pages. Unchanged resume reused verified stages; a deliberately modified report was refused and its exact original bytes restored. Existing public v0.0.1 assets passed download, checksum, signer/issuer, source and public-tag checks. API doubles establish orchestration behavior; no new signature, draft or publication was made.

Same-runner benchmark https://github.com/bpcakes/jury/actions/runs/34367818557 ran the identical 94-test CLI inventory with zero ignored or failed tests at each optimization level. Test execution fell from 1588.7620s to 85.5034s (18.581x); compilation increased from 61.3799s to 108.6485s. Both retained debug assertions and overflow checks. Adopted opt-level 1; the execution ratio is not a whole-CI-job speedup.

Pinned upstream Jig source 45449a67ba897fd924b92d6f24a7138c5dd159d2 and removed duplicate legacy gate definitions while retaining all five profile checks. Upstream full local workspace checks passed, and all five original target receipts were reused on revalidation. Jury's required test command passed on final source 9529bbf62c135b26632a7983492a680e7634d079 in 83.1s; subsequent work check reused that original test receipt and ran only the four remaining gates. After a real Beads notes update, work check executed zero targets and reused all five original receipts; work evidence and gates remained fresh. The default upstream freshness policy remains conservative; Jury explicitly declares its root Beads tracker as bookkeeping. Source, config, runner and documentation changes still invalidate evidence.

Release validation run https://github.com/bpcakes/jury/actions/runs/34370041747 completed all 15 jobs successfully despite subsequent ordinary pushes. The actual CLI dispatched source a7eb2540deb37539073f03f6205e039b6c839f00 in run https://github.com/bpcakes/jury/actions/runs/34373840546. Its file-budget check exposed a missing local main branch in candidate checkouts. The dispatched policy now explicitly uses origin/main with the same merge-base comparison. All 15 jobs passed for corrected source 9529bbf62c135b26632a7983492a680e7634d079 in https://github.com/bpcakes/jury/actions/runs/34374555615. The actual CLI exited successfully and saved that exact CI run ID. The failed earlier run exited nonzero and did not create CI approval state. All four requested capabilities are implemented and pushed; upstream PR https://github.com/bpcakes/jig-sh/pull/23 carries the runtime fix and fixture portability corrections. The pinned runtime itself passed Jury's installed-runtime checks and final release validation.
