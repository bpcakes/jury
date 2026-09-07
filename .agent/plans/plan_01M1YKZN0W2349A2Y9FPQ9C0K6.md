# Repair rollover validation boundaries

J18 must refuse a source that became stale during preparation, preview valid historical lineages, preserve actionable preparation errors, and avoid repeated full destination validation. This plan is consumed by the J18 implementer/reviewer for these four observed defects; archive it when J18 is accepted and recovery no longer needs this work's context. Jury remains pre-alpha. No cryptographic construction, persisted format or release scope changes are intended.

## Progress

- [x] Research the four findings and protocol/catalog open questions against current code.
- [x] Implement source publication freshness guard and regressions (focused authenticated-state tests pass; native pre-publication regression is running).
- [ ] Commit shared active registration-role selection and historical preview regression.
- [ ] Commit preparation error arbitration and regressions.
- [ ] Commit reusable authenticated destination validation and regressions.
- [ ] Run required repository checks and full workspace tests; record actual results and finish J18 if acceptance is satisfied.

## Surprises & Discoveries

The source worktree and per-vault/per-principal checkpoint have different scopes: another clone shares the latter without changing the former. Locking alone does not refresh earlier authentication. Catalogs deliberately retain removed bootstrap roles. Core preparation already selects active roles, but CLI preview enumerates retained proofs. Provider finish checks unused requests even when preparation failed before access. Historical direct verification fully validates twice; both direct and governed verification replay bootstrap state after catalog validation already did so.

Registration capsules explicitly open 32-byte plaintexts (identity.rs); only ItemCreate and ItemSlotsReplace carry slots (protocol types.rs). Endpoint selection follows current item slot policy digests (policy/state.rs). Catalog validation enforces canonical ordering and already rejected VaultPrincipal proofs before J18, so no compatibility repair is needed. Recovery requires approvals (policy/witness.rs); historical policy definitions are supplied to replay. Source bridge-only verification intentionally does not substitute for full destination verification. Existing provider feature forcing and explicit conformance modes need no change for these four defects.

## Decision Log

Keep guards private and short-lived. Acquire the source lock after interactive preparation, authenticate current audit/checkpoint/receipts and compare source bytes before destination writes or endpoint registration. Keep it through publication. Use the same guard for saved-candidate resume and completed cleanup. Do not mutate the source or weaken known-local rollback refusal. This provides known-local freshness, not global freshness.

Expose one core operation for validated active registration requirements, used by preparation and preview; keep historical evidence intact. Make provider finalization consume the preparation Result: recorded access failures take precedence over the generic core wrapper; core errors take precedence over unused requests; enforce complete consumption on success only.

Return authenticated bootstrap state from existing validation instead of supplying untrusted PolicyState to a bypass API. Share it privately between catalog and destination verification. Preserve current artifact validation, migration verification, retained evidence authentication and distinct fresh/historical rules; no durable cache.

## Outcomes & Retrospective

First slice implements the common source guard. Authenticated-state tests pass for current/stale/divergent source, lock retention, audit tail and corrupted local files. The native race fixture initially used an invalid backup/output boundary; corrected fixture rerun is pending. Remaining slices and final verification are pending. Baseline is 373fef9 (exact HEAD captured by Jig). J18 remains in progress until the fixes and checks actually pass.

## Context and work

CLI publication.rs owns output creation, endpoint registration and durable completion. recovery.rs routes saved candidates through it but has a completed-output cleanup branch. PrincipalLocalState authenticates audit, checkpoint and receipts; CheckpointCandidate compares validated source ancestry with that checkpoint. Filesystem LockedVaultState owns the existing exclusive per-vault lock.

Core rollover/registration.rs and governed/roles.rs own source role selection; CLI governed.rs owns preview. governed/access.rs translates Recovery access errors from CLI adapters into core provider errors. Core transfer/catalog.rs validates current plus retained role evidence; rollover/bootstrap/retained.rs checks initial signed provenance. direct.rs and governed/verify.rs must reuse those results without dropping any checks.

## Concrete steps and validation

Work from /home/aa/Documents/jury. Implement each slice with a regression that fails for the original defect, run its targeted cargo tests, inspect git diff, then commit that slice separately. Use generic fixture identities and actual signed local state. For source freshness cover unchanged bytes with advanced and divergent checkpoints, authenticated audit tails and corrupted state, lock retention, saved resume and completed cleanup. For roles cover removal after an initial governed bootstrap while another role remains; preview count must equal fresh challenges. For errors cover early label refusal with valid unconsumed access entries, recorded provider failure precedence and unused entries on success. For validation retain tamper, historical mutation/removal and migration coverage; malformed current descendants must still fail.

Run scripts/jig check fmt and clippy, relevant cargo tests and default scripts/jig work check for the plan (includes complete workspace tests and required gates). Inspect scripts/jig work evidence and gates, then finish. Do not turn a static replay-count reduction into an unmeasured speed claim. All code slices are separately committed; final receipt/tracker changes may be a final metadata commit.

## Idempotence and recovery

No data migration. Existing pending snapshots and owner-authenticated bindings remain byte compatible. A stale source fails before new output or remote registration; saved candidates remain available for explicit recovery but cannot override a newer checkpoint. A failed check stays unresolved and is rerun after repair. Preserve append-only Jig state, use br only, flush after tracker mutations, and never push without instruction.
