# Harden J23 verification boundaries

Consumer: J22 witnessed-access implementation and J25/J26 release review.
Feature gated: trustworthy offline receipt verification, strict witness
rotation/recovery, bounded operational status, and non-mutating database audit.
Observed defect classes: duplicated request validation, unauthenticated collector
metadata reported as verified, unproven policy ancestry, unsafe threshold
recovery, positional descriptor comparison, quadratic status payloads,
noncanonical policy input, repeated receipt encoding, and read-write offline
audit. Close this active plan through `scripts/jig work finish` after full
workspace tests and applicable gates pass; the resulting append-only receipt is
the minimal recovery evidence and the plan is no longer active.

## Progress

- [x] Research the frozen protocol, state machines, current call sites, and
  SQLite read-only behavior; resolve the six review questions without changing
  the J19-frozen documents.
- [x] (2026-09-03 12:08Z) Centralized receipt policy/request validation, corrected time semantics, and
  reported collector-field and trust-root provenance honestly.
- [x] (2026-09-03 12:08Z) Required exact authenticated policy ancestry for rotation/recovery and
  enforced complete reseal plus non-decreasing recovery threshold.
- [x] (2026-09-03 12:08Z) Replaced quadratic operational-status acknowledgements with one anchor and
  bounded per-vault summaries.
- [x] (2026-09-03 12:08Z) Centralized and pinned the policy-material codec, rejected noncanonical CLI
  input, and avoided repeated maximum-size receipt serialization.
- [x] (2026-09-03 12:08Z) Opened offline database audits read-only without chmod, WAL reconfiguration,
  or sidecar creation.
- [x] (2026-09-03 12:09Z) Ran targeted tests, `scripts/jig work check`, the full workspace suite,
  and applicable gates; closed J23 and finished this plan successfully.

## Surprises & Discoveries

- Receipt outcome, reason, and issue time are in the receipt core, but the core
  has no authenticating signature unless an endpoint acknowledgement or
  completion is present. Signed decisions remain independently trustworthy.
- The protocol deliberately omits action-manifest bytes from receipts, so an
  offline verifier cannot re-evaluate automatic target membership. J22 must
  perform that check before assembling a receipt.
- Checkpoint advancement is intentionally allowed to retire the accepting
  witness: revocation becomes effective only after each witness durably accepts
  the descendant checkpoint.
- SQLite documents `SQLITE_OPEN_READONLY` for an existing non-writable database;
  immutable mode is unsuitable for a live database because it skips locking and
  change detection.
- The final repository LOC gate uses the default-main baseline, not only the
  plan baseline. It exposed oversized aggregation points elsewhere on the
  branch; their items were split mechanically into responsibility-oriented
  include files before the final gate run.

## Decision Log

- Keep the frozen witness-v1 protocol bytes unchanged. Strengthen validators
  and verification-result provenance around that contract.
- Treat receipt core metadata as collector-reported unless a valid endpoint
  record authenticates the core. Never label embedded policy alone as an
  independently pinned trust root.
- Require prior and next canonical owner-signed policy material for rotation;
  terminal `PolicyState` snapshots alone cannot prove ancestry.
- Preserve acceptance of self-retiring descendant checkpoints, while request
  contribution checks continue to require active membership.
- Centralize the existing compact-JSON byte format behind a versioned codec and
  golden tests. A future protocol revision may adopt a different canonical
  encoding, but J19-frozen v1 bytes cannot change here.
- Require audit input to be a stopped or copied database with no SQLite
  sidecars, then open it read-only with SQLite's immutable URI flag. Never use
  immutable mode against potentially live state.

## Outcomes & Retrospective

The review findings were a mix of local boundary omissions and a deeper
structural problem. Individual comparisons were missing, but the recurring
cause was duplicated validation and representation knowledge across the live
witness, offline receipt verifier, CLI, persistence adapter, and operational
status API. The implementation now has one shared request-policy validator, one
versioned policy-material codec, exact policy-journal ancestry, identity-keyed
rotation comparison, one-pass receipt digest derivation, a linear status
shape, and a dedicated non-mutating audit opener.

The fixes landed as independent commits:

- `94fe9f5` unifies receipt request validation and evidence provenance.
- `8f4bc03` proves rotation ancestry and recovery safety.
- `d2b57aa` makes operational status linear.
- `cdcb2bd` centralizes canonical receipt material.
- `60fb647` makes offline audit non-mutating.
- `68e357a` qualifies receipt and status claims in documentation.
- `3f48a9e` and `9e07f47` split oversized protocol, verifier, persistence,
  CLI, server, and test aggregation surfaces without changing their items.

The final `scripts/jig work check` passed all required gates. Its full
`cargo test --workspace` run passed in 517.1 seconds, including 101
`jury-core` tests, 36 `jury-process` tests, frozen witness-v1 vectors,
self-hosted witness tests, split-write recovery, and doc tests. Rustfmt,
Clippy, contract validation, and the default-main LOC policy also passed.

## Context and Orientation

`crates/jury-core/src/witness_receipt.rs` verifies portable public evidence.
`crates/jury-core/src/witness_operations.rs` verifies checkpoint propagation,
rotation, and recovery. `crates/jury-core/src/witness_engine.rs` owns live
witness validation and operational status. `crates/jury-witness/src/persistence.rs`
owns SQLite lifecycle operations. CLI presentation lives under
`crates/jury/src/cli/`.

## Plan of Work

Implement small behaviorally coherent slices in the order listed in Progress.
Each slice gets focused regression tests and a separate commit. Shared
validation should make the live engine and offline verifier depend on the same
policy/request invariants where their evidence overlaps; manifest-only checks
remain explicitly outside offline verification.

## Concrete Steps

1. Add shared request-policy validation and receipt evidence provenance; update
   CLI JSON/human output and receipt tests.
2. Change rotation/recovery verification to consume authenticated policy
   material, compare exact journal ancestry, match descriptors by identity, and
   cover all items crossing the policy boundary.
3. Redesign status output around one signed anchor plus compact vault entries.
4. Add the sole v1 policy-material encoder/decoder and the sole one-pass receipt
   digest calculation path; route all callers through them.
5. Add a read-only audit opener and filesystem-preservation tests.
6. Run formatter, clippy, full tests, contract/applicable gates, inspect the
   final diff and history, then close the bead and plan.

## Validation and Acceptance

Every original review reproducer must fail before its fix and pass afterward.
No frozen document changes are allowed. Final acceptance requires
`scripts/jig check fmt`, `scripts/jig check clippy`, `scripts/jig check test`,
`scripts/jig work check`, and applicable `scripts/jig work gates` success.

## Idempotence and Recovery

All verification and audit paths are read-only. Commits provide recovery points
between slices. If a slice fails, repair forward from its preceding commit;
never weaken assertions, regenerate security vectors, or alter frozen protocol
text to obtain green tests.

## Interfaces and Dependencies

Do not add a runtime Jig dependency. Use existing `jury-protocol` wire types,
`jury-core` policy replay and crypto verification, Rusqlite, and the CLI's safe
public-file helpers. Public breaking changes are acceptable only where an
existing API cannot express the evidence needed for a sound answer, and must be
updated atomically across all in-repository callers.
