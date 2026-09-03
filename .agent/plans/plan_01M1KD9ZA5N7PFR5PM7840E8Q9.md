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
- [ ] Centralize receipt policy/request validation, correct time semantics, and
  report collector-field and trust-root provenance honestly.
- [ ] Require exact authenticated policy ancestry for rotation/recovery and
  enforce complete reseal plus non-decreasing recovery threshold.
- [ ] Replace quadratic operational-status acknowledgements with one anchor and
  bounded per-vault summaries.
- [ ] Centralize and pin the policy-material codec, reject noncanonical CLI
  input, and avoid repeated maximum-size receipt serialization.
- [ ] Open offline database audits read-only without chmod, WAL reconfiguration,
  or sidecar creation.
- [ ] Run targeted tests, `scripts/jig work check`, the full workspace suite,
  applicable gates, close J23 again, and finish this plan.

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
- Use a normal read-only SQLite connection for audit. Do not use immutable mode
  against potentially live state.

## Outcomes & Retrospective

Pending implementation and verification.

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
