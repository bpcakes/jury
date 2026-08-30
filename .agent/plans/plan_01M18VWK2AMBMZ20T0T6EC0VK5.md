# Implement J03 native identifiers and the adapter seam

This plan supplies `jury-core` callers implementing J05, J06, J13, and J19A,
plus downstream storage/reference adapters. It gates stable bounded Jury-native
identifiers, names, selectors, grants, revisions, safe lookup displays, and
translation of external references without importing routing or Git authority
into signed state. The observed defect class is that the scaffold has no domain
types, permitting unbounded strings, routing syntax, name-existence oracles,
and adapter-controlled identity. Close this record after the required tests and
repository gates pass and `jury-qv4.2.2` is closed.

## Progress

- [x] Commit the pre-existing workspace at `d3d7f1d` and use it as the exact
  implementation baseline.
- [x] Claim `jury-qv4.2.2` and inspect the root/crate guidance and J03 contract.
- [x] Implement typed IDs, names, caller inputs, selectors, grants, roles,
  revisions, epochs, accessible catalog lookup, and safe display projections.
- [x] Implement the external reference trait and bounded non-serializable
  repository/global/explicit storage context.
- [x] Add property, negative, dependency, adapter, Git-context, and lookup-oracle
  tests.
- [x] Run the required Jig work checks and gates, inspect the final diff, close
  the Bead, and finish this work record.

## Surprises & Discoveries

- The master plan already fixes the item-name plaintext region at 64 bytes and
  the accessible item count at 1,024, so the J03 bounds can match later vault
  format work without inventing competing limits.
- `jury-core` had no third-party runtime dependencies. The implementation adds
  only Serde at runtime; property-test and JSON support remain dev dependencies.
- The protocol crate must not depend on core, so J03 does not create a protocol
  dependency cycle. J19 retains ownership of independent protocol wire schemas.

## Decision Log

- Decision: use typed nonzero 256-bit IDs with exact lowercase-hex wire forms.
  Rationale: fixed bytes are stable cryptographic identity while strict parsing
  prevents alternate textual representations.
- Decision: use a 1-64 byte ASCII canonical name profile with alphanumeric
  endpoints and `-`, `.`, `_` internally. Rationale: rejecting Unicode rather
  than normalizing it avoids Unicode-version drift, bidi controls, and
  cross-script confusables in security-relevant names.
- Decision: keep unconfirmed caller inputs and confirmed accessible catalog
  names as distinct Rust types. Only confirmed projections implement display;
  raw names and selectors redact `Debug` output.
- Decision: make the adapter trait return only `FieldSelector`. It has no type
  channel for stable IDs, grants, Git authorship, or review state.
- Decision: keep explicit homes in a bounded path type with no Serde support,
  separate from every domain and signed-state type.

## Outcomes & Retrospective

J03 is implemented and `jury-qv4.2.2` is closed. Focused tests and the required
Jig contract, Rust LOC, formatting, warnings-denied Clippy, and workspace-test
gates pass. The tests demonstrate canonical round trips, strict negative
parsing, uniform lookup errors, dependency separation, external-context erasure,
and redacted projections. This remains solo implementation and verification,
not independent review or security certification.

## Context and orientation

`crates/jury-core/src/domain/` owns semantic values and their invariants.
`crates/jury-core/src/adapter.rs` owns non-authoritative routing seams.
`crates/jury-core/tests/` exercises public behavior and architecture boundaries.
`docs/naming.md` records the operator/developer-visible canonical profile.

No cryptographic primitive, signature format, vault file, or witness protocol
is implemented here. Later tasks use these values but remain responsible for
their own reviewed preimages and parser-wide allocation bounds.

## Plan of work

1. Make invalid identity, role scope, revision, epoch, and name states
   unrepresentable or fallibly constructible.
2. Keep caller inputs unconfirmed until an accessible decrypted catalog maps a
   canonical name to an opaque item ID.
3. Limit downstream translation to canonical selectors and keep all filesystem
   and source-control routing outside serializable domain types.
4. Validate behavior with generated round trips and adversarial fixtures, then
   run the repository's locked test, formatting, Clippy, LOC, policy, and
   contract checks selected by Jig.

## Concrete steps

From `/home/aa/Documents/jury`:

    cargo test -p jury-core --all-targets
    cargo tree -p jury-core --prefix none
    scripts/jig work check --plan-id plan_01M18VWK2AMBMZ20T0T6EC0VK5
    scripts/jig work gates --plan-id plan_01M18VWK2AMBMZ20T0T6EC0VK5

Success means all commands exit zero, `cargo tree` contains no Jig crate, and
the final diff contains no production external-routing literal or serializable
storage/Git context.

## Validation and acceptance

The public acceptance surface is:

- exact ID and name parsing plus Serde round trips;
- rejection of empty, oversized, Unicode, normalization, confusable, separator,
  traversal, noncanonical hex, and zero inputs;
- identical `ItemUnavailable` results for inaccessible and nonexistent names;
- no external URI, project, Git ref, author, signature, or review data in native
  selector/identity JSON;
- a core manifest/lock and `cargo tree` with no Jig crate;
- all repository-required Rust checks passing.

## Idempotence and recovery

All code/test/doc edits are ordinary Git changes based on `d3d7f1d`. Test and
gate commands are read-only except for normal build output and append-only Jig
receipts. If a check fails, keep the Bead and plan open, fix the concrete defect,
and rerun that check; do not weaken assertions, regenerate expected output, or
change a gate to obtain green status.

## Interfaces and dependencies

The runtime dependency is `serde` for validated wire conversion. `proptest` and
`serde_json` are test-only. Public entry points are `jury_core::domain` and
`jury_core::adapter::ExternalReferenceAdapter`; storage adapters may inspect a
validated `AbsoluteVaultHome`, but no domain type contains one.
