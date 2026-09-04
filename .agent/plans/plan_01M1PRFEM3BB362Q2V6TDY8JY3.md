# Harden J17 recovery compatibility and transaction boundaries

This work repairs the confirmed defects from the comprehensive review of the
unpublished J17 backup and recovery implementation. The concrete consumers are
the J17 owner recovery commands and the J25 adversarial corpus. The plan closes
after separately committed fixes and the full repository gates pass.

## Progress

- [x] Establish a clean format, Clippy, and full-test baseline at
  `0f6c624767727e16021b0cdbfb8415f6df9c7af6`.
- [x] Research persisted-state, platform, passphrase, capacity, and restore
  retry contracts in repository documentation and Linux primary sources.
- [ ] Stop eager ambient credential capture before process protection.
- [ ] Restore compatibility with valid pre-change multi-owner histories.
- [ ] Split restore validation from publication and type committed outcomes.
- [ ] Make create-new and repository metadata publication durable and
  filesystem-capability aware.
- [ ] Move alias decisions to retained filesystem identities.
- [ ] Aggregate all protection degradation and remove infallible archive copies.
- [ ] Add the accepted regression, retry, compatibility, and CLI test matrix.
- [ ] Run format, Clippy, test, contract, work evidence, and work gates; close
  `jury-qv4.2.17` and this plan only after all pass.

## Surprises & Discoveries

- `JURY_NEW_PASSPHRASE` is deliberately one command-scoped automation
  credential. Interactive restores still prompt separately for each role.
- First-0.x capacity refusal without audit pruning or lineage rollover is an
  explicit contract; J18 owns later rollover work. This plan must not add a
  hidden compaction or migration policy.
- `RENAME_NOREPLACE` is Linux-specific and underlying-filesystem dependent.
  POSIX `linkat` is atomic create-only, but network filesystems can return an
  ambiguous failure and therefore require identity-based reconciliation.
- The baseline suite passes but takes roughly twenty minutes; focused crate and
  named tests are the iteration loop, with the full suite reserved for the end.
- The first plan-scoped gate run overlapped another workspace's large Rust
  build and timed out in the pre-existing self-hosted loopback integration
  test. The exact failing test passed immediately in isolation, so this is a
  recorded baseline timing flake rather than evidence about the J17 changes.

## Decision Log

- Preserve all frozen backup, vault, identity, receipt, and marker bytes.
- Treat eager secret capture, informal restore phases, and lexical alias checks
  as structural faults. Apply Split Phase, Replace Primitive with Object, and
  Move Function so invariants live in the protected-input, restore, and
  filesystem owners.
- Treat replay rejection, degradation aggregation, and ciphertext cloning as
  isolated omissions. Keep their fixes in separate commits from refactoring.
- Accept existing valid histories that predate complete implicit owner-slot
  construction; enforce complete owner slots on newly constructed mutations.
- Do not add per-role environment variables, audit pruning, or rollover.
- Keep public crate APIs compatible unless a new additive result type is needed
  to make a committed filesystem outcome explicit.

## Outcomes & Retrospective

Pending. Record the resulting boundaries, tests, commits, and any deferred risk
after verification.

## Context and orientation

The affected paths are `crates/jury/src/secret_input.rs` and `cli/environment.rs`
for credential capture; `crates/jury-core/src/policy/replay/operations.rs` for
persisted replay; `crates/jury/src/cli/backup_commands/restore/**` for recovery
phases; `crates/jury-filesystem/src/{private_output,repository,state_root}.rs`
for capability-held publication; and `crates/jury-core/src/{crypto,backup}.rs`
for bounded allocation. Repository policy requires Linux-only support, exact
retry after partial cross-directory restore, and compatibility for persisted
state that can straddle a deployment.

## Plan of work

1. Introduce a late-bound secret source so production environment values are
   read only after process dump suppression. Characterize exact byte and bound
   behavior, then remove secrets from the production `Environment` snapshot.
2. Add a base-compatible multi-owner replay fixture and remove the newly added
   unconditional historical invariant while retaining complete new slot
   construction.
3. Replace restore booleans with closed enums and split opening/validation from
   publication. Bind expected genesis and drill source identity before the
   first write; capture fallible timestamps before commit.
4. Centralize atomic create-new publication in `jury-filesystem`, preserve the
   single-rename state machine, and surface filesystems without
   `RENAME_NOREPLACE` as a specific unsupported capability. A hard-link
   fallback would introduce a second durable name and ambiguous network-
   filesystem failures. Atomically write `.gitattributes` and sync creation of
   `.jury`.
5. Represent marker cleanup as an explicit committed cleanup outcome and avoid
   deleting an object that was not the authenticated marker. Add retry/fault
   coverage for every role and cleanup state.
6. Compare retained directory identities and ancestry for all restore inputs
   and outputs, including bind-mount aliases where the test environment permits.
7. Aggregate every captured credential's degradation state and transfer large
   ciphertext buffers without infallible cloning.
8. Fill the reviewed command matrix: expected genesis, reuse identity,
   overwrite, role-target mismatch, existing state, marker mismatch, aggregate
   capacity, and the deliberate shared automation-passphrase contract.

## Concrete steps

After each numbered implementation slice, run `cargo fmt --all -- --check` and
the smallest affected package or named test. Commit only a green slice. Use
`scripts/jig work check` when a slice crosses repository boundaries. At the end
run `scripts/jig check fmt`, `scripts/jig check clippy`, `scripts/jig check test`,
`scripts/jig check contract`, `scripts/jig work evidence`, and
`scripts/jig work gates`.

## Validation and acceptance

Acceptance is the criteria recorded on `jury-qv4.2.17`. Tests must assert
observable behavior or durable state, not private helper calls. Persisted-format
fixtures must be generated from the pre-change behavior or encoded as exact
generic artifacts. Fault tests must prove both the returned classification and
the filesystem state that permits or refuses retry.

## Idempotence and recovery

Each commit is independently revertible. Refactoring commits preserve behavior;
behavior-changing commits follow their characterization tests. If a slice
cannot be proven green, revert only that uncommitted slice and stop on the last
green commit. Tracker and Jig state are append-only and close only after final
verification.

## Interfaces and dependencies

No new runtime dependency is planned. Use existing `cap-std`, `cap-fs-ext`,
`rustix`, `jury-protected`, and typed CLI/core errors. Do not introduce Jig into
runtime crates, expose paths or secrets in errors, weaken no-follow/hard-link
checks, or change security-critical wire encodings.
