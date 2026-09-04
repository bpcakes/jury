# Repair J17 backup and restore boundaries

This ExecPlan is a living document maintained under `.agent/PLANS.md`. It delivers `jury-qv4.2.16`. Its concrete consumers are the `jury backup create`, `verify`, `restore`, and `drill` commands and the J25 adversarial corpus. The observed defects are unavailable backups under ordinary locked-memory limits, late and unattributed archive-capacity failure, a create-new publication state that exact retry cannot reconcile, missing degraded-protection output, and an observational locked read that mutates the directory tree. Close this plan after the focused regressions, full test suite, and required Jig gates pass; the plan and append-only Jig receipts remain as the restartable implementation record.

## Purpose / Big Picture

After this work, a small backup succeeds under the default strict memory policy without trying to lock its 4 MiB padded archive, while compact credentials and keys remain in page-dedicated protected memory. Oversized audit, checkpoint, or receipt input fails before large allocation and names the metadata class. Create-new publication has only two outcomes—published and parent-synced, or published with parent sync uncertain—because an atomic no-replace rename removes the temporary-hard-link cleanup window. Restore and drill report emergency protection degradation, and locked reads do not create absent principal directories.

## Progress

- [x] (2026-09-04T15:14:40Z) Reproduce and source-check every merged-review finding.
- [x] (2026-09-04T15:14:40Z) Resolve the four open design questions from the master plan, recovery guide, prior ExecPlans, implementation commits, and CLI contract.
- [x] (2026-09-04T15:14:40Z) Create and claim `jury-qv4.2.16`; start this Jig session at baseline `abcaa931ffdda0e07200add6dd0e48fa29ebdeee`.
- [ ] Replace format-sized `ProtectedMemory` with bounded zeroizing bulk bytes and preserve encoding/resource error classes.
- [ ] Enforce a cumulative local-state budget during hardened reads and report exact capacity classes from core encoding.
- [ ] Make `LockedVaultState::read` use the existing-only principal capability.
- [ ] Replace create-new hard-link publication with an atomic no-replace rename and remove the unreconcilable cleanup outcome.
- [ ] Represent restore identity creation versus reuse as a typed strategy and aggregate degraded-protection status into restore/drill output.
- [ ] Run focused tests after each slice, then formatting, clippy, the full test suite, plan-aware checks, and required gates; close the bead and work session.

## Surprises & Discoveries

- Observation: The 64 MiB protected-memory extension was added by commit `da8d4c3` as a narrow response to a review finding that the 32 and 64 MiB wire buckets exceeded the prior 16 MiB protected ceiling. It was not an architecture amendment.
  Evidence: `docs/jury-v1-master-plan.md` states that serializer scratch and bulk decrypted bodies are short-lived zeroizing memory without promised `mlock` coverage, while `da8d4c3` introduced `MAX_EXTENDED_PROTECTED_BYTES` and tested only `EmergencyAllowDegraded`.
- Observation: `jury-protected::SecretBytes` already owns non-growing heap bytes through `Zeroizing<Vec<u8>>`, so the repair does not need a second bulk-secret wrapper.
  Evidence: `crates/jury-protected/src/secret.rs` zeroizes on drop and refuses reallocation during extension.
- Observation: `jury-filesystem` already depends on pinned safe `rustix`; enabling its filesystem feature permits capability-relative `renameat2(RENAME_NOREPLACE)` without adding unsafe Jury code.
  Evidence: `crates/jury-filesystem/Cargo.toml` pins `rustix = 1.1.4`, and the provider exposes `fs::renameat_with` plus `RenameFlags::NOREPLACE`.

## Decision Log

- Decision: Keep the frozen 4, 8, 16, 32, and 64 MiB backup wire buckets, but place the padded plaintext in `SecretBytes`, not `ProtectedMemory`.
  Rationale: Bucket size is a wire-format privacy property. Page locking is a compact-secret lifetime property. Coupling them made ordinary resource limits disable the feature and contradicted the master plan.
  Date/Author: 2026-09-04 / Codex
- Decision: Remove the 64 MiB `ProtectedMemory` escape hatch rather than weakening strict protection for that allocation.
  Rationale: A per-allocation preferred lock would make the same type mean both fail-closed compact protection and best-effort bulk protection. The existing `SecretBytes` boundary makes the distinction explicit and smaller.
  Date/Author: 2026-09-04 / Codex
- Decision: Preserve one command-scoped `JURY_NEW_PASSPHRASE` for all newly sealed identities, while keeping separate interactive captures.
  Rationale: Section 18.4 explicitly selects the existing singular command-scoped environment contract. Changing it would be a new CLI/environment API rather than a repair.
  Date/Author: 2026-09-04 / Codex
- Decision: Preserve sequential exact retry and do not add concurrent-restore support in this repair.
  Rationale: The durable marker contract promises an exact later retry, not concurrent execution. Atomic create-new marker publication rejects two fresh transactions; a new cross-directory concurrency protocol requires separate design and evidence.
  Date/Author: 2026-09-04 / Codex
- Decision: Replace the internal identity target path plus reuse boolean with a create-or-reuse enum.
  Rationale: Clap excludes invalid flag combinations at the transport boundary, but the transaction model should also make invalid combinations unrepresentable.
  Date/Author: 2026-09-04 / Codex
- Decision: Use atomic no-replace rename for create-new publication and delete the temporary-cleanup outcome.
  Rationale: Retaining a hard-link cleanup state forces every transaction consumer to reconcile a second link that hardened reads correctly reject. Removing the state at the filesystem boundary reduces all callers' bug surface.
  Date/Author: 2026-09-04 / Codex

## Outcomes & Retrospective

Work is in progress. This section will record the final behavior, verification receipts, commits, and any remaining limitations.

## Context and Orientation

`crates/jury-protected/src/memory.rs` owns compact page-dedicated memory whose strict policy requires OS locking, dump exclusion, fork exclusion, guards, and canaries. `crates/jury-protected/src/secret.rs` owns ordinary heap-backed sensitive bytes that are zeroized and do not grow unexpectedly. `crates/jury-core/src/backup.rs` and `backup/codec.rs` build and parse the exact-bucket encrypted archive; `crates/jury-core/src/crypto.rs` owns storage AEAD operations. The wire format remains in `crates/jury-protocol/src/backup_v1.rs` and must not change.

`crates/jury-filesystem/src/private_input.rs` performs bounded no-follow reads, `local_state.rs` holds the vault edit lock and descends to principal files, and `private_output.rs` publishes prepared sibling files. `crates/jury/src/cli/backup_commands.rs` reads local state and maps core errors into stable value-free CLI codes. `crates/jury/src/cli/backup_commands/restore.rs` and its `model.rs` and `publication.rs` modules own the durable cross-directory restore marker and exact-retry state machine.

“Compact protected memory” means small passphrases, keys, and seeds whose mapping must satisfy the selected OS controls. “Bulk zeroizing memory” means bounded serializer or decrypted-body bytes that are erased on drop but are intentionally not promised `mlock` coverage. “Atomic no-replace rename” means moving the already-synced temporary file to an absent destination in one kernel namespace operation that fails if the destination exists.

## Plan of Work

First, extend `SecretBytes` with a fallible fixed-length zeroed allocation and mutable slice access. Add core bulk AEAD helpers that encrypt from and decrypt into `SecretBytes`; keep existing compact AEAD functions for identities and items. Change backup creation/opening to use the bulk helpers, map allocation failure to `ResourceUnavailable`, map impossible codec failure to `InvalidFormat`, and remove the extended protected-memory ceiling. Prove a strict-policy small backup succeeds while compact protected-memory bounds remain unchanged.

Second, add `BackupCapacityClass` to `BackupError` and make `encoded_payload_len` check every vault, catalog, identity, audit, checkpoint, and receipt addition against the exact maximum logical payload. Add a caller-selected bounded locked read in `jury-filesystem`, splitting file-size exhaustion from link/type failure. In the CLI, read local files sequentially against a cumulative 64 MiB preliminary budget so a single oversized class is rejected from metadata before allocation; the core exact budget accounts for envelope framing and reports the final crossing class. Tests must verify audit attribution and prove later files are not read or allocated after exhaustion.

Third, route `LockedVaultState::read` through `principal_root_existing`. Add a regression that an absent principal read returns `NotFound` without creating its hexadecimal directory.

Fourth, enable the pinned `rustix` filesystem feature and change create-new publication to capability-relative `renameat_with(..., RenameFlags::NOREPLACE)`. Delete `PublishedButTemporaryCleanupFailed` and its downstream mutation recovery reason. Keep parent-directory sync as the only non-ideal committed outcome. Tests must prove create-new publication leaves exactly one destination link, rejects a competing destination, and reports injected parent-sync failure without a temporary sibling.

Fifth, define a `RestoreIdentityTarget` enum with `Create(&Path)` and `Reuse(&Path)` variants and derive path, marker state, passphrase source, and output reporting from it. Aggregate degradation from the backup, owner, additional-role, and source-drill passphrase captures into `RestoredInstallation`, JSON details, and human output. Extend restore tests for create/reuse modeling and degraded output.

Each behavior slice is committed separately after its focused tests pass. Plan and tracker updates are committed independently from product slices so a reviewer can inspect each invariant without unrelated changes.

## Concrete Steps

Run all commands from `/home/aa/Documents/jury`.

For protected/core work, run:

    cargo test -p jury-protected --all-targets
    cargo test -p jury-core backup --all-targets

For capacity and read behavior, run:

    cargo test -p jury-filesystem --all-targets
    cargo test -p jury-core backup --all-targets
    cargo test -p jury --bin jury cli::backup_commands -- --nocapture

For publication and restore behavior, run:

    cargo test -p jury-filesystem --all-targets
    cargo test -p jury --bin jury cli::backup_commands -- --nocapture
    cargo test -p jury --test native_cli backup -- --nocapture

After integration, run:

    scripts/jig check fmt
    scripts/jig check clippy
    scripts/jig check test
    scripts/jig work check
    scripts/jig work evidence
    scripts/jig work gates

The final commands must exit zero. The exact receipt IDs and any transient failure evidence will be recorded in `Outcomes & Retrospective`.

## Validation and Acceptance

A strict-policy core backup round trip with a minimal vault must succeed without `--allow-degraded-protection`, demonstrating that its 4 MiB padded buffer does not consume the lock budget. Tests must still prove `ProtectedMemory::initialize_supported` rejects values above the ordinary large ceiling.

An audit file larger than the remaining preliminary archive budget must return a class-specific `backup-audit-capacity-exhausted` error after metadata inspection rather than allocating the file. Exact core payload overflow must identify whichever metadata class crosses the logical payload maximum. Encoding failures must never map to `backup-protection-unavailable`.

An absent-principal locked read must return `NotFound` and leave no new directory. A create-new prepared file must publish with one link and no temporary sibling. Injected parent-sync failure must leave a readable single-link destination and the existing committed-unsynced outcome.

Restore and drill JSON must contain `protection_degraded`, and human output must state its value. Create and reuse identity targets must be constructed through distinct enum variants. All pre-existing exact-retry fault cases must continue passing.

## Idempotence and Recovery

Tests use temporary directories and generic fixtures and may be rerun safely. Product edits preserve the backup wire format and do not migrate persisted data. If a focused slice fails, keep its regression and repair the owning layer before continuing; do not weaken assertions, regenerate unrelated golden data, or broaden degraded behavior. Atomic no-replace publication is fail-closed on unsupported platforms or filesystems. Git commits are additive checkpoints and must not discard unrelated user changes.

## Artifacts and Notes

The comprehensive review fingerprint was `0348ab00a465092d67abc7c837e079727bb5a2b0da86cdd240d2acfaa480e0ad` over `cb69f838140d36e57a43c8c2c74941a2cf44da52..abcaa931ffdda0e07200add6dd0e48fa29ebdeee`. Claude and Codex independently identified the publication-state and capacity-boundary defects. Claude alone identified the protected-memory, error-classification, and non-creating-read defects; Codex alone identified degraded restore output.

## Interfaces and Dependencies

`jury_protected::SecretBytes` will expose a fallible zeroed constructor and mutable slice without exposing provider handles. `jury_core::backup::BackupCapacityClass` will be a value-free public enum available through `BackupError::capacity_class()`. `LockedVaultState::read_bounded` will accept a caller maximum no greater than the file-kind maximum. `PublicationOutcome` will retain only `PublishedAndSynced` and `PublishedButParentUnsynced`. `RestoreIdentityTarget` remains private to the CLI restore model. No new cryptographic primitive, wire field, runtime Jig dependency, secret output, or real credential is introduced.

Revision note (2026-09-04): Replaced the initial one-line plan body with the researched, self-contained implementation and validation plan because the open design questions are now resolved.
