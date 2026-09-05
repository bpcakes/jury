# Complete J25 adversarial tests and measured budgets

This living ExecPlan follows `.agent/PLANS.md` and delivers `jury-qv4.6.1`.
Consumer: J26 release candidate validation. Feature gated: complete active Linux
direct and witnessed lifecycle. Observed gaps: no coverage-guided parser harness
or declared scenario measurement runner, and incomplete joined adversarial
coverage. Retain this minimal restartable record until J25 closes, then retain
only required provenance. Jury remains an externally unreviewed pre-alpha and
must not be used for real secrets.

## Purpose / Big Picture

Operators must be able to exercise hostile inputs against real parsers,
transactions, the CLI, and self-hosted witnesses, reproduce findings, and measure
supported operations. Existing unit tests alone do not deliver the complete
J25 outcome. Implement the entire active scope below before J26 release binding.

## Progress

- [x] (2026-09-05) Read full J25 scope and J01A obligations; claim the ready bead.
- [x] Record HEAD `0fb0950ce48e16a6950381a1dbcb28e50d75a9a5` and preserve existing
  uncommitted DU-001–004 changes. The preceding audit's complete workspace suite
  passed in 787.8 seconds on this tree.
- [x] (2026-09-05) Preserve the operator's concurrent move of `main` to
  `48946faa10f7c0ae16f00c9a4d654d24a37fdb12`. The intervening commit changes
  only `README.md` and `SECURITY.md`; it does not overlap J25 source or tests.
- [x] (2026-09-05) Inventory public/private untrusted parsers and connect each
  parser family to a coverage-guided target or an owning malformed-input test.
  The exact parser and legacy-test inventories are complete below.
- [x] (2026-09-05) Inventory every durable transaction family and connect its
  commit boundaries to exact old/new-state tests. The executable crash/failure
  coverage map is recorded below; actual abrupt-process coverage remains open
  where the map currently relies on injected adapter failures.
- [x] (2026-09-05) Implement four coverage-guided parser targets with valid
  generic seeds and accepted-path bitmask oracles; run the pinned bounded Linux
  smoke locally and wire it into `security-invariants.yml`. Remote CI execution
  remains unobserved and is tracked by the final Linux-CI milestone.
- [x] (2026-09-05) Complete independent policy, mutation, replay, and recovery
  state models. The new exhaustive mutation/replay/recovery models and existing
  policy set model pass against production transitions.
- [x] (2026-09-05) Correct linked and separate Git-directory ancestry tracking.
  Shared refs and packed refs now come from the common Git directory, the three
  per-worktree namespaces remain local, bounded recursive symbolic refs are
  resolved, reftable refuses as unsupported, and meaningful path whitespace is
  preserved. Real Git tests cover ordinary/common ref movement, shadow shared
  refs, symbolic cycles, common-directory retargeting, whole-repository and
  linked-worktree path substitution, malformed refnames, and
  post-audit/pre-publication movement. Focused filesystem and mutation tests
  pass.
- [x] (2026-09-05) Implement and execute the bounded repository-local lifecycle
  leak scan with exact synthetic passphrase/plaintext needles, all named Git and
  evidence surfaces, explicit omissions, and a seeded-leak detector. The local
  run inspected 28 log and 13 error entries plus worktree, index, object, diff,
  hook, filter, JSON, receipt, snapshot, fixture, and controlled crash-artifact
  roots, including two artifacts captured from an actual SIGKILL probe;
  it found zero exact hits. This remains scoped evidence, not universal proof.
- [x] (2026-09-05) Commit hostile transfer artifacts in a real Git repository
  with forged author and `gpgsig` metadata. Native inspection rejects both
  conflict-marker output and a structurally coherent semantic splice without
  mutating repository or local state. A real `git check-attr` invocation also
  confirms the shared vault has unset diff and merge attributes.
- [x] (2026-09-05) Make the prior alternate-provider experiment reproducible.
  The committed runner checks 27 positive and 87 negative HPKE,
  AES-256-GCM-SIV, HKDF, HMAC, and Ed25519 cases with pinned BoringSSL, plus
  both Argon2id profiles with system libargon2. The selected-provider seven-test
  conformance suite and alternate runner pass locally; pinned native Linux CI
  wiring is present but remote execution remains unobserved.
- [x] (2026-09-05) Fill parser-adapter negative gaps. Witness credentials now
  exercise exact length/character/newline, permission, hard-link, and symlink
  cases; config files exercise malformed, unknown, oversized, relative, and
  non-file input; persisted SQLite rows exercise malformed JSON and generation
  mismatch. CLI policy catalog, restore marker, template, and witness endpoint
  parsers now have direct malformed/noncanonical tests, and the authenticated
  backup payload parser rejects truncated magic/version and hostile lengths.
  The 25-test `jury-witness` library suite and focused new core/CLI parser tests
  pass locally. In the full 50-test Jury library run, the other 48 tests passed;
  an initially incorrect assertion treated a dotted canonical field name as
  malformed, and the corrected focused test passes.
- [x] (2026-09-05) Repair initial-vault commit ordering found by the transaction
  inventory. The shared vault used to publish before its three authenticated
  local files, allowing a crash to leave a visible vault with partial local
  state. Local audit, checkpoint, and receipts now each require a durable
  publication before the shared vault can become visible. An injected boundary
  test checks exact filesystem state after all four publication points and
  passes. The real native identity/vault/status/execution lifecycle also passes
  against the reordered implementation (one test, 411.91 seconds).
- [x] (2026-09-05) Complete cross-boundary Git, direct/witnessed, crash,
  cancellation, and policy/mutation/replay/recovery model coverage. In addition
  to exact injected transaction cut points, native Linux now SIGKILLs the shared
  atomic publisher before publication, after rename/before parent sync, and
  after durable publication; every restart sees a complete old/new file and can
  publish a successor. Self-hosted witness and anchor services are separately
  SIGKILLed and restarted against their existing SQLite databases. The full
  133-test core suite, 42-test filesystem suite, 36-test process suite, two-test
  self-hosted service suite, and witnessed-only CLI read/inject/run/exec flow
  pass locally; network/process suites required an unrestricted native rerun
  after the sandbox returned `EPERM` before product assertions.
- [x] (2026-09-05) Complete provider differential, misuse, hostile-KDF, and
  side-channel work. The pinned BoringSSL/system-libargon2 runner agrees on the
  complete positive primitive corpus and normalized malformed-input corpus;
  production wrapper tests exercise storage-AEAD nonce reuse, HPKE/KEM misuse,
  and exact identity/backup Argon2 profile boundaries. The source-backed J01B
  side-channel map remains applicable to the pinned provider tree. Repeatable
  release cases now compare interleaved authentication failures at declared
  populations: HPKE invalid encapsulation/ciphertext (`n=400` each), stored
  AEAD first/last tag byte (`n=2,000` each), and HMAC first/last tag byte
  (`n=20,000` each). The final release-mode run recorded absolute Welch
  statistics of 1.13, 2.51, and 1.14 under a predeclared gross-divergence
  threshold of 10. The exact staged-candidate rerun after CI portability fixes
  recorded 0.48, 0.67, and 1.35. These are noisy
  regression smoke tests, never constant-time proof.
- [x] (2026-09-05) Implement and execute all required measurements and the
  scoped leak scan. The 46-case release-mode runner records operation time,
  whole-process wall/RSS, normalized scaling series, machine/compiler details,
  and a product/tool working-tree digest in
  `target/j25-measurements/report.json` for J26. The digest excludes only the
  append-only `.agent/plans/`, `.agent/state/`, and `.beads/` process/tracker
  paths and is `97303acb384475125f8a94ca155438100795f2f50efe610ad5a6bbfea19b2c28`.
  On the documented Threadripper/Linux/rustc 1.97.1 host, 1,000-item
  validation took 170.6 ms, 65,536-proof ancestry validation took 3.10 s,
  hardened identity/backup KDFs took 1.53/1.53 s, and hostile `u32::MAX` KDF
  headers refused in 61.5/1.4 us without KDF-sized RSS. The maximum non-KDF
  process RSS was 116,816 KiB for a near-cap transfer inspection. All 40 exact
  supported-scale and smoke operations succeeded; six intentional hard/misuse
  cases refused. No absolute SLO or constant-time claim is inferred.
- [x] (2026-09-05) Complete the final working-tree security diff scan. One
  low-severity linked-worktree ref-resolution defect reproduced against real
  Git; namespace-correct recursive resolution, unsupported-backend refusal,
  exact path parsing, and retained-path revalidation close it and its equivalent
  representations. The original trigger and focused compatibility suite pass.
  Separate crypto/core and filesystem/CLI/witness/CI passes found no other
  surviving candidate; no confirmed finding remains unresolved.
- [x] (2026-09-05) Run the plan-bound local Linux verification. Fresh Jig
  receipts pass contract, Rust file-size policy, formatting, Clippy, and the
  complete workspace test suite; `work evidence` and all six configured gates
  match the current worktree. The complete test target passed in 874.1 seconds.
  The separate 46-case release measurement runner, repository leak scan,
  bounded fuzz smoke, alternate-provider comparison, and direct/witness gate
  checks also pass locally.
- [x] (2026-09-05) Diagnose the first native CI execution without weakening a
  product invariant. Rust 1.98 newly linted four exact-length hexadecimal loops
  and four imports; the equivalent `as_chunks::<2>()` loops and import cleanup
  pass Rust 1.98 Clippy and the Rust 1.90 workspace check. The agent-map gate now
  lists both conformance guides. GitHub's 64 KiB `RLIMIT_MEMLOCK` reproduced the
  measurement failure at the strict 1 MiB case, so only the measurement job's
  shell receives a bounded 64 MiB limit. Under that exact limit all 46 cases,
  including strict 1 MiB and 16 MiB locked allocations, pass locally. A fresh
  exact staged-candidate Jig run passes all five required targets; the complete
  workspace test target took 834 seconds, and aggregate evidence plus all six
  configured gates are fresh and passing.
- [x] (2026-09-05) Integrate Linux CI; run full verification and work gates;
  audit every requirement, disposition findings, and close J25 only on complete
  evidence. Exact commit `0cc80f701ee9938f00710fb1d1b97f1fa5c070ec`
  passed Agent Map Check run `33968386662`, Repo Policy run `33968386692`,
  Security invariants run `33968386675`, and Rust Tests run `33968386759`.
  Every job in those four native Linux workflows completed successfully.

## Surprises & Discoveries

Existing CLI and owning-crate tests contain substantial crash and lifecycle
coverage; policy replay already has a set-model property test. No fuzz harness or
benchmark runner exists initially. `cargo fuzz` is missing; nightly Rust is
installed. Exact legacy commit `eed70cee337b0067ed92deb9fa05017b0b284605` exists
in `../jig-sh`. J25's complete specification is substantially larger than the
short Bead description and remains fully in scope.

LeakSanitizer cannot attach under the local ptrace-constrained runner and aborts
after otherwise clean fuzz campaigns. The smoke gate therefore keeps
AddressSanitizer enabled but explicitly disables LeakSanitizer; this is not
treated as memory-leak or repository secret-leak evidence. A 30-second protocol
campaign executed 120,228 inputs without a crash. The later four-target smoke
completed without a crash; its accepted-path unit oracle covers 9 protocol, 17
witness, 6 authenticated-core, and 11 CLI/name/identifier/config parser paths.

The linked-worktree ancestry implementation originally read refs only from the
per-worktree Git directory. Real linked worktrees keep ordinary branch refs and
packed refs in their common Git directory, so a force-update could escape the
digest. Hardened common-directory retention fixes that gap. The same audit found
that symbolic `HEAD` values admitted parent components and that intermediate ref
directories were not opened no-follow; both now fail closed. The lifecycle leak
runner also confirmed two environmental refusal paths: group-writable public
fixtures and an invalid ancestor `/tmp/.git` are rejected before use, so the
runner fixes its fixture mode and keeps public output inside its controlled
worktree.

## Decision Log

Use a separate tooling workspace for libFuzzer so it does not enter Jury's runtime
graph or change the frozen provider lock. Use actual coverage-guided execution,
meaning mutation guided by newly reached code, with explicit run/input budgets.
Do not describe smoke execution as exhaustive. Preserve frozen bytes and durable
formats. TUI, macOS, devices, Jig migration, rollover/suite migration, managed
service, and external review remain deferred. Before operator authorization, no
commit or push was requested.

On 2026-09-05 the operator authorized committing and pushing the exact tested
candidate so its native Linux GitHub Actions workflows can execute.

The first remote run must not be counted as J25 completion: Repo Policy passed,
but the measurement job inherited GitHub's 64 KiB locked-memory limit, Rust
1.98 Clippy rejected newly redundant forms that Rust 1.97 accepted, and the
agent-map gate found two omitted conformance guides. Fix each root cause and
require a fresh exact-commit run rather than accepting partial workflow success.

## Outcomes & Retrospective

Complete. The active J25 scope is implemented and verified locally and in native
Linux CI at exact commit `0cc80f701ee9938f00710fb1d1b97f1fa5c070ec`.
The adversarial corpus covers the inventoried parsers and durable transaction
boundaries, exercises actual abrupt-process recovery, checks the frozen direct
and witnessed protocols, compares the alternate primitive provider, scans the
named repository surfaces for exact leak needles, and records the required
46-case resource report for J26. The measurements are host-specific observations
and establish no performance SLO, certification, or independent review. Jury
remains an externally unreviewed pre-alpha and must not be used for real secrets.

## Context and Orientation

`crates/jury-protocol` owns vault, identity, backup, transfer, plaintext, and
witness decoding. `jury-core` authenticates policy, audit, checkpoint, receipt,
registration, transfer, backup, and witness state. `jury-filesystem` owns retained
path handles, bounds, locks, and atomic publication. `jury` owns private input,
CLI parsing, restore markers, and multi-file reconciliation. `jury-witness`
owns HTTP, SQLite, anchors, and recovery. `jury-process` and `jury-protected`
own containment and secret memory. Read their nearest AGENTS.md before editing.

Authoritative scope: `docs/jury-v1-master-plan.md` J25 (8158 onward), legacy
baseline (6008 onward), and `docs/security/jury-v1-suite.md` J01A oracles.
Inspect every test at the exact legacy commit under
`crates/jig-vault/src/vault_tests/**`, `run/tests/**`, `backup/tests.rs`,
`store/tests/**`, `crates/jig-vault-tui/src/tests.rs`,
`crates/jig/src/cli/tests/vault_lifecycle.rs`, and
`crates/jig/src/runtime/vault/tui/tests/**`. Assign each port unchanged in intent,
adapt to Jury, supersede with a named stronger test, or reject with rationale.
Do not copy obsolete v2 expected values or activate deferred TUI behavior.

## Exact legacy test disposition inventory

Baseline `eed70cee337b0067ed92deb9fa05017b0b284605` contains 179 `#[test]`
records in the requested paths. The denominator is 179: 75 are superseded by
named Jury coverage and 104 are rejected because their exact feature is outside
the active release. `run/tests/**` contains zero files at this exact revision.
These grouped dispositions apply to every test record in each named file; the
only mixed files enumerate their exceptions below.

- All 72 tests in `crates/jig-vault-tui/src/tests.rs` and all 11 tests in
  `crates/jig/src/runtime/vault/tui/tests/{core,lifecycle}.rs` are rejected for
  this release because J24/TUI is deferred. Activating UI behavior here would
  violate J25's scope. Their underlying input, output, mutation, backup, and
  plaintext-sink invariants are covered at the owning non-TUI Jury boundaries.
- All seven tests in `crates/jig-vault/src/backup/tests.rs` are superseded by
  `jury-core/src/backup_tests.rs`, `jury/tests/native_cli/backup.rs`, and
  `jury/src/cli/backup_commands/tests/reconciliation.rs`, which exercise the
  Jury-v1 envelope, authenticated roles, native CLI, exact publication fault
  points, retries, and containment. Jig-v1/v2 wording is not carried forward.
- In `crates/jig-vault/src/store/tests/path_resolution.rs`,
  `resolve_creates_private_directory` is superseded by the hardened state-root
  and local-state integration tests. `resolve_uses_the_verified_physical_macos_temp_path`
  is rejected because active 0.x is native Linux and macOS is deferred.
- All five tests in `crates/jig-vault/src/vault_tests/exec.rs` are superseded by
  `jury-process` setup, I/O, redaction, failure, cancellation, and complete-tree
  cleanup tests together with native direct/witnessed exec coverage.
- All eight tests in `crates/jig-vault/src/vault_tests/import.rs` are rejected as
  exact OnePassword/Jig migration cases because J15/Jig migration is outside
  the active release. Their general read-only preview, stale-plan, atomicity,
  fault/retry, bound, and concurrency properties are superseded by Jury's
  strict transfer import, mutation commit, output containment, and restore
  reconciliation tests.
- In `crates/jig-vault/src/vault_tests/legacy.rs`,
  `create_open_set_list_remove_secret` is superseded by the native Jury main
  flow and item/mutation tests. The other 12 tests are rejected because they
  assert Jig-v1/v2 compatibility or migration: `new_vaults_use_version_two_envelopes`,
  `cli_generated_v1_fixture_opens_lists_and_maps_concealed_fields`,
  `cli_generated_v1_fixture_runs_without_emitting_plaintext`,
  `cli_generated_v1_fixture_supports_transparent_exec_as_concealed`,
  `cli_generated_v1_fixture_migrates_without_rewriting_its_audit_prefix`,
  `cli_generated_v1_fixture_validates_header_before_salt_and_payloads`,
  `cli_generated_v1_fixture_validates_kdf_before_wrapped_payloads`,
  `cli_generated_v1_fixture_decodes_wrapped_payload_before_state_payload`,
  `version_one_fixture_remains_readable_and_uses_the_original_state_shape`,
  `version_one_state_ignores_stray_kind_values_and_treats_every_entry_as_concealed`,
  `version_two_state_rejects_unknown_field_kind`, and
  `explicit_migration_reseals_version_one_under_version_two_aad`. Jury's own
  frozen v1 parser-order and authentication tests supersede only the general
  fail-closed intent, not these obsolete expected values.
- All eight tests in `crates/jig-vault/src/vault_tests/lifecycle.rs` are
  superseded by native identity/vault lifecycle, private output containment,
  KDF-boundary, mutation fault/retry, and backup/recovery coverage.
- All 15 tests in `crates/jig-vault/src/vault_tests/management.rs` are
  superseded by Jury policy/item mutation tests and the independent mutation
  state model, including collisions, conditional preconditions, labels,
  kinds, removals, preservation, and no-write refusal.
- All 30 tests in `crates/jig-vault/src/vault_tests/mutations.rs` are
  superseded by Jury protocol/core mutation, identity, authenticated local
  state, exact KDF/resource-bound, publication/reconciliation, and native CLI
  tests. This ports the invariant intent without importing Jig-v1/v2 formats.
- All seven tests in `crates/jig-vault/src/vault_tests/reveal.rs` are superseded
  by native direct read/template injection tests, bounded private output,
  authenticated audit state, and process redaction/failure tests.
- The single `parses_vault_lifecycle_commands` test in
  `crates/jig/src/cli/tests/vault_lifecycle.rs` is superseded by Jury CLI parser
  and native command-flow tests.

This inventory does not claim that grouped test names alone prove J25. Its
countermetric is the still-open parser/transaction inventory and the executable
focused/full checks required below.

## Exact parser boundary inventory

The coverage-guided denominator is 43 accepted top-level parser paths. The
`fuzz/src` bitmask tests require a valid generic seed to reach every bit, while
libFuzzer supplies malformed mutations. These paths are grouped as follows:

- Nine protocol paths in `fuzz/src/protocol.rs`: vault, identity, transfer
  envelope, authenticated parsed transfer, backup header, backup envelope,
  item descriptor, canonical item state, and framed item state across all 14
  bucket identifiers.
- Seventeen witness paths in `fuzz/src/witness.rs`: action manifest, request,
  approval, cancellation, checkpoint, decision, response, anchor, database
  state, rotation, recovery, owner label, receipt acknowledgement, completion,
  receipt material, receipt JSON, and request signature preimage. Their nested
  enums, identifiers, presentations, targets, replay records, contributions,
  and refusal values deserialize through these top-level wire artifacts.
- Six authenticated-core paths in `fuzz/src/core_artifacts.rs`: registration
  challenge and proof, transfer catalog, validated transfer, receipt policy
  material, and public witness policy material.
- Eleven caller-input paths in `fuzz/src/input_boundaries.rs`: full CLI argv,
  identity name, item selector, field selector, item-name input, field-name
  input, vault/principal/item identifier text, witness config JSON, and anchor
  config JSON. Protocol container fuzzing separately reaches the complete set
  of fixed-width/base64 and nonzero typed wire values.

The remaining untrusted parsers deliberately stay private because they consume
authenticated/decrypted state or combine parsing with filesystem, database, or
network authority. They are exercised at their owning boundaries:

- `PrincipalLocalState::verify_files` drives audit JSONL, checkpoint, and
  receipt parsing. `local_state_tests` covers edits, reordered/truncated tails,
  blank and unterminated lines, noncanonical documents, missing files, wrong
  keys/scopes, invalid receipt shapes, and MAC/cross-link failures.
- Backup `parse_padded_payload` and its private recovery body parser are reached
  by real archive round trips plus direct authenticated tests for nonzero
  padding, truncated magic/version, zero/oversized length words, inconsistent
  logical length, ciphertext tamper, and wrong passphrases.
- Jury's private policy catalog, restore marker, template, restricted
  environment/mapping, witness endpoint, request/approval/checkpoint, and
  principal-descriptor adapters have direct malformed, bound, canonicality,
  or authenticated native tests. Public artifact bodies they embed also run
  through the protocol/core fuzz targets above.
- Witness service/anchor configs, private bearer credentials, persisted SQLite
  state, HTTP wire artifacts, and canonical principal paths have direct tests
  for malformed and unknown input, byte/resource bounds, authority/path shape,
  token character/length and link/permission rejection, mismatched database
  generations, bounded wire output, and noncanonical IDs. Witness messages and
  persisted logical state also run through the witness fuzz target.
- Filesystem byte reads and path selection are bounded I/O/authority checks,
  rather than byte-format decoders. Their traversal, symlink, replacement,
  permission, size, component, repository, linked-worktree, and concurrent
  mutation corpus lives in `jury-filesystem` owning tests and native CLI tests;
  identity and domain selector syntax runs through the input fuzz target.

The countermetric is parser reachability, not the number of tests: a private
parser without either a real owning-boundary malformed case or a reachable
top-level fuzz path reopens this inventory. Coverage campaigns remain bounded
evidence and do not establish exhaustive input safety.

## Exact durable transaction inventory

There are seven durable transaction families. File-producing commands that use
the same retained-capability publisher are one family because their commit and
crash behavior is implemented entirely by that shared primitive; the operation
tests still verify their format and authority preconditions.

- **Single-file retained publication.** Identity create/passphrase change,
  backup and transfer output, checkpoint/policy/request/approval/receipt
  artifacts, private plaintext output, local receipt replacement, and detached
  shared artifacts prepare a complete synced sibling and then perform one
  no-follow, precondition-checked namespace publication. Filesystem tests cover
  the pre-publication drop (old/absent destination and temporary cleanup),
  concurrent or replaced destination, successful atomic publication, and
  post-publication parent-sync failure (complete new file with typed uncertain
  durability). Native command tests cover no-clobber and readback. No caller can
  observe a partial destination through this primitive.
- **Initial vault plus local custody.** Audit, checkpoint, and receipts now
  publish durably before the shared vault. The new
  `vault_initialization_publishes_shared_state_only_after_all_local_state` test
  injects failure after each local file and after the shared file: before the
  final point the shared vault is absent; after it, all four exact files exist.
  Generic single-file tests cover interruption within each publication.
- **Authenticated vault mutation.** The durable order is audit intent, optional
  policy catalog, shared encrypted vault, then checkpoint. Mutation commit tests
  cover refusal before the intent, Git movement after the intent, catalog
  conflict/rollback, shared commit followed by checkpoint failure or unsynced
  parent, and retry/reconciliation without duplicate audit events. The local
  state crash-split test admits only an authenticated audit tail ahead of the
  checkpoint. The shared artifact is the commit point and outcomes after it are
  typed as committed recovery, rather than false rollback.
- **First transfer installation.** Policy catalog and three exact local-state
  files reconcile under the vault lock before the shared vault publishes.
  `assert_first_install_retry_recovers_exact_partial_state` removes the shared
  vault and one local file, proves retry restores the exact prior bytes, then
  proves a conflicting partial file blocks publication. Descendant updates use
  the authenticated mutation family above.
- **Backup restore/drill.** A durable marker binds every output and precedes
  owner/optional-role identity, vault, local-state, and cleanup publication.
  Restore tests inject after marker, every identity role, vault, and each state
  file; an exact retry finishes the same transaction, a changed target is
  refused, and marker cleanup is separately tested before rename, after
  quarantine, and after an injected parent-sync failure.
- **Witness logical state plus external anchor.** The order is SQLite state with
  a pending signed anchor, external compare-and-swap, readback, then local mark
  published. Engine tests inject before and after the database commit, after
  anchor publication, during local marking, and during readback; retries preserve
  one logical mutation and stable response bytes. `split_write.rs` repeats the
  model with real independent SQLite databases and rejects either one-sided
  rollback. Anchor compare-and-swap tests cover absent, equal, stale, foreign,
  and monotonic successor states.
- **Witness database lifecycle.** Initialization, backup, and restore use a
  temporary synced database, validated schema/kind/quick-check, no-clobber
  publication, and parent sync. Owning tests cover absent initialization,
  reinitialization/overwrite refusal, successful readback, malformed state,
  lock timeout without commit, immutable offline audit, and validated backup
  restore. Anchor database backup/restore has the same no-clobber/readback tests.

The injected boundary tests establish family-specific old/new and retry oracles;
the native Linux SIGKILL tests establish that the shared file publisher and both
self-hosted database processes survive abrupt process loss. This is process-crash
evidence, not kernel power-loss evidence. J25 remains open until the final native
Linux gates pass and the configured CI corpus runs on the candidate tree.

## Plan of Work

### Milestone 1: Executable parser coverage

Add a pinned `fuzz/` tooling workspace with real parser oracles, valid generic
seeds, malformed inputs, and accepted-input canonical round trips. Cover vault,
identity, backup header/envelope, transfer, descriptor/body plaintext, witness
request/manifest/approval/cancellation/response/receipt/recovery/rotation,
registration, policy material, local state, CLI/config/path parsing. Inventory
private parsers and exercise owning boundaries without exposing secret APIs.
Run bounded coverage-guided campaigns, preserve failures for minimization and
regression tests, and ensure accepted seed paths actually execute. Hostile public
header tests must refuse before expensive KDF work.

### Milestone 2: Joined failure and state transitions

Extend owning tests and native CLI tests for whole-repository substitution,
malicious `.git`/`.jury`, symlinked and linked worktrees, fresh clones without
trust, checkout/reset/force-push rollback, forged Git metadata, conflict/merge
output, concurrent worktrees, strict descendants, and divergence. Join direct
and witnessed candidates with request/manifest consistency, approval counts,
replay/expiry, checkpoint/anchor recovery, contribution assembly, receipts, and
explicit direct downgrade reporting. Independent state models compare production
policy/mutation/replay/recovery transitions against their invariants. For every
durable transaction, cover create, execute, failure, retry, resume, cleanup,
replay, and supersession, with faults before/during/after commit and an exact
old/new-state oracle. Fill actual filesystem, entropy, clock, network, database,
process, and cancellation gaps using existing fault seams where available.

### Milestone 3: Provider and resource boundaries

Read exact J01A oracles and pinned provider sources. Exercise every positive
vector and field mutation; malformed keys/ciphertexts/signatures; wrong domain,
suite, order, widths, identifiers, roles, revisions, seals, nonces, fingerprints,
hashes; entropy failures, eight zero IDs/collisions, allocation/KDF failures.
Compare independently implemented providers wherever viable, including normalized
rejection semantics. Inject nonce/key reuse for each AEAD/KEM wrapper and prove
only accepted misuse resistance or duplicate refusal. Exhaust Argon2 public
work/memory/lanes/length limits before costly work. Review secret-dependent paths
against constant-time contracts and add meaningful differential timing tests
with declared populations/limitations. Never regenerate vectors to force green,
widen tolerances, or treat timing measurements as constant-time proof.

### Milestone 4: Measurements and scoped leak evidence

Create runnable measurements of production operations with documented machine,
OS/compiler, inputs, repetitions, wall time, and peak memory. Predeclare sample
denominators and countermetrics, especially refusal versus successful operations.
Measure validation at 1/50/256 principals and 10/100/1,000 items; policy replay at
1/100/4,096 revisions; proofs at 1/1,000/65,536; one-item unlock; descriptor
catalogs at 1/10/100/1,000 grants; ten-item inject preflight; reader grant;
revocation/reseal at 1 KiB, 1 MiB, and near file cap; multi-item principal
replacement; hard-cap refusal; transfer inspect and strict-descendant dry-run.
Measure portable/hardened identity and backup KDF wall time/RSS, hostile headers,
Linux protected-memory lock/unlock/zeroize and locked bytes, every padding bucket,
and proof-history growth under documented cover cadences. Investigate pathological
superlinear behavior outside documented audit verification and non-KDF peak memory
over the 16 MiB artifact cap plus bounded touched-item state. No guessed SLO.

Run a generic repository-local lifecycle with synthetic recognizable needles and
scan worktree, index, objects, diffs, hooks, filters, logs, errors, JSON, receipts,
snapshots, fixtures, and crash artifacts. Enumerate inspected surfaces/omissions
and prove the scanner detects seeded leaks. Never claim universal absence. Any
retained measurement/evidence artifact must name J26 as consumer, the actual
defect class, and its deletion condition; avoid standalone process dashboards.

### Milestone 5: Native integration and completion

Wire executable checks into native Linux CI using pinned tools/actions. Run the
workflow commands locally and inspect actual CI execution when available; never
claim remote execution from local evidence. Audit the entire requirement list,
repair confirmed defects, and keep J25/J26 open for medium-or-higher findings.
Preserve existing tests and limits. Run final full tests and required work gates,
then close the bead and flush tracker changes only when all scope is proved.

## Concrete Steps

Work from `/home/aa/Documents/jury`. Install development tooling with
`cargo install cargo-fuzz --version 0.13.2 --locked`. Use
`cargo test -p <owning-crate> <test-filter> --locked` for focused tests. Once the
harness exists, run `cargo +nightly fuzz run <target> -- -max_total_time=30
-rss_limit_mb=2048`; record actual executions/coverage, not an exhaustive claim.
Add exact benchmark and leak commands here when implemented.

Final commands: `scripts/check-direct-crypto-gate`, `scripts/check-witness-gate`,
`scripts/jig check fmt`, `scripts/jig check clippy`, `scripts/jig check test`.
Run `scripts/jig work check --plan-id plan_01M1R6TJPEC3KDN1QGBPYBCN6Q`, then
`work evidence` and `work gates` with that plan ID before `work finish`.
Zero selected tests is not proof.

## Validation and Acceptance

Every public parser needs malformed input coverage; every durable transaction
needs before/during/after crash tests. All named Git/trust/import scenarios must
cross real boundaries. Provider agreement, misuse, and KDF refusal must satisfy
the frozen oracle. Every declared measurement scenario must execute; refusal at
a supported scale exposes a defect rather than completing the measurement.
The corpus must run in native Linux CI. No material unresolved finding or false
performance, safety, independent-review, or completion claim is allowed.

## Idempotence and Recovery

Keep generated corpus/scratch files in named temporary or ignored tooling
directories. Preserve failing seeds until regression tests exist. Never mutate
real vaults or delete unrelated temporary files. Preserve all pre-existing user
edits. No durable migration is intended. Update this plan after milestones and
interruptions; partial completion never closes the full objective.

## Interfaces and Dependencies

Harnesses call real APIs; secret-bearing APIs must not expand for convenience.
Private test seams belong in owning modules. Keep new fuzz dependencies separate
from frozen runtime provider inputs. Any security-boundary implementation repair
must satisfy applicable `docs/architecture.md` gates first.

Revision note (2026-09-05): Expanded the initial note into full J25 scope and
implementation milestones after inspecting source and the complete specification.
