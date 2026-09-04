# Repair J22 witnessed authorization invariants

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current while implementation proceeds. Maintain it according to `.agent/PLANS.md`.

## Purpose / Big Picture

J22 added witnessed request, approval, cancellation, and governed execution, but an independent Claude-plus-Codex review found several places where the implementation compiles and passes its original tests while violating the intended security or availability model. After this repair, checkpoints identify the exact current policy branch, historically minted witnessed item policies remain usable across unrelated descendant policy revisions, a threshold cannot be vetoed by one bad endpoint, governed children receive only approved environment and stdin inputs, and policy/output validation fails before an item is stranded or a one-process authorization is consumed.

The observable result is a witnessed-only item that remains usable after an unrelated policy mutation, rejects a sibling policy fork, succeeds with exactly `t` valid witnesses despite up to `n - t` invalid or unavailable peers, cancels every reachable witness, launches governed children with a closed environment and stdin, and rejects unusable review-label policy configurations before mutation. The CLI and documentation also state which names and template bytes become public and no longer advertise an unusable workload flag.

This remains externally unreviewed pre-alpha software and must not be used for real secrets. This plan does not revise the frozen wire encoding, cryptographic construction, or conformance vectors. It restores the already-specified meaning of existing fields.

Process-artifact justification: the concrete consumer is the engineer implementing and reviewing the reopened `jury-qv4.4.4`; the named feature is J22 witnessed authorization; the observed defect classes are policy-fork acceptance, descendant-policy stranding, quorum veto, undeclared child inputs, incomplete preflight, and public-contract drift; this plan is closed after each repair slice is committed, focused regressions and the full repository gates pass, and the Bead is closed again.

## Progress

- [x] (2026-09-04 07:03Z) Ran graph-aware Beads triage, reopened and claimed `jury-qv4.4.4`, and started Jig plan `plan_01M1NKMNM2ZQE9MX03BPDWN54C` at Git baseline `7c9f7e2`.
- [x] (2026-09-04 07:03Z) Researched all three review open questions against the frozen protocol, master plan, prior direct-mode behavior, current CLI, and J22 plan; none requires operator input.
- [x] (2026-09-04 07:08Z) Committed the already-tested J22 product source as `08e988f feat(witness): deliver governed authorization UX`; active Jig/Beads state remains unstaged.
- [x] (2026-09-04 07:30Z) Repaired policy identity, descendant validation, read capability, policy-label usability, and approval decision timing; added fork, unrelated-revision, reader-file, unsafe-label, and fail-before-mutation regressions; committed as `230f7f8 fix(witness): separate current and minting policy anchors`.
- [x] (2026-09-04 07:49Z) Replaced fail-fast collection with a shared threshold-aware reducer, independently validated/opened contributions, retained only counted witnesses for receipts, classified endpoint failures before reduction, and made cancellation a full fan-out with exact counts; committed as `25dcce9 fix(witness): tolerate non-counting endpoint failures`.
- [x] (2026-09-04 08:05Z) Carried typed authority into process setup, cleared governed environment/stdin, acquired a capability-safe receipt destination precondition before request publication or opening, and added ambient-input and occupied-receipt regressions; committed as `47c68a0 fix(exec): bind governed child inputs and outputs`.
- [x] (2026-09-04 07:56Z) Aligned governed read selectors with request execution, made selector failures typed argument errors, reused exact transfer validation for local catalogs, exposed deliberately public review labels, removed the dead workload option, and corrected public-data documentation; committed as `25ef2ff fix(cli): align governed public contracts`.
- [x] (2026-09-04 08:09Z) The first complete plan-aware check passed tests, formatting, Clippy, and contract validation but found three hard LOC violations; moved cohesive witnessed round-trip fixtures, approval tests, and execution support into existing submodule directories without behavior changes, reran focused tests/Clippy/LOC, and committed as `2d31e62 refactor(witness): split oversized review modules`.
- [x] (2026-09-04 08:27Z) Removed one leading blank line missed because rustfmt does not discover an `include!`-only test file, committed as `9fdcfc4 style(witness): normalize extracted test module`, and passed the isolated full `scripts/jig check test` target in 564 seconds after a duplicate-concurrency Jig run produced non-reproducible process-timing failures.
- [x] (2026-09-04 09:05Z) Passed an isolated full workspace test run and the final plan-aware work check: five of five gates executed and passed (contract, Rust LOC, formatting, Clippy, and full tests); reviewed the eight-commit series and clean product diff. Lifecycle closure and metadata commit follow this final plan update.

## Surprises & Discoveries

- Observation: the checkpoint/request hash regression does not require a protocol revision.
  Evidence: `docs/jury-v1-master-plan.md` and `docs/security/witness-v1/state-machines.md` require same-sequence hash changes to be rejected; the pre-J22 validator compared checkpoint/request hashes with `PolicyState::terminal_revision_hash()`. J22 removed that comparison while solving the separate circular witness-policy anchor.
- Observation: one field name, `vault_policy_hash`, has different legitimate meanings in different typed messages.
  Evidence: a `WitnessPolicy` embedded in policy revision N must bind revision N-1 to avoid hashing itself, while a checkpoint or request created after revision N must bind the terminal hash of the current policy state. The wire structs are distinct, so the implementation can restore those meanings without changing bytes or schemas.
- Observation: detached request execution is intentionally unavailable rather than an implementation gap.
  Evidence: `RequestSessionIdentity` is nonserializable, the J22 plan forbids secret-bearing snapshots, `request create` reports `later_execution_available: false`, and README/self-hosting documentation direct users to a foreground operation. Approval artifacts also serve live foreground requests, so the approver cannot infer liveness from the signed request alone.
- Observation: template literal text is deliberately public request material.
  Evidence: the frozen `ActionManifestV1` represents template literals as public arguments and secret substitutions as typed placeholders. `template_manifest_arguments` implements that exact split. The missing part is prominent disclosure, not a different encoding.
- Observation: writing a decrypted value to a private local file is a read use, not an item mutation.
  Evidence: the role model says a reader may decrypt but not publish item mutations; pre-J22 `field_read` used `Capability::Read` for both stdout and private-file sinks. Mapping `WritePrivateFile` to `Capability::Write` conflates a local sink with vault mutation.
- Observation: the repository's warnings-as-errors Clippy policy also applies to panic convenience methods in tests.
  Evidence: the first policy-slice regression used `expect_err`; `cargo clippy -D warnings` rejected it under `clippy::expect-used`. It was replaced by a fallible match and committed separately as `0074507` before the threshold slice.
- Observation: `cargo test -p jury-witness self_hosted` is only a name filter and ran zero service tests.
  Evidence: the command reported every target as filtered. The corrected `cargo test -p jury-witness --test self_hosted -- --nocapture` ran and passed both self-hosted service tests.
- Observation: the plan-aware `rust-file-loc` gate compares changed Rust files with the post-policy-slice base `230f7f8`, so the threshold/execution additions exposed three real oversized modules even though application tests passed.
  Evidence: its exact JSON report named `item_tests/witnessed.rs` at 887 LOC, `witness_approval.rs` at 821 LOC, and `execution_commands.rs` at 1,310 LOC. After cohesive file splits they are 314, 559, and 838 LOC respectively, and the unchanged gate reports no errors.
- Observation: `scripts/jig work check` launches the configured `jig.test` gate and repository `api:test` target concurrently, causing two complete process-heavy Jury suites to contend on this host.
  Evidence: one duplicate run failed native child cleanup in one suite and the one-second escaped-pipe-owner deadline in the other; the prior complete run passed both suites, affected focused tests passed, and a subsequent isolated `scripts/jig check test` passed every workspace and doc test including both named failures. No timeout or assertion was weakened.

## Decision Log

- Decision: keep the frozen wire schema and give each typed `vault_policy_hash` field its correct lifecycle meaning.
  Rationale: checkpoint/request terminal hashes reject sibling forks; witness-policy predecessor hashes avoid circular self-binding. These invariants are compatible and need separate validation helpers, not another field or regenerated vector.
  Date/Author: 2026-09-04 / Codex.
- Decision: validate a witness policy's minting anchor as historical ancestry while binding every new checkpoint/request to the current policy sequence and terminal hash.
  Rationale: current policy access checks enforce revocations, while an unchanged item slot may safely retain the witness policy under which its capsules were created. Requiring the minting sequence to equal the current global sequence strands unrelated items after any policy journal append.
  Date/Author: 2026-09-04 / Codex.
- Decision: make per-witness transport and contribution failures inputs to a threshold reducer rather than global errors.
  Rationale: `t`-of-`n` availability explicitly tolerates up to `n - t` unavailable or malicious witnesses. Local request/checkpoint invalidity remains a global error because it is validated before network contact; one endpoint's claim never is.
  Date/Author: 2026-09-04 / Codex.
- Decision: carry execution authority as a typed value into child setup.
  Rationale: a string used only for output cannot change environment/stdin behavior. Direct mode may retain its documented transparent behavior; witnessed-approved mode must clear all ambient inputs not present in the approved manifest.
  Date/Author: 2026-09-04 / Codex.
- Decision: answer the detached-request question through existing requester disclosure, document public template/review-label material, and restore private-file reads to read capability.
  Rationale: detached non-resumption and public template literals are necessary consequences of the existing security design; the capability mapping is a concrete authorization bug.
  Date/Author: 2026-09-04 / Codex.
- Decision: use direct cutovers for these unreleased internal semantics.
  Rationale: the repository is pre-alpha, J22 has not been committed or released, and no deployed request/checkpoint state needs a staged compatibility path. No persisted wire schema changes.
  Date/Author: 2026-09-04 / Codex.
- Decision: satisfy the LOC gate with module extraction only, not threshold changes or suppression.
  Rationale: the gate identified an actual concentration/change-amplification issue. The relevant test fixtures and parsing/digest helpers already formed cohesive units and could move behind `mod`/`include!` boundaries without API or runtime changes.
  Date/Author: 2026-09-04 / Codex.

## Outcomes & Retrospective

The baseline, four product repair slices, and one behavior-preserving source-organization slice are complete. Research found four shared root causes rather than thirteen unrelated mistakes: overloaded policy identity, fail-fast per-member errors at a threshold boundary, direct-mode process semantics leaking into governed execution, and validation/preparation occurring after destructive or authorization-consuming steps. The policy slice restored exact current-branch binding without changing the frozen wire format and preserved historically minted witnessed slots across unrelated revisions. The threshold slice now treats endpoint failures as reducer inputs, opens each contribution before counting it, and prevents one bad member from vetoing a valid subset. The execution slice closes ambient child inputs under governed authority and rejects an occupied receipt destination before publishing a request or opening an item. The contract slice removes an advertised no-op, shares exact label-set validation, makes public review labels visible, and gives governed read the same opaque-ID selector model as request execution. The LOC-driven module split reduces change amplification without changing behavior or gate thresholds.

The final isolated `scripts/jig check test` passed every workspace, integration, service, process, protocol-vector, and doc test in 564 seconds. The final `scripts/jig work check` then passed all five required gates with batch receipt `receipt_01M1NT2NP67T6E6ZQ6JY20TEPH`: contract, Rust LOC, formatting, Clippy, and the full test suite. No frozen protocol encoding, cryptographic construction, conformance vector, gate threshold, test assertion, or timeout was changed. The detached-request, public-template, and private-file capability questions were resolved from existing normative sources and required no operator input.

## Context and Orientation

The repository is a Rust workspace. `crates/jury-protocol` owns exact canonical messages. `crates/jury-core` owns policy replay, witness validation, request construction, response/contribution validation, and the mode-neutral `ItemAccessProvider`. `crates/jury` owns CLI parsing, HTTP transport, request orchestration, process use, and user-facing output. `crates/jury-witness` owns the `juryd` HTTP adapter. Transport or terminal types must not enter core, and Jig must not become a runtime dependency.

A policy journal is an append-only authenticated sequence. Its terminal revision hash identifies the exact current branch. A witness policy is embedded in one journal revision and therefore binds that revision's predecessor hash; otherwise its own digest would recursively depend on itself. A witnessed item slot records the witness policy and policy sequence used to create its sealed shares. Later unrelated policy revisions do not change those shares, but every new request must still be checked against current access and a current owner-signed checkpoint.

A witness threshold `t` among `n` members promises conditional availability when any `t` valid members respond. Invalid, malicious, stale, or unavailable members must not count, but up to `n - t` of them must not veto the valid subset. An encrypted contribution is not valid merely because its outer signature is valid: the endpoint must decrypt it to the fresh request-session key and verify its share index and commitment before counting it.

Direct execution intentionally preserves ordinary transparent environment/stdin behavior. Governed execution is different: the approved manifest says environment injections are the only environment metadata in the child, and `stdin: none` means no inherited stdin. `ExecutionEvidence` currently carries authority only as a display string, so the common runner cannot enforce that distinction.

The starting working tree contains the complete J22 feature relative to `7c9f7e2`, plus append-only Jig/Beads state. It already passed the full workspace suite and all six prior Jig gates before review. Because the user requested separate commits, the source feature baseline must be committed before repairs so each review fix has an intelligible diff. Active `.agent/state` and `.beads` changes remain for the final metadata commit.

## Plan of Work

The baseline slice commits the existing J22 application source, tests, Cargo lockfile, README, and self-hosting documentation. It excludes `.agent` and `.beads` state so the repair lifecycle is recorded only after it completes. No source changes occur in this slice.

The policy slice introduces one `PolicyState` helper that resolves the predecessor hash for an arbitrary historical sequence. `WitnessPolicy` and owner review labels validate against that historical minting anchor. `VaultPolicyCheckpointV1` and `WitnessRequestV1` are constructed from and validated against the current terminal sequence/hash. Item-slot lookup continues to bind the exact current slot identity but no longer incorrectly equates the slot's minting sequence with the request's current checkpoint sequence. Tests construct an unrelated descendant revision and a sibling same-sequence fork. The same slice maps `WritePrivateFile` to read capability and makes review-label creation use the same nonempty UTF-8/control-free display invariant as approval validation. A human field-consuming rule must have at least one usable field label before `prepare_rekey` can clear direct slots.

The threshold slice centralizes reserve/decide collection so `request execute`, read, inject, and child execution do not maintain divergent loops. A typed private transport failure enum distinguishes unavailable, stale, denied, replay, expired, cancelled, authentication, and invalid-response outcomes. HTTP 408, 413, 429, 5xx, and non-JSON error bodies are availability failures. Core response processing validates each response independently, decrypts and commitment-checks each approving contribution independently, discards invalid or duplicate members, and reconstructs after exactly `t` valid shares. Cancellation attempts every endpoint, validates every response, and reports full, threshold-effective, too-late, or partial fan-out without claiming that failed endpoints cancelled.

The execution slice replaces the string authority in `ExecutionEvidence` with a typed direct/witnessed authority. Governed child setup calls `env_clear`, adds only manifest-authorized injections/files, and uses null stdin unless the manifest supplies secret stdin. Direct execution retains its established transparent and brokered environment semantics. Receipt assembly and public-file preparation occur after authorization collection but before opening the item or spawning a child; publication occurs only after successful use. Holding `PreparedPublicFile` across the use gives the existing capability-safe expected-state check real force and prevents a known collision from consuming the request session.

The contract-cleanup slice documents that transfer artifacts contain deliberately public review labels and that witnessed template literals travel in the public manifest. Transfer inspection exposes those public labels losslessly. `PolicyCatalogV1` calls the same canonical review-label-set validator used by transfer parsing. The always-rejected `--workload` option is removed. Governed read help explains that positional selectors are public review labels, and failed label/path resolution returns `InvalidArguments` rather than an authentication-class error.

Each slice adds tests that would fail on the reviewed implementation and passes its owning crate tests before commit. Do not weaken existing assertions, regenerate frozen vectors, add suppression pragmas, or commit generated success artifacts.

## Concrete Steps

Work from `/home/aa/Documents/jury`.

Commit the J22 baseline with only product source, tests, Cargo metadata, README, and self-hosting documentation staged. Review `git diff --cached --check` and commit as `feat(witness): deliver governed authorization UX`.

For policy identity and usability, edit `crates/jury-core/src/policy/state.rs`, `crates/jury-core/src/witness_validation.rs`, `crates/jury-core/src/witness_client.rs`, `crates/jury-core/src/witness_client/control.rs`, `crates/jury-core/src/witness_approval.rs`, and focused tests; edit `crates/jury/src/cli/policy_commands.rs` and native CLI tests. Run:

    cargo test -p jury-core witness -- --nocapture
    cargo test -p jury --test native_cli witnessed -- --nocapture

Commit as `fix(witness): separate current and minting policy anchors`.

For threshold transport, edit `crates/jury-core/src/access_provider/witnessed.rs`, `crates/jury/src/cli/witness_transport.rs`, `request_commands.rs`, `request_commands/support.rs`, and focused core/CLI/service tests. Run:

    cargo test -p jury-core witnessed -- --nocapture
    cargo test -p jury --test native_cli witnessed -- --nocapture
    cargo test -p jury-witness self_hosted -- --nocapture

Commit as `fix(witness): tolerate non-counting endpoint failures`.

For governed execution and receipt preparation, edit `crates/jury/src/cli/execution_commands.rs`, `execution_commands/witnessed.rs`, `request_commands.rs`, and `template_commands.rs` plus focused tests. Run:

    cargo test -p jury execution_commands -- --nocapture
    cargo test -p jury --test native_cli witnessed -- --nocapture

Commit as `fix(exec): bind governed child inputs and outputs`.

For public contracts, edit `crates/jury/src/cli/access_execution_args.rs`, `policy_args.rs`, `context.rs`, `transfer_commands.rs`, relevant tests, `README.md`, and `docs/self-hosting-juryd.md`. Run:

    cargo test -p jury --all-targets -- --nocapture
    cargo test -p jury-core transfer -- --nocapture
    cargo run -p jury -- read --help
    cargo run -p jury -- policy require-witnessed --help

Commit as `fix(cli): align witnessed public contracts`.

Finally run:

    scripts/jig work check --plan-id plan_01M1NKMNM2ZQE9MX03BPDWN54C
    scripts/jig work evidence --plan-id plan_01M1NKMNM2ZQE9MX03BPDWN54C
    scripts/jig work gates --plan-id plan_01M1NKMNM2ZQE9MX03BPDWN54C
    scripts/jig check test
    git diff --check

Expect zero failures and no suppressed stderr. Finish the Jig work record, close `jury-qv4.4.4` as completed, run `br sync --flush-only`, and commit the append-only `.agent`/`.beads` metadata as `chore(agent): close J22 review repairs`.

## Validation and Acceptance

Policy tests must demonstrate that a request/checkpoint from sibling policy branch A is rejected by branch B even when sequence, witness policy, item slot, and principals otherwise match. A witnessed item must complete a new request after an unrelated item or principal policy revision, while current revocations and changed witnessed authority still reject stale artifacts. A reader must complete `write-private-file`; the same reader must remain unable to mutate the item.

Policy CLI tests must provide no field label and a control-character label, observe a typed argument/policy error, and prove the vault/catalog bytes remain unchanged. A valid subset of field labels remains allowed and constrains which fields can be requested.

Threshold tests must use a 2-of-3 policy and prove success with two valid contributions plus one unavailable endpoint, one well-formed stale refusal, one malformed response, and one encrypted contribution with an invalid share commitment. The invalid member never appears in receipt counted decisions. Fewer than two valid members must preserve the strongest truthful terminal status. Cancellation must contact a later healthy endpoint after an earlier failure and report whether acknowledgements make future quorum impossible.

Execution tests must set an ambient non-Jury variable and provide readable inherited stdin. A witnessed-approved child sees neither unless represented in its manifest, while explicit direct transparent mode keeps its existing behavior. An already-existing receipt path must fail before item opening or child spawn; a successful operation publishes exactly one contribution-free receipt afterward.

Contract tests must show transfer inspection and docs disclose public review labels and template literals, locally parsed review-label sets obey transfer ordering, `--workload` is absent from help, and governed selector/path errors use `InvalidArguments` without suggesting signature failure.

The full repository suite and every required Jig gate must pass from the final committed source. Review `git log --oneline 7c9f7e2..HEAD` and ensure each commit corresponds to one plan slice and contains its regression tests.

## Idempotence and Recovery

All source edits are behavior-preserving outside the named witnessed paths. Focused tests can be rerun safely. HTTP/cancellation tests use local generic fixtures and bounded timeouts. No real credentials, private names, or secrets enter source or output.

If a slice fails, fix it in the working tree before committing; do not amend an earlier committed slice unless its own stated invariant is false. If a later slice reveals an earlier design error, make a new focused corrective commit and record the discovery here. Never regenerate J19 conformance vectors, lower a threshold, accept a sibling fork, persist a request-session private key, or restore ambient inputs merely to make tests green.

The current pre-alpha checkout has no deployed J22 state. Old in-process request artifacts naturally expire and are not resumable. No destructive repository reset or checkout is permitted; preserve append-only `.agent/state` and `.beads` changes for the final metadata commit.

## Artifacts and Notes

Authoritative baseline:

    Git commit: 7c9f7e229b0c953e915e6091da0efec85c9729d8
    Bead: jury-qv4.4.4, reopened and in_progress
    Jig plan: plan_01M1NKMNM2ZQE9MX03BPDWN54C
    Initial reviewed fingerprint: b86bd2006fc5152e2df5a295cf7fc3293fdd52a1884729ada4f57069741b4b40

Open-question answers:

    Detached request execution: intentionally unavailable; requester is already warned.
    Template literals: intentionally public manifest bytes; add explicit disclosure.
    Private-file read capability: must be Read; current Write mapping is a defect.

The comprehensive review was same-scope across Claude and Codex. Both independently found the policy-hash and single-bad-witness defects. Claude alone identified descendant-policy stranding, HTTP classification, transfer disclosure, selector/preflight/flag/catalog drift. Codex alone identified unusable label configurations, undeclared child inputs, cancellation fan-out, and approval timestamp drift.

## Interfaces and Dependencies

In `PolicyState`, add a crate-visible helper equivalent to:

    fn predecessor_hash_for_sequence(&self, sequence: u64) -> Option<&Digest32>

Use it only for values whose type is `WitnessPolicy` or `OwnerReviewLabelV1`. Checkpoints and requests compare their existing `vault_policy_hash` to `terminal_revision_hash()` and their sequence to `sequence()`.

In the CLI transport adapter, introduce a private typed error with a finite kind enum. Reserve, decide, and cancel return that type. It must convert to a public `CliError` only at the outer command boundary; collection logic matches enum variants, never string codes.

In the core access provider, response validation and contribution opening are per-member operations. The reducer retains at most one valid response per witness ID and share index and passes exactly the lowest `t` valid shares to interpolation. Invalid protected shares are wiped through existing protected/zeroizing containers.

In execution, replace `ExecutionEvidence.authority: &'static str` with a private enum whose methods provide the display label and whether the action is governed. `apply_environment` and stdin selection require that enum.

For receipt output, return a small private prepared-receipt value holding `PreparedPublicFile` plus the public receipt digest. Construct it before opening; publish it after the use succeeds. Do not expose filesystem authority or receipt contents across crate boundaries.

Revision note (2026-09-04): replaced the initial short work body with a self-contained repair plan after resolving the review's open questions and proving the checkpoint correction restores existing frozen semantics without a J19 protocol revision.
