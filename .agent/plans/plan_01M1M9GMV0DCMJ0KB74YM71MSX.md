# Deliver witnessed request, approval, and governed open UX

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current while implementation proceeds. Maintain it according to `.agent/PLANS.md`.

## Purpose / Big Picture

After J22, a user can ask Jury to read, inject, or execute against a witnessed-only item without a direct recipient slot. Jury constructs and signs one exact request plus action manifest, obtains independent signed approvals when policy requires them, contacts every configured `juryd`, validates a threshold of revision-scoped encrypted contributions, opens only the requested revision through the existing `ItemAccessProvider` consumer boundary, and emits a contribution-free receipt. Users can also inspect, approve or deny, cancel, execute, and observe a request through stable human and JSON CLI contracts. A later item revision remains inaccessible through the earlier authorization because the request, contributions, and reconstructed secret bind the exact revision seal and request-session key.

This is pre-alpha functionality. It must never be described as protecting real secrets, independently reviewed, or proof that an endpoint executed an action, forgot plaintext, or resisted exfiltration.

Process-artifact justification: the concrete consumer is the engineer or agent implementing and reviewing `jury-qv4.4.4`; the named feature is J22 witnessed open and approval UX; the observed defect class is omission or drift among the protocol, session, witness transport, protected-key, CLI-rendering, and execution boundaries; this plan ceases to be active and may be removed after `scripts/jig work finish` records passing J22 evidence and the Bead is closed.

## Progress

- [x] (2026-09-03 18:43Z) Verified a clean `main` baseline at `7c9f7e2`, read `agent-map.md`, `crates/AGENTS.md`, `.agent/PLANS.md`, the J22 Bead, and the normative J19/J22 protocol and architecture sections.
- [x] (2026-09-03 18:43Z) Claimed `jury-qv4.4.4` and confirmed J10, J13, J14, J19, J21, and J23 are closed dependencies.
- [x] (2026-09-03 21:05Z) Added frozen private-presentation and owner-review-label protocol values plus shared request/manifest/presentation validation and exact vector, malformed-shape, forged-label, stale-label, wrong-scope, missing-entitlement, and complete-render tests.
- [x] (2026-09-03 21:05Z) Added request construction, role-bound request/approval signing, fresh protected request-session keys, shared response validation, quorum reconstruction, and `WitnessedItemAccessProvider`; a real no-direct-slot body opens only through independently signed and encrypted witness responses, while a response for another session fails before the consumer.
- [x] (2026-09-03 21:05Z) Replaced caller-supplied review-label digests in `policy require witnessed` with owner-signed item/field review labels retained in the authenticated public catalog; the native policy conversion test and crate checks pass.
- [x] (2026-09-03 22:18Z) Added bounded public request/cancellation persistence and an authenticated blocking witness client with explicit exact endpoint sets, owner-private credential files, pinned HTTPS roots, loopback-only opt-in HTTP, disabled redirects, bounded responses, and no persisted session keys or contributions.
- [x] (2026-09-03 22:18Z) Added stable `request create|inspect|status|execute|cancel`, `approve`, and owner-signed checkpoint human/JSON CLI contracts; detached requests state that later execution is unavailable, while foreground execution retains the fresh protected session receiver, renders complete review material, gathers signed decisions, and emits a contribution-free receipt.
- [x] (2026-09-03 23:36Z) Routed `read`, `inject`, `exec`, and `run` through governed witnessed authorization by default, retained explicit `--direct`, and made unilateral versus witnessed authority visible in human and JSON output.
- [x] (2026-09-04 00:28Z) Added foreground automatic, asynchronous human approval, cancellation-race, malicious-response, wrong-session, digest-broadening, no-early-spawn, leakage, and revision-freshness evidence. The engine-backed CLI fixture completes governed read/inject/run/exec twice against two independent engines; the core provider fixture rejects the old request after reseal and succeeds only with a fresh request session and quorum.
- [x] (2026-09-03 23:36Z) Updated README and self-hosting documentation with the foreground approval sequence and exact receipt, endpoint-retention, authorized-child, and pre-alpha nonclaims; removed statements that J22 remains unimplemented.
- [x] (2026-09-04 00:28Z) Completed the test-quality audit against baseline `7c9f7e2`: baseline witness protocol/engine/service tests pass, candidate core and lifecycle tests pass, two isolated mutants are killed (lossy approval rendering and skipped owner-label signature verification), and the exact lifecycle is stable across two consecutive 258–260 second runs. The remaining audit limitation is that the CLI fixture uses a minimal HTTP adapter around real `WitnessEngine` instances; the production `juryd` adapter passes its separate self-hosted suite.
- [x] (2026-09-03 22:56Z) Ran `scripts/jig work check`, the full workspace test suite, and all six required Jig gates. Test, Clippy, formatting, contract, Rust file-size, and verify evidence are fresh and passing; `git diff --check` is clean, the frozen 25-file audit set has zero changes, and the acceptance audit found no confirmed J22 defect.

## Surprises & Discoveries

- Observation: J20 already supplies strict witness-side reserve/decide/cancel evaluation, response signing, replay state, and request/manifest equality checks, but the equality validator is private to `witness_engine.rs` and no endpoint-side request builder or response collector exists.
  Evidence: `crates/jury-core/src/witness_engine.rs` exposes `WitnessEngine::{reserve,decide,cancel}` while `crates/jury/src` contains no request or approval command family.
- Observation: J10 already models `WitnessPending`, `Approved`, `Denied`, `Expired`, `Stale`, `Replay`, `Unavailable`, `Cancelled`, and `InsufficientQuorum`, and snapshots retain only public request and revision digests. J22 must feed this state machine real provider outcomes instead of adding a parallel session model.
  Evidence: `crates/jury-core/src/session.rs` defines `WitnessRequestBinding`, validates it against the exact revision token, and persists no request-session private key or contribution.
- Observation: the frozen protocol describes `OwnerReviewLabelV1` and `ApprovalPresentationEntryV1`, but the Rust protocol currently implements only the public `ApprovalTargetV1` and `ActionManifestV1` types. Complete human approval is therefore currently impossible and must be implemented before any approval command is enabled.
  Evidence: `docs/security/witness-v1/protocol.md` contains both private-display schemas; `crates/jury-protocol/src/witness_v1.rs` includes no presentation module or label type.
- Observation: witness descriptors intentionally contain cryptographic identity and share metadata but no network address. Witness URLs, CA certificates, and client credentials must remain endpoint-local configuration, not authenticated vault or request state.
  Evidence: `crates/jury-core/src/policy/witness.rs::WitnessPolicyDescriptor` has no URL; `juryd` protects `/v1/requests/*` with a separate client credential.
- Observation: the frozen J19 corpus encodes the optional owner review label as an optional self-delimiting structured value, not as an additional length-prefixed byte string.
  Evidence: the initial implementation with an inner JCE1 `bytes` prefix failed `review_label_and_private_presentation_match_the_frozen_vectors`; matching `conformance/witness-v1/vectors.json` requires presence tag plus exact canonical label bytes.
- Observation: a witnessed policy introduced by policy revision N cannot bind revision N's resulting hash because the witnessed-policy digest is itself embedded in that revision. The existing CLI correctly stored the predecessor hash, but request/checkpoint validation incorrectly required the terminal hash, so real CLI-created witnessed policy could never validate.
  Evidence: `policy_require_witnessed` sets `vault_policy_hash` before preparing the next journal revision; validation now requires `PolicyState::current_predecessor_hash()` and all 34 witness-engine tests pass with the actual non-circular contract.
- Observation: the frozen construction requires a fresh independent request-session HPKE key. A later process cannot execute a publicly persisted request because persisting or deriving its private session key would violate the construction and J22's no-secret-bearing-snapshot rule.
  Evidence: `RequestSessionIdentity` intentionally has no serialization or private-byte accessor; asynchronous human approval therefore requires a foreground coordinator that writes public request evidence and retains the session identity only in protected process memory.
- Observation: `WritePrivateFile` is a secret-read use case whose output capability is `Capability::Write`; hard-coding `Capability::Read` at the CLI provider boundary caused the first real governed file-read workflow to reject its own signed manifest.
  Evidence: the provider now derives the capability from the authenticated operation through the shared `witness_operation_capability` mapping, and the lifecycle fixture completes its private-file read.
- Observation: raw protocol serde is complete but not by itself a meaningful command review because byte-valued executable, argument, and environment names appear as base64 data.
  Evidence: the complete review now includes lossless byte-escaped operation displays plus typed secret targets, while retaining the authenticated raw request, manifest, and presentation; the renderer mutation test fails when printable bytes are replaced.
- Observation: `juryd` reports a too-late cancellation as transport status `too-late` alongside the already-approved response, whose signed reason remains `none`.
  Evidence: the CLI now classifies the race from the authenticated transport status after validating the signed response instead of demanding a synthetic `CancellationTooLate` signature that the service never emits.
- Observation: the normal dirty-worktree Rust file-size check does not include untracked source files, so a passing local check can miss a newly added oversized module.
  Evidence: a temporary-index simulation exposed the new-file coverage gap. The source was reorganized into focused child modules, after which `scripts/jig check rust-file-loc --staged --json` reported no errors and the normal required gate passed without increasing any grandfathered parent.

## Decision Log

- Decision: build J22 on the existing `ItemAccessProvider` and `PrincipalVaultSession` boundaries instead of adding CLI-specific decrypt helpers or a second session state machine.
  Rationale: this is the acceptance seam shared by direct and witnessed modes, keeps revision secrets scoped to an immediate consumer, and makes no-child-before-authorization testable in one place.
  Date/Author: 2026-09-03 / Codex.
- Decision: represent witness service locations and transport credentials in a bounded private endpoint-local config selected explicitly by the CLI; do not add them to `WitnessPolicyDescriptor`, the vault file, action manifest, or receipt.
  Rationale: service routing is deployment state, while the frozen cryptographic state binds witness IDs and key fingerprints. Mixing the two would make transport routing part of the portable cryptographic contract and contradict the project boundary.
  Date/Author: 2026-09-03 / Codex.
- Decision: do not persist request-session private keys, decrypted contributions, reconstructed revision secrets, or partially collected shares. Persist only public request/manifest/presentation artifacts, signed decisions, terminal public status, cancellation intent, and contribution-free receipts; executing a request that needs endpoint secrets must retain them only in protected process memory for that foreground attempt.
  Rationale: J10 and J19 forbid secret-bearing snapshots, while the threat model permits endpoint memory retention but not reusable or durable contribution state.
  Date/Author: 2026-09-03 / Codex.
- Decision: human approval is fail-closed until the full private presentation has been validated and rendered without truncation; JSON output carries bounded complete fields and never acts as an implicit approval confirmation.
  Rationale: J22 explicitly forbids digest-only, opaque-target, and lossy-render approval.
  Date/Author: 2026-09-03 / Codex.
- Decision: interpret a witnessed policy's `vault_policy_hash` as the exact predecessor hash of the policy revision that carries it, and require both the matching sequence and `current_predecessor_hash()` in request/checkpoint validators.
  Rationale: this matches the existing policy-construction flow and is the only non-circular authenticated binding; requiring the resulting revision hash would demand a cryptographic fixed point.
  Date/Author: 2026-09-03 / Codex.
- Decision: accept the endpoint set explicitly on each networked command as bounded `WITNESS_ID,BASE_URL,CREDENTIAL_FILE[,CA_CERTIFICATE]` values instead of creating a durable endpoint-config artifact.
  Rationale: the concrete CLI argument is private deployment routing, is validated before identity unlock, exactly matches the authenticated request witness set, and avoids introducing another human-read process/config artifact or persisting credentials in portable vault state.
  Date/Author: 2026-09-03 / Codex.
- Decision: derive the access-provider capability from the signed operation for every governed path and bind private-file output destinations as `WritePrivateFile`, while stdout remains `ReadStdout`.
  Rationale: this keeps the common provider preflight exact and prevents adapters from supplying a capability that disagrees with the authenticated manifest.
  Date/Author: 2026-09-04 / Codex.
- Decision: expose explicit `verified` and `contains_contribution_material` booleans in offline receipt-verification JSON.
  Rationale: the verifier already established the cryptographic result and the receipt schema is public-only; making both properties machine-visible gives the CLI lifecycle test a direct stable oracle instead of inferring them from prose.
  Date/Author: 2026-09-04 / Codex.

## Outcomes & Retrospective

J22 is implemented and passes the complete repository gate set. The delivered path includes exact request and private-presentation validation, role-bound checkpoint/request/approval/cancellation creators, owner-signed review labels, fresh nonserializable request sessions, authenticated bounded witness transport, a no-direct-slot witnessed provider, complete non-lossy approval review, request lifecycle commands, governed read/inject/exec/run defaults, explicit unilateral direct mode, cancellation-race handling, and contribution-free receipts with explicit offline-verification output. The engine-backed CLI lifecycle proves pending authorization prevents output or child execution, asynchronous independent approval unlocks read/inject/run/exec, receipts contain no contribution material, cancellation can report authenticated too-late status, and protected fixture values do not leak into repository, state, or artifact trees. A complementary core fixture proves an old request, response set, and session cannot open a resealed revision, while a fresh request and quorum succeed.

The test-quality audit outcome is **ACCEPT WITH RESIDUAL RISK**, evidence tier A1 overall with focused A2 oracle analysis for the approval boundary. Baseline replay passed; the candidate suites passed; two isolated mutations were killed by exact rendering and forged-label-signature tests; two consecutive lifecycle runs were stable; and a post-gate hash comparison found zero changes across 25 frozen production/test files. Residual composition gaps are explicit: the CLI lifecycle uses a minimal loopback HTTP adapter around real independent `WitnessEngine` instances rather than the `juryd` process, while the production `juryd` adapter is covered separately; successful interactive approval is not driven through a PTY, although nonterminal refusal, core approval signing, and the asynchronous approval lifecycle are covered; and the CLI operation lifecycle and next-revision freshness proof are complementary fixtures rather than one monolithic fixture. These are limitations on proof strength, not confirmed product failures.

All source remains pre-alpha. The outcome does not establish that Jury protects real secrets, that an endpoint executed or forgot plaintext, or that any review was independent security review.

## Context and Orientation

The repository is a Rust workspace. `crates/jury-protocol` owns exact versioned wire and canonical-encoding types. `crates/jury-core` owns policy validation, identities, sessions, access providers, witness response processing, and cryptographic orchestration. `crates/jury-filesystem` owns capability-safe public/private persistence. `crates/jury` is the synchronous native Linux CLI and process-use adapter. `crates/jury-witness` is the self-hosted `juryd` HTTP service. Transport and terminal concerns must not leak into core.

A revision seal is the random identifier authenticating one descriptor or body revision. A witnessed slot contains Shamir shares of that revision secret, independently sealed to configured witnesses. A request-session key is a new HPKE key pair generated for one request; witnesses encrypt their one-time response shares to its public key. An action manifest is the complete public, secret-free description of the requested use, including typed secret placeholders. A private presentation opens commitments to meaningful item, field, working-directory, and output-destination displays for a human approver. An approval is a separate approver identity's signed decision, not transport login and not a vault-principal or witness signature. A witnessed access provider accepts enough valid responses, opens contribution envelopes into protected memory, checks commitments, interpolates exactly the lowest threshold share indexes, validates the reconstructed revision secret by opening the selected ciphertext, and exposes it only through `ScopedRevisionAccess`.

The frozen format and behavior are in `docs/security/witness-v1/protocol.md`, `construction.md`, `state-machines.md`, and `threat-model.md`; J22's scope and tests are duplicated in `docs/jury-v1-master-plan.md` and Bead `jury-qv4.4.4`. `crates/jury-core/src/witness_engine.rs` is the witness-side verifier and should be refactored only enough to share pure validators with endpoint and approval paths. `crates/jury-core/src/session.rs` already owns public session transitions. `crates/jury-core/src/access_provider.rs` already owns the direct implementation and must gain the witnessed implementation without weakening direct preflight. `crates/jury/src/cli/access_commands.rs` and `execution_commands.rs` currently hard-wire `DirectItemAccessProvider`; these call sites must use one mode-neutral operation boundary.

Durable client state belongs under the existing owner-only platform state root, never in `.jury/` or the portable vault. Creation writes the complete public request bundle atomically. Status reconciliation validates every newly received signed artifact before replacing state. Cancellation writes local intent before contacting witnesses and preserves the distinction between cancelled and too-late. Expiry, denial, replay, stale policy, unavailable transport, and insufficient quorum are terminal or retryable exactly as described by `SessionPhase`; retries reuse the same signed request and expiry and never mint an extended copy. A changed vault checkpoint or revision supersedes rather than silently broadens a request.

## Plan of Work

Milestone 1 makes request construction and approval review possible without networking. Add canonical protocol types for owner review labels and private presentation entries, including subject/presentation enums, canonical encoding, commitments, digests, bounds, ordering, and redacted `Debug`. Add core validation that first performs the common public request/manifest equality check and then verifies the exact private presentation against current policy, current item revision, private names available to the approver, owner-signed labels, normalized directory/output descriptors, and current time. Extract or expose the witness engine's pure equality check so witness, automatic policy, approval, and endpoint paths cannot drift. Add builders that accept an already resolved typed operation description, derive every duplicated field from one source, generate request ID/nonce and a fresh protected session key, sign only after validation with a `VaultPrincipalIdentity`, and produce `WitnessRequestBinding`. Add an approval builder that accepts only a validated/render-complete token and signs with `ApproverIdentity`.

This milestone is complete when protocol vector/unit tests prove every one-bit or duplicated-field mismatch changes or invalidates the digest; presentation tests reject absence, truncation/loss flags, opaque human targets, forged/stale labels, missing entitlement, wrong item/field revision, working-directory/sink commitment mismatch, and extra or missing entries; and role tests prove vault-principal and witness identities cannot enter the approver signer API.

Milestone 2 makes endpoint authorization operational. Add an endpoint-side `WitnessRequestCoordinator` in `jury-core` with a transport trait expressed in typed request/response values and value-free error kinds. It reserves with every intended witness, submits the current signed approval set, validates every response signature and exact request/manifest/session/checkpoint/expiry binding against current policy, classifies denial/stale/replay/unavailable separately, selects distinct current approving witnesses, and reconstructs only at threshold. Add `WitnessedItemAccessProvider` in `access_provider.rs` which performs the same ancestry and capability preflight as direct access, consumes protected request-session private material and validated response contributions, and invokes the existing scoped consumer. Ensure all partial protected buffers are wiped on success, denial, error, cancellation, or panic.

In `crates/jury`, add a bounded blocking HTTPS client for `juryd`'s existing `/v1/requests/reserve`, `/decide`, and `/cancel` routes. Add a private local configuration schema mapping each authenticated witness ID to one URL, CA certificate, and distinct client credential file; validate absolute no-symlink/private-file boundaries before identity/passphrase prompts. Add filesystem helpers for atomic owner-only public request bundles and status records under the platform state root. The bundle contains no session private key or response contribution. Foreground create-and-execute retains the protected session key only in process memory; a later asynchronous execute must create a fresh request rather than pretending durable public state can restore it.

This milestone is complete when fake-transport and self-hosted juryd tests cover pending, automatic approval, human approvals, wrong witness/session/signature, malicious response, partial quorum, denial, stale policy/checkpoint, replay, expiry, unavailable service, and cancellation races, and when scans/assertions show no contribution, private key, revision secret, or field value in Debug, JSON, state files, or logs.

Milestone 3 exposes stable user workflows and joins them to existing use cases. Extend `crates/jury/src/cli.rs` and `dispatch.rs` with `RequestCommand::{Create,Inspect,Status,Execute,Cancel}` and a top-level `Approve` command supporting explicit deny reasons. Define bounded operation-specific arguments that reuse the same typed parsing as `read`, `inject`, `exec`, and `run`. Human inspect/status output reveals names only after the selected identity proves entitlement; JSON contains complete bounded public scope plus meaningful presentation only when authorized. The approve command unlocks an approver identity, validates current descriptor and policy, performs the common request/manifest check, validates every presentation entry, prints every security-relevant field in full with no terminal-width truncation, requires an explicit terminal confirmation for approval, and then signs. Non-interactive automation must use an automatic approver policy; it cannot assert that a human reviewed an opaque JSON digest.

Refactor field read, template injection, transparent exec, and brokered run so they all accept the same provider/use-case operation. Default selection follows authenticated item policy: witnessed-only and mixed use witnessed authorization; direct mode requires an explicit `--direct` flag and output always says `authority: direct-unilateral`. Do not spawn or prepare a child with secret material until the provider returns `WitnessedApproved`. Request status and command errors use stable distinct codes and exits for pending, denied, expired, stale, replay, unavailable, cancelled, and insufficient quorum.

This milestone is complete when CLI parser, human-output, JSON-schema, and workflow tests exercise create/inspect/approve/deny/status/execute/cancel and the default/explicit-direct distinction. Existing direct tests must remain valid after updating invocations to state direct intent where required.

Milestone 4 proves the complete product outcome and updates documentation. Build an end-to-end generic fixture with separate `ExamplePrincipal`, two `ExampleApprover` identities, and multiple self-hosted witnesses. Create a witnessed-only item with no direct slot; authorize and complete read, inject, transparent exec, and brokered run; verify the portable contribution-free receipt offline; mutate/reseal the item; prove the old request and retained endpoint-visible artifacts cannot open the new seal; obtain a new approval quorum and succeed. Add command-digest broadening, cancellation-race, no-child-before-authorization, response tamper, and leak scanning tests. Update README and self-hosting docs to explain client configuration and to state all receipt, endpoint-retention, transport-health, execution, and pre-alpha nonclaims.

This milestone is complete only after all focused tests and repository checks pass and a requirement-by-requirement audit identifies direct evidence for every Required Test and Acceptance Criterion in `jury-qv4.4.4`.

## Concrete Steps

Work from `/home/aa/Documents/jury`.

First create and maintain this Jig work session. Confirm it remains attached with:

    scripts/jig work status

For Milestone 1, edit `crates/jury-protocol/src/witness_v1.rs` and focused files below `crates/jury-protocol/src/witness_v1/`; edit `crates/jury-core/src/identity.rs`, `witness_validation.rs`, and a new focused `witness_client.rs` or smaller child modules exported from `crates/jury-core/src/lib.rs`. Run:

    cargo test -p jury-protocol witness_v1 -- --nocapture
    cargo test -p jury-core witness_client -- --nocapture
    cargo test -p jury-core witness_engine -- --nocapture

For Milestone 2, edit `crates/jury-core/src/access_provider.rs` plus focused endpoint modules, `crates/jury-filesystem` only for generic capability-safe persistence helpers, and `crates/jury` for transport/config adapters. Run:

    cargo test -p jury-core access_provider -- --nocapture
    cargo test -p jury-core witness_client -- --nocapture
    cargo test -p jury-witness self_hosted -- --nocapture
    cargo test -p jury native_cli -- --nocapture

For Milestone 3, edit `crates/jury/src/cli.rs`, `cli/dispatch.rs`, new focused request/approval/transport modules, and the existing access/execution modules. Keep command parsing in `jury`, invariant checking in `jury-core`, and canonical wire behavior in `jury-protocol`. Run:

    cargo run -p jury -- request --help
    cargo run -p jury -- approve --help
    cargo test -p jury --test native_cli -- --nocapture

For Milestone 4, add end-to-end tests under `crates/jury/tests/native_cli/` and, if a real multi-service harness is clearer, `crates/jury-witness/tests/`. Use only generic fixture names and values. Then run:

    scripts/jig work check
    scripts/jig work evidence
    scripts/jig work gates
    scripts/jig check fmt
    scripts/jig check clippy
    scripts/jig check test

Expect every command to exit zero without suppressed stderr. Review `git diff --check`, `git diff --stat`, and the full diff for leaked fixtures, stale J22-deferral text, and missing dependent updates. If and only if every acceptance item has direct evidence, run `scripts/jig work finish`, close `jury-qv4.4.4` with reason `Completed`, and `br sync --flush-only`.

## Validation and Acceptance

Protocol validation must prove canonical encodings and digests, not merely serde round trips. Changing any request breadth field—item, field set, role, operation, executable identity, public argument, placeholder, environment injection, stdin target/mode, directory, sink, assurance, timeout, or output limit—must change the workload and/or manifest and request digest. A correctly signed request whose duplicate differs from its manifest must fail before display, policy matching, approval signing, or network submission.

Meaningful approval must be exercised at every supported terminal width. The rendered form may wrap but may not elide, truncate, hash-only, hide behind scrolling, or omit any security-relevant field. A human decision is impossible if the private presentation is absent, incomplete, opaque, forged, stale, or cannot be independently checked. A machine-only automatic rule uses zero commitments and the canonical empty presentation and never produces a human-review claim.

Authorization validation must accept only current independent approver signatures and current distinct witness responses for the exact request session. Tests must include forged/replayed/revoked decisions, wrong request/manifest/policy/witness-set/key-epoch/expiry, malicious contribution envelopes, duplicated witnesses, and a response encrypted to another session. No direct recipient slot, raw key, epoch root, share, or reusable contribution may be introduced or exposed.

The user-observable end-to-end acceptance transcript must show a witnessed-only item's request becoming pending, gaining separate approvals, reaching quorum, completing read/inject/exec/run, and producing a receipt that verifies offline while stating its nonclaims. After the item's next revision, execution with the earlier request must return a distinct stale or wrong-scope result and no child process may start; a new exact request and fresh quorum must then succeed.

The completion audit maps every bullet in the Bead's Outcome, Scope, Required Tests, and Acceptance Criteria to a source path and a passing test or observed command. Green unit tests alone do not prove full UX completion.

## Idempotence and Recovery

Builders are pure except for explicit random and clock inputs, so failed construction writes nothing and can be retried. Public request-state writes use prepare-and-publish operations and preserve prior valid state if publication fails. Retrying network submission reuses the same signed request and is idempotent at `juryd`; it never changes expiry or request ID. A cancellation retry reuses the same signed cancellation. A terminal stale, replayed, denied, expired, or cancelled request cannot be regenerated in place; create a new request from current authenticated state.

Never recover by weakening assertions, regenerating security vectors, widening tolerances, adding suppression pragmas, printing protected material, or falling back to direct access. If a request-session secret is lost after process exit, retain the contribution-free public history but create a new request; do not persist or reconstruct the old secret. If the worktree becomes dirty from unrelated user changes, preserve them and keep J22 edits scoped.

## Artifacts and Notes

Authoritative baseline:

    Git commit: 7c9f7e2 chore(agent): close J23 hardening work
    Bead: jury-qv4.4.4, status in_progress
    Dependencies: J10/J13/J14/J19/J21/J23 closed
    Initial gap: no `jury request` or `jury approve`; README says request/open remains J22 work

The J19 gate is already closed and binds the exact construction/protocol inputs. J22 may implement those frozen primitives and messages but must not silently revise the construction, vectors, threat model, or gate verifier to make implementation easier.

## Interfaces and Dependencies

At the protocol boundary, implement exact bounded types corresponding to `OwnerReviewLabelV1`, `ApprovalPresentationEntryV1`, and the complete presentation list described in `docs/security/witness-v1/protocol.md`. Their canonical methods must follow the existing pattern: `canonical_bytes`, `digest` or `commitment`, and `validate_shape`, using only existing JCE1 canonical helpers and SHA-256 domains. Do not serialize private presentation material into `WitnessRequestV1`, `WitnessResponseV1`, or `WitnessReceiptV1`.

At the core boundary, expose one pure common function that validates `WitnessRequestV1` against `ActionManifestV1` and exact current policy/item evidence. Introduce validated wrapper tokens that cannot be constructed by adapters and are required by approval signing and automatic matching. Add request/approval creators with explicit `RandomSource`, protected-memory policy, and clock inputs. Export role-specific signing only through these validated creators; do not make raw identity signing public.

Add a transport-independent coordinator trait whose adapter method set matches reserve, decide, and cancel and whose outputs are typed `WitnessResponseV1` or bounded public status. Add `WitnessedItemAccessProvider` implementing the existing generic `ItemAccessProvider::access_revision`; it must return the existing `ItemAccessOutcome::Witnessed` variants for non-complete states and `AccessCompletion::WitnessedApproved` only after threshold reconstruction validates the requested ciphertext.

At the CLI boundary, use `reqwest`'s blocking rustls client already present in the workspace lockfile, with a bounded body, explicit timeout, configured CA, no insecure non-loopback HTTP, no redirects to a different authority, and a separate client bearer credential. Keep its types private to `crates/jury`. Use `jury-filesystem` capabilities for all local private config and request-state reads/writes. Structured output uses serde structs with `deny_unknown_fields`, bounded enums/IDs, and no provider strings or secrets.

Revision note (2026-09-03): created the initial self-contained J22 plan after inspecting the live Bead, dependency seams, frozen protocol, current session/provider APIs, and absent CLI workflow. The milestone split is chosen to make security-critical validation independently provable before transport or UX can call it.

Revision note (2026-09-03): implemented the first Milestone 1 protocol increment. Added exact owner-label and private-presentation values and recorded the corpus-defined structured-optional encoding after the frozen vector caught an incorrect extra length prefix.

Revision note (2026-09-03): completed the protocol/core authorization increment and recorded the non-circular predecessor-hash semantics and foreground-only request-session lifetime discovered while integrating the real CLI-produced policy state.

Revision note (2026-09-03): completed implementation, split oversized new Rust modules after staged-policy simulation exposed untracked-file blindness, reran the full workspace and all required gates, froze and rechecked the audited source/test set, and recorded the acceptance outcome and residual proof limitations before work closure.
