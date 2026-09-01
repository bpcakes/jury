# Finish J13 native identity, administration, read, and injection CLI

This plan completes Beads task `jury-qv4.3.2`. Its concrete consumer is the
native Linux `jury` operator CLI and the release tasks J14/J22 that depend on
its guarded access surface. It gates the defect class in which command adapters
bypass item-scoped authorization, mutate before validating quorum/mode changes,
or leak plaintext through output. The plan is complete and may be archived when
the task's acceptance criteria are proven and the bead is closed.

## Progress

- [x] Reconcile the active bead with `docs/jury-v1-master-plan.md` and inspect
  the existing identity/vault foundation at baseline
  `3571ff806b4f7666318a81247c923554e6cb3f6d`.
- [x] Add the complete bounded command grammar and stable human/JSON result and
  error contracts for J13's active Linux scope.
- [x] Route selected-item discovery/read/mutation through `ItemAccessProvider`,
  with uniform unavailable behavior and no unrelated body decryption.
- [x] Implement principal/access/witness-policy administration, authenticated
  dry-runs, commit-compatible previews, quorum preflight, and explicit direct
  downgrade acknowledgement.
- [x] Implement field/item operations, controlled read/private output,
  all-or-nothing template injection, privacy cover, local audit verification,
  and public history/capacity status.
- [x] Implement public identity descriptor/proof artifacts and the clone trust
  workflow required for first private use.
- [x] Exercise repository/global/explicit/detached homes and the complete Linux
  CLI suite, then run Jig fmt, clippy, test, and contract gates.
- [x] Perform a requirement-by-requirement completion audit, update docs,
  close `jury-qv4.3.2`, flush Beads, and finish this work session.

## Surprises & Discoveries

- The current CLI is intentionally only a foundation: identity
  init/list/status/passphrase change and empty-vault init/status. No J13
  administration, item, read, inject, audit, or cover command exists yet.
- J11 already supplies exact mutation plans and Git-backed durable commit, while
  J10 supplies the mode-neutral `ItemAccessProvider` and scoped session seams.
  J13 should compose those APIs rather than introduce adapter-only decryption.
- The existing commit adapter is repository-specific even though core mutation
  preconditions explicitly allow detached stores. J13 must add the detached
  publication path rather than silently limiting mutation to Git homes.
- Frozen witness capsules are ordered by Shamir share index, while policy
  membership is canonicalized by principal ID. Validation and construction must
  therefore compare the member set independently and order capsules by share
  index; zipping the two orders rejects valid witnessed policy.
- Owner grant/revoke and principal replacement affect every item in one policy
  revision. Per-item mutation validation cannot prove that global invariant, so
  the core now prepares opaque components and validates the complete batch once.
- A new direct recipient is itself a unilateral-access expansion even when an
  item was already in direct mode. The acknowledgement check now covers that
  recipient-set expansion and normalizes principal replacement so key rotation
  is not misclassified as a downgrade.

## Decision Log

- Keep cryptographic and authorization decisions in `jury-core`; keep command
  parsing, protected input, controlled sinks, and stable presentation in
  `crates/jury`.
- Treat direct, witnessed-only, and mixed as path-specific states. Mixed mode
  suppresses item-level quorum claims instead of being presented as witnessed
  protection.
- Use one authenticated current-artifact load for preview and bind a real commit
  to its exact artifact/repository preconditions. `--json` never implies
  confirmation.

## Outcomes & Retrospective

J13 now ships the native Linux identity, vault, item/field, principal/access,
witness-policy configuration, read/private-output/inject, privacy-cover, audit,
and public history/capacity command surface. Registration proofs bind the vault,
candidate signing and recipient keys, requested role, owner, expiry, and random
challenge response. Item reads and mutations resolve through the scoped access
provider, multi-item authority changes publish one validated revision, detached
homes use the same durable mutation/reconciliation rules, and direct-recipient
expansion requires an explicit acknowledgement before private input.

Acceptance is covered by the four native CLI integration cases: direct operator
workflow, witnessed-only configuration plus impossible-quorum/implicit-direct
refusals, explicit detached-home mutation, and non-terminal passphrase refusal.
Adversarial core tests cover registration substitution/tampering/expiry and
atomic multi-item owner grant/revoke. Final evidence is the passing Jig `test`
receipt `receipt_01M1CW5GE5WMHG390XFXGP9B94`, clippy receipt
`receipt_01M1CVTSMKNC6PHJEPKFDE5EV7`, contract receipt
`receipt_01M1CVTRC8H9W6JXWYJV21YKCS`, format receipt
`receipt_01M1CVTS8ZFB62233JGSP0E5H2`, and Rust LOC receipt
`receipt_01M1CVTRNYYH6EMP52E6SWBCGA`. The CLI implementation and integration
tests are organized by responsibility into bounded Rust modules; the LOC gate
passes without exclusions or threshold changes.

Witnessed request/approval/open execution remains J22 work. Portable transfer of
the local signed role-descriptor and witness-policy catalog remains J16/J23
work. The README states both limits and retains the repository-wide pre-alpha
warning; J13 does not claim that Jury protects secrets.

## Context and orientation

`crates/jury/src/cli.rs` owns Clap parsing and presentation.
`crates/jury/src/home.rs` owns deterministic home selection.
`crates/jury/src/mutation_commit.rs` composes core mutation plans with durable
shared and local state. `crates/jury-core/src/access_provider.rs` is the only
selected-item opening seam, `session.rs` provides catalog-scoped operations,
`item.rs` prepares item creation/rekeying, and `mutation.rs` validates complete
artifact transitions. `crates/jury-filesystem` owns no-follow bounded I/O and
atomic publication. Linux end-to-end tests live in
`crates/jury/tests/native_cli.rs`.

## Plan of work

First make the command and result contracts explicit. Then add a reusable
authenticated command context that selects the home and identity, validates the
public vault, verifies or initializes clone-local state under explicit trust,
and exposes only `ItemAccessProvider`-backed item operations. Compose item and
policy changes into `VaultMutationPlan`, support both repository and detached
atomic publication, and surface exact committed/recovery states. Add controlled
plaintext sinks and a bounded parser for injection before integrating principal
registration and witnessed-policy artifacts. Finish with adversarial Linux
workflows and documentation that says only what actually ships.

## Concrete steps

1. Expand parser tests and output/error schemas for every J13 family.
2. Add public status/history and audit verification, which require no plaintext
   sink, and prove their value-free output.
3. Add authenticated identity/vault loading and accessible descriptor catalog
   discovery through `DirectItemAccessProvider`.
4. Add item creation, field mutation/list/read, private output, injection, and
   cover, with exact mutation-plan and publication results.
5. Add principal challenge/proof, add/replace/remove/owner changes, access
   mutations, and role-specific approver/witness membership.
6. Add witnessed-policy require/status/explain and direct-mode acknowledgement,
   rejecting impossible quorum or membership changes before mutation.
7. Add clone trust and detached-home publication, then run complete tests and
   update README/architecture nonclaims.

## Validation and acceptance

Focused development uses `cargo test -p jury --test native_cli` and crate unit
tests. Final verification uses `scripts/jig work check`,
`scripts/jig check fmt`, `scripts/jig check clippy`,
`scripts/jig check test`, and `scripts/jig check contract`. Acceptance requires
fresh-operator witnessed-only configuration with both quorums, pre-mutation
rejection of impossible quorums and implicit direct downgrades, provider-backed
selected-item operations, deterministic home/trust behavior, stable leak-free
human and JSON output, and help that preserves Linux/pre-alpha nonclaims.

## Idempotence and recovery

All mutation previews are read-only. Durable mutation retries use the exact
target digest and the existing audit/checkpoint reconciliation path; they never
regenerate entropy or signatures after a shared artifact commit. Output
destinations are create-new unless explicit overwrite is requested and validated.
Interrupted work can resume from this plan and current Beads/Jig state.

## Interfaces and dependencies

J13 depends on the J03 domain identifiers, J10 item-access provider/session,
and J11 mutation plan/commit APIs. It must not add a Jig runtime dependency.
J14 consumes the resulting item resolution and controlled injection contracts;
J22 consumes the witnessed policy and request-ready surface later.
