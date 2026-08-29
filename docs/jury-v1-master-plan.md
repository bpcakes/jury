# Jury format v1 / product 0.x master plan

Status: authoritative implementation plan; pre-alpha; no production security claims.

Plan date: 2026-08-28.

Product: Jury, the experimental portable vault with witnessed open as its
defining authority path.

Primary repository: this Jury repository.

Legacy source repository: the sibling Jig repository at baseline commit
`eed70cee337b0067ed92deb9fa05017b0b284605`.

Legacy source-plan digest:
`ed670ec63eaa9814ea0a01a0d4b2af6a65ccb68e68e307bac9109dd4286fb49a`.

The exact source snapshot is preserved at
`docs/provenance/jig-vault-security-scopes-plan.source.md`.

That snapshot was an uncommitted 7,810-line working-tree document when imported.

This document, not the snapshot, is Jury's normative plan.

## 0. How to use this plan

### 0.0 Witnessed-first release scope

This section supersedes conflicting direct-only or deferred-witness language
elsewhere in this document.

- The active deliverable is an experimental witnessed-access Jury `0.x` release
  using `jury-vault` format version 1 and witness protocol version 1.
- J19-J23 are release-critical outcomes. Governed items require fresh signed
  approval and witness contributions for the exact revision seal and action
  manifest before read, inject, or exec can cross the guarded item boundary.
- Direct slots remain supported as an explicit unilateral bootstrap, recovery,
  or low-assurance mode. Any usable direct slot defeats the quorum claim for that
  item and must be reported as such.
- Every `0.x` build retains the pre-alpha warning and is not for real secrets.
- J01A and J01B gate shared primitives and direct cryptography. J19 separately
  gates witnessed/distributed cryptographic implementation and requires
  independent review of the exact construction, vectors, proof, and revision.
  Self-review or AI-assisted review never satisfies that gate.
- The current release has 30 active outcomes: J01A, J01B, J02-J14, J16-J26,
  and the J19A-J19D gate components. J15 is post-`0.x` compatibility work and
  does not gate release. J26 may not ship by excluding, stubbing, or relabeling
  J19-J23.
- The fourteen planning reviews in section 25 are historical. No readiness
  report, certificate, matrix, dashboard, or evidence ledger is required unless
  it has a concrete consumer, named gate, observed defect, and deletion
  condition.

### 0.1 Purpose

This plan moves the valuable Jig vault v3 security-scopes design into Jury as a
standalone product design rather than treating Jury as another Jig version.

The public version reset is intentional:

- the product begins as Jury `0.x` and reaches product `1.0` only after its
  security and release gates pass;
- the portable artifact begins with magic `jury-vault` and format version `1`;
- the witness wire protocol begins at protocol version `1`;
- the Jig v3 artifact is never shipped as a compatibility predecessor to Jury;
- Jig v1 and Jig v2 remain legacy import sources, not Jury format versions.

This distinction prevents three unrelated compatibility dimensions from being
collapsed into one number.

Every implementation bead may use a task-local ExecPlan when the work is
complex, but the bead owns a concrete result rather than the act of planning.

### 0.2 Normative language

`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` express implementation
requirements in decreasing order of force.

A later protocol specification may make a requirement stricter.

It may not weaken a security invariant here without an explicit plan revision,
threat-model explanation, and new negative tests.

Examples illustrate behavior and do not override typed schemas or test vectors.

### 0.3 Precedence

The Jury-specific rules in section 0 define the architecture and vocabulary;
sections 1 through 24 elaborate them with source-derived detail.

Any contradiction between them is a plan defect rather than an implementation
choice and must be corrected before the affected public surface freezes.

The main known precedence rules are:

1. `jury-vault` format v1 replaces the proposed Jig vault format v3.
2. Native Jury storage has typed `ItemName` and `FieldName` values, never
   `jig://` strings.
3. A downstream adapter may parse `jig://ITEM/FIELD` and translate it at its
   own boundary.
4. Every recipient slot is algorithm-tagged and versioned.
5. Witnessed open is the defining active `0.x` path. Direct and witnessed slots
   are both frozen in format v1 before implementation and share one guarded
   item-access architecture.
6. Callers receive capability-scoped item operations through an unwrapper; they
   never receive identity private-key handles.
7. Witness requests, replay state, approvals, receipts, and `juryd` are active
   release contracts; none may expose epoch roots or reusable contributions.
8. Importing Jig v2 creates a new Jury home and never replaces the Jig source.
9. Native Jury CLI and TUI behavior belongs here; compatibility behavior of
   `jig vault ...` belongs in `docs/jig-cutover-plan.md`.
10. Jury has no runtime, build, protocol, environment, or home-resolution
    dependency on Jig.

If an implementation agent finds another contradiction, it MUST stop that bead,
record the exact conflict, and resolve it in the plan before freezing a public
format or protocol.

### 0.4 Decision summary

Jury owns five independently versioned surfaces:

| Surface | First public identifier | Compatibility owner |
| --- | --- | --- |
| Product release | experimental `jury 0.x` | CLI/release policy |
| Portable artifact | `jury-vault`, version `1` | `jury-core` |
| Witness messages | protocol version `1` | `jury-protocol` |
| Receipts | receipt version `1` | `jury-protocol` |
| Jig adapter | downstream-defined | Jig cutover plan |

The separation matters because the witness service can evolve without rewriting
the vault, and the Jig adapter can evolve without entering Jury's domain model.

### 0.5 Product promise

Jury's initial experiment is witnessed open. A governed operation binds the
exact requested action and revision seal, collects current approver signatures,
obtains contributions from the required witnesses, and releases only scoped
revision secrets to the guarded operation. No one witness has unilateral access
under the accepted J19 construction and deployment assumptions.

Direct local access remains available only when policy and format explicitly
include a direct slot. That recipient has unilateral access; the product must
surface that fact and make no quorum claim for the affected item.

No Jig process is required to operate a Jury vault.

An authorized endpoint can retain plaintext or revision secrets it legitimately
receives.

The first release therefore MUST NOT claim:

- use-without-view on an ordinary endpoint;
- deletion of plaintext already observed by an authorized principal;
- retroactive revocation of retained ciphertext and keys;
- authoritative global freshness for offline copies;
- resistance to an already-compromised endpoint during authorization;
- protection from root, a debugger controlling the process, DMA, or
  hibernation capture;
- any assurance beyond the exact scope and revision of J19's independent review.

Witnessed access is active through the J19-reviewed construction. Other
attested, post-quantum, or threshold schemes remain later recipient-slot
algorithms and require their own scope decision, threat model, and conformance
corpus.

### 0.6 Delivery boundary

Jury v1 includes:

- encrypted local human and machine identities;
- a portable encrypted artifact;
- signed public policy over opaque item identifiers;
- private item and field names;
- per-revision descriptor/body seal secrets for direct and witnessed access;
- exact reader and writer grants;
- cryptographic rekeying for effective reader-set changes;
- partial unlock and scoped sessions;
- direct and witnessed recipient slots frozen together in format v1;
- a stable unwrapping interface;
- signed approval and exact action-manifest workflows;
- replay-safe witness contributions and a self-hostable `juryd`;
- offline-verifiable decision receipts and witness recovery operations;
- local audit and rollback checkpoints;
- transfer, backup, recovery, and history rollover;
- copy-on-write Jig v1/v2 migration;
- a native `jury` CLI and `jury-tui`;
- adversarial, property, fuzz, failure-injection, and benchmark gates;
- reproducible experimental releases with inspectable cryptographic code.

Jury v1 excludes:

- a general-purpose secrets database API;
- automatic background distribution of a changed artifact;
- transparent synchronization between divergent offline copies;
- enterprise identity integrations unless separately scheduled after the core;
- a proprietary cryptographic server path;
- an in-place rewrite of a Jig vault;
- dual writes between Jig v2 and Jury;
- a runtime library dependency from Jury to any Jig crate;
- a courtroom metaphor in protocol or implementation types.

### 0.7 Repository architecture

The workspace starts with these packages:

| Package | Owns | Must not own |
| --- | --- | --- |
| `jury-core` | domain rules, vault state, identity orchestration, item access | HTTP, terminal rendering, Jig types |
| `jury-protocol` | bounded request, approval, response, and receipt contracts | storage, HTTP, databases, terminal rendering |
| `jury` | command parsing, input/output, process adapter | cryptographic policy decisions |
| `jury-tui` | keyboard UI and presentation state | raw key access, transport policy |
| `jury-witness` | transport-independent witness engine and `juryd` adapters | CLI/TUI state, raw application secrets |

`jury-core` and `jury-protocol` MUST remain acyclic foundation crates.

If shared primitive types are needed, move a narrowly scoped representation to a
small leaf crate only after the dependency cannot be expressed through an
existing boundary.

Do not make `jury-core` depend on server databases, HTTP clients, Tokio, Ratatui,
or command-line parsers.

Do not make `jury-protocol` depend on `jury-core`; it must remain usable by an
independent verifier and non-Rust implementation.

Adapters MAY depend on both foundations.

### 0.8 Native domain model and adapter rule

Jury's native domain types are semantic values rather than URI-shaped strings:

```text
VaultId
PrincipalId
ItemId
ItemName
FieldName
ItemSelector
FieldSelector
Grant
KeyEpoch
PolicyRevision
ItemRevision
```

The portable artifact stores random `ItemId` values publicly and encrypted
`ItemName`/`FieldName` values privately.

It does not store `jury://`, `jig://`, filesystem paths, project identifiers, or
adapter routing information.

The native CLI accepts a canonical item name plus field name as separate typed
arguments or one documented selector syntax.

That syntax is a CLI concern and is not serialized into the cryptographic
domain.

A Jig adapter owns this translation:

```text
jig://ExampleItem/EXAMPLE_FIELD
        |
        v
JigReferenceAdapter::resolve()
        |
        v
FieldSelector { item: ItemName("ExampleItem"), field: FieldName("EXAMPLE_FIELD") }
```

The adapter MUST reject routing components Jury does not understand.

It MUST NOT add Jig identifiers to signed preimages, item plaintext, audit
events, or witness requests.

This keeps a future Git client, shell integration, or CI runner from inheriting
Jig's syntax.

### 0.8A Git-backed native storage and trust

Inside a Git worktree, Jury's native default home is:

`<worktree-root>/.jury/`

The portable shared artifact is:

`<worktree-root>/.jury/vault.json`

It is encrypted, signed, intended to be committed, and remains Jury's shared
source of truth. Git transports and versions the artifact. Git does not enforce
Jury authorization, authenticate a mutation, establish freshness, or replace
Jury's signed policy and item ancestry. Git authorship, signed commits, pull
request approval, protected branches, and merge commits never grant Jury
principal authority.

Jury V1 does not use clean/smudge encryption filters and never materializes a
plaintext vault in the worktree. `jury init` creates a repository-local
`.jury/.gitattributes` rule that disables ordinary textual diff and merge for
`vault.json`. Any optional semantic diff or merge driver invokes Jury's bounded
public operations; absence or failure of that driver leaves a conflict rather
than falling back to textual merge.

The fixed `.jury/vault.json` path is sufficient for V1 discovery. A later
`.jury/config.toml`, if introduced, is public non-authoritative configuration:
it cannot redirect outside `.jury`, select a private identity, weaken
verification, or serve as the trust pin for an artifact committed beside it.

Native home selection has this precedence:

1. an explicit `--home PATH`;
2. an explicit `--global`, which conflicts with `--home`;
3. the absolute `JURY_HOME` non-interactive override when neither flag is set;
4. the nearest containing Git worktree root's `.jury` home;
5. the platform global default.

The Linux global default is
`${XDG_DATA_HOME:-$HOME/.local/share}/jury/vaults/default`. macOS uses
`~/Library/Application Support/jury/vaults/default`. Windows uses the
documented per-user local application-data directory under
`jury/vaults/default`. An explicit Jig adapter always passes an absolute home
and does not participate in native discovery.

Repository discovery walks ancestors to the nearest bounded no-follow `.git`
directory or linked-worktree `.git` file and does not place its path, repository
name, Git object ID, ref, remote, or configuration into Jury domain types,
signatures, policy, item bodies, witness messages, audit events, or receipts.
Nested repositories and worktrees select their nearest worktree root.

Private identities remain under the section 12.1 platform data root. Local
rollback and operational state instead lives below a separate platform state
root:

- `${XDG_STATE_HOME:-$HOME/.local/state}/jury/vaults` on Linux;
- `~/Library/Application Support/jury/state/vaults` on macOS;
- the documented per-user local application-state directory under
  `jury/state/vaults` on Windows.

`JURY_STATE_HOME` overrides that state root. The resolved state path is:

`<state-root>/<vault-id>/<genesis-fingerprint>/<principal-id>/`

It contains checkpoint, audit, receipts, locks, and recoverable local
transaction state. It must not equal, contain, or be contained by the selected
vault home or Git worktree. Clones and linked worktrees for the same vault,
genesis, and principal share this state and its cross-process lock. Normal
transfer and Git history contain none of it.

A fresh clone has no retained checkpoint. Before private work, an interactive
operator must explicitly confirm the validated genesis fingerprint. A
non-interactive caller must supply the expected fingerprint from a trust source
outside the cloned repository. A fingerprint stored in the same repository is
useful for display but is not an independent substitution defense.

Opening an older Git commit or a divergent branch never silently lowers retained
state. Strict descendants may advance it. Independent-item progress is offered
to the J16 authenticated merge. A behind artifact, policy fork, same-item fork,
wrong genesis, or cross-lineage artifact fails closed with value-free status.
Historical inspection, if exposed, is explicitly non-mutating and cannot
perform private use or lower the retained checkpoint.

J16 owns bounded public verification, value-free semantic diff, and
ancestry-aware three-way merge over explicit base/ours/theirs artifacts. Every
input is independently parsed and authenticated. Conflict markers fail before
private work. Git's merge result is never accepted merely because Git produced
it.

Git history is permanent for Jury's security claims. A removed direct recipient
who retained an old private key and old repository objects may decrypt old
ciphertext addressed to that key. Rekeying and principal replacement protect
later revisions only; affected external credentials still require rotation.
Witnessed paths retain their exact revision and freshness rules. Documentation
also discloses public principal/grant relationships, opaque item counts, size
buckets, revision activity, and Git timing. Users who reject those metadata
leaks use `--home` or `--global` detached storage.

### 0.9 Item-key unwrapping boundary

Item access is expressed through an interface, conceptually:

```rust
pub trait ItemAccessProvider {
    type Error;

    fn access_revision<T>(
        &self,
        request: RevisionAccessRequest<'_>,
        use_secrets: impl FnOnce(&mut ProtectedRevisionSecrets) -> Result<T, Self::Error>,
    ) -> Result<T, Self::Error>;
}
```

The exact Rust signature may change to support async witness transport without
infecting synchronous core state with runtime-specific traits.

The semantic contract MUST NOT change:

- the caller supplies a validated, authorization-scoped request;
- the implementation selects and validates exactly one supported recipient
  path and the requested revision seal;
- raw identity private keys never leave the identity provider;
- raw witness keys never leave the witness provider;
- a direct implementation decapsulates only the requested revision secrets and
  zeroizes all intermediate and optional epoch state before invoking the
  consumer;
- a witnessed implementation never reconstructs, receives, or exposes the item
  epoch root or any material reusable for another revision;
- descriptor and body revision secrets are separate types scoped to one vault,
  item, epoch, role, revision, and random revision seal identifier;
- the closure cannot store a borrow of the protected revision secrets;
- errors contain no slot ciphertext, secret-dependent detail, or key bytes;
- cancellation and failure zeroize partially assembled material;
- success does not imply the endpoint forgot the resulting plaintext.

Direct and witnessed implementations share the same authorization preflight,
`ProtectedRevisionSecrets` result type, and audit boundary.

The CLI, TUI, importer, backup code, and Jig adapter MUST call item use cases,
not an identity decryption primitive.

### 0.10 Algorithm-tagged recipient slots

The artifact uses a closed, versioned union such as:

```text
RecipientSlotV1 =
  | DirectHpkeV1 { recipient, encapsulated_key, ciphertext, bindings }
  | WitnessedV1  { policy_id, endpoint_commitment, witness_set, capsules, bindings }
```

The serialized representation contains an explicit algorithm tag and slot
schema version before algorithm-specific fields.

Every variant shares these authenticated bindings:

- vault ID;
- item ID;
- key epoch;
- policy sequence;
- recipient principal ID or witnessed-policy ID;
- exact access role;
- cryptographic suite;
- slot schema version.

Every encrypted descriptor/body seal additionally binds its content revision,
role, and fresh random 32-byte `RevisionSealId`. A witnessed capsule binds one
exact revision seal and contains or reconstructs only that seal's revision
secret. It never contains an epoch root or reusable witness contribution.

Unknown tags or versions fail closed.

No reader may interpret an unknown witnessed slot as direct HPKE.

No writer may silently downgrade a witnessed item to direct mode.

An explicit owner-authorized policy operation records any slot-algorithm change,
increments the key epoch, rotates any construction-internal epoch secret, creates
fresh revision seal identifiers, reseals
descriptor and body ciphertext, and replaces the complete slot set.

One authenticated suite identifier is fixed at lineage genesis. There is no
suite negotiation, preference list, retry under another suite, classical/PQ
fallback, or mixture of active suites inside a lineage. Unknown suites fail
before private work. Suite change requires authenticated decryption and
re-encryption into a new lineage as specified in section 10.1.

Direct HPKE ships first because it supplies a testable local vertical slice.

The format and APIs are nevertheless frozen only after the witnessed variant's
bindings and downgrade rules are specified.

### 0.11 Witness request contract

A witnessed request is request-specific and bounded.

Its signed canonical preimage contains at least:

- protocol family and version;
- request ID generated from cryptographic randomness;
- client nonce;
- vault ID and genesis fingerprint;
- current policy sequence and policy digest;
- item ID;
- item key epoch and slot identifier;
- requesting principal ID and signing-key fingerprint;
- requested operation;
- command, workload, or output-sink digest when relevant;
- action-manifest digest when approval is possible;
- issuance time;
- absolute expiry time;
- optional not-before time;
- request-specific suite KEM/HPKE session public key;
- requested witness-policy identifier;
- client signature.

The operation is a typed enum.

It MUST distinguish at least read-to-stdout, write-private-file, template
injection, child-process environment, child-process stdin, item mutation,
backup, recovery, and administrative rekey.

A request for one operation cannot be replayed as another.

The command digest binds the normalized executable and argument bytes actually
approved; it MUST NOT include secret values.

Any request field duplicated by `ActionManifestV1` exists for bounded policy
routing, not as a second source of truth. Before rendering, automatic matching,
signing an approval, or counting a decision, the common protocol validator
requires canonical semantic equality for operation, vault/item/field selectors,
principal, policy revision, command/workload/output-sink binding, expiry, and
every other overlapping field. Both individually valid objects are rejected if
any duplicated field differs; neither the approver nor witness may select which
copy to trust.

If a platform cannot prove a stable executable identity, the receipt states the
weaker command-binding semantics.

Witnessed authorization is denied when the client's checkpoint proves the
request is based on stale policy.

An offline endpoint without acceptable freshness proof receives a typed
freshness error rather than an optimistic approval.

#### 0.11.1 Approver identity, action manifest, and decision

Approval identity is independent of vault-principal and witness identity. A
`WitnessPolicyV1` contains versioned `ApproverDescriptorV1` entries with an
opaque approver ID, strict suite verification-key bundle and fingerprint, key
epoch, status, allowed operation classes, and the exact approval rule. Reusing the same
person or hardware for another role does not reuse its key or collapse those
roles in protocol state.

Every request that can require human or machine approval binds an
`action_manifest_digest`. `ActionManifestV1` is a bounded canonical typed
description of what the endpoint will do. As applicable it contains the
operation, opaque item and field selectors, a policy-authenticated
`ApprovalTargetV1`, normalized executable identity and argument bytes with
secret values represented only by typed placeholders, a normalized
working-directory descriptor and commitment, injected environment-variable
names, stdin mode, a typed output-sink descriptor and commitment, and platform
assurance level. It never contains a secret value. `ApprovalTargetV1` binds every
opaque item and field ID plus the policy revision to either a name whose
descriptor the approver is entitled to decrypt or an owner-signed, bounded,
non-secret review label with an explicit label revision. Working-directory and
output-destination descriptors likewise contain their exact normalized
non-secret display bytes or an owner-signed meaningful review label; a hash or
opaque ID is not a display opening. Labels need not reveal private canonical
names or paths, but they must distinguish the intended target or sink
meaningfully to the approver. The manifest may travel to an entitled approver
over a separate confidential channel, but its exact canonical bytes hash to the
digest in the client-signed request.

An interactive approval is forbidden unless the approver client possesses the
complete manifest, recomputes the bound digest, verifies the request, and renders
every security-relevant field and a verified human-readable approval target in a
non-truncated review screen. An opaque digest or opaque target alone is not an
approvable description. Automatic approval may match opaque selectors only
through explicitly typed policy fields or an exact manifest digest; this path
does not claim human review.

`ApprovalDecisionV1` has one canonical signed preimage containing at least:

- approval protocol family, version, and random approval ID;
- exact request digest and action-manifest digest;
- witness-policy identifier and revision;
- approver ID, signing-key fingerprint, and key epoch;
- approve or deny plus one bounded value-free reason code;
- issuance, optional not-before, and expiry no later than request expiry;
- a cryptographic nonce and the exact intended witness set;
- the approver signature.

Every witness verifies the decision signature, current approver membership,
operation scope, policy revision, times, request and manifest digests, and
the request/manifest semantic-equality invariant above before counting it.
Identical replay for the same request is idempotent; any changed bytes or use
with another request fails closed. An approver decision cannot mint or extend a
request, contribution, or expiry.
Transport authentication may rate-limit or route approval messages but cannot
replace this signed decision.

### 0.12 Witness response contract

A witness response is signed by the witness and encrypted to the
request-specific session key when it contains a secret contribution.

Its canonical preimage contains at least:

- protocol family and version;
- response ID;
- exact request digest;
- witness ID and signing-key fingerprint;
- witness-policy identifier;
- decision: approve, deny, or error;
- stable non-secret reason code;
- witness policy checkpoint or revision;
- issuance and expiry times;
- encrypted contribution digest and encapsulation metadata when approved;
- witness signature.

The server MUST NOT return a contribution in a denial or error.

The endpoint verifies every witness signature, request digest, expiry, witness
membership, policy checkpoint, contribution envelope, and quorum rule before
assembling the exact revision-scoped descriptor/body secret authorized by the
request. It never assembles an epoch root.

Partially valid quorums fail closed and zeroize collected contributions.

The first witnessed cryptographic construction is deliberately not fixed by
this plan.

The protocol bead MUST compare at least:

- independently encrypted shares created at item-key rotation;
- key-derivation or contribution schemes with request-specific release;
- retention consequences when an authorized endpoint stores all prior
  contributions and revision secrets;
- witness compromise and rotation consequences;
- quorum membership changes;
- recovery and offline backup behavior;
- standard threshold constructions when they genuinely improve the claim.

A static `HKDF(device_share || witness_share)` design is not accepted merely
because it is simple: an endpoint that retains the witness share may bypass the
witness later. J19 must select a reviewed distributed-decryption, threshold-KEM,
or equivalently analyzed construction and prove that an endpoint retaining all
earlier responses cannot open a later `RevisionSealId` without a fresh quorum.

The J19 witnessed construction needs deterministic vectors and an explicit
statement of what retained endpoint material enables. Independent cryptographic
review of the exact construction and revision is mandatory; until its findings
are dispositioned and bound into the machine gate, witnessed implementation and
J26 remain blocked.

### 0.13 Replay, expiry, and freshness

HPKE does not provide application replay protection, message ordering, or
downgrade prevention.

`juryd` therefore maintains durable replay state for every accepted request ID
and request digest until a bounded retention horizon beyond expiry.

The database portion of a decision uses one serialized state-generation
transaction:

1. parses within bounds;
2. validates protocol and suite;
3. verifies the client signature;
4. validates witness policy and membership;
5. checks issuance, not-before, expiry, and allowed clock skew;
6. verifies policy freshness evidence;
7. reserves the request ID and digest;
8. evaluates approval rules;
9. creates and durably seals one stable encrypted response contribution if
   approved, without releasing it;
10. appends the durable decision and receipt material;
11. commits a signed next-generation anchor candidate that names the exact
    external predecessor and authenticates the security-state digest;
12. compare-and-swaps that candidate into the external anchor only when the
    expected predecessor still matches;
13. reads back and verifies the exact external candidate; and
14. only then returns or acknowledges the stable response.

Checkpoint ingestion, replay reservation, decision recording, response sealing,
and compaction use this same generation protocol. No checkpoint acknowledgement
or contribution leaves the service from an externally unanchored generation.
Concurrent writers serialize before choosing a predecessor.

A duplicate request returns the prior stable decision or a typed replay denial.

It never creates a fresh contribution with a new expiry.

Clock behavior is injected in tests.

Production deployments require monotonic-duration checks within a process and
wall-clock checks across restarts.

Clock rollback beyond policy tolerance fails closed and raises an operator
health event without logging the request body.

Replay storage has a documented capacity bound and compaction rule.

Compaction cannot remove a request before every response and receipt using it is
expired plus the configured safety horizon.

Witness policy freshness is defined by `VaultPolicyCheckpointV1`, whose
canonical signed content binds the vault ID, genesis fingerprint, policy
sequence and hash, witnessed-policy ID and revision, exact witness and approver
sets, predecessor checkpoint digest, and issuing owner. A witness is provisioned
with the genesis fingerprint and initial witnessed policy through an explicit
operator-confirmed registration. It accepts an equal checkpoint idempotently or
a strictly validated descendant whose owner authority is proven by the complete
intervening policy chain. It rejects gaps, lower sequences, same-sequence hash
changes, forks, unknown owners, or silent witness/approver-set replacement.

A request is approvable only against the witness's exact current checkpoint. An
older endpoint receives `StalePolicy`; a valid endpoint ahead of the witness
receives `WitnessBehind` and cannot obtain a contribution until the checkpoint
update is durably accepted. A revocation is authoritative for a witnessed
operation only after the required witness set has accepted its checkpoint. CLI,
TUI, and receipts report per-witness checkpoint state and never infer global
freshness for offline artifacts.

`juryd` also persists a signed `WitnessStateAnchorV1` containing its witness
identity and key epoch, monotonically increasing state generation, per-vault
checkpoint high-water marks, replay-retention horizon, database-state digest,
predecessor-anchor digest, and issuance time. The authenticated security-state
digest excludes only inert local acknowledgement/cache metadata. Production
contribution service requires comparison with an operator-configured rollback
anchor outside the restored transactional database, such as an independently
versioned object, hardware monotonic store, or transparency service selected and
reviewed by J19.

Startup and crash reconciliation have three accepted cases. If database and
external anchor match exactly, service may resume. If the database contains
exactly one fully committed, signed next-generation candidate whose predecessor
is the current external anchor, no output or checkpoint acknowledgement has yet
escaped; the service may repeat the compare-and-swap and exact readback before
serving. If the external anchor already equals that candidate, a crash occurred
after publication and the stored sealed response may be returned idempotently.
Every other state—including database behind external, more than one unanchored
generation, same-generation digest conflict, missing predecessor, or external
anchor ahead on another branch—fails closed. It requires a database recovery
that exactly matches the external anchor or the new-witness rotation below; an
old database can never refresh or overwrite a later anchor.

Recovery without a valid rollback anchor requires a new witness identity and
explicit owner-authorized witness-policy rotation before it can contribute. It
does not inherit the old witness's membership or claim replay continuity.

### 0.14 Receipts

Every witnessed decision produces a value-free, independently verifiable
receipt.

The receipt binds:

- request digest;
- action-manifest digest and value-free rendered-scope summary;
- public request scope;
- witness-policy identifier;
- every counted signed approver decision and approver key epoch;
- participating witness identities;
- each signed witness approve/deny decision;
- quorum evaluation result;
- policy checkpoint;
- issuance and expiry;
- client acknowledgement when the operation begins;
- optional completion outcome without secret output;
- receipt schema version.

Receipts MUST NOT contain:

- item or field plaintext names unless the request policy explicitly makes
  them public;
- secret values;
- private keys or shares;
- passphrases;
- environment values;
- raw command output;
- filesystem paths with private project identifiers;
- authentication tokens;
- unbounded error messages.

Offline verification uses only public vault, approver, and witness descriptors,
signed policy checkpoints, the receipt, and the published canonicalization
rules.

A receipt proves that named parties signed a decision over a request digest.

It does not prove the endpoint executed the command, forgot the key, or avoided
copying plaintext.

It also does not prove that a compromised approver device faithfully displayed
the verified action manifest. Witnessed approval assumes the approver key and the
approver client's verification/rendering path are trustworthy at decision time.

### 0.15 Threat actors added by witnessed mode

The threat model includes:

- a malicious or compromised endpoint;
- one compromised witness;
- a malicious managed-witness operator;
- a network attacker who can delay, replay, drop, or reorder messages;
- a stale or rolled-back witness database;
- a clock-skew or clock-rollback condition;
- an operator who misconfigures quorum membership;
- a compromised approval UI;
- a colluding endpoint and sub-quorum of witnesses;
- a witness signing-key compromise;
- denial of service by any participant;
- a malicious artifact holder who mutates public metadata or ciphertext;
- an authorized former reader retaining historical material.

The v1 claim SHOULD tolerate compromise of fewer witnesses than the configured
quorum only if the selected construction actually enforces that threshold.

The plan MUST state separately what happens when the endpoint colludes with one
witness, when a quorum colludes without the endpoint, and when old witness keys
are compromised after rotation.

A compromised approval UI can lie about what it renders or misuse an available
approver key. Cryptography can bind the signed decision to verified manifest
bytes but cannot make a compromised display truthful; resistance to that actor
requires a separately reviewed trusted-display or attested-approver mode and is
not a Jury v1 claim.

Availability is not secrecy.

A witness may always deny or disappear; backup and recovery must document how
operators regain availability without silently weakening authorization.

### 0.16 Witness service architecture

`juryd` is an adapter around a small policy/replay engine.

The core engine takes bounded verified inputs and returns a typed decision plus
receipt material.

Transport adapters own TLS, HTTP or RPC framing, authentication rate limits,
request body caps, and graceful shutdown.

Persistence adapters own atomic replay reservations, decision durability,
schema migration, backup, and restore.

They also own monotonic policy-checkpoint updates and signed state-anchor
publication. The contribution engine is unavailable until restored database
state has been compared with the configured external rollback anchor.

Key providers own witness signing keys and any share/contribution keys.

Approver keys use a separate provider boundary and are never witness signing or
contribution keys merely because one operator controls both roles.

The server process never parses a Jury item body and never needs item or field
names to evaluate an opaque request.

Self-host and managed deployments run the same cryptographically relevant code.

Commercial value may exist in operation, federation, support, HSMs, compliance,
and availability, but no proprietary server path may gain hidden decryption
authority.

### 0.17 Migration rule

Jig migration is import, not format upgrade.

The target workflow is conceptually:

```console
jury migrate jig-vault --from /absolute/legacy/home --to /absolute/absent/jury/home
jury migrate verify --home /absolute/new/jury/home --against /absolute/legacy/home
jury status --home /absolute/new/jury/home
```

The migration:

- opens Jig v1/v2 with a compatibility reader isolated from Jury's native
  writer;
- creates an absent Jury home;
- generates or selects a Jury owner identity;
- maps grouped legacy fields into private Jury items;
- preserves supported timestamps, kinds, and values;
- creates a signed source-migration attestation using hashes and terminal audit
  evidence, never secret values;
- verifies the complete destination after fsync;
- leaves the Jig source byte-for-byte unchanged;
- emits an explicit cutover manifest and rollback instructions;
- performs no dual writes;
- refuses an existing destination unless an explicit separate recovery workflow
  applies.

The migrated vault is a new Jury lineage with a new vault ID and format v1
genesis.

Jury does not claim cryptographic ancestry that Jig v2 could not prove.

### 0.18 Selective reuse rule

The existing Jig vault and TUI are evidence and component sources, not Jury's
architecture.

Candidate components for history-preserving extraction are:

| Jig source area | Jury destination concern | Reuse posture |
| --- | --- | --- |
| `secret.rs` | protected byte ownership and zeroization | extract, rename, audit |
| `redact.rs`, `exec_output.rs` | bounded streaming redaction | extract, generalize |
| `path_security.rs`, `output/` | hardened path and private output | extract, generalize |
| `exec_process.rs`, `process_pipe.rs`, `run/process*` | owned child trees and cleanup | extract or replace dependency |
| `template.rs` | bounded template parsing/injection | extract behind Jury selectors |
| `backup/restore_linux.rs` | filesystem restore protections | extract tests and primitives |
| `vault_tests/`, `run/tests.rs`, TUI tests | failure/adversarial cases | port behavioral intent |

The following areas are explicitly replaced:

| Jig source area | Reason |
| --- | --- |
| `format.rs` | v2 vault-wide envelope conflicts with Jury format v1 |
| `crypto.rs`, `vault/envelope.rs` | vault-wide passphrase/DEK is wrong boundary |
| `vault.rs` facade and unlock state | whole-vault unlock leaks across items |
| `audit.rs` key derivation | identity-local and witnessed evidence need new roots |
| `types.rs` URI references | `jig://` is adapter-only |
| `store.rs` home/env policy | Jury owns XDG paths and `JURY_*` variables |
| Jig CLI runtime adapters | downstream integration belongs to cutover plan |

No extracted module is accepted because it has many tests.

Each candidate receives:

1. a dependency inventory;
2. an invariant inventory;
3. an API leak review;
4. fixture sanitization;
5. behavior-preserving port tests;
6. Jury-specific adversarial tests;
7. platform verification;
8. removal of Jig environment and type coupling.

### 0.19 History-preserving extraction

History preservation happens before large anonymous copies land in Jury.

The recommended workflow is:

1. keep the current Jury scaffold uncommitted or commit it as one explicit
   scaffold baseline;
2. clone the Jig repository into a temporary extraction repository;
3. use `git filter-repo` with an explicit allowlist of whole source paths and
   tests selected by the component audit;
4. rename the filtered paths into a temporary `jury-legacy-components` tree;
5. add the filtered repository as a temporary remote to Jury;
6. merge its unrelated history with an explicit provenance commit;
7. move and decouple files in ordinary reviewable commits;
8. record original Jig commit IDs in the resulting file history and migration
   notes;
9. remove the temporary remote after verification.

Filtering whole files preserves meaningful blame better than synthesizing new
files from copied functions.

When only a small subset of a mixed file is reusable, import the whole file's
history into a temporary path, then extract and delete in Jury commits.

The extraction allowlist MUST be reviewed before running because filter tools
rewrite history and accidental paths can import unrelated project material.

Run it only against a disposable clone, never the user's Jig working tree.

### 0.20 `jig-owned-process`

Jury MUST NOT depend on the `jig-owned-process` crate.

The owning delivery task compares two acceptable outcomes:

- extract the generic process-tree primitives and their history into a neutral
  Jury-owned or separately published crate; or
- implement the same narrow contract using a maintained general dependency plus
  Jury-specific cleanup tests.

The decision is based on cancellation semantics, Unix process-group behavior,
Windows job-object behavior, signal forwarding, bounded capture, dependency
maintenance, and license compatibility.

The public API should express `OwnedChild`, kill-tree, wait, timeout, and cleanup
outcomes without exposing Jig types.

A build-time Jig harness remains permitted; a Cargo dependency does not.

### 0.21 Standards and current dependency grounding

Load-bearing cryptographic choices are grounded in primary sources:

- HPKE construction and application responsibilities: RFC 9180,
  <https://www.rfc-editor.org/rfc/rfc9180.html>;
- Argon2id profiles and security guidance: RFC 9106,
  <https://www.rfc-editor.org/rfc/rfc9106.html>;
- Ed25519 encoding and verification: RFC 8032,
  <https://www.rfc-editor.org/rfc/rfc8032.html>;
- X25519 field and all-zero checks: RFC 7748,
  <https://www.rfc-editor.org/rfc/rfc7748.html>;
- ML-KEM: FIPS 203,
  <https://csrc.nist.gov/pubs/fips/203/final>;
- post-quantum and PQ/traditional hybrid HPKE work: active
  `draft-ietf-hpke-pq`,
  <https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/>;
- XChaCha20-Poly1305 construction and interoperability profile:
  `draft-irtf-cfrg-xchacha-03`,
  <https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/>;
- threshold-cryptography terminology and ongoing standardization context:
  NIST Threshold Cryptography,
  <https://csrc.nist.gov/projects/threshold-cryptography>.

The source plan named exact prerelease or rapidly moving Rust dependencies.

Jury does not freeze those package versions in this project plan.

The cryptographic-provider bead MUST query current upstream documentation,
crate metadata, repository maintenance, RustSec advisories, feature trees,
licenses, MSRV, zeroization behavior, and official test vectors immediately
before selection.

One surfaced HPKE implementation has moved repositories since the Jig plan was
written; that is enough evidence that training-time package memory is not a
release decision.

J01A must compare the security properties and operational costs before choosing
the suite; this plan does not preselect XChaCha20-Poly1305 or classical HPKE.
At minimum it compares AES-256-GCM-SIV, one-key/one-seal RFC 8439
ChaCha20-Poly1305, and the expired XChaCha Internet-Draft profile for storage,
plus classical RFC 9180 HPKE and the active `draft-ietf-hpke-pq` pure-PQ and
X25519+ML-KEM-768 hybrid profiles. It separately decides post-quantum
confidentiality and post-quantum authenticity. Every non-final specification is
pinned by revision and treated as work in progress. J01B then selects providers
only for the accepted construction and proves the exact semantics against
independent vectors.

FIPS-validated deployment is an explicit Jury v1 non-goal. FIPS 203 is primary
specification evidence for ML-KEM, not a claim that Jury, its provider, build,
platform, or deployment is FIPS validated.

### 0.22 Direct-mode implementation gate

No `0.x` build is production cryptography. Direct cryptographic code lands only
after these minimum drift and correctness controls exist:

- the explicit threat model and nonclaims;
- frozen direct-slot and storage schemas with bounds;
- canonical preimage documentation;
- deterministic vectors generated independently of production builders;
- provider due diligence and official known-answer tests;
- direct recipient-slot downgrade rules;
- a machine-validated `docs/security/jury-v0-direct-crypto-gate.toml` binding the
  accepted suite, provider revisions, specification hashes, and vector hashes;
- recovery semantics for lost identities;
- executable negative and failure-injection tests;
- prominent experimental/no-independent-review/non-production nonclaims.

J01A owns the shared primitive and direct-slot requirements. J01B owns provider due
diligence, wrapper proof, and the minimal gate manifest. J02 protected primitives
and J03 non-cryptographic domain types may precede it. J04 and every encrypted
identity, direct item, or backup path depend on the accepted J01A/J01B gate.

Before any direct cryptographic target is admitted, a repository-owned CI
check must reject a missing, malformed, stale, or hash-mismatched gate manifest.
The manifest is evidence, not an override: changing the bound protocol,
construction, provider revisions, canonical preimages, or vectors closes the
gate until J01A/J01B evidence is refreshed.

The experimental `0.x` release requires:

- the direct vertical slice passes the conformance corpus;
- the J19 independently reviewed witnessed-construction gate is current;
- a witnessed-only item passes request, meaningful approval, quorum,
  read/inject/exec, receipt, next-revision denial, rotation, and recovery tests;
- migration is copy-on-write and rollback-tested;
- backups are restored in real drills;
- release build instructions are exercised; reproducibility exceptions are
  documented without creating a separate certification process;
- artifacts have signatures, SBOMs, provenance, and checksums;
- exact licenses and trademark policy are committed;
- documentation states endpoint retention, historical decryptability, and the
  exact scope of J19 review without implying whole-product review;
- the scaffold/no-real-secrets warning remains in every `0.x` release.

### 0.23 Witnessed implementation gate

J19 is an additional hard gate, not a design note. Before witnessed or
distributed cryptographic implementation lands, it MUST freeze the exact
construction and protocol schemas, prove the endpoint-retention claim for later
revision seals, publish independent vectors, obtain independent cryptographic
review of the exact revision, disposition every material finding, and bind all
of that evidence in `docs/security/jury-v1-crypto-gate.toml`.

Changing the construction, contexts, schemas, vectors, reviewed revision, or a
material finding disposition closes the gate. J20-J23 and the witnessed parts
of J05/J07/J08/J10 cannot bypass it with coordination, static share release, a
mock quorum, or self-review. If the review cannot be obtained, J26 stays open.

## 1. Executive decision

Jury vault should add cryptographic access control at the canonical item boundary.

A canonical item is the first version of a security scope.

In the motivating example, the items are `Development`, `Staging`, and
`Production`.

The Jury v1 vault remains one logical, portable `vault.json` artifact.

The artifact contains public, signed opaque item and access metadata plus
separately encrypted item descriptors and bodies.

Canonical item names are private by default.

The public policy identifies an item only by a random stable item ID.

A small descriptor encrypted under an item- and revision-specific descriptor secret
contains the canonical item name, so a selected identity discovers names only
for items it may currently read.

Every item key epoch fixes one effective reader set. Each descriptor and body
seal has an independent revision secret and fresh random `RevisionSealId`.
Direct recipient capsules release only the exact revision secret. Witnessed
capsules use the J19-reviewed distributed-decryption construction and never
expose or reconstruct an epoch root. J19 may admit an internal epoch root only
if it proves writer creation, mixed-mode equivalence, and retention safety; no
public item callback receives one.

The first slot families are direct HPKE and witnessed access.

An item may intentionally contain both families for different principals. Such
an item is mixed-mode: status, receipts, UI, and documentation describe the
selected principal's access path, and the item is never called quorum-controlled
as a whole. `witnessed-only` means every current access path is witnessed and
revision-scoped; one current direct slot is sufficient to make an
item-level quorum claim false and, for a PQ lineage, one classical slot to the
same secret is sufficient to defeat the post-quantum confidentiality claim.

There is no Jury v1 passphrase that unlocks the whole vault for every recipient.

Every recipient instead owns an encrypted local identity with:

- the selected suite's recipient private-key material;
- the selected suite's signing-key material;
- a local audit/checkpoint seed;
- a stable public principal descriptor.

The selected identity's passphrase unlocks only that local identity.

An owner grants `reader` or `writer` access to a principal for an item.

An owner has read/write/admin access to every item and therefore has one
configured unwrapping path for every active item.

Ordinary CLI and TUI inventory views show only named items accessible to the
selected identity.

The full artifact still reveals opaque item count, exact public artifact and
transfer length, encrypted-body size buckets, revision activity, principals,
and item/principal access relationships.

Every effective reader-set change increments the item key epoch, rotates any
construction-internal epoch secret, creates fresh descriptor/body seal
identifiers and revision secrets, and reseals the current item descriptor and
body.
A grant therefore excludes the new reader from retained pre-grant ciphertext,
while a revocation excludes the removed reader from future ciphertext.

Removing write access without removing read access is a signed policy change and
does not rotate the key epoch or reseal unchanged content. Every future content
seal still receives a fresh revision secret.

Signed policy and item-revision chains make unauthorized edits rejectable by an
honest Jury client.

They do not stop an authorized reader from copying plaintext.

They do not make a revoked person forget data they already decrypted.

They do not provide forward secrecy for retained historical artifacts if a
recipient's private key is stolen later. Changing only the identity passphrase
preserves that key material; principal replacement and item rekeying
protect later epochs, not earlier artifacts.

They do not provide authoritative global freshness when files are exchanged
offline.

Organizations that require immediate authoritative revocation, SSO lifecycle,
dynamic credentials, or a universal latest revision must combine Jury with an
online control plane or choose a central secrets manager rather than treating
Jury's portable artifact or witnessed release gate as equivalent.

## 2. Why this design

The current Jig v2 envelope has one passphrase-derived wrapping key.

That key unwraps one vault-wide data-encryption key.

That data-encryption key decrypts one serialized state containing every field.

Anyone who can unlock the envelope can therefore decrypt Production, Staging,
Development, legacy values, and all field metadata.

Adding an ACL field inside that encrypted state would improve user experience but
would not create a security boundary.

The same vault-wide key would still be present on every authorized developer's
machine.

The client could be patched to ignore the ACL.

Splitting environments into separate v2 vault homes would create real key
separation, but it would abandon the requested single-vault distribution model,
duplicate lifecycle operations, and make canonical references depend on an
external scope selection.

The chosen design retains the single artifact and moves the key boundary inward
to the item.

The choice mirrors the useful part of several competitor models:

- Doppler assigns project roles and access to selected environments/configs.
- Infisical scopes roles by environment, path, secret name, and tags.
- HashiCorp Vault authorizes capabilities on secret paths and denies by default.
- Bitwarden Secrets Manager grants people, groups, and machine accounts read or
  read/write access to projects.
- 1Password normally uses separate vaults as the cryptographic sharing boundary,
  while documenting that some finer app permissions are only client-enforced.
- SOPS and age demonstrate recipient-wrapped file encryption, but their usual
  file boundary is coarser than the desired item boundary.

Jury's typed item-plus-field selector gives the product a natural scope boundary
without embedding repository or environment routing syntax.

The item boundary also supports a direct migration from the v2 grouped field
model.

## 3. Product outcomes

The feature is complete when all of the following statements are true.

1. A developer granted Development and Staging can carry the same `vault.json`
   as an owner without decrypting or discovering Production's item name from the
   artifact or conforming UI.

2. A Production deploy principal can use Production through its configured
   direct or witnessed slot without receiving a reusable vault-wide passphrase.

3. An unauthorized principal cannot learn an item's canonical name or its field
   names, kinds, timestamps, lengths, or values.

4. Opaque item IDs, envelope count and sizes, principal labels, roles, and access
   relationships are explicitly documented metadata leaks.

5. A reader cannot publish an item mutation that another conforming Jury client
   accepts unless policy grants that principal writer or owner authority.

6. A non-owner cannot publish an access-policy mutation that another conforming
   Jury client accepts.

7. Adding or removing effective read access increments the affected key epoch,
   rotates any construction-internal epoch secret, creates fresh descriptor/body
   revision secrets and seal identifiers, reseals both ciphertexts, and replaces
   the complete access-path set.

8. The revocation output tells the owner to rotate the underlying external
   credentials when prior disclosure matters.

9. Existing `ITEM/FIELD` references continue to identify fields without
   repository or vault routing in the reference.

10. Read, inject, exec, run, TUI, audit, backup, and restore flows have
    explicit Jury v1 behavior and fail closed at access boundaries.

11. Jig v1 and Jig v2 vaults remain readable only through the explicit
    migration compatibility adapter.

12. Migration to Jury v1 is explicit and one way.

13. Binaries reject unknown Jury format, slot, protocol, and receipt versions
    rather than silently interpreting them.

14. A normal transfer contains no private identity, local operational audit,
    checkpoint, or local operation receipt.

15. An owner backup is clearly labeled as identity recovery material and can
    restore both the vault and an owner identity; direct items recover locally,
    while witnessed paths retain and report their J19-defined dependencies.

16. Offline forks and rollbacks are detected whenever the receiving installation
    has a prior authenticated checkpoint that proves the conflict.

17. The documentation does not claim retroactive revocation, “use without
    view,” universal artifact freshness, forced endpoint forgetting, or deletion
    resistance.

18. A selected principal can see its own accessible item/role matrix, explain or
    preflight a required capability without reading a field, and receive one
    uniform unavailable result for inaccessible and nonexistent item names.

19. An owner can register a principal and grant its initial exact item roles in
    one atomic policy revision, and can batch several exact grants for one
    principal without intermediate policy states.

20. Transfer inspection, import dry-run, and local export-status commands explain
    authenticated public deltas, conflicts, and accessible-name changes before
    mutation without disclosing inaccessible names.

21. Every shared-state mutation reports that redistribution is recommended, and
    local status distinguishes the current vault revision from the last revision
    exported on that installation without claiming delivery to anyone.

22. Policy-changing commands provide authenticated dry-run previews; revocation
    and owner removal show exact key rotations, affected opaque or accessible
    items, and external-credential warnings before commit.

23. Local identities have explicit names, can be listed without unlocking, and
    are selected by name or an unambiguous explicit file option without automatic
    key probing.

24. Interactive and scripted initialization can create several initial private-
    name items with the first owner and ends with fingerprint, recovery, and
    onboarding next steps.

25. Owner recovery status distinguishes identity coverage, captured vault
    revision, backup age, local verification state, and whether a real restore
    drill has been recorded, without pretending that an unobserved off-machine
    drill occurred.

26. The TUI provides accessible-only role filters, owner access-matrix editing,
    disabled-command reasons, exact committed-versus-retryable results, and
    copyable references only for item names the selected identity can decrypt.

27. A new recipient cannot decrypt retained item ciphertext created before its
    grant, even when that ciphertext came from the immediately preceding valid
    vault revision.

28. Before permanent policy or item-proof histories reach their hard caps, an
    owner can create a separately trusted, signed Jury v1-to-Jury v1 rollover lineage
    without overwriting or weakening the old lineage.

29. Fingerprints, duplicate-key rejection, registration proofs, and principal
    replacement operate on one canonical Jury encoding of every selected-suite
    public-key component; alternate encodings or omitted/reordered hybrid
    components cannot create a second apparent cryptographic identity.

30. Every new Jury v1 identity/backup records one exact bounded Argon2id profile;
    passphrase change upgrades weak profiles, preserves stronger profiles by
    default, and hostile headers cannot request arbitrary pre-authentication
    memory.

31. A Jury v1 owner backup uses an independently captured passphrase by default and
    can restore the same owner principal into a freshly sealed identity that no
    longer depends on the former live identity passphrase.

32. Before any private unlock, Jury disables process core dumps and prepares a
    page-dedicated protected-memory boundary; compact credentials and keys never
    silently fall back to ordinary pageable allocator storage.

33. An identity may require both its passphrase and one explicitly enrolled OS
    keychain, Secure Enclave, TPM 2.0, or FIDO2 protector, with no passphrase-only
    bypass slot and backup-based recovery onto replacement hardware.

34. Encrypted item bodies and encrypted backups expose only fixed size buckets
    rather than exact logical/recovery lengths, while optional signed cover reseals are
    indistinguishable from ordinary body updates in shared state and documentation
    states the remaining public-framing and timing/activity leaks.

35. Every recipient slot has an authenticated algorithm tag, and an unknown or
    downgraded slot fails closed.

36. Direct and witnessed access use the same `ItemAccessProvider` semantics; no
    CLI, TUI, importer, or downstream adapter receives raw identity private keys
    or epoch roots.

37. A witnessed request is bound to the exact vault, item, epoch, policy,
    principal, operation, workload digest, expiry, nonce, and request-specific
    response key.

38. A witness durably rejects replay before returning contribution material, and
    crash/retry behavior cannot mint a second contribution or extend expiry.

39. Offline receipts verify signed decisions without secret values and state
    clearly that they do not prove endpoint execution or forgetting.

40. A customer can self-host the cryptographically relevant witness service,
    and the managed offering uses the same protocol and security-critical code.

41. Every counted approval is a replay-bounded signature by a current approver
    over the exact request and verified action-manifest digest; an interactive
    approver sees the complete non-truncated manifest and a policy-authenticated
    meaningful target, field, working directory, and output destination rather
    than only a digest, opaque selector, or commitment.

42. Every production witness advances policy checkpoints monotonically, refuses
    requests against older policy, and stops contribution release after restore
    until an external rollback anchor proves the recovered checkpoint and replay
    state are current enough.

## 4. Non-goals

The first Jury v1 release does not attempt to provide:

- a hosted plaintext secrets database or a service with unilateral decryption;
- SSO, SCIM, OIDC, LDAP, or directory synchronization in the core milestone;
- expiring *stored grants*; witnessed requests themselves are short-lived;
- IP or device-posture conditions beyond explicitly bound workload evidence;
- a remotely authoritative history for the portable vault artifact;
- a universal latest revision when valid artifacts can move offline;
- secret leasing or dynamic credential generation;
- transparent rotation of credentials in third-party systems;
- 1Password import; it may be reconsidered after Jury v1, but is not part of the
  v1 delivery contract;
- prevention of screenshots, memory inspection, shell capture, or deliberate
  exfiltration by an authorized reader;
- protection when the approver device, approval rendering path, or approver key
  is already compromised at decision time;
- cryptographic “execute but never reveal” semantics for a local child process;
- field-level ACLs inside an item;
- wildcard, tag, path-expression, or group grants in Jury v1.0;
- automatic conflict resolution for concurrent writes to the same item;
- any post-quantum confidentiality or authenticity claim not explicitly selected
  and proven by J01A/J01B; HNDL resistance remains a mandatory decision, not an
  implicit non-goal;
- recipient forward secrecy or post-compromise secrecy for historical artifacts;
  later theft of a long-lived recipient private key can expose retained artifacts
  from epochs in which that principal had a direct slot even when the KEM resists
  quantum cryptanalysis;
- SSH-agent, age-plugin, or browser-extension identities;
- public discovery of item or field names inside an inaccessible item;
- concealment of opaque envelope count, exact revision sequence, principal
  descriptors, or public item/principal access relationships;
- complete traffic-analysis resistance: size buckets and optional cover reseals
  do not hide filesystem access, transport timing, policy changes, an absent
  cover schedule, or correlation by an observer with prior artifacts;
- protection against a privileged kernel/root attacker, live process memory
  inspection after unlock, suspend-to-disk without OS encryption, DMA, or
  physical acquisition; protected pages and disabled dumps narrow ordinary
  paging/crash exposure but are not a hardware isolation boundary;
- general access-request/invitation workflows or automatic distribution; the
  bounded owner-issued registration challenge and response exist only to prove
  control of both keys in a public principal descriptor;
- compatibility for writing Jury v1 with an older binary;
- a down-migration from Jury v1 to v2.

Direct principal grants are intentional for the first version.

The serialized subject shape must be versioned so a later release can add groups
without interpreting an unknown subject as a principal.

## 5. Threat model

### 5.1 Actors

The design distinguishes these actors.

`Owner`

An owner administers principals and item access.

An owner can read and write every item.

An owner signs policy revisions.

`Writer`

A writer can decrypt and mutate one granted item.

A writer signs item revisions.

A writer cannot change access policy.

`Reader`

A reader can decrypt one granted item.

A reader cannot publish an accepted mutation to that item.

`Machine`

A machine principal uses the same cryptographic identity shape as a person but is
marked as a machine in public policy.

A machine may be a reader or writer.

A machine may not be an owner in Jury v1.0.

`Distributor`

A distributor can copy, truncate, replay, combine, or replace transfer files.

A distributor is not trusted with plaintext or signing authority.

`Endpoint`

An endpoint runs the Jury client, holds the selected local identity, constructs
witness requests, and consumes an authorized operation.

An endpoint may be honest, compromised before approval, or malicious after an
otherwise valid approval.

`Witness`

A witness verifies a request, evaluates one configured policy, durably rejects
replay, and signs its decision.

A witness does not parse item plaintext and does not receive an exportable
complete endpoint identity.

`Approver`

An approver is a human or machine actor whose authenticated decision may be one
input to witness policy.

Approval identity, witness identity, and vault principal identity are separate
roles even when one person controls all three in a development fixture.

An approver has a dedicated versioned descriptor and signing key. It signs an
exact request and action-manifest digest; transport login or possession of a
vault-principal key is not itself approval authority.

`Network attacker`

A network attacker can observe public framing and delay, duplicate, replay,
reorder, truncate, or replace request and response messages.

TLS is defense in depth; message signatures and request binding remain required.

`Revoked principal`

A revoked principal retains every file, key, plaintext, child-process copy, and
backup it obtained before revocation.

`Later-compromised recipient`

An attacker who later steals a principal's static recipient private-key material
can open direct slots addressed to that key in retained historical artifacts.
This remains true even for a PQ KEM: HNDL resistance concerns future
cryptanalysis of recorded public material, not later theft of the private key.
The attacker does not gain a later epoch created by principal replacement or
reader-set rekey unless it also compromises a then-authorized identity.

`Local attacker`

A different OS user may try to read or replace local files.

Existing private-directory, symlink, hard-link, atomic-write, and advisory-lock
protections remain in scope.

The threat also includes accidental or later collection of ordinary process core
dumps, crash bundles, and pageable secret buffers after Jury has released them.
Jury must disable its own dumpability before unlock and keep compact credentials
and keys in dedicated locked, dump-excluded pages. It does not claim protection
when a privileged kernel, debugger, or account controller reads live memory.

`Identity-file thief without enrolled hardware`

An attacker may copy a device-bound identity file and know or guess its
passphrase without possessing the enrolled keychain/Secure Enclave/TPM/FIDO2
protector. The identity remains locked because device-bound mode has no portable
passphrase-only slot. A thief controlling both the OS account and protector use
is outside this boundary.

An attacker with full control of the authorized user's process or account is out
of scope.

### 5.2 Protected assets

The design protects:

- canonical item names and deleted-item former names for inaccessible items;
- field values in inaccessible items;
- field names in inaccessible items;
- field kinds in inaccessible items;
- field timestamps in inaccessible items;
- field value lengths in inaccessible items;
- exact logical item-body and unpadded backup-recovery lengths beyond their
  public buckets;
- optional item epoch secrets, descriptor/body revision secrets, and KDF/
  decapsulation intermediates;
- identity private encryption and signing keys;
- local audit/checkpoint authentication seeds;
- accepted policy authorship;
- accepted item-update authorship;
- known local revision freshness.

### 5.3 Intentionally public metadata

The shared vault exposes:

- vault ID and creation time;
- format and cryptographic suite identifiers;
- item stable IDs;
- active opaque item count;
- item tombstones containing opaque IDs and authenticated final hashes, but no
  former names;
- principal stable IDs;
- principal labels;
- whether a principal is human or machine;
- principal public encryption and verification keys;
- item roles and access relationships;
- policy revision counts and timestamps;
- item revision counts and timestamps;
- ciphertext body-size buckets, but not exact logical body lengths;
- exact total public artifact/transfer length and parseable public framing;
- the single fixed encrypted item-descriptor length;
- key-rotation epochs;
- signatures and hashes.

Canonical item names live only in per-item encrypted descriptors.

An artifact holder can still correlate opaque item IDs with principals, grants,
revision cadence, and size buckets and may infer a scope from external knowledge.

The UI and documentation must say that item-name confidentiality is not item-
existence, relationship, exact activity, or complete traffic-analysis
confidentiality.

### 5.4 Security claims

Given secure primitives and uncompromised private keys, a principal without a
current authorized direct or witnessed path cannot recover the current
descriptor or body revision secret. A witnessed path never yields the item's
epoch root.

The same principal cannot decrypt that item's descriptor and therefore cannot
recover its canonical name from the Jury v1 artifact.

A conforming client rejects a policy revision not signed by an owner authorized
under the immediately preceding accepted policy state.

A conforming client rejects an item revision not signed by a writer or owner
authorized under the referenced policy state.

A conforming client rejects missing active items, duplicate IDs, duplicate slots,
unknown algorithms, malformed chains, unsupported subjects, stale local policy,
and stale local item revisions.

A local checkpoint makes a later rollback detectable on that installation.

A fresh installation cannot distinguish two otherwise valid offline forks without
an external trusted checkpoint.

A conforming witness rejects an expired, not-yet-valid, malformed, wrong-policy,
wrong-item, wrong-epoch, wrong-operation, or replayed request. It rejects a stale
request relative to its durably accepted monotonic checkpoint and refuses all
contributions after recovery until an external rollback anchor validates that
checkpoint and replay-state generation.

A conforming endpoint rejects a witness response that does not bind the exact
request digest and request-specific session key.

A valid witnessed receipt authenticates the recorded decisions and scope, not
the endpoint's later behavior.

### 5.5 Security limitations

A direct-path reader receives the exact revision secret from its direct capsule.
A malicious replacement client controlling that endpoint can retain the secret
and plaintext for that revision. It can also use the long-lived recipient key to
open later direct capsules addressed to it, because direct mode intentionally
has no fresh-witness requirement.

A witnessed-path reader receives only the authorized revision secrets. It can
retain plaintext and those secrets and can reopen that already released
revision, but the J19 construction must prevent that retained material from
opening a later revision seal without fresh authorization.

Policy signatures stop honest recipients from accepting unauthorized changes;
they do not constrain a modified client on the reader's own machine.

Reader-set changes define a new key epoch. A grant protects retained earlier
ciphertext from the new reader, and a revocation protects later ciphertext from
the removed reader.

It cannot revoke earlier plaintext, a previously decrypted item name, or
ciphertext plus an earlier key.

Classical RFC 9180 HPKE does not provide recipient forward secrecy. If J01A
selects it, anyone who later obtains a recipient's static private key can open
that recipient's retained direct capsules and decrypt matching historical
ciphertext. Identity passphrase change only re-encrypts the same
private key. A PQ or hybrid KEM may add harvest-now/decrypt-later resistance but
does not make plaintext or revision secrets already obtained by an
endpoint disappear. Principal replacement plus reader-set rekey excludes the
old key from later epochs but cannot make earlier disclosures safe.

If a Production credential might have been learned, the external Production
credential must be rotated after the Jury access revocation.

Local audit files can be deleted with the local account.

They are tamper-evident, not deletion-proof.

Witness availability is not guaranteed.

A witness can deny service, lose replay state, suffer clock failure, or return a
signed denial.

The endpoint can retain a contribution or item key received during a legitimate
authorization; witnessed mode gates release but cannot force an ordinary
endpoint to forget.

Witness freshness is not universal vault freshness. Until the required witness
set has durably accepted a newer policy checkpoint, an offline policy change or
revocation is not authoritative for that witnessed path. A witness restored
without a valid external rollback anchor cannot safely resume contribution
service under its old identity.

Approval authenticity does not make a compromised approval client trustworthy.
Jury v1 assumes that the approver key is protected and that the approver client
faithfully verifies and renders the complete action manifest at decision time.

## 6. Legacy Jig v2 implementation map

The existing v2 format lives in `crates/jig-vault/src/format.rs`.

`VaultFile` currently contains:

- one authenticated header;
- one passphrase-wrapped vault data-encryption key;
- one encrypted state nonce;
- one encrypted state ciphertext.

`VaultState` is one `BTreeMap<String, SecretEntry>`.

`crates/jig-vault/src/vault/envelope.rs` derives one Argon2id wrapping key,
unwraps one data-encryption key, decrypts the complete state, and derives the
audit key from that vault-wide key.

`crates/jig-vault/src/vault.rs` keeps the complete `VaultFile`, plaintext
`VaultState`, data-encryption key, and audit key in one `OpenVault`.

Every public mutation currently serializes and reseals the complete state.

`VaultRevision` is an opaque pair derived from vault ID and state nonce.

`VaultSnapshot` exposes metadata for every field and every legacy secret after a
complete unlock.

`crates/jig-vault/src/audit.rs` maintains a local HMAC-SHA256 JSONL chain.

The HMAC key is derived from the vault-wide data-encryption key.

The chain detects edited records and broken links, but not deletion or rollback
without an external checkpoint.

`crates/jig-vault/src/store.rs` owns `vault.json`, `audit.jsonl`, `vault.lock`, a
16 MiB vault read limit, a 256 MiB audit read limit, private permissions,
symlink refusal, and atomic writes.

`crates/jig/src/runtime/vault.rs` selects repo, global, or explicit-home scope and
captures the passphrase.

Canonical references remain contextual to that selected scope.

`crates/jig-vault-tui` consumes metadata-only snapshots through a CLI-owned
backend and keeps one process-local credential.

The Jury v1 implementation must preserve these hardened boundaries while replacing
the one-key/full-state assumption.

## 7. Competitor findings and implications

### 7.1 Doppler

Doppler exposes project roles and per-environment/config access.

Its advanced-permissions example explicitly supports write access to development
and CI, read-only access to staging, and visibility without secret access to
production.

Removing access is enforced by Doppler's service in dashboard and API requests.

Implication for Jury:

Use the environment-like item as the default scope and distinguish read and
write, but do not copy Doppler's server-backed “visible without secret access”
inventory behavior.

An offline Jury recipient should discover an item name only after its configured
path releases the exact descriptor revision secret.

Do not copy the claim of immediate revocation because offline files lack a
continuously consulted authority.

### 7.2 Infisical

Infisical's RBAC assigns permissions to human and machine identities.

It can condition secret access on environments, paths, names, and tags.

Its roles are additive.

Implication for Jury:

Support both human and machine principals and default deny.

Start with exact item grants rather than prematurely adding a policy-expression
language.

### 7.3 HashiCorp Vault

HashiCorp Vault authenticates a client, associates policies with a token, and
authorizes capabilities against paths.

Policies are deny by default and separate read, create, update, delete, list, and
other capabilities.

The server also supplies the current policy and token authority.

Implication for Jury:

Separate read, write, and administer roles, and validate every operation against
the latest accepted signed policy.

Document that Jury does not have Vault's online token revocation or central
freshness.

### 7.4 1Password

1Password organizes sharing primarily by vault and assigns people and groups to
those vaults.

Its documentation distinguishes server-enforced access from client-enforced app
permissions and warns that a determined team member can bypass client-only
controls.

Implication for Jury:

Treat encryption keys, not UI affordances, as the read boundary.

Be candid that read/write separation is an acceptance rule at an endpoint that
already receives plaintext; cryptography does not stop a modified authorized
client from attempting to publish bytes.

### 7.5 Bitwarden Secrets Manager

Bitwarden assigns people, groups, and machine accounts to projects with read or
read/write access.

Implication for Jury:

Use a compact reader/writer model for item data and a separate owner role for
policy administration.

Machine principals must be first-class, not a later token-shaped exception.

### 7.6 SOPS, age, and dotenvx

SOPS and age use recipient encryption for portable files.

dotenvx uses separate encrypted environment files and environment-specific keys.

These tools prove that offline recipients are practical, but their common
security boundary is a whole file.

Implication for Jury:

Use recipient wrapping for direct paths and revision-scoped witnessed capsules
inside one authenticated vault artifact.

Avoid requiring one file per environment merely to gain key separation.

### 7.7 Product position

Jury v1 occupies a deliberate middle ground.

It is stronger than a shared encrypted dotenv or one-passphrase local vault
because recipients receive different cryptographic capabilities.

It remains an offline collaboration artifact, not a centralized secrets control
plane.

## 8. Terminology

`Vault artifact`

The portable, signed, encrypted `vault.json` file.

`Identity`

One local encrypted private-key file plus its public descriptor.

`Principal`

A policy entry representing a human or machine identity.

`Owner`

A human principal with global read, write, and policy-administration authority.

`Reader`

A principal allowed to unwrap and decrypt one item.

`Writer`

A principal allowed to read one item and publish signed item revisions.

`Item`

The canonical access-control and encryption compartment addressed by the first
segment of `ITEM/FIELD`; its stable ID is public and its canonical name is
encrypted.

`Item descriptor`

A small encrypted record containing the canonical item name independently of the
larger encrypted field body.

`Item body`

The encrypted field map and field metadata for one item.

`Item root key`

An optional construction-internal epoch secret admitted only if J19 selects and
proves a reviewed distributed PRF/KDF design. It is never an application-facing
or witnessed-endpoint value. The conservative random-revision-secret design has
no item root key.

`Revision seal identifier`

A fresh random 32-byte public identifier binding one descriptor or body seal to
its exact KDF context and witnessed capsule. Reuse in a lineage is invalid.

`Descriptor revision secret`

A suite-sized AEAD secret scoped to one descriptor revision and seal identifier.

`Body revision secret`

A suite-sized AEAD secret scoped to one item-body revision and seal identifier.

`Direct key slot`

An HPKE capsule containing one exact descriptor/body revision secret for one
principal and `RevisionSealId`.

`Witnessed capsule`

A construction-specific envelope for one exact revision seal. It never contains
or reconstructs an epoch root or contribution reusable for another seal.

`Policy revision`

An owner-signed, hash-linked atomic change set.

`Item revision`

A writer-signed, hash-linked encrypted item generation.

`Proof`

The metadata, ciphertext digest, author, parent hash, and signature of an older
item revision after its ciphertext has been discarded.

`Checkpoint`

Local authenticated state recording the highest policy and item revisions seen
by one identity on one installation.

`Transfer`

A vault-only package for collaboration that never contains private identity or
local audit material.

`Backup`

Owner-only encrypted recovery material that includes a complete vault, owner
identity, local audit, and checkpoint.

## 9. Access model

### 9.1 Principal kinds

The wire model supports exactly these Jury v1 principal kinds:

- `human`;
- `machine`.

Unknown kinds fail closed.

A human may hold owner authority.

A machine cannot hold owner authority in Jury v1.0.

The rule avoids unattended policy-admin credentials in the first release.

### 9.2 Item roles

The wire model supports exactly:

- `reader`;
- `writer`.

`writer` includes `reader`.

Absence of a grant means no access.

There is no explicit `deny` entry because Jury v1.0 has direct grants only.

Owner authority is vault-global rather than another per-item role.

Every active owner is an effective writer and reader of every active item.

### 9.3 Effective access

For an item and principal:

1. If the principal is an active owner, effective access is owner.

2. Otherwise, use the exact active direct grant for that principal and item.

3. Otherwise, deny access.

The policy validator rejects duplicate grants.

The validator rejects a key slot without effective reader access.

The validator rejects missing key slots for any effective reader, writer, or
owner.

The validator rejects multiple current slots for the same item, key epoch, and
principal.

### 9.4 Administration rules

Only an active owner under the previous accepted policy state may sign the next
policy revision.

Genesis contains exactly one human owner.

At least one human owner must remain active.

Adding an owner rotates and reseals every active item once, replaces every slot
set, and adds that principal under the new epoch in the same atomic policy
transaction.

Removing an owner increments every affected item key epoch, rotates any
construction-internal epoch secret, and creates fresh content revision secrets.

Owner revocation must be executed by a different remaining owner.

The owner being removed cannot authorize the command with its own selected
identity in Jury v1.0.

The remaining acting owner signs every replacement item revision under the new
policy sequence, where that acting owner still has authority.

Removing a principal is prohibited while any direct grant or current key slot
still refers to it.

Principal registration may be combined with exact initial item grants and their
reader-set rotations in one owner-signed policy revision.

The transaction resolves every requested name through the owner's decrypted
catalog and commits all grants or none.

The CLI may offer an explicit `--revoke-all` workflow that performs all required
rotations, but it must present the complete item count and require interactive
confirmation or an explicit automation flag.

### 9.5 Role changes

Reader to writer:

- append an owner-signed policy revision;
- retain the same key epoch, current seals, and access path;
- allow future item signatures by that principal.

Writer to reader:

- append an owner-signed policy revision;
- retain the same key epoch, current seals, and access path;
- reject future item signatures from that principal under the new policy.

No access to reader or writer, and reader or writer to no access, are effective
reader-set changes. For either direction:

- owner unwraps and decrypts the current descriptor and item body;
- rotate any construction-internal epoch secret and generate fresh
  descriptor/body revision secrets and seal identifiers;
- increment key epoch;
- increment descriptor revision and reseal descriptor and item body with
  independent fresh nonces;
- create slots only for the complete new effective reader set;
- append an owner-signed policy revision binding the new epoch, replacement
  descriptor metadata, and new current item revision hash;
- append a new owner-signed item revision;
- persist both changes atomically.

Initial readers supplied during item creation do not require an extra rotation
because no earlier item ciphertext exists. A repeated grant that leaves the
effective role unchanged is rejected as a no-op. Reader-to-writer and
writer-to-reader changes retain the key epoch and current seals because the
effective reader set is unchanged. A later content mutation still uses a new
revision seal identifier and secret.

Reader or writer to no access is called read revocation. No access to reader or
writer is called a read grant. Both are reader-set changes.

### 9.6 Item creation and deletion

An owner creates an item.

Initial creation generates an opaque item ID, fresh descriptor and body
revision secrets and seal identifiers, key epoch one, encrypted
descriptor revision one, item revision one, and access paths for every owner plus
explicitly granted principals.

The creator may grant initial readers and writers in the same policy revision.

An item name must satisfy the existing canonical `VaultItem` rules.

An active item name must be unique.

The acting owner proves uniqueness by decrypting the descriptors of every active
item before creation or rename.

Public validation can prove stable-ID uniqueness and descriptor authenticity but
cannot prove plaintext-name uniqueness without an owner session.

Item deletion is an owner policy operation.

Deletion leaves a signed public tombstone containing item ID, deletion policy
sequence, final descriptor digest, and final item revision hash.

The current descriptor ciphertext, body ciphertext, and key slots are removed
from the live artifact.

The tombstone prevents the same historical item from silently reappearing.

It does not revoke retained copies.

### 9.7 Item and field renames

An item rename is an owner policy change because canonical names affect reference
routing and global uniqueness even though names are encrypted.

It increments the descriptor revision and re-encrypts only the small descriptor
with a fresh nonce, `RevisionSealId`, and independent descriptor revision
secret.

It does not increment the key epoch or reseal the item body.

A field rename is a writer item mutation.

Field names remain inside the encrypted item body.

Existing compatibility rules about source and destination references remain.

## 10. Cryptographic suite

### 10.1 Suite identifiers

J01A assigns the first Jury v1 suite identifier only after its property matrix
and alternative analysis are reviewed. This plan deliberately does not name the
winner in advance.

The matrix records, for every candidate construction:

- classical confidentiality and authenticity;
- harvest-now/decrypt-later resistance for stored recipient slots;
- post-quantum authenticity as a separate property from confidentiality;
- recipient-compromise history exposure and other forward-secrecy nonclaims;
- nonce-misuse behavior, key commitment/binding, and catastrophic-reuse modes;
- standardization maturity, interoperability, provider diversity, and vector
  quality;
- public/private key, encapsulation, signature, and per-recipient artifact size;
- CPU, memory, startup, backup, and migration cost on supported platforms;
- portability, hardware/provider constraints, and operational failure modes.

At minimum J01A compares:

- storage AEAD: AES-256-GCM-SIV, one-key/one-seal RFC 8439
  ChaCha20-Poly1305, and XChaCha20-Poly1305 pinned to the exact expired draft;
- recipient wrapping: classical RFC 9180 HPKE, pure ML-KEM HPKE, and
  X25519+ML-KEM-768 hybrid HPKE pinned to the exact active IETF draft;
- strict Ed25519 and a reviewed hybrid-signature alternative if post-quantum
  authenticity is required;
- the complete KDF schedule, password KDF, device-factor combiner, randomness,
  and all size/count/resource limits.

The HNDL trade is explicit. Hybrid X25519+ML-KEM-768 preserves the classical
component if the PQ component fails and provides PQ confidentiality if ML-KEM
holds, but the current draft's public key is 1,216 bytes and encapsulation is
1,120 bytes instead of X25519's 32-byte values. It also adds implementation,
dependency, vector, migration, and draft-churn risk. Pure ML-KEM-768 is slightly
smaller than the hybrid but abandons the classical safety net. Classical HPKE is
smaller and more mature but retained ciphertext becomes decryptable if a future
quantum attacker obtains the recipient's long-term key.

FIPS-validated deployment is not required and must not influence the winner.
FIPS 203 may define ML-KEM while Jury remains an ordinary non-validated product.

The selected suite identifier is authenticated at lineage genesis. Exactly one
suite is valid for the entire lineage. There is no negotiation, preference list,
retry under a second suite, classical/PQ fallback, dual wrapping of the same
root, or mixed active suite. Unknown identifiers fail before private-key or KDF
work.

A suite change creates a new lineage. The owner validates the old lineage,
creates new vault/genesis identifiers, keys, seal identifiers, ciphertexts, and
slots under the new suite, and signs a migration statement binding old genesis,
old terminal revision and suite, new genesis and suite, and a canonical manifest
of migrated item digests. The old lineage is retained unchanged. In-place suite
mutation is invalid. Re-encryption protects the new lineage only; an adversary
who retained the old artifact can continue attacking it under the old suite, so
migration is never described as retroactive HNDL protection or revocation.

### 10.2 Provider proof gate

Use maintained implementations of the accepted HPKE and KEM specifications
rather than constructing an ECIES-like scheme or hybrid combiner from raw curve,
KEM, KDF, and AEAD calls.

Do not choose an exact Rust package or version from this plan or before J01A
freezes the suite.

J01B selects current implementations only for the J01A suite after checking:

- compatibility with the workspace MSRV recorded at implementation time;
- exact default-disabled feature trees;
- provider repository ownership and maintenance history;
- published security advisories and RustSec status;
- every normative standard or pinned draft and its known-answer vectors;
- strict key and signature validation;
- fallible entropy paths without hidden panics;
- zeroization behavior of concrete private-key and intermediate types;
- absence of unwanted plugin, shell, SSH, PEM, PKCS#8, legacy, and hazmat
  surfaces in the product build;
- license compatibility;
- deterministic cross-provider positive and negative fixtures;
- dependency duplication and supply-chain footprint;
- independent verification by a second vector implementation.

The due-diligence record includes the exact crate versions, source revisions and
checksums, features, `cargo tree`, advisory snapshot, licenses, MSRV, unsafe-code
posture, wrapper behavior, and rejected alternatives.

Entropy failures become typed value-free errors before partial cryptographic
output escapes.

Tests inject entropy failure, provider error, malformed public keys and
ciphertexts, all-zero classical shared secrets when applicable, non-canonical
signatures, resource-limit violations, and zeroization on all exits. At least
two independent implementations agree on success outputs and rejection
semantics for every load-bearing construction.

Do not enable unrelated plugin, SSH, PEM, legacy, or hazmat surfaces.

The suite remains exactly specification- and vector-defined even if a concrete
Rust provider changes.

### 10.3 Key generation

Generate independent random private keys for the suite's recipient KEM and
signature constructions.

Do not derive one private key from the other.

Do not derive principal private keys from a human passphrase.

The passphrase only protects random private keys at rest.

Generate every random revision secret and optional construction-internal epoch
secret independently with the OS random source. Never use an optional epoch
secret directly as an AEAD key.

Generate a fresh random 32-byte `RevisionSealId` and a fresh suite AEAD nonce on
every descriptor or body seal, including unchanged-body cover reseals.

Generate a fresh KEM encapsulation for every direct key slot and every
revision-scoped witnessed capsule that uses one.

### 10.4 Key identifiers and fingerprints

Each principal gets a random ULID principal ID.

Jury public descriptors admit exactly one application-level encoding for the
selected suite's recipient public-key bundle. J01A freezes its component order,
lengths, validation rules, and canonical bytes. If the suite contains X25519,
the encoding is the 32-byte little-endian `u` coordinate emitted by deriving the
public key from the stored private key, with the top bit clear and the integer
strictly below `2^255 - 19`; alternate RFC 7748 encodings are rejected. If the
suite contains ML-KEM, its encapsulation key uses the exact FIPS 203 and pinned
HPKE-profile encoding and length. Hybrid components cannot be omitted,
reordered, or silently treated as a classical key.

The public descriptor also has a SHA-256 fingerprint over a canonical encoding of:

- descriptor format version;
- principal ID;
- principal kind;
- canonical recipient public-key bundle;
- canonical verification-key bundle.

Public-key uniqueness compares each canonical recipient and verification key
component independently of principal ID and fingerprint, so an alternate
encoding or hybrid-component substitution cannot evade duplicate-key rejection
or masquerade as a fresh key during principal replacement.

The descriptor includes the suite's strict self-signature over that same
domain-separated canonical descriptor, excluding the signature field itself.

That self-signature proves control of the signing key only. Before policy
addition, the acting owner issues a single-use registration challenge containing
a random 32-byte response encrypted to the descriptor's HPKE public key. The
candidate identity decrypts it and signs a response transcript that binds the
vault ID, issuing owner, challenge ID, descriptor fingerprint, HPKE
encapsulation/ciphertext digest, and recovered response. The owner verifies its
own challenge signature, the exact recovered response, and the candidate
signature before committing `principal_add`.

Challenge and response use dedicated HPKE `info`, AAD, and signature domains.
They are portable public artifacts, contain no identity private material, are
bound to one vault and descriptor, and are consumed by the successful add. The
shared policy stores the descriptor and owner-authorized addition, not the
off-policy random response. Duplicate-principal validation prevents replay after
addition. A core principal-add API must receive a successfully verified proof;
raw wire replay still treats the preceding owner's signature as the public
authorization boundary.

Display fingerprints in a grouped lowercase representation.

Machine-readable output uses the full lowercase hex digest.

Import never trusts a user-supplied fingerprint field without recomputing it.

### 10.5 Domain separation

Every signature, hash, KDF, HPKE `info`, HPKE AAD, and suite AEAD AAD has a
distinct ASCII domain prefix.

The Jury v1 implementation must provide one module of typed preimage builders.

Callers must not concatenate free-form strings ad hoc.

Every variable-length field is length-prefixed by its UTF-8 or byte length.

Every integer uses fixed-width big-endian encoding in cryptographic preimages.

Lists are encoded in validated canonical order.

JSON bytes are never signed directly.

This avoids dependence on serializer whitespace or object-key ordering.

Before the wire format freezes, the format-v1 specification must document the exact byte layout
for every preimage: domain-prefix bytes, discriminant/tag bytes, field order,
integer widths, length widths, optional-value encoding, and list ordering. A
checked-in generic vector corpus must contain exact hexadecimal preimages,
digests, item-subkey KDF contexts and outputs, HPKE `info`/AAD, suite AEAD AAD,
descriptor bytes, and strict signature bytes for every variant. Tests compare
production builders byte-for-byte with vectors produced by an independent
fixture encoder rather than round-tripping through the same builder.

### 10.6 Item descriptor and body encryption

Every descriptor or body seal has an independently random 32-byte
`RevisionSealId` and an independent suite-sized revision secret. J19 chooses one
reviewed creation construction:

- generate the revision secret randomly, wrap it separately to each direct
  recipient, and place it in a threshold/distributed-decryption capsule for the
  witnessed path; or
- derive it with a reviewed distributed PRF/KDF construction that lets direct
  and witnessed paths obtain the same output without exposing a reusable epoch
  root to the witnessed endpoint.

The first option is the conservative baseline because an author can create a
new capsule from public keys and a malicious endpoint retaining old plaintext,
keys, and transcripts has no algebraic route to the independently random next
secret. Its cost is one new direct capsule per recipient and one new witnessed
capsule for every seal. The second may reduce capsule churn but is accepted only
if J19 identifies a maintained, independently reviewed construction and proves
writer creation, mixed-mode equivalence, rotation, and retention behavior; a
bespoke HKDF over static shares is invalid.

Whichever construction J19 selects, its canonical secret-derivation or capsule
context contains at least:

- a distinct descriptor/body domain;
- suite ID and schema version;
- vault ID and item ID;
- key epoch and exact content role (`descriptor` or `body`);
- descriptor or item revision number;
- the fresh `RevisionSealId`.

No revision or seal identifier is omitted. Distinct descriptor, body, and role
contexts cannot collide. J01A freezes any extract/expand functions, salt
behavior, output lengths, context encoding, and maximum work before J01B selects
providers. J19 freezes the distributed construction before J05 or J07 freezes
its format.

The implementation exposes distinct non-interchangeable descriptor- and
body-revision-secret types plus an internal epoch-root type only if the reviewed
construction requires one. All use zeroizing storage. KDF and decapsulation
state remain in the shortest possible scope and are dropped before the consumer
callback. J01B documents the provider's real zeroization behavior rather than
inferring it. No public callback receives an epoch root, and a witnessed
implementation never obtains one.

Nonce uniqueness remains mandatory even if J01A selects a misuse-resistant
storage AEAD. Replay validation rejects reuse of a `(key epoch, role, revision,
RevisionSealId, nonce)` tuple and rejects a seal identifier already used by any
descriptor or body seal in the lineage.

Each item then has two independently sealed suite-AEAD ciphertexts:

- a small descriptor ciphertext containing `ItemDescriptorV1`, encrypted with
  the descriptor revision secret;
- the existing field-body ciphertext containing `ItemStateV1`, encrypted with
  the body revision secret.

`ItemDescriptorV1` has one canonical 256-byte binary plaintext encoding:

- byte 0 is descriptor schema version one;
- bytes 1 through 2 are the unsigned 16-bit big-endian UTF-8 name length;
- bytes 3 through 66 are a 64-byte name region containing the exact canonical
  item-name bytes followed by zero padding;
- bytes 67 through 255 are reserved zero bytes.

The decoder rejects a name length above 64, invalid UTF-8 or canonical item
syntax, a nonzero byte in either padding region, or any plaintext length other
than 256. Consequently every Jury v1 descriptor ciphertext has the same length; the
public length is checked against that constant rather than treated as private
metadata.

Descriptor associated data binds:

- domain `jury-vault-v1-item-descriptor`;
- vault ID;
- item ID;
- key epoch;
- monotonically increasing descriptor revision;
- descriptor plaintext schema version.

Creation, rename, and every reader-set change use fresh descriptor nonces.

Rename increments the descriptor revision and replaces only descriptor
ciphertext.

Every reader-set change advances the key epoch, rotates any construction-
internal epoch secret, generates fresh descriptor and body seal identifiers and
revision secrets, and therefore re-encrypts both ciphertexts.

The owner-signed policy operation binds descriptor revision, nonce, ciphertext
length, and SHA-256 ciphertext digest.

Public validators authenticate those fields without learning the name.

Do not use a public hash, deterministic encryption, or name-derived item ID;
canonical environment names have a small guessable dictionary.

The item body uses the selected storage AEAD with its suite-defined fresh nonce
and body revision secret.

`ItemStateV1` is serialized as a four-byte big-endian logical-length prefix,
canonical body bytes, and zero padding to the smallest allowed plaintext bucket:
4 KiB, 8 KiB, 16 KiB, 32 KiB, 64 KiB, 128 KiB, 256 KiB, 512 KiB, 1 MiB, 2 MiB,
4 MiB, or 8 MiB. The decoder requires an exact bucket length, a representable
logical length, canonical body decoding within that prefix, and all-zero
remaining padding. No compression occurs before encryption.

The public envelope records the bucket ID and exact corresponding ciphertext
length, not the logical length. Capacity preflight includes base64/JSON overhead;
an item that cannot fit its next bucket under the 16 MiB artifact ceiling fails
before mutation. The 1 MiB per-field limit remains, while the 8 MiB padded-body
ceiling deliberately bounds aggregate fields in one item.

Its associated data binds:

- domain `jury-vault-v1-item-body`;
- vault ID;
- item ID;
- key epoch;
- item revision number;
- plaintext schema version.

It deliberately does not bind the encrypted mutable item name or descriptor
revision.

It deliberately does not bind the policy sequence because role-only policy
changes that preserve the effective reader set do not reseal unchanged item
content.

The signed item revision binds the policy sequence used to authorize the writer.

A writer may run `jury privacy cover --item ITEM`. It decrypts and
canonically reserializes the unchanged logical body, chooses the same bucket,
uses a fresh nonce, and publishes an otherwise ordinary signed item revision
with no public cover/no-op discriminator. Shared-state observers therefore
cannot distinguish that revision from a real same-bucket logical update by its
format. It still consumes one proof-history entry, changes the file, requires
redistribution, and records an explicit event only in the acting identity's
private local audit.

Cover reseals provide useful scheduled cover activity but do not conceal which
opaque item changed, policy mutations, artifact access/transport times, missed
schedule intervals, or comparisons with endpoints that know the plaintext.

### 10.7 Algorithm-tagged recipient slots

Every slot begins with a bounded algorithm tag and slot-schema version.

`direct-hpke-v1` uses the J01A HPKE profile to encrypt the exact suite-sized
revision secret to one principal recipient public key. If J19 accepts an
epoch-secret optimization, it must use a separately tagged slot and still expose
only revision secrets through the common API.

Its HPKE `info` binds:

- domain `jury-vault-v1-direct-revision-secret-slot`;
- suite ID;
- slot schema;
- vault ID;
- item ID;
- key epoch;
- content role, revision number, and `RevisionSealId`;
- recipient principal ID.

Its HPKE AAD binds:

- policy sequence that introduced the slot;
- recipient public-key fingerprint;
- exact role at that policy sequence;
- slot algorithm tag;
- downgrade-protection metadata.

`witnessed-v1` identifies a witnessed policy, endpoint commitment, witness set,
construction identifier, content role, revision number, `RevisionSealId`, and
bounded algorithm-specific capsules. Each capsule is valid for exactly that
revision seal and releases or reconstructs only its revision secret.

Its exact contribution construction is frozen by the protocol task only after
retention, collusion, witness rotation, recovery, and deterministic vectors are
reviewed.

All witnessed request and response messages bind the same vault, item, epoch,
policy, principal, content role, revision, `RevisionSealId`, slot, and
construction identifiers.

An epoch root, static share of it, or contribution reusable across revision seal
identifiers is never stored in a witnessed slot, response, or endpoint-visible
capsule. Direct capsules wrap the exact revision secret unless J19 explicitly
accepts a separately tagged internal-epoch optimization; the common consumer API
never exposes epoch state.

Slots are contained in and authenticated by an owner-signed policy change.

Granting or revoking effective read access creates a new epoch and an entirely
new set of revision-scoped direct and witnessed capsules.

Changing a slot algorithm also creates a new epoch.

Changing the lineage suite is not a slot-algorithm change. It uses the
authenticated new-lineage migration in section 10.1 and never installs old- and
new-suite slots beside one another.

Mixed direct and witnessed slot sets are permitted only when owner policy names
each path explicitly. No evaluator may infer witnessed protection for one
principal from another principal's witnessed slot, and no downgrade may add a
direct slot without the ordinary owner-authorized new-epoch replacement.

A new reader never receives a revision secret used before its grant.

The only public item-key operation is the `ItemAccessProvider` boundary in
section 0.9; no adapter gets a raw private-key or epoch-root accessor.

### 10.8 Signatures

Policy revisions use the J01A-selected strict signature suite by an active
owner.

Item revisions use the same suite's signature construction by a writer or owner
authorized under the referenced policy sequence.

Verification uses the exact strict rules, canonical encodings, and hybrid
component requirements frozen by J01A. If the suite claims post-quantum
authenticity, every required classical and PQ component is bound and verified;
there is no verify-any fallback.

Reject non-canonical keys and signatures according to the selected library's
strict API.

Do not expose raw signing primitives.

### 10.9 Protected memory and dump exclusion

Private identity plaintext, optional item epoch secrets, descriptor/body revision secrets,
KDF intermediates, decrypted item descriptors, canonical item names held by a
session, decrypted item bodies, serialized plaintext bodies, resolved field
values, signing keys, and HPKE secret keys must be held in zeroizing containers
wherever the Rust type system and selected dependencies allow.

Before passphrase capture, hardware-protector use, or any private-key operation,
the CLI/TUI process lowers `RLIMIT_CORE` to zero. Linux additionally sets
`PR_SET_DUMPABLE` to zero. Failure stops before unlock unless the operator uses
the explicit `--allow-unprotected-memory` emergency override and confirms the
degradation; non-interactive use additionally requires
`JURY_ALLOW_UNPROTECTED_MEMORY=1`. This variable is removed before every
child process. Public validation/status commands do not need the override because
they never capture or derive secrets.

Add a page-dedicated, non-growing `ProtectedMemory` allocation owned by
`jury-core` or a neutral extracted leaf crate. Compact passphrases captured through Jury-owned input, Jury-generated
identity roots and private keys, signing keys, optional epoch secrets, revision secrets,
audit/checkpoint seeds, and RNG seeds enter it without a prior Jury-owned ordinary
`String`/`Vec` copy. External keychain, Secure Enclave, TPM, and FIDO APIs may
return short OS/library-owned buffers that Jury cannot allocate itself; copy those
immediately into `ProtectedMemory`, zero or release the source through the
provider API where supported, and record any unavoidable non-zeroizable provider
copy in that adapter's assurance documentation. No ordinary Jury-owned provider
copy may outlive the call. On Linux protected pages require
`mlock2(MLOCK_ONFAULT)` with a verified `mlock` fallback,
`MADV_DONTDUMP`, and `MADV_DONTFORK`; on macOS they require `mlock`, while the
process-wide zero core limit supplies the dump control. Guard pages and page-
rounded bounds prevent neighboring general allocations from being locked or
exposed. Setup is all-or-nothing and drop zeroizes before unlock/unmap. Linux
fork tests prove `MADV_DONTFORK` mappings are absent in the child. macOS code
must not execute user-controlled work between fork and exec; post-exec tests
prove the protected mappings are gone, while the zero core limit remains
inherited on both platforms.

If the supported OS cannot lock the compact protected allocation, unlock fails
closed unless the same explicit emergency override is active. JSON/human status
reports `required`, `active`, `degraded_by_override`, or `unsupported` without
addresses or secret-dependent detail. TUI sessions always keep their retained
identity material in protected pages and display persistent degraded state when
the override is used.

Bulk decrypted item bodies, serializer scratch, redaction copies, child-process
copies, and the 128–512 MiB Argon2 workspace remain short-lived zeroizing memory
but are not promised `mlock` coverage. Process-wide dump suppression covers
ordinary cores; encrypted swap/hibernation and privileged live-memory controls
remain deployment requirements. Documentation must not claim protection from
root, a debugger already controlling the process, suspend images, DMA, or an
authorized child that receives plaintext.

Public keys, opaque item IDs, hashes, signatures, and ciphertext need not be
zeroized.

Document unavoidable serializer and OS child-process copies just as the current
vault does.

Do not weaken `SecretBytes` non-growing allocation behavior.

## 11. Jury vault format version 1

### 11.1 Top-level shape

The conceptual top-level structure is:

```text
VaultFileV1 {
  header: VaultHeaderV1,
  policy: PolicyJournalV1,
  items: map<ItemId, ItemEnvelopeV1>,
}
```

The actual persisted encoding is pretty-printed JSON for operator inspection and
bounded cross-language tooling; it does not inherit a Jury predecessor format.

Secret-bearing and canonical item-name plaintext remains nested only inside item
ciphertext.

The native writer has only Jury format-v1 Serde types.

Jig v1/v2 compatibility types live in a read-only migration module and never
flow into the native writer.

Do not add Jury fields to the read-only Jig v2 compatibility struct.

Parse the minimal discriminating header first, enforce the total byte limit, then
deserialize the version-specific body.

### 11.2 Header

`VaultHeaderV1` contains:

- `magic = "jury-vault"`;
- `version = 1`;
- `vault_id`;
- `created_at_ms`;
- `suite`;
- `policy_schema = 1`;
- `item_schema = 1`;
- `identity_schema = 1`;
- `genesis_fingerprint`.

The Jury v1 header has no passphrase KDF, salt, wrapped vault DEK, or vault-wide state
nonce.

Those fields remain only in read-only Jig v1/v2 compatibility types.

`genesis_fingerprint` is the SHA-256 digest of the canonical signed genesis
record.

### 11.3 Policy genesis

`PolicyGenesisV1` contains:

- vault ID;
- policy sequence zero;
- creation timestamp;
- suite ID;
- exactly one human owner public descriptor;
- empty opaque item inventory;
- empty grants;
- zero previous-policy hash;
- genesis owner signature.

For a Jig v1/v2 migration only, genesis also contains an authenticated
`source_migration` attestation with source version, migration ID, SHA-256 digest
of the final preserved legacy audit bytes, and the verified terminal legacy
audit MAC.

For a Jury v1 rollover only, genesis instead contains an authenticated
`source_rollover` attestation with the source vault ID, source genesis
fingerprint, terminal source vault revision, rollover ID, and the acting source
owner's signature over that complete bridge plus the destination vault ID and a
canonical unsigned bootstrap-manifest digest. The manifest commits the complete
destination principals, owners, grants, items, and ciphertext metadata created
by its first policy revision. It excludes all signatures and the genesis
fingerprint, avoiding a hash/signature cycle. New Jury v1 vaults omit both
attestations, and a genesis containing both is invalid.

The owner self-signature provides integrity, not third-party identity proof.

The first import is trust on first use.

The CLI must show and optionally require the owner fingerprint during first
installation.

### 11.4 Policy journal

`PolicyJournalV1` contains genesis plus an ordered list of
`SignedPolicyRevisionV1`.

Every revision contains:

- monotonically increasing sequence;
- previous policy revision hash;
- timestamp;
- author principal ID;
- an ordered non-empty list of typed operations;
- resulting normalized policy-state hash;
- signature.

The validator replays the journal from genesis.

It checks author authority before applying each operation.

It computes the resulting normalized state and compares its hash.

It rejects sequence gaps, duplicate sequences, empty changes, unknown operations,
invalid transitions, and trailing unreferenced material.

### 11.5 Policy operations

The first schema supports these typed operations:

- `principal_add`;
- `principal_label_change`;
- `principal_remove`;
- `owner_grant`;
- `owner_revoke`;
- `item_create`;
- `item_rename`;
- `item_delete`;
- `item_role_change`;
- `item_reader_set_change`;
- `item_slots_replace`;
- `principal_replace`.

An API-level transaction may encode several operations in one revision.

`item_create` and `item_rename` bind the resulting descriptor revision, key
epoch, nonce, ciphertext length, and ciphertext digest.

`item_reader_set_change` represents any change to effective reader membership,
including item grant/revoke, owner grant/revoke, or the simultaneous old-key/
new-key substitution in `principal_replace`. It binds the exact prior and next
reader IDs, replacement descriptor metadata, and replacement current body
revision because both ciphertexts move to fresh seal identifiers and independent
revision secrets in the new key epoch.

`principal_replace` atomically substitutes a fresh principal descriptor for an
existing principal and copies its kind, label, direct grants, and owner status.
It must be paired with exactly one reader-set change and slot replacement for
every item the old principal could read, so old and new recipient keys never
share an item epoch. The old principal is absent from the resulting normalized
state.

The validator enforces legal combinations.

For example, `item_reader_set_change` must be paired with
`item_slots_replace` for the next epoch and must bind the replacement current
item revision hash. Neither operation is legal alone, and a reader-set change
may not retain any prior construction-internal epoch secret or prior-epoch
capsule.

Unknown operation names fail closed.

### 11.6 Normalized policy state

Journal replay produces:

- active principals by principal ID;
- active owners;
- active opaque items by item ID, kind, and authenticated descriptor metadata;
- item tombstones;
- direct item grants;
- current key epoch per item;
- current direct and witnessed capsules per item, recipient, and revision seal;
- current item revision hash expected after policy-bound rotations.

All maps are deterministically ordered.

No plaintext item name or field metadata appears in normalized policy state.

### 11.7 Item envelope

`ItemEnvelopeV1` contains:

- stable item ID;
- current descriptor revision;
- current descriptor `RevisionSealId`;
- current descriptor nonce;
- current descriptor ciphertext;
- zero or more prior revision proofs;
- exactly one current signed item revision;
- current body `RevisionSealId`;
- current item body nonce;
- current item ciphertext.

The public policy state contains only the expected descriptor metadata.

An authorized session requests the exact descriptor revision secret through its
configured `ItemAccessProvider` and decrypts the descriptor to obtain the
canonical name. The provider discards every epoch root and KDF intermediate
before the callback, and the session discards the descriptor secret immediately
after catalog construction. A body access is a separate request for the current
body revision secret.

The item map key and all embedded IDs must agree with the envelope item ID.

The map key must equal the embedded item ID.

Every direct key slot and witnessed capsule records the policy sequence and
effective access role under which it was issued so authenticated bindings remain
reproducible after a later reader/writer role change that intentionally retains
the same access path. Witnessed capsules additionally bind the exact content
role, revision, and seal identifier.

### 11.8 Item revision

`SignedItemRevisionV1` contains:

- vault ID;
- item ID;
- monotonically increasing item revision number;
- one previous item revision hash, or the zero hash for creation;
- key epoch;
- policy sequence used for authorization;
- author principal ID;
- timestamp;
- item body nonce;
- ciphertext length;
- SHA-256 ciphertext digest;
- plaintext schema version;
- strict suite signature bundle.

The ciphertext is stored beside the current revision rather than inside the
signed metadata.

The validator recomputes its digest and length.

### 11.9 Revision proofs

When an item is updated, the previous current revision becomes a proof.

A proof preserves the complete signed revision metadata and signature.

It discards the prior ciphertext bytes after retaining their digest and length in
signed metadata.

It retains the prior public nonce because that nonce is part of the signed
revision preimage.

Proofs form a complete chain from revision one to the parent of current.

This lets a fresh recipient validate authorship and ancestry without receiving
old secret ciphertext.

It also lets a transfer importer determine whether one branch is a strict
descendant of another.

The validator rejects missing proof links, duplicate revision numbers, parent
hash mismatches, policy references outside the validated journal, and authors who
lacked writer authority at their referenced policy sequence.

### 11.10 Item plaintext

`ItemStateV1` contains:

- plaintext schema version one;
- a deterministic map from field name to `ItemFieldV1`.

`ItemFieldV1` contains:

- base64 field value;
- exact decoded value length;
- field kind;
- creation timestamp;
- update timestamp.

The item ID and name are not duplicated in the field-body plaintext.

Field references are reconstructed from the decrypted current item descriptor
plus decrypted field name.

Decoded lengths and all existing concealed/text validation rules are rechecked
after decryption.

### 11.11 Legacy compartment

Unrepresentable legacy names migrate into one reserved owner-only compartment.

The compartment has a generated stable item ID and policy kind `legacy`.

It does not claim a canonical `VaultItem` name.

Its encrypted descriptor contains the reserved owner-visible display label
`(legacy)`.

Its body stores the existing legacy name map and metadata.

Only owners receive key slots.

The compatible `vault secret` commands route a representable legacy name to its
canonical item/field and enforce that item's role.

Only an unrepresentable name routes to this owner-only legacy compartment.

Conversion to a canonical field is one atomic owner operation touching the legacy
compartment, destination item, item revisions, and local audit.

### 11.12 Bounds

Retain the existing 16 MiB persistent `vault.json` read/write ceiling for the
first release.

Retain the 1 MiB per-field value limit and existing concealed minimum.

Retain the 1,024-field import limit.

Add explicit parse-time caps for:

- 256 active principals;
- 1,024 active plus tombstoned items;
- 16,384 active direct grants;
- 16,384 current key slots;
- 4,096 policy revisions;
- 65,536 item revision proofs across the artifact;
- 256 bytes per public label;
- exactly 256 plaintext bytes per encrypted item descriptor, retaining the
  existing 64-byte canonical item-segment limit;
- fixed encoded lengths for every key, nonce, digest, and signature.

The total 16 MiB limit remains authoritative even when individual count limits
would allow more. Public JSON framing is deliberately not padded: a parseable
padding field would reveal its own length and let an artifact holder recover the
unpadded public size. Exact public artifact/transfer length remains a documented
leak while encrypted item bodies hide their logical lengths within buckets.

Deserializers must reject oversized base64 text before decoding to avoid
allocation amplification.

The implementation may propose a larger file cap only with benchmark evidence,
documented backup implications, and an explicit plan amendment.

Every mutation preflight computes its resulting policy, item-proof, slot, item,
and total encoded-size counts before writing. A mutation that would cross a hard
cap fails with the typed `Capacity` error and an exact `jury history
rollover` next step; it never commits a state that cannot still be rolled over.
Rollover itself reads but does not grow the source and therefore remains
available at a source cap.

### 11.13 Authenticated history rollover

Jury V1 does not prune or rewrite a vault's signed policy or item-proof ancestry in
place. An explicit owner-only rollover creates a new Jury v1 lineage in an absent
vault home.

The rollover validates and checkpoints the source, decrypts its current logical
state as an owner, and creates a new vault ID, genesis fingerprint, item IDs,
revision seal identifiers and secrets, capsules, nonces, ciphertexts, and
revision-one chains.
It reproduces only active
principals, owners, direct roles, current item descriptors/bodies, and the
owner-only legacy compartment. Tombstones and prior policy/item proofs stay
available in the unchanged source rather than being copied as live history.

Current effective readers receive new-lineage slots; removed principals do not.
The new genesis carries the signed `source_rollover` bridge from section 11.3.
That bridge authenticates provenance but does not make the new vault the same
lineage: transfer merge rejects cross-lineage updates, and each installation
must explicitly trust/install the new genesis fingerprint.

Rollover writes only to hardened absent destinations, supports a complete
dry-run, never replaces or deletes the source, and emits exact backup,
redistribution, and old-lineage retention guidance. A fresh owner backup and
fresh local export receipt are required for the new lineage; an old backup does
not claim to cover it.

## 12. Identity lifecycle

### 12.1 Storage location

Private identities live outside every vault home.

The default identity root follows the platform data-directory convention:

- `${XDG_DATA_HOME:-$HOME/.local/share}/jury/identities` on Linux;
- `~/Library/Application Support/jury/identities` on macOS;
- the documented per-user local application-data directory on Windows.

`JURY_IDENTITY_HOME` overrides that identity root.

It must not equal, contain, or be contained by the selected vault home.

In particular, identities cannot live below a Jig source home or a Jury vault
home.

The default named identity file is:

`<identity-root>/default.identity.json`

An explicit `--identity NAME` resolves only the validated local name
`<identity-root>/<NAME>.identity.json`.

An explicit `--identity-file PATH` is the unambiguous path override.

`JURY_IDENTITY` is the non-interactive name override.

`JURY_IDENTITY_FILE` is the non-interactive path override.

The identity name, identity-file, and identity-home overrides are captured and
removed from child environments alongside reserved passphrase variables.

An explicit vault `--home` does not move the identity into that vault home.

### 12.2 Identity file

The public portion contains:

- magic and identity format version;
- principal ID;
- principal kind;
- suite-defined recipient public-key bundle;
- suite-defined verification-key bundle;
- recomputable fingerprint;
- identity creation time;
- KDF profile ID, exact Argon2id version/parameters, and salt;
- protection mode and bounded provider metadata;
- identity-root wrap algorithm and nonce;
- private-payload AEAD algorithm and nonce.

The encrypted private payload contains:

- suite-defined recipient private-key material;
- suite-defined signing-key material;
- random 32-byte local audit/checkpoint seed.

Generate a random 32-byte identity root. The exact J01A-selected
domain-separated KDF derives a payload key that encrypts the private payload
with the selected storage AEAD. The passphrase/device unlock key wraps only the
identity root under a separate fresh nonce and role. Root and payload keys are
distinct non-interchangeable types.

Associated data binds every public identity-file field and a payload role.

The public header records a KDF profile ID, the exact Argon2id version and
parameters, and a 16-byte random salt. Jury V1 admits only these exact profiles:

- `portable-v1`: Argon2id version 1.3, 131,072 KiB memory, three passes, four
  lanes, and a 32-byte output;
- `hardened-v1`: Argon2id version 1.3, 524,288 KiB memory, three passes, four
  lanes, and a 32-byte output.

`portable-v1` is the mandatory interoperable default and minimum for every new
Jury v1 identity and backup. `hardened-v1` is an explicit operator choice using the
current implementation's maximum accepted memory. It is a Jury profile, not a
claim to implement RFC 9106's first recommended profile (2 GiB, one pass, four
lanes). Jury's portable profile already exceeds that RFC's memory-constrained
profile (64 MiB, three passes, four lanes) while retaining three passes. Raising
the pre-authentication memory ceiling requires supported-platform and peak-RSS
evidence plus a new profile ID; implementations never silently reinterpret an
existing profile.

Before allocating Argon2 memory or capturing a passphrase, decode bounded scalar
fields and require an exact recognized profile-ID/parameter tuple. A known ID
with changed parameters, an unknown ID, arbitrary in-range parameters, excessive
parallelism, or an over-ceiling memory request fails as a typed format error.
Legacy identity and backup versions retain their version-specific validation and
must not inherit broader Jury v1 limits.

The 12-byte minimum passphrase remains an input floor, not an entropy claim.
Human guidance recommends generated multi-word passphrases and explains that KDF
cost cannot compensate for a guessable passphrase.

Jury v1 passphrases are exact valid UTF-8 byte strings from 12 through 1,024
bytes. Implementations perform no Unicode normalization, case folding, trimming,
or locale transformation. Interactive capture removes only the terminal line
ending; embedded NUL, carriage return, or line feed is rejected. Environment and
file-descriptor inputs must decode as UTF-8 and produce the identical byte
sequence. Bounds and encoding are checked before Argon2 allocation, and errors
never echo the input. Documentation warns that visually identical Unicode text
with different encodings is a different passphrase. Identity and Jury v1 backup
decoders share this exact contract.

Changing the identity passphrase generates a new KDF salt, identity root, root-
wrap nonce, and payload nonce and re-encrypts the same private payload. It is
storage-credential rotation, not recipient or signing key rotation, and it does
not prevent unchanged recipient private-key material from opening matching
direct slots in retained historical artifacts.

Passphrase change defaults to the stronger of the identity's recognized current
profile and `portable-v1`; it upgrades any supported legacy/weaker profile and
never silently downgrades `hardened-v1`. Operators may request
`--kdf-profile hardened`. A portability downgrade requires both
`--kdf-profile portable` and `--allow-kdf-downgrade`, plus an interactive warning
or the existing non-interactive confirmation contract. Reads report an available
profile upgrade but never rewrite an identity as a side effect.

#### Device-bound identity protection

Identity protection mode is exactly one of:

- `portable`: the profile-derived passphrase key is domain-separated with HKDF
  to form the identity-root wrap key;
- `device-bound`: unlock requires both the profile-derived passphrase key and one
  enrolled protector response. HKDF-Extract uses the passphrase key as salt and
  the normalized 32-byte protector response as input keying material, then an
  exact context binding identity format, principal ID, protection mode, provider
  kind, opaque credential ID, and provider challenge/salt derives the wrap key.

There is one active protection method and one wrapped identity root. A device-
bound identity never retains a passphrase-only recovery slot, cached protector
response, exported hardware private key, biometric data, PIN, or TPM/FIDO
authorization secret. Provider metadata is local identity-header data and never
enters shared vault policy, transfers, audit details, or child environments.

Support these versioned providers behind one typed `IdentityProtector` boundary:

- `keychain-v1`: a random 32-byte factor stored under application-scoped OS
  keychain access control. macOS Keychain and Linux Secret Service adapters are
  labeled `os-protected`, not automatically `hardware-backed`;
- `secure-enclave-p256-v1`: macOS Secure Enclave P-256 key agreement against an
  identity-bound peer public point, with the non-exportable private key stored by
  Keychain and user presence/verification required for human identities;
- `tpm2-sealed-v1`: a random 32-byte factor sealed and unsealed through a direct
  TPM 2.0 TSS API under a recorded bounded policy. The default binds to the TPM
  and object authorization, not volatile PCR values; a PCR-bound policy requires
  a separately versioned profile plus tested firmware-update and backup recovery.
  Jury never shells out to `tpm2-tools` with secret material;
- `fido2-hmac-secret-v1`: a credential-scoped CTAP2 `hmac-secret`/PRF response to
  the identity-bound 32-byte challenge, requiring user presence and verification
  for human identities.

The provider returns only a normalized factor into `ProtectedMemory`; it never
receives the passphrase, identity root, HPKE/signing private keys, or decrypted
item data. Status reports the provider kind, assurance class (`os-protected` or
`hardware-backed`), presence/verification policy, availability, and opaque
credential fingerprint without hardware serial numbers or attestation claims.
Unknown providers, algorithms, policy fields, response lengths, or credential
substitution fail before identity-root unwrap.

Each adapter must meet Rust 1.88, direct-API/no-secret-shellout, bounded
cancellation, temporary-buffer accounting, and real-device conformance
requirements. If an advertised adapter cannot meet them, implementation stops
and records that provider as unavailable; it must not silently substitute an OS
keychain or label software storage as hardware-backed. Removing a required
provider from the release needs an explicit plan amendment.

Enrollment, rebind, or removal first unlocks the existing method, verifies a
current owner-backup receipt or emits an explicit recovery warning, then creates
a fresh identity root/salt/nonces and atomically replaces the identity file.
Removing a protector requires `--allow-portable-downgrade` plus confirmation.
Provider cancellation, timeout, lockout, removal, or device loss never falls
back to passphrase-only unlock. Recovery decrypts an independent owner backup and
enrolls a replacement protection method while resealing the same principal keys.

Human FIDO2 and Secure Enclave modes require user presence/verification on every
unlock. Machine identities may use TPM2 or an explicitly non-interactive
keychain policy; status and documentation state the reduced physical-presence
property. No provider is silently selected from ambient devices.

### 12.3 Identity commands

Add:

```text
jury identity init [--name NAME] [--kind human|machine] [--label LABEL] \
  [--kdf-profile portable|hardened] \
  [--protection portable|keychain|secure-enclave|tpm2|fido2] \
  [--protector ID]
jury identity list
jury identity status [--name NAME]
jury identity public [--out FILE] [--overwrite]
jury identity prove --challenge CHALLENGE --out PROOF [--overwrite]
jury identity passphrase change [--kdf-profile portable|hardened] \
  [--allow-kdf-downgrade]
jury identity protection status
jury identity protection enroll --provider PROVIDER [--protector ID]
jury identity protection rebind [--protector ID]
jury identity protection remove --allow-portable-downgrade
```

`identity init` refuses an existing destination.

Identity names use a strict portable component grammar, never contain path
separators, and are not security identities.

It prompts twice or consumes the existing non-interactive new-passphrase policy.

It prints principal ID and fingerprint, never private keys.

`identity status` does not decrypt private keys. It reports the public header's
profile ID, exact parameters, and whether a stronger supported profile is
available, plus protection/provider metadata and local provider availability,
while marking file fields unauthenticated until a later unlock succeeds. Public-
header inspection never claims that the passphrase, hardware response, or private
payload is valid and never invokes a protector.

`identity list` scans only direct identity-root children matching the canonical
filename grammar, validates their public headers, and never unlocks or probes
private material.

Human output always identifies the selected vault, identity name, label, kind,
and grouped fingerprint before a protected mutation.

Labels are display-only and never resolve authorization targets.

`identity public` exports only a signed/self-consistent public descriptor through
the existing hardened private-file sink.

The public descriptor contains no claim that a label is verified identity.

`identity prove` validates the owner-signed, vault- and descriptor-bound
registration challenge, decrypts its HPKE payload with only the selected
identity, and writes the signed public proof through the same hardened sink. It
never emits the recovered response to terminal, JSON, audit, or diagnostics.

### 12.4 Principal key replacement

Principal public keys are immutable. Rotation creates a fresh identity with a
fresh principal ID and atomically replaces the old principal through the
`principal_replace` transaction; there is no in-place key edit.

The acting owner verifies a fresh registration proof for the new descriptor.
The transaction copies the old principal's kind, display label, direct roles,
and owner status, rotates every item readable by the old principal exactly once,
issues slots to the resulting reader set using only the new key, and removes the
old principal. Any partial copy or surviving old slot is invalid.

Replacement establishes post-compromise recovery only for the newly created item
epochs. Retained earlier vaults, transfers, backups, or ciphertext remain within
the old HPKE key's exposure and must not be described as revoked.

If the old principal is an owner, a different remaining owner must authorize the
replacement, and at least one such owner must remain. Operators should maintain
two human owners before a sole-owner key needs replacement; Jury v1.0 has no
cryptographic way to distinguish a legitimate sole owner from an attacker who
already controls that owner's signing key.

### 12.5 Passphrase compatibility

The read-only Jig migration adapter accepts `JIG_V2_VAULT_PASSPHRASE` only for
opening its source Jig v1/v2 envelope.

For Jury v1, `JURY_IDENTITY_PASSPHRASE` supplies the knowledge factor for the
selected local identity. A device-bound identity also invokes its exact recorded protector;
the environment variable alone is insufficient and no environment variable may
supply the provider response, PIN, biometric data, or presence assertion.

The CLI prompt changes from `Vault passphrase` to `Identity passphrase` after
detecting Jury v1 from the public header.

`jury passphrase change` remains a compatibility alias.

On Jury v1 it changes only the selected identity-file passphrase and returns explicit
JSON fields showing `target = "identity"`.

The preferred documented spelling becomes
`jury identity passphrase change`.

### 12.6 Multiple identities

The default release supports one explicitly named or explicitly pathed selected
identity per command and per TUI session.

It does not automatically try every identity file.

Automatic probing would leak membership through timing and multiply passphrase
prompts.

If the selected principal is absent from policy, return a safe principal-not-
registered error.

If it is registered but lacks an item slot, return item access denied.

There is no mutable project-local “current identity” pointer in Jury v1.0.

Scripts and operators select a non-default identity explicitly, preventing a
checkout from silently switching a global identity.

### 12.7 Machine identities

Machine identities use encrypted identity files and the same passphrase capture
environment as humans.

They do not use bearer tokens in Jury v1.0.

Automation supplies `JURY_IDENTITY` or `JURY_IDENTITY_FILE` plus
`JURY_IDENTITY_PASSPHRASE` through its own secret mechanism.

An explicitly enrolled TPM2 or non-interactive keychain protector may supply the
second factor. FIDO2 and human-presence policies are not suitable for unattended
automation and never downgrade themselves when no user is present.

Both variables are removed before child execution.

Machine identity documentation must emphasize filesystem permissions, CI secret
storage, and rotation.

### 12.8 Identity loss

Losing the only owner private identity without an owner backup makes policy
administration and owner-only item recovery impossible.

This is an intentional cryptographic property.

The CLI warns at vault creation and owner addition until a successful owner backup
has been created locally.

The warning state is local metadata, not a bypass.

## 13. Policy validation

### 13.1 Validation order

Opening a Jury v1 vault performs these steps before item decryption:

1. Read `vault.json` under the existing total byte cap.

2. Parse and validate the minimal header.

3. Enforce suite and schema support.

4. Decode fixed-size public keys, hashes, and signatures with strict lengths.

5. Validate genesis self-signature and header fingerprint.

6. Replay every policy revision from genesis.

7. Validate normalized policy invariants.

8. Validate each item proof and current revision signature against historical
   policy authority.

9. Validate opaque inventory completeness, authenticated descriptor metadata,
   and tombstones without decrypting names.

10. Load and authenticate the selected local checkpoint.

11. Reject policy or item revisions older than the checkpoint.

12. Locate the selected principal and, when name routing or item inventory is
    requested, build an accessible catalog by invoking only that principal's
    granted access paths for current descriptor revision secrets and decrypting
    only their small descriptors.

13. Ensure providers discard catalog-build epoch roots and KDF intermediates
    before callbacks, then discard descriptor revision secrets after descriptor
    decryption. If the same operation immediately opens that item body, request
    and retain only the exact body revision secret required by the item guard.

14. Decrypt and validate only requested item bodies, except operations that
    explicitly require several items.

The accessible catalog maps canonical item names to stable item IDs and roles.

It rejects duplicate decrypted names within the selected principal's accessible
set.

An owner catalog covers every active item and is therefore the authority used to
enforce global name uniqueness before owner mutations.

The first Jury v1 implementation intentionally chooses bounded descriptor scanning
over a duplicated per-principal encrypted index.

The descriptor scan touches only small ciphertexts and avoids catalog fan-out on
every grant, rename, and revoke; J25 must benchmark it at the declared item
scales.

### 13.2 Historical authority

An item revision references a policy sequence.

The validator checks writer authority in the replayed state at that exact
sequence.

An item revision may remain current after later role removal.

It does not become invalid merely because its author is no longer a writer.

A new item revision must reference the current accepted policy sequence.

This prevents a removed writer from authoring against an old policy after the
local client has accepted the removal.

### 13.3 Fork rules

Policy history must be linear.

Two policy journals that diverge after a common sequence are a policy fork.

No automatic merge is allowed.

Item history is linear per item.

Two revisions with the same parent are an item fork.

Different items may advance independently under the same policy and can be
merged.

The transfer importer accepts only strict ancestry or independent-item progress.

It rejects same-item and policy forks with metadata-only conflict details.

### 13.4 Local checkpoint

Each selected identity maintains a local authenticated checkpoint for each vault
ID.

The checkpoint records:

- highest accepted policy sequence and hash;
- highest accepted current revision number and hash for every active item;
- accepted tombstones;
- last successful transfer ID when applicable.

The checkpoint is authenticated with the exact J01A-selected MAC and KDF using a
key derived from the identity's local seed and vault ID.

It lives under:

`<state-root>/<vault-id>/<genesis-fingerprint>/<principal-id>/checkpoint.json`

It contains no secret values.

The containing directory and file use existing private path protections.

Checkpoint update follows successful vault verification and, for mutation, the
atomic vault write.

A checkpoint write failure after a successful vault mutation is reported as a
committed-primary-action plus recovery warning, matching the TUI's existing
committed-action distinction.

The next open may safely advance a behind checkpoint after validating the vault's
chains.

It must never silently lower a checkpoint.

### 13.5 Fresh installation trust

Installing a transfer or opening a fresh Git clone has no local freshness
history.

The importer validates all signatures and then presents:

- vault ID;
- genesis owner principal ID;
- genesis owner fingerprint;
- current policy sequence;
- selected principal's accessible decrypted item names and effective roles.

Interactive installation requires exact fingerprint confirmation.

Automation requires `--trust-genesis-fingerprint FULL_HEX`.

This is trust on first use.

Organizations needing stronger provenance must distribute the fingerprint through
an independent trusted channel.

## 14. Partial unlock and core API

### 14.1 Open states

Replace the single full-state `OpenVault` assumption with staged internal states:

```text
ParsedVault
  -> ValidatedPublicVault
  -> PrincipalVaultSession
  -> one or more UnlockedItem guards
```

`ValidatedPublicVault` contains only public policy, opaque item IDs, ciphertext,
hashes, and signatures.

`PrincipalVaultSession` holds one selected principal capability and an on-demand
accessible descriptor catalog containing only names that principal may decrypt.

In direct mode the capability is backed by a locally unlocked identity.

In witnessed mode it is backed by an `ItemAccessProvider` that may obtain
request-scoped witness contributions; the session does not pretend it owns a
raw identity decryption key.

`UnlockedItem` holds one body revision secret and decrypted item body in
zeroizing storage. It does not retain the item epoch root.

Dropping an item guard wipes its body revision secret and plaintext.

Do not decrypt any item body during ordinary open.

Name-based routing and item browsing may decrypt every accessible small
descriptor, but never an inaccessible descriptor or an untargeted item body.

An explicit aggregate snapshot or unfiltered field list may decrypt every
accessible item to produce its documented accessible field rows; that is a
bounded caller-requested multi-item operation, not an implicit session-open side
effect.

### 14.2 Snapshot contract

Evolve `VaultSnapshot` without exposing inaccessible field metadata.

Add an accessible item row shape containing:

- stable item ID;
- decrypted item name or legacy label;
- selected principal's effective role: `owner`, `writer`, or `reader`;
- key epoch;
- current item revision number;
- optional field count only when the caller explicitly decrypts that item body;
- optional updated timestamp only when the caller explicitly decrypts that item
  body.

The snapshot's accessible field records contain the existing metadata.

Inaccessible opaque envelopes contribute no item rows, names, counts, timestamps,
or `FieldRecord` values.

Legacy metadata is present only for owners who unlock the legacy compartment.

The existing `fields` projection remains for source compatibility where
possible, but callers must switch item browsing to the new item rows.

### 14.3 Revision contract

For Jury v1, `VaultRevision` becomes an opaque digest of:

- vault ID;
- current policy hash;
- every active item ID and current item revision hash in sorted order;
- every tombstone in sorted order.

Do not expose the digest representation publicly.

Optimistic mutation and import preconditions continue to compare exact
authenticated state under the lock.

### 14.4 Error taxonomy

Add stable error kinds:

- `AccessDenied`;
- `Conflict`;
- `Capacity`;
- `Unsupported`.

Use `Authentication` for wrong identity passphrase or failure to unwrap a slot
that should belong to the selected principal.

Use `AccessDenied` when policy grants no item read or write authority.

Use `Conflict` for stale revisions, transfer forks, and checkpoint rollback.

Use `Capacity` when a valid current state cannot accept a requested mutation
without crossing a hard count or encoded-size cap. Report only safe counts and
the exact history-rollover next step.

Use `Serialization` or `Authentication` for malformed or invalidly signed shared
state according to whether structure or authenticity failed.

Use `Serialization` for duplicate canonical names discovered inside an
authenticated accessible descriptor set; never choose one ambiguous item.

Error messages must never confirm an item name or include a field name when the
selected identity cannot resolve that name through its accessible catalog.

For either an inaccessible item named `Production` or a nonexistent name supplied
by the caller, return the same `AccessDenied` kind and a message such as
`vault item 'Production' is unavailable for selected identity`.

The echoed name is caller input, not confirmation that the item exists.

Do not distinguish inaccessible from nonexistent item names or disclose whether
a requested field exists inside an inaccessible item.

### 14.5 Mutation authorization

Every core mutation method determines all touched items before decrypting or
writing.

It checks effective roles for all touched items.

It verifies current policy, item chains, local audit, and checkpoint under the
same vault edit lock.

It decrypts only touched items.

It appends local audit intent before saving new shared state.

It signs item or policy revisions as required.

It writes one complete `vault.json` atomically.

It advances the local checkpoint.

Crashes may leave local audit intent ahead of state as today.

State must not lead the authenticated item/policy signatures embedded in that
same state.

### 14.6 Multi-item operations

Legacy conversion, owner grant/revoke, principal revoke-all, and some transfer
merges touch multiple compartments.

They preflight every required item slot and body before the first durable write.

They retain all decrypted bodies in bounded zeroizing containers only for the
transaction lifetime.

If any item cannot be decrypted, authorized, validated, or resealed, no shared
state is written.

## 15. Local operational audit

### 15.1 Split authenticity from activity

The embedded policy and item signature chains are the portable authenticity
record.

The local audit remains an operational activity record for reads, injections,
execs, runs, backups, identity actions, and failures.

Do not export local audit in a normal transfer.

### 15.2 Per-principal audit path

Jury V1 audit events live at:

`<state-root>/<vault-id>/<genesis-fingerprint>/<principal-id>/audit.jsonl`

The HMAC key is derived from the selected identity's local seed and vault ID.

This avoids a new vault-wide audit key that every principal would need.

It also prevents two principals sharing one machine from accidentally treating
each other's local chain as their own.

### 15.3 Audit schema

Bump local audit event version for Jury v1.

Every Jury v1 event includes safe metadata for that selected principal:

- principal ID;
- vault ID;
- current policy sequence;
- operation ID;
- action;
- item ID and decrypted item name only when the selected principal already
  resolved that descriptor for the successful action;
- outcome or failure stage;
- previous MAC and MAC.

Never record field values.

Continue recording accessible field references where the selected principal
already decrypted the item and the action-specific projection permits it.

Do not record guessed item or field names when access fails at the item
boundary.

### 15.4 Audit verification

`vault audit verify` verifies the selected principal's local Jury v1 log.

It also reports the presence and terminal MAC of a preserved Jig v1/v2 audit when a
migration archive exists.

Because the v2 DEK-derived audit key is deliberately discarded after migration,
later verification recomputes the archive byte digest and compares it with the
owner-signed `source_migration` attestation.

The output labels this `migration-attested legacy archive`, not a freshly
recomputed v2 HMAC verification.

The command clearly labels each as local evidence.

It does not claim to verify other principals' activity.

### 15.5 Checkpoint relationship

Audit and checkpoint use separate HKDF subkeys from the local identity seed.

The checkpoint stores the latest local audit MAC.

The audit genesis stores the initial checkpoint digest.

This binds the two local files for ordinary tamper detection while retaining the
documented deletion/rollback limitation.

### 15.6 Audit scalability

Do not add audit rotation to this feature.

Preserve the existing 256 MiB cap and full-chain verification behavior unless a
separate concrete performance change is justified.

Benchmarks in the hardening bead must measure the added public-chain validation
cost separately from local audit cost.

### 15.7 Authenticated local operation receipts

Jury V1 keeps bounded local-only operation evidence at:

`<state-root>/<vault-id>/<genesis-fingerprint>/<principal-id>/receipts.json`

The file is authenticated with a distinct HKDF-derived HMAC key from the selected
identity seed and vault ID.

It stores at most the latest successful:

- transfer export ID, vault revision, time, and output digest;
- owner backup ID, captured vault revision, time, and payload digest;
- verification for that backup ID and time;
- real restore drill for that backup ID and time.

It contains no passphrase, private key, item name, field metadata, value, or
trusted destination path.

Receipts do not participate in public policy, item validation, rollback maxima,
or remote freshness.

They are not included in normal transfer.

They may be included as prior local context in an owner backup, but backup
creation records its new receipt only after output commit and cannot claim that
the just-created receipt is inside the same backup.

A receipt-write failure after an export, backup, or drill primary commit returns
a committed-primary-action warning and exact local status limitation.

## 16. CLI contract

### 16.1 Command families

Add these command families:

```text
jury identity ...
jury principal ...
jury access ...
jury transfer ...
jury history ...
```

Keep existing field, secret, read, inject, exec, run, audit, backup,
passphrase, status, migrate, init, and TUI families.

### 16.2 Principal administration

Add:

```text
jury principal list
jury principal challenge --from PUBLIC_DESCRIPTOR --out CHALLENGE \
  [--overwrite]
jury principal add --from PUBLIC_DESCRIPTOR \
  --proof PROOF [--reader ITEM]... [--writer ITEM]... [--dry-run]
jury principal replace PRINCIPAL --from PUBLIC_DESCRIPTOR --proof PROOF \
  [--dry-run]
jury principal label PRINCIPAL --label LABEL
jury principal remove PRINCIPAL [--dry-run]
jury principal remove PRINCIPAL --revoke-all [--dry-run]
jury principal grant-owner PRINCIPAL [--dry-run]
jury principal revoke-owner PRINCIPAL [--dry-run]
```

All commands except list require selected owner identity.

`principal list` shows public principal metadata and opaque effective counts, not
inaccessible item names or field metadata.

`principal challenge` validates the descriptor self-signature and fingerprint,
refuses an already registered ID or key, encrypts a random response to the
candidate HPKE key, signs the bound challenge as the selected owner, and writes
only the public challenge artifact through a hardened sink.

`principal add` validates the matching registration proof and refuses duplicate
principal IDs or public keys. A descriptor or suite self-signature alone is
insufficient.

Adding a principal with no repeated role options grants no item access.

Adding a principal with initial `--reader`/`--writer` options resolves every name
through the owner's descriptor catalog, rotates and reseals each affected item,
and commits registration plus reader-set changes in one policy revision.

It preflights the complete batch before writing and rejects duplicate or
contradictory item arguments.

Successful human output prints the new principal's full ID, grouped fingerprint,
granted role summary, and exact next transfer-export command.

`principal replace` requires a new principal ID and keys, a fresh challenge and
proof, and the exact old principal ID rather than a label. Its dry-run lists all
roles copied, every item epoch rotated, old slots removed, and whether a second
owner is required. Commit is all-or-nothing.

Owner grant shows the number of item key epochs it will rotate and slot sets it
will replace.

Owner revoke shows the number of item key epochs and current seals it will
replace.

It refuses self-revocation and instructs the operator to use a different
remaining owner identity.

Last-owner removal fails.

Machine owner grant fails.

### 16.3 Item access administration

Add:

```text
jury access list --me
jury access list ITEM
jury access matrix
jury access explain ITEM [--require read|write]
jury access check ITEM --require read|write|owner
jury access grant ITEM --principal PRINCIPAL --role reader|writer \
  [--dry-run]
jury access grant --principal PRINCIPAL \
  [--reader ITEM]... [--writer ITEM]... [--dry-run]
jury access change ITEM --principal PRINCIPAL --role reader|writer \
  [--dry-run]
jury access revoke ITEM --principal PRINCIPAL [--dry-run]
```

`access list --me` unlocks the selected identity and shows only decrypted
accessible item names, exact roles, and the capabilities each role implies.

`access list ITEM` requires the selected identity to resolve that item name
or be an owner, then shows the public grant relationships for that resolved
opaque item ID.

`access matrix` is owner-only because only an owner can decrypt every item name.

It displays principals as labels plus grouped fingerprints but uses full
principal and item IDs in structured output and mutation requests.

`access explain` describes the selected principal's effective role and whether a
requested capability is present without reading a field.

`access check` performs the same authenticated capability preflight with stable
success/access-denied exit behavior for scripts.

Both commands return the identical unavailable result for an inaccessible and a
nonexistent caller-supplied item name.

Mutation commands require owner authority.

Granting reader or writer increments the item key epoch, rotates any
construction-internal epoch secret, generates fresh descriptor/body revision
secrets and seal identifiers, reseals both ciphertexts with independent fresh
nonces, and replaces the complete capsule set.

The repeated batch form applies all exact grants in one policy revision and
performs only one identity-passphrase capture.

Changing reader/writer role does not reseal.

Revoking performs the same rotation and reseal transaction for the smaller
reader set.

Grant and revoke output contains:

- item name;
- principal ID;
- prior role;
- old and new key epoch;
- resulting reader count;
- `backward_secrecy_established: true` for grants;
- `external_credential_rotation_required: true` for revokes in JSON;
- a human warning that grants cannot expose retained older ciphertext and
  revocation cannot erase retained plaintext or older keys.

### 16.4 Common policy preview and mutation results

Every principal, owner, item-policy, and access mutation accepts `--dry-run`.

A dry-run performs the same bounds, identity, public-chain, descriptor-catalog,
authorization, slot, body, and optimistic-revision preflight needed by the real
operation but writes no shared state, local audit intent, checkpoint, backup
receipt, or export receipt.

Preview output includes:

- acting vault and selected identity name, label, kind, and grouped fingerprint;
- current policy sequence and opaque vault revision;
- exact principal and role changes;
- accessible item names for the acting identity and opaque item IDs otherwise;
- item and descriptor key epochs before and after;
- number of descriptors and bodies that will be resealed;
- remaining recipient counts;
- whether external credential rotation may be required;
- whether redistribution will be recommended after commit.

The real command rechecks the exact preview revision under the edit lock and
fails with `Conflict` rather than applying a stale preview.

Interactive destructive commands require the existing exact-confirmation style.

Non-interactive automation must provide the command's explicit confirmation flag
and every required target; it never receives an implicit yes from `--json`.

Multi-item operations may report pre-commit progress on a terminal, but JSON and
non-terminal output remain deterministic.

Every successful shared-state mutation returns:

- previous and current opaque vault revisions;
- `vault_changed = true`;
- `redistribution_recommended = true`;
- `last_exported_revision` when known locally;
- an exact human next step using `jury transfer export`.

These fields mean only that the local artifact changed.

They never claim that another recipient received or accepted the revision.

### 16.5 Item creation and guided initialization

The first write to a missing canonical item remains able to create the item for
compatibility, but only for an owner.

A writer cannot create a new item merely by setting a field.

Add an explicit owner command:

```text
jury item create ITEM
jury init [--item ITEM]...
```

It may accept repeated initial `--reader` and `--writer` principal IDs.

TUI item creation uses the same core transaction.

Repeated `vault init --item` arguments create private-name empty item
descriptors, epoch-one keys and bodies, and owner slots in the initial owner
policy transaction.

Interactive `vault init` creates the named owner identity first when it is absent,
clearly reports that an unused identity can remain if later vault creation fails,
offers repeated initial items, and ends with:

- vault ID and genesis fingerprint;
- selected owner identity name and fingerprint;
- created item names visible only to that owner until grants are added;
- owner-backup warning and exact backup command;
- exact principal-onboarding and transfer next steps.

There are no hard-coded semantics for `Development`, `Staging`, or `Production`.

### 16.6 Existing list and read commands

`vault field list` with no item returns fields only from decryptable items.

It does not return inaccessible item rows, names, or a locked-item count.

`vault field list ExampleItem` returns the uniform item-unavailable
`AccessDenied` before attempting a field lookup when Production is inaccessible
or nonexistent.

`vault secret list` is a compatibility projection.

It returns canonical secret names from accessible items and unrepresentable names
from the legacy compartment only for owners.

Set/remove route representable names to the canonical item and enforce its role;
unrepresentable names require owner access.

`vault read` unwraps and decrypts only the addressed item.

Existing controlled sinks and reveal rules remain unchanged.

### 16.7 Inject

Template parsing still occurs before credential capture.

After public validation, collect every distinct referenced item.

Preflight read access to every referenced item.

If any item name is unavailable to the selected identity, fail before writing any
output.

Decrypt each accessible item at most once.

Do not disclose whether the item or field exists beyond the selected identity's
accessible catalog.

Continue exact output and audit lifecycle behavior.

### 16.8 Transparent exec

Restricted dotenv parsing remains before credential capture.

Collect every distinct referenced item and validate access before child spawn.

Resolve all referenced fields atomically from one authenticated vault revision.

If any access or field resolution fails, no child starts.

Strip all Jury identity/backup, migration-source, and new-passphrase variables,
and add
`JURY_IDENTITY`, `JURY_IDENTITY_FILE`, and
`JURY_IDENTITY_HOME` to the stripped set.

Continue inherited stdin/environment, streaming independent redaction, and exact
child status.

Only concealed fields from accessible items become redaction needles.

### 16.9 Brokered run

The legacy-name broker first applies the existing exact, unambiguous
`SecretName`-to-`VaultReference` conversion.

A representable name resolves from its canonical item and uses that item's read
role.

An unrepresentable name resolves only from the owner-only legacy compartment.

Do not invent a more permissive fuzzy conversion.

All existing child-process containment, timeout, capture, cleanup, and redaction
invariants remain.

### 16.10 Status

`vault status` remains non-creating and does not unlock an identity.

For Jury v1 it reports safe public fields:

- format version;
- vault ID;
- suite ID;
- current policy sequence;
- active principal count;
- active item count;
- tombstone count;
- policy-revision and item-proof usage against each hard cap;
- encoded-size headroom and `rollover_recommended` without item names;
- `cryptographic_scopes = true`.

It may validate public signatures because no private key is needed.

If public validation fails, status reports a sanitized invalid-state error rather
than counts from untrusted structures.

It does not report selected-principal access without an identity unlock.

### 16.11 History rollover

Add:

```text
jury history status
jury history rollover --home ABSENT_HOME [--dry-run]
```

`history status` is the stable spelling for the public capacity fields also
shown by `vault status`. `history rollover` requires an owner identity, validates
the entire source and local checkpoint, applies the absent-home and alias checks
used by restore, and previews the new vault ID/fingerprint, active object counts,
fresh-encryption count, bridge digest, backup requirement, and trust/
redistribution steps. It never overwrites, truncates, or deletes the source.

### 16.12 JSON stability

Every new structured response has explicit tests in
the `jury` adapter, CLI parser tests, and consumer workflow tests.

Never place private keys, optional epoch secrets, revision secrets, KDF
intermediates, wrapped-key plaintext, field values, or raw decrypted bodies in
JSON.

Fingerprint, principal ID, role, opaque item ID, key epoch, revision, and public
counts are permitted.

An item name is permitted only in output produced after the selected identity has
decrypted that item's descriptor, or in owner-authorized output where the owner
has decrypted every relevant descriptor.

### 16.13 Witness requests, approvals, and receipts

The native command families include:

```text
jury request create --item ITEM --operation OPERATION [operation arguments]
jury request inspect REQUEST
jury request status REQUEST
jury request cancel REQUEST
jury approve REQUEST [--deny --reason CODE]
jury receipt inspect RECEIPT
jury receipt verify RECEIPT [--checkpoint FILE]
jury witness list
jury witness health
```

An operation that targets a witnessed slot may create and execute a request in
one foreground command when policy permits automatic witness decisions.

Interactive approval returns a request handle and never prints secret
contributions.

It first verifies and renders the complete `ActionManifestV1`, then signs a
dedicated `ApprovalDecisionV1` with the selected approver identity. Approval is
disabled when only the request or manifest digest is available. Transport login,
a vault identity, or a witness key never silently supplies approver authority.

`request inspect` reveals only public scope authorized by the selected identity
and the receipt metadata boundary.

Expiry, denial, replay, stale policy, incomplete quorum, and unavailable witness
have distinct stable error kinds and exit codes.

`receipt verify` is offline, value-free, non-creating, and requires no identity
unlock when all names remain opaque.

Machine-readable output uses bounded enums and IDs, not provider error strings.

Cancellation marks local intent but cannot retract a request already approved by
an independent witness; output states that limitation.

## 17. Transfer workflow

### 17.1 Purpose

Transfer distributes shared encrypted state between developers and machines.

It is not a backup.

It is not an invitation containing private credentials.

### 17.2 Commands

Add:

```text
jury transfer export --out FILE [--overwrite]
jury transfer inspect --in FILE [--against-current] [--me]
jury transfer import --in FILE [--dry-run]
jury transfer status
```

An owner uses principal and access commands before export when onboarding a new
recipient.

Any registered principal may export a validated current artifact.

Export never decrypts item descriptors or bodies.

After the output file commits successfully, export records the transfer ID,
current opaque vault revision, timestamp, and output digest in the selected
principal's authenticated local state.

It does not record or claim recipient delivery.

`transfer inspect` validates the transfer envelope and inner public chains before
displaying source vault, genesis and exporter fingerprints, policy ancestry,
opaque item/revision deltas, and predicted conflicts.

`--against-current` compares with the selected local home without mutating it.

`--me` additionally unlocks the selected identity and labels only item deltas
whose descriptors that identity can decrypt from the local or incoming accepted
state.

`transfer import --dry-run` executes the complete authenticated merge and
selected-identity preflight but writes no vault, audit, checkpoint, or export
receipt.

`transfer status` unlocks the selected identity, compares the current revision
with that installation's last successful export receipt, and reports `never
exported`, `matches last local export`, or `changed since last local export`.

It never reports `distributed`, `synchronized`, or an equivalent remote claim.

### 17.3 Transfer package

The transfer envelope contains:

- transfer magic and format version;
- transfer ID and creation timestamp;
- exact source vault ID;
- exact source Jury v1 `vault.json` bytes;
- source public revision digest;
- exporting principal ID;
- exporter signature over envelope metadata and vault digest.

It contains no private identity.

It contains no local audit.

It contains no local checkpoint.

It contains no local operation receipts.

It contains no plaintext item names or field metadata.

The inner vault contains every opaque item envelope and its encrypted descriptor
and body, including items inaccessible to the exporter.

The 32 MiB maximum accommodates one maximum 16 MiB inner JSON vault plus
binary-envelope or base64 overhead while remaining a strictly bounded input.

The transfer's exact length and public metadata remain visible. Encrypted body
buckets prevent it from revealing exact logical body lengths, but public framing
can still be parsed and measured.

### 17.4 Absent-home import

Import into an absent home:

1. validates path and package bounds before passphrase capture;

2. validates exporter signature and complete inner Jury v1 public state;

3. unlocks the selected local identity;

4. checks that its principal is registered;

5. requires at least one effective item access unless `--allow-no-access` is
   explicit;

6. decrypts only the selected identity's accessible item descriptors and shows
   their names and roles;

7. performs the trust-on-first-use fingerprint confirmation;

8. stages a private vault home;

9. installs `vault.json`, local audit genesis, and local checkpoint;

10. atomically publishes the absent home using the existing supported platform
   guarantees.

The first local audit event records transfer ID and exporter principal ID.

### 17.5 Existing-home import

Import into an existing home requires the same vault ID and genesis fingerprint.

The importer validates both local and incoming structures completely.

Policy journals must be equal or one must be a strict prefix of the other.

If incoming policy is behind, it cannot lower local policy.

If incoming policy is ahead and descends from local, it becomes the candidate
policy.

For every item:

- identical current revision is unchanged;
- incoming strict descendant advances local;
- local strict descendant remains local;
- independent progress on different items is merged;
- divergence for the same item is a conflict;
- missing active items are invalid;
- tombstones obey the selected descendant policy.

Current descriptor ciphertext and metadata must match the selected descendant
policy.

A descriptor change can advance only through its owner-signed policy branch; it
does not auto-merge independently of policy.

When an item branch advances concurrently with a policy branch, the importer
rechecks the advancing revision's author and key epoch against the selected
current policy.

It accepts the advance only if that author is still an effective writer/owner and
the revision epoch equals the selected current item epoch.

An unchanged historical current revision remains valid after its author is later
downgraded or removed; only a newly merged advance must pass this current-policy
check.

This allows unrelated policy changes plus an authorized item write to merge while
rejecting a stale removed writer and any pre-rotation item ciphertext.

The fully merged candidate is validated against the selected policy before one
atomic write.

No merge writes partially.

### 17.6 Fork recovery

Jury V1.0 does not auto-merge two writes to the same item or two policy forks.

The conflict reports public policy metadata, opaque item IDs, and branch revision
hashes.

It may attach a decrypted item name only when the selected identity can resolve
that item in a locally accepted or fully validated incoming branch.

Recovery is explicit:

1. retain both transfer files;

2. open copies in separate explicit vault homes;

3. have an owner or authorized writer inspect the competing item values through
   controlled sinks;

4. choose one canonical branch;

5. reapply any desired values to that branch as a new signed revision;

6. redistribute the canonical artifact.

Do not add a `--force` overwrite that bypasses ancestry or checkpoint checks.

### 17.7 Raw copying

Users may still copy `vault.json` directly.

Opening a copied file validates its public chains and local checkpoint.

The supported transfer commands add provenance, merge rules, bounds, safe path
handling, and first-use fingerprint confirmation.

Documentation should recommend transfer commands rather than raw replacement.

## 18. Backup and recovery

### 18.1 Backup meaning

The Jury v1 command surface includes:

```text
jury backup create --out FILE [--overwrite] \
  [--kdf-profile portable|hardened] [--reuse-identity-passphrase]
jury backup status
jury backup verify --in FILE
jury backup drill --in FILE --vault-out ABSENT_PATH \
  --identity-out ABSENT_PATH [--identity-kdf-profile portable|hardened] \
  [--identity-protection portable|keychain|secure-enclave|tpm2|fido2] \
  [--protector ID]
jury backup restore --in FILE --identity-out ABSENT_PATH \
  [--identity-kdf-profile portable|hardened] \
  [--identity-protection portable|keychain|secure-enclave|tpm2|fido2] \
  [--protector ID]
```

A Jury v1 backup is owner identity recovery material and must be treated as
highly sensitive.

Anyone who has the backup passphrase can recover the included owner private
identity and every item for which that identity has a current direct slot.

The CLI must state that direct recovery power before creation and in help text.

Backup is not the developer distribution path.

### 18.2 Authorization

Only an active owner may create a Jury v1 backup.

The selected identity must have a valid current key slot for every active item.

Backup preflight verifies the selected owner's configured direct slot for every
active item. It need not decrypt every item body merely to copy authenticated
ciphertext.

The owner identity public descriptor must match current policy.

Successful backup creation records an authenticated local recovery receipt with
backup ID, payload digest, captured vault revision, owner principal fingerprint,
creation time, and verification state.

The receipt stores no passphrase, private key, field value, item name, or trusted
destination path.

### 18.3 Backup envelope

Bump the backup envelope and payload versions.

The outer backup uses Argon2id plus the J01A-selected storage AEAD and exact
suite KDF.

Its public header records and enforces the exact Jury v1 KDF profiles from section
12.2 before Argon2 allocation. `portable-v1` is the default;
`--kdf-profile hardened` selects `hardened-v1`. Backup files are immutable, so a
profile change affects newly created backups rather than rewriting old ones.

Retain the existing 64 MiB total backup envelope ceiling. Before outer
encryption, pad the authenticated payload to the smallest exact 4, 8, 16, 32, or
64 MiB envelope target after accounting for framing, nonce, tag, and encoded
header. The target bucket ID is associated data; decrypted padding must be all
zero. A backup leaks only its target bucket, not its exact recovery-payload size.

If vault, identity, local audit, checkpoint, optional legacy audit, and framing do
not fit the bounded payload budget, backup creation fails before output commit and
reports which metadata class exceeded the budget without exposing event content.

For Jury v1, backup creation first unlocks the selected owner identity, then captures
a separate backup passphrase twice. Interactive prompts say `Identity
passphrase` and `Backup passphrase` and never carry one response into the other.
Automation uses `JURY_BACKUP_PASSPHRASE`; there is no fallback to
`JIG_V2_VAULT_PASSPHRASE` or `JURY_IDENTITY_PASSPHRASE`.

Deliberate reuse requires `--reuse-identity-passphrase`, an explicit owner-
identity-recovery warning, and normal confirmation. Without that flag, an equal
backup and identity passphrase is rejected. The flag contains no secret and does not
place a passphrase on argv. All backup-capable child paths remove
`JURY_BACKUP_PASSPHRASE` from descendant environments.

The encrypted payload contains:

- exact `vault.json` bytes;
- a canonical owner identity recovery payload containing the selected
  principal's suite-defined recipient and signing private keys plus local
  audit/checkpoint seed inside the outer encrypted payload;
- the matching public identity descriptor, but not an independently
  passphrase-encrypted copy of the live identity file;
- selected identity path metadata without trusted absolute-path installation;
- selected principal's local audit bytes;
- selected principal's checkpoint bytes;
- selected principal's prior authenticated local receipt bytes;
- the preserved legacy `audit.jsonl` archive when the Jury v1 genesis contains a
  matching source-migration attestation;
- source vault ID and format version;
- source identity principal ID and fingerprint;
- backup creation metadata and payload digests.

Changing the live identity passphrase does not rewrite old backups.

`backup verify` decrypts and validates a specified backup, all embedded public
chains, private-to-public owner identity correspondence, local audit/checkpoint,
and the recovered owner's ability to derive each directly recoverable current
revision secret without exposing an item epoch root or publishing a restore.
Core archive verification requires the backup passphrase, not the historical
live identity passphrase;
updating a local receipt also unlocks the currently selected identity that
authenticates that receipt.

After successful verification it updates the matching authenticated local
recovery receipt.

`backup status` unlocks the selected owner identity and reports:

- whether a successful backup receipt exists for this vault and identity;
- captured versus current vault revision;
- backup age and last full verification time;
- identity recovery coverage;
- whether a full restore drill has been recorded locally;
- exact next commands for create, verify, or drill.

The result says `unknown` when a backup or drill occurred elsewhere without a
local authenticated receipt.

It never infers that a file still exists or remains readable merely from a prior
creation receipt.

### 18.4 Restore destinations

Jury V1 restore takes an absent vault home and either:

- an absent `--identity-out PATH`; or

- `--reuse-identity PATH` naming an existing identity whose decrypted public and
  private key material exactly matches the backed-up principal.

For an absent identity target, restore captures a new identity passphrase twice,
uses `portable-v1` by default or the explicit `--identity-kdf-profile`, and seals
the recovered private payload with a fresh identity root, salt, and nonces. It
uses portable protection by default or enrolls the explicit
`--identity-protection`/`--protector` through the normal provider boundary before
publishing either destination. The backup passphrase alone never becomes the
installed identity passphrase or hardware factor. Non-interactive restore uses
the existing command-scoped `JURY_NEW_PASSPHRASE` contract for the new
identity credential; interactive hardware presence/verification cannot be
bypassed by an environment variable.

For `--reuse-identity`, restore unlocks that identity with its separate current
identity passphrase and proves private-key and seed correspondence. It neither
reseals nor overwrites the existing file.

Do not install an untrusted absolute path from backup metadata.

The default proposed identity output is under the identity root and must be shown
before mutation.

An existing nonmatching identity fails before vault-home publication.

### 18.5 Restore transaction

Cross-directory publication cannot be represented as one rename.

Use an explicit recoverable transaction:

1. validate source, vault target, identity target, parents, bounds, and platform
   support;

2. decrypt and validate the full backup in private staging;

3. verify inner vault signatures and backed-up checkpoint/audit;

4. verify recovered owner private/public correspondence and every required item
   slot, then either prepare a freshly sealed identity under the new identity
   passphrase or unlock and prove exact `--reuse-identity` correspondence;

5. create a private restore transaction marker in the verified identity-target
   parent, named `.jury-vault-restore-<transaction-id>.json`, containing only
   random ID, target paths, public IDs, payload digest, and publication state;

6. publish a new identity only if its target is absent;

7. publish the absent vault home atomically;

8. create a restore audit event and advance checkpoint in the installed home;

9. remove the transaction marker after both publications and syncs succeed.

If identity publication succeeds but vault publication fails, retain the valid
identity and marker and report an exact safe retry.

Never overwrite or delete a pre-existing identity.

Never report a partially published restore as rolled back unless exact inode and
ownership proofs make rollback safe.

### 18.6 Legacy backups

Continue decoding existing v1 backup envelopes and embedded v2 vaults.

Restoring a legacy backup yields its original v2 vault and audit.

The operator then runs explicit v2-to-Jury v1 migration.

Do not rewrite legacy backup bytes in place.

### 18.7 Recovery drills

`backup drill` reuses the real restore transaction into explicitly absent vault
and identity destinations, opens the restored owner session, validates every
accessible encrypted descriptor, verifies every owner slot, audit, and
checkpoint, and only then records a successful drill receipt in the source
owner's authenticated local state.

It leaves the restored copy in place for operator inspection and never deletes
it automatically.

Failure after the restore's primary commit is reported as a committed restore
with an unrecorded source drill receipt, not as a safe automatic retry.

Documentation includes a generic `ExampleVault` recovery drill:

- create owner backup;
- restore to a new explicit home and identity path;
- confirm genesis fingerprint and owner principal;
- verify audit;
- read one generic test field through a controlled sink;
- delete the drill copy only through an explicitly operator-directed cleanup,
  outside automated tests.

## 19. Copy-on-write migration from Jig v1/v2

### 19.1 Eligibility

`jury migrate jig-vault --from SOURCE --to ABSENT_DESTINATION` accepts a valid
Jig v1 or Jig v2 vault through a read-only compatibility adapter.

The adapter may internally normalize Jig v1 through the proven Jig v2 reader,
but it never writes that normalization to the source.

The command rejects a Jury artifact as the wrong import family and rejects
unknown Jig versions.

### 19.2 Identity choice

Migration requires a Jury human identity that will become genesis owner.

If the selected identity does not exist, migration first creates one outside the
vault home using the normal identity flow.

If it exists, migration unlocks it separately.

Interactive prompts clearly distinguish:

- old vault passphrase;
- selected identity passphrase.

Automation uses:

- `JIG_V2_VAULT_PASSPHRASE` for the v2 vault;
- `JURY_IDENTITY_PASSPHRASE` for an existing selected identity.

The Jig vault passphrase MUST NOT silently become the Jury identity passphrase.

Interactive reuse requires an explicit warning and re-entry; automation uses a
separate Jury identity-passphrase source.

All reserved variables are removed before child execution.

### 19.3 Data mapping

For every canonical Jig v1/v2 secret name:

1. parse its `ITEM/FIELD` representation;

2. group it by canonical item name;

3. generate one stable item ID per group;

4. create item key epoch one with fresh descriptor/body revision secrets and
   seal identifiers;

5. create descriptor revision one containing the canonical item name and encrypt
   it under the fresh descriptor revision secret with a fresh
   descriptor nonce;

6. preserve field value, kind, creation time, update time, and exact decoded
   length;

7. create item revision one signed by the genesis owner;

8. create an owner key slot.

Unrepresentable v2 names move into the reserved owner-only legacy compartment
with metadata preserved and its descriptor label encrypted like every other item
name.

The Jury destination gets a fresh vault ID and Jury genesis timestamp.

The signed source-migration attestation records the source family, source
version, a digest of the source artifact, and verified legacy audit bridge.

Migration dry-run reports only names visible through the v2 owner unlock and
writes no identity unless the operator proceeds to the real migration.

### 19.4 Audit bridge

Before destination creation, verify the entire available Jig audit using its
version-specific audit key.

Do not append a migration intent to the Jig audit because the source is
immutable.

Create a random migration ID in the destination manifest instead.

Copy `audit.jsonl` into a destination legacy-evidence directory as an immutable
archive; do not move or modify the source file.

Hash its exact source bytes and bind that digest plus the verified terminal MAC
into the owner-signed Jury v1 source-migration attestation.

Create the Jury v1 owner-local audit genesis referencing:

- migration ID;
- source product and format version;
- legacy terminal audit MAC when the source version provides one;
- Jury v1 genesis fingerprint;
- initial checkpoint digest.

Do not claim that the new identity can authenticate arbitrary historical v2
events without the preserved v2 archive and original verified bridge.

### 19.5 Atomicity and recovery

Open the Jig source through hardened handles and hold its advisory lock when the
legacy implementation supports one.

Record source device, inode or file identity, size, and digest before reading.

Verify the same identity and digest before declaring migration complete.

Create the destination under an absent sibling staging directory with private
permissions.

Write its vault, local audit, checkpoint, legacy evidence, and migration
manifest; fsync every file and directory required by the platform durability
contract; then atomically rename the staging directory to the absent
destination.

No operation replaces `SOURCE/vault.json`.

Identity creation may leave an unused valid Jury identity if later migration
fails; the failure explains that safe residue.

Use the migration ID to recognize and either resume or safely remove only the
matching destination staging directory.

Never rerun item encryption with ambiguous identity, source digest, vault ID, or
destination state.

### 19.6 Previously distributed copies

Every old v2 copy and backup still contains all old secrets under its shared
passphrase.

Migrating the live copy does not revoke them.

The migration success output and documentation instruct the owner to rotate
Production credentials if the old v2 artifact was distributed beyond the new
Production access set.

### 19.7 New vault cutover

`jury init` creates Jury format v1 from the first usable release.

Jury never creates Jig format v1 or v2.

Tests retain read-only Jig fixtures solely for compatibility and migration.

## 20. TUI behavior

### 20.1 Session credential

For Jury v1 the TUI retains one process-local unlocked identity credential or the
minimum encrypted credential state needed to reopen it per action.

It does not retain optional epoch secrets or revision secrets after use.

Lock, inactivity, authentication loss, audit failure, signal shutdown, and exit
drop identity material, snapshots, and protected inputs.

The retained identity root/private keys and passphrase/provider factors reside
only in `ProtectedMemory`. Before the first unlock the TUI disables core dumps;
protected-memory or provider degradation is a persistent header state rather
than a transient toast.

### 20.2 Item browser

The item list shows only items whose descriptors the selected identity can
decrypt.

Each row has a role badge:

- `OWNER`;
- `WRITE`;
- `READ`.

The browser provides `All accessible`, `Writable`, and `Readable` filters plus a
one-keystroke `Show my access` summary.

It never creates placeholder rows, locked counts, or guessed labels for opaque
inaccessible envelopes.

When a caller-supplied reference cannot be resolved through the accessible
catalog, the UI shows the uniform item-unavailable message without adding it to
history or confirming existence.

The persistent header shows selected vault, identity name, label, kind, grouped
fingerprint, and owner/registered state without private key material.

### 20.3 Command availability

Read/reveal/export commands require reader, writer, or owner.

Field mutation, rename, kind change, import, and item-content deletion require
writer or owner.

Item create, item rename, item delete, principal management, and access management
require owner.

Reader rows keep mutation commands disabled with a stable role-based reason.

Commands with no selected row explain the required role rather than silently
doing nothing.

Copy-reference is available only for decrypted accessible item names.

The UI model uses exact item IDs internally even when names change.

### 20.4 Access tools

Add owner-only Tools palette entries for:

- principals;
- item access;
- grant role;
- change role;
- revoke and rotate;
- replace principal keys;
- transfer export/import;
- owner backup;
- identity protection status/enroll/rebind/remove;
- body-size/privacy status and cover reseal;
- history status and rollover.

Principal onboarding is a guided challenge/proof/fingerprint/initial-role/review/
apply flow using one atomic policy mutation, followed by an explicit transfer-
export step.

The owner access view is a principal-by-item matrix built only after the owner
decrypts every descriptor.

Matrix edits are staged locally, reviewed as one diff, and committed as one
batch policy revision.

Transfer tools include inspect, dry-run import, local export status, and
accessible-name/public-opaque delta views.

Backup tools include recovery status, verify, and the explicit restore-drill
workflow.

Every protected mutation goes through the same single backend worker and joins
before terminal restoration.

Grant, revoke, principal replacement, and owner-change forms display accessible
names to the acting owner, affected item count, descriptor/body reseal counts,
key epochs, and the applicable backward-secrecy or external-credential warning.

After every shared-state mutation, a persistent result banner states that local
state changed and offers the exact transfer-export action.

### 20.5 Metadata boundary

Extend `VaultBackend`, `VaultAction`, `VaultActionResult`, and snapshot types with
metadata-only access records and committed-action results.

No optional epoch secret, revision secret, KDF intermediate, private key, decrypted
body, or field value enters the Ratatui model.

Only names from descriptors decrypted for the selected identity may enter the
model, and lock/exit wipes the accessible catalog and rendered protected inputs.

Peek and export remain immediate controlled sinks.

Access-denied errors map to `VaultUiErrorKind::Unsupported` only if the running
backend lacks Jury v1 support; ordinary policy denial gets a new `Access` kind.

Conflict errors remain non-authentication failures and do not automatically lock
the session unless public validation or checkpoint authenticity failed.

### 20.6 Responsive layouts and tests

Update wide and compact layouts.

Test accessible-only item discovery, mixed roles, filters, identity header, owner
matrix and onboarding tools, principal replacement, long safe labels, small
terminals, selection stability after rename, post-revoke row disappearance,
transfer/recovery/history status, rollover preview, redistribution banners,
committed-action refresh failure, lock wiping, and denied command availability.

Ratatui buffer tests assert that fixture secret values, private keys, and every
inaccessible fixture item name never appear.

### 20.7 Witnessed workflow

The TUI exposes pending requests, expiry countdowns, participating witness
identities, safe decision codes, quorum progress, and offline receipt status.

It never stores or renders witness contributions.

Approval details show the principal, operation, accessible item name when the
approver is entitled to know it, or otherwise the owner-signed non-secret review
label, issue time, expiry, policy checkpoint, and witness policy. A raw opaque
selector is never the interactive target. For execution or injection, the
screen also shows the complete
verified `ActionManifestV1`: normalized executable identity, every non-secret
argument or typed secret placeholder with its verified field label, exact
normalized working-directory display or authenticated review label, injected
variable names, stdin mode, exact output-sink destination display or
authenticated review label, platform assurance, and the recomputed
command/workload digest. Commitments are verified but are never the only human
display. Security-relevant fields cannot be hidden by scrolling, truncation,
terminal width, or an “advanced” disclosure.

Approve and deny actions require that exact review screen, use the same core
request/manifest verifier as the CLI, and produce a dedicated signed
`ApprovalDecisionV1`. The action is disabled when the full manifest is absent,
its digest differs, its rendering is lossy, its approval target cannot be
verified and rendered meaningfully, or the approver descriptor is stale.

An approval UI cannot broaden a request; any change creates a different digest
and requires a new signed request.

Expired requests become terminal without retrying under a new expiry.

Witness health is clearly separated from authorization state: a green transport
check does not mean a request is approved or the vault is fresh.

Receipt inspection states the nonclaim that a signed decision does not prove
the endpoint forgot plaintext or completed the intended command.

## 21. Safety invariants

The following existing invariants remain binding.

- Native selectors remain typed item-plus-field values and never route Jig or
  repository scope.
- Raw values never pass through structured emitters, MCP, receipts, logs, or
  `Debug`.
- Existing pre-passphrase input and path validation remains.
- Reveal operations consume plaintext only in immediate selected sinks.
- Concealed and text values are encrypted identically.
- Only concealed values become output-redaction needles.
- Private filesystem permissions, no-follow reads, symlink refusal, hard-link
  alias checks, locks, atomic writes, and parent syncs remain.
- Mutations append local audit intent before shared state save.
- Transparent exec and brokered run retain their distinct process contracts.
- Backup restore never overwrites an existing vault home.
- `SecretBytes` does not reallocate while extending.
- Redaction remains a backup control, not the security boundary.

Add these Jury v1 invariants.

- Private identity files never reside in a transfer package.
- A normal transfer never contains local audit or checkpoint files.
- A normal transfer never contains local operation receipts.
- A backup containing identity material is owner-only and clearly labeled.
- Public policy validates before any key unwrap.
- Every recipient slot has an authenticated algorithm tag and schema version.
- Items may mix direct and witnessed slots, but security claims and UI state are
  path-specific; any current direct slot forbids an item-level quorum claim.
- Unknown slot algorithms, protocol versions, and receipt versions fail closed.
- Callers never obtain raw identity or witness private-key handles.
- Direct and witnessed access pass through `ItemAccessProvider` semantics and
  expose only exact revision secrets to common item code.
- Witness request IDs are durably reserved before an approval contribution is
  returned.
- Every counted approval is a strict J01A-suite signature by a current
  independent approver identity over the exact request and action-manifest
  digest; transport authentication never substitutes for this signature.
- Interactive approval is impossible without a complete, digest-verified,
  non-truncated action-manifest rendering containing every security-relevant
  operation and sink field plus policy-authenticated meaningful target, field,
  working-directory, and output-destination displays.
- Every request/manifest field pair is canonically equal before automatic
  matching, human rendering, approval signing, or witness counting; two valid
  but inconsistent objects fail closed.
- Expiry, request digest, vault, item, epoch, principal, operation, policy, and
  session key are verified before contribution assembly.
- A replay never extends expiry or produces fresh contribution material.
- Witness policy checkpoints advance only through validated signed descendants;
  stale, ahead, forked, or rolled-back states fail with distinct safe errors.
- Production witness contribution service remains disabled after startup or
  restore until an external signed rollback anchor validates checkpoint and
  replay-state high-water marks.
- Partially assembled witnessed material is zeroized on denial, timeout,
  cancellation, malformed response, and insufficient quorum.
- Receipts remain value-free and cannot be used as item-key slots.
- Public structures contain no canonical active or former item name, reversible
  name digest, or name-derived item ID.
- A selected identity decrypts descriptors only for item slots it currently
  holds; inaccessible descriptors never enter snapshots, JSON, TUI buffers,
  errors, audit events, or receipts.
- Name routing returns one result for inaccessible and nonexistent caller-
  supplied item names.
- Requested item access validates before field existence.
- Untargeted item bodies are never decrypted merely to build the accessible-name
  catalog.
- Every current effective reader has exactly one configured current access path
  per required content seal.
- Every current direct slot and witnessed capsule belongs to an effective
  reader and the capsule binds one exact revision seal.
- Every effective reader-set change increments key epoch, rotates any
  construction-internal epoch secret, creates fresh descriptor/body seal
  identifiers and revision secrets,
  reseals both ciphertexts, and replaces every current access path.
- A read grant never wraps a revision secret used by ciphertext from before the
  grant.
- Read revocation always increments key epoch and creates new revision secrets.
- Optional epoch secrets are never passed directly to an AEAD; descriptor and body
  revision secrets are derived through the exact distinct suite-KDF contexts
  from section 10.6.
- Revision secrets are unequal and non-interchangeable across content role,
  revision, and `RevisionSealId`; nonce uniqueness is enforced independently
  within each encryption domain.
- Witnessed paths never release or reconstruct an epoch root. Retained endpoint
  state can reopen an already released revision but cannot open a later seal
  without fresh authorization under the J19 compromise assumptions.
- Each lineage authenticates exactly one suite; no negotiation, fallback, or
  mixed active suite exists, and suite migration creates a new lineage.
- Write-only role changes never claim cryptographic read revocation.
- Every decrypted item descriptor is exactly the canonical fixed-size encoding;
  descriptor ciphertext length never varies with the private item name.
- Principal addition and replacement require a verified vault- and descriptor-
  bound proof of control for every required recipient and signing key component.
- Every stored public key uses the single canonical J01A encoding; hybrid
  components cannot be omitted, reordered, or substituted during fingerprint
  and duplicate-key checks.
- Principal public keys are immutable; replacement removes every old slot and
  rotates each inherited readable item exactly once.
- Identity passphrase change preserves principal keys. Principal replacement and
  reader-set rekey protect later epochs only and never claim recipient forward
  secrecy for retained historical artifacts.
- Every Jury v1 identity and backup header names one exact allowlisted Argon2id
  profile; validation rejects profile/parameter mismatch and excessive resource
  requests before KDF allocation or passphrase capture.
- Identity passphrase change upgrades weak/legacy profiles, preserves an existing
  hardened profile by default, and never silently downgrades KDF cost.
- Jury V1 owner backups use an independently captured passphrase by default and carry
  sufficient encrypted recovery material to reseal the owner identity under a
  newly selected identity passphrase.
- Private commands disable process core dumps before secret capture. Compact
  credentials, provider outputs, identity roots/private keys, optional epoch and
  revision secrets, audit seeds, and RNG seeds use page-dedicated locked/dump-excluded memory
  or fail before unlock unless an explicit degraded-mode override is recorded.
- Device-bound identity unlock combines the passphrase-derived key with exactly
  one enrolled provider response; the identity file contains no portable bypass
  slot or cached provider secret.
- A device-protector provider receives no passphrase, identity root, optional
  item epoch secret, revision secret, principal private key,
  or plaintext vault data, and cancellation/loss never triggers fallback.
- Every item body plaintext and complete Jury v1 artifact uses one exact allowed size
  bucket. Logical lengths and zero padding authenticate inside body AEAD; package
  padding is strictly bounded and transfer/backup framing binds its bucket.
- A cover reseal has the same shared item-revision form as a real body update,
  uses a fresh nonce, consumes history, and never claims to hide policy changes,
  opaque item identity, file access, transport timing, or missed cadence.
- Every policy mutation is signed by an owner authorized in the prior state.
- Every item mutation is signed by a writer authorized at its referenced policy
  state.
- Local checkpoints never move backward.
- Dry-run policy and transfer operations never mutate shared or local state.
- A local export receipt proves only which revision this installation exported,
  never delivery or remote acceptance.
- Identity labels never resolve authority, and identity selection never probes
  multiple private keys automatically.
- Transfer import never force-overwrites a fork.
- History rollover creates a distinct signed lineage in an absent home and never
  prunes, replaces, or relabels the source lineage.
- Jury V1 readers reject unknown algorithms, schemas, operations, subject kinds, and
  roles.
- Older readers reject Jury v1.

## 22. Validation and test strategy

### 22.1 Test layers

Each delivery bead adds tests with the implementation it changes.

The final hardening bead adds cross-cutting negative, fuzz, and performance
coverage; it does not postpone ordinary regression tests.

Use these layers:

- unit tests for canonical preimages and validators;
- normative and independent known-answer tests for every selected HPKE/KEM and
  signature component;
- format fixtures for Jig v1, Jig v2, valid Jury v1, and invalid Jury v1;
- property tests for policy replay and revision chains;
- mutation tests for byte tampering and reordered structures;
- core API tests for partial unlock and authorization;
- CLI parser, output, help, and raw-output tests;
- TUI model/render/backend contract tests;
- end-to-end consumer workflows;
- platform-specific path and restore tests;
- size and latency benchmarks with declared fixtures.

### 22.2 Required principal matrix

Every relevant operation is tested as:

- owner;
- writer for target item;
- reader for target item;
- registered but no-access principal;
- unknown principal;
- removed principal;
- wrong identity passphrase;
- unavailable, cancelled, substituted, and successful device-bound protector;
- protected-memory/core-dump setup failure with and without explicit degraded
  override;
- valid identity with corrupted private payload.

### 22.3 Required item matrix

Exercise:

- Development accessible while the Production descriptor is inaccessible and
  its name is absent from snapshots, errors, JSON, and TUI buffers;
- Production readable but not writable;
- Production writable;
- empty item;
- concealed and text fields;
- maximum value;
- every body-size bucket boundary and a one-byte-over transition;
- same-bucket body mutations and unchanged-body cover reseal;
- multiple items in one inject/exec;
- legacy compartment;
- renamed item;
- deleted item tombstone;
- key epoch after grant;
- key epoch after revoke;
- retained pre-grant ciphertext rejected by the newly granted identity;
- owner addition and removal.

### 22.4 Negative crypto fixtures

Include fixtures for:

- wrong HPKE recipient;
- modified slot encapsulation;
- modified wrapped revision secret;
- modified or repeated `RevisionSealId`;
- witnessed capsule or response moved across content role, revision, seal,
  suite, or epoch;
- one hybrid KEM or signature component omitted, corrupted, or replaced by a
  classical-only fallback;
- wrong slot AAD field;
- modified item nonce;
- modified ciphertext;
- modified ciphertext digest;
- body logical length outside its authenticated bucket, nonzero body padding,
  unknown body bucket, and one-byte-short/long bucket ciphertext;
- modified descriptor nonce;
- modified descriptor ciphertext;
- modified descriptor digest or length;
- variable-length, nonzero-padded, or otherwise noncanonical descriptor
  plaintext;
- descriptor metadata not matching the latest policy operation;
- duplicate decrypted accessible item name;
- public/name-derived item ID or plaintext item name fixture;
- invalid or non-canonical selected-suite signature component;
- omitted, reordered, or independently valid but mismatched hybrid signature
  component when applicable;
- non-canonical or wrong-length selected-suite recipient public key;
- X25519 high-bit/field-range and all-zero shared-secret cases when X25519 is a
  selected component;
- ML-KEM malformed key/ciphertext and implicit-rejection cases when ML-KEM is a
  selected component;
- descriptor self-signature paired with an HPKE key whose private key the
  submitter does not control;
- registration response for the wrong vault, owner, challenge, descriptor, or
  HPKE ciphertext;
- replayed registration response;
- signature by a reader;
- signature by a removed writer against new policy;
- policy signature by a non-owner;
- policy sequence gap;
- policy parent mismatch;
- item proof gap;
- item parent mismatch;
- duplicate slot;
- slot for denied principal;
- missing owner slot;
- missing active item;
- reappearing tombstone;
- unknown suite/schema/role/subject/operation;
- unknown identity/backup KDF profile, known profile with altered Argon2
  version/memory/passes/lanes/output length, and over-ceiling pre-authentication
  memory or parallelism;
- unknown/substituted identity protector, changed provider challenge or opaque
  credential ID, short/long provider response, passphrase-only bypass slot, and
  provider fallback after cancellation/timeout;
- lowered local checkpoint;
- same-item fork;
- policy fork.
- principal replacement that retains one old key slot, misses one inherited
  role, or skips one required item rotation;
- rollover bridge with a changed source ID, genesis fingerprint, terminal
  revision, rollover ID, or owner signature.
- a retained historical artifact that remains decryptable after later compromise
  of its then-authorized recipient key, paired with an assertion that passphrase
  change does not alter that result and principal replacement protects only the
  new epoch.

Each test asserts stable error kind and absence of fixture secret bytes in display
and debug output.

### 22.5 Migration fixtures

Keep the checked-in generic v1 fixture.

Add a generic v2 fixture with:

- `Development` and `Production` canonical items;
- concealed and text fields;
- one unrepresentable legacy name;
- nontrivial timestamps;
- a valid audit chain.

Migration tests assert exact logical value and metadata preservation, new owner
access, fixed-size canonical item descriptors, item separation, legacy owner-only
behavior, audit bridge, retry states, and old-reader fail-closed behavior.

No fixture contains private project or customer identifiers.

### 22.6 Transfer tests

Test:

- absent-home trust-on-first-use install;
- wrong genesis fingerprint;
- recipient registered but no access;
- `--allow-no-access` install;
- inspect without identity shows only opaque deltas;
- inspect `--me` labels only decryptable descriptors;
- import dry-run predicts the exact merge and writes no local or shared state;
- transfer status distinguishes never exported, matching, and changed locally;
- export receipt never claims delivery;
- identical import no-op;
- incoming policy descendant;
- local policy descendant;
- independent changes to two items merge;
- same-item fork rejects;
- policy fork rejects;
- rollback below checkpoint rejects;
- exporter signature tamper rejects;
- transfer contains no identity/audit/checkpoint bytes;
- source and destination alias checks;
- interrupted install leaves documented recoverable state.

### 22.7 Backup tests

Test:

- owner backup and fresh restore;
- reader/writer backup rejection;
- wrong backup passphrase;
- independent identity and backup passphrases, rejected implicit reuse, and
  explicit warned reuse;
- portable and hardened backup profile round trips;
- hostile profile headers fail before Argon2 allocation or passphrase capture;
- identity mismatch;
- absent identity installation;
- absent identity recovery reseals the same principal keys and local seed under
  a new identity passphrase, salt, nonce, and selected profile;
- portable and each available device-bound restore enrollment; lost old hardware
  is not required and the restored identity has no portable bypass unless that
  mode was explicitly selected;
- exact existing identity reuse;
- nonmatching existing identity rejection;
- identity published then vault publication failure and safe retry;
- legacy backup restore compatibility;
- backup contains owner recovery capability;
- backup status before creation, after creation, after vault advance, and after
  verification;
- backup verify updates only authenticated local recovery status;
- real drill restores to absent targets, validates owner descriptors/slots, and
  records success without deleting the drill copy;
- drill receipt failure after restore reports committed restore;
- transfer cannot be decoded as backup and vice versa;
- exact backup envelope buckets and authenticated rejection of wrong bucket or
  nonzero padding;
- no private bytes in errors or structured output.

### 22.8 Child-process tests

For exec and run, test mixed accessible and denied references.

Assert no child marker is created when any reference is denied.

Assert all reserved credential environment variables are absent from the child.

Assert protected pages are absent or unreadable after fork, compact parent
secrets never enter argv/environment/pipes, and inherited core-size limits keep
secret-delivery children from producing ordinary cores.

Retain existing Unix process-tree, redaction, status, timeout, and output-cap
tests unchanged unless Jury v1 data setup requires adapter changes.

### 22.9 Performance budgets

Measure rather than guess.

Record on a documented development machine:

- public validation time at 1, 50, and 256 principals;
- public validation time at 10, 100, and 1,000 items;
- policy replay at 1, 100, and 4,096 revisions;
- item proof validation at 1, 1,000, and 65,536 proofs;
- one item unlock;
- accessible descriptor catalog construction at 1, 10, 100, and 1,000 granted
  items;
- ten-item inject preflight;
- reader grant;
- read revocation and reseal at 1 KiB, 1 MiB, and near file cap;
- multi-item principal replacement;
- Jury v1-to-Jury v1 rollover at policy, proof, and total-file cap thresholds;
- transfer merge for independent items;
- transfer inspect and dry-run near the file cap;
- Jig v1/v2-to-Jury-v1 migration near file cap;
- portable and hardened identity/backup KDF wall time and measured peak RSS;
- rejected hostile KDF headers showing bounded pre-KDF work and no requested
  attacker-sized allocation;
- protected-memory allocation/lock/unlock/zeroize costs and minimum required
  locked-byte budget on Linux and macOS;
- each hardware provider's cold/warm unlock latency, cancellation/timeout, and
  concurrent-attempt behavior without fabricated availability targets;
- body/backup padding overhead at every bucket and proof-history growth under
  documented cover cadences.

The first release has no absolute latency SLO, but pathological superlinear
behavior outside the already documented local-audit verification cost blocks
release.

Outside an intentionally selected KDF invocation, peak memory must remain bounded
by the 16 MiB artifact cap plus explicitly bounded decrypted touched-item state,
not total unconstrained input. KDF benchmarks account separately for the exact
portable/hardened profile memory and concurrent transient buffers.

### 22.10 UX contract tests

Test:

- identity names resolve only inside the identity root and explicit identity-file
  selection is unambiguous;
- identity list reads public headers without private-key unlock or automatic
  probing;
- protected prompts and TUI headers identify the exact selected identity;
- `access list --me` and ordinary TUI snapshots contain only accessible names;
- `access explain` and `access check` prove capabilities without reading fields;
- inaccessible and nonexistent names have identical error kind, text shape, JSON
  shape, and exit behavior;
- principal add with initial grants is one policy revision or no change;
- principal add rejects a missing, mismatched, or replayed registration proof;
- principal replacement copies the exact authority set or changes nothing;
- repeated batch grants are atomic and reject duplicate/contradictory roles;
- every policy dry-run writes no shared or local bytes;
- a stale preview conflicts at commit;
- mutation output always includes local redistribution guidance;
- repeated init items create private descriptors and no public plaintext names;
- principal labels remain display-only and ambiguous labels never select an
  authorization target;
- human progress output is absent from JSON and non-terminal modes.

### 22.11 Commands

At minimum, relevant beads run:

```text
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Before final integration:

```text
scripts/jig check test
scripts/jig check fmt
scripts/jig check clippy
scripts/jig check contract
cargo run -p jury -- --help
cargo run -p jury-witness --bin juryd -- --help
```

Run the workspace's recorded MSRV check when dependency changes land.

The `scripts/jig` commands are repository harnessing only and must not add a Jig
runtime dependency.

### 22.12 Witness protocol and server matrix

Protocol tests cover:

- exact canonical request, response, and receipt preimages;
- exact canonical action-manifest, approver-descriptor, approval-decision,
  policy-checkpoint, and witness-state-anchor preimages;
- cross-implementation positive vectors;
- one-bit mutations in every signed and encrypted field;
- unknown algorithms and versions;
- wrong vault, genesis, item, epoch, slot, principal, role, policy, operation,
  workload digest, session key, request ID, or witness set;
- individually valid request/manifest pairs with each duplicated scope, policy,
  expiry, command, working-directory, field, and sink binding changed in turn;
- issuance just inside and outside allowed skew;
- not-before and expiry boundaries;
- duplicate request ID with identical bytes;
- duplicate request ID with different bytes;
- different request ID with replayed signature;
- response replay against a new session key;
- forged, stale, revoked, wrong-policy, wrong-request, wrong-manifest, expired,
  duplicate, and conflicting approver decisions;
- approval refusal when a manifest is absent, digest-mismatched, lossy, or
  truncated at every supported terminal width;
- approval refusal for an opaque target, forged/stale review label, wrong opaque
  ID binding, opaque field/working-directory/output destination, or absent
  private-name entitlement without an owner-signed label;
- approval after policy revocation;
- witness membership rotation during a request;
- insufficient, duplicate, and unauthorized witness responses;
- denial mixed with approvals;
- corrupted encrypted contributions;
- endpoint cancellation before and after durable witness decision;
- endpoint retention analysis fixture for every selected construction;
- witness signing-key and contribution-key rotation;
- replay-database rollback and restore;
- checkpoint downgrade, same-sequence fork, skipped update, witness-behind
  refusal, external-anchor loss/conflict, and new-identity recovery;
- server crash before reservation, after reservation, after decision, and after
  commit but before response;
- transaction retry without a second contribution;
- clock rollback and forward jump;
- replay compaction safety horizon;
- transport body and concurrency limits;
- rate-limit behavior without identity or item enumeration;
- graceful shutdown with in-flight requests;
- receipt verification without network or private keys;
- proof that receipt fixtures contain no item value, private name, environment,
  path, token, key, passphrase, or raw provider error.

Deployment tests run the same conformance suite against in-memory, local
single-node, and multi-process self-host fixtures.

Managed-only infrastructure may add tests but may not replace the public server
conformance suite.

## 23. Rollout and compatibility

### 23.1 Release shape

Deliver Jury v1 in one release only after core, CLI, TUI, migration, transfer,
backup, witnessed protocol, `juryd`, receipts, documentation, and compatibility
tests are complete.

Do not ship a writer before the supported reader and migration recovery exist.

Do not hide incomplete access enforcement behind a production feature flag.

Internal development may use test-only constructors and fixtures.

### 23.2 Read matrix

The new binary:

- creates, reads, and writes Jury format v1 with a selected identity;
- inspects Jig v1/v2 only through an explicit read-only migration adapter;
- migrates Jig v1/v2 to an absent Jury destination;
- never writes Jig formats;
- rejects unknown Jury format versions and unknown slot algorithms.

Jig binaries:

- continue reading their supported Jig artifacts;
- do not search Jury homes or interpret `jury-vault` magic;
- integrate only through the separate staged cutover plan.

### 23.3 Native command contract

Jury owns native repository/global/explicit-home selection, safe raw-output
flags, identity selection, private output, inject, and child-process behavior.

It does not promise Jig command spelling or `jig://` parsing.

`JIG_V2_VAULT_PASSPHRASE` is accepted only by explicit migration commands and is
always removed before child execution.

Jury identity commands use `JURY_IDENTITY_PASSPHRASE` and the `JURY_*` namespace.

Jury-native Git-worktree discovery is specified in section 0.8A and J13. Jig
compatibility aliases, Jig-specific project-context mapping, and reference
translation are specified only in `docs/jig-cutover-plan.md`.

### 23.4 Documentation cutover

Update:

- `README.md`;
- `docs/configuration.md`;
- `docs/public-contract.md`;
- CLI long help and help snapshots;
- crate-level `AGENTS.md` invariants;
- `agent-map.md` only if ownership/entrypoints move;
- `CHANGELOG.md`.

Examples use `ExampleProject`, `ExampleVault`, Development, Staging, Production,
and generic principals only.

Documentation explicitly distinguishes private item names from the still-public
opaque envelope count, sizes, principals, grants, and revision activity.

It covers access-at-a-glance, capability checks, batch onboarding, policy
dry-runs, transfer inspection/status, redistribution reminders, named identities,
guided initialization, principal key replacement, capacity monitoring,
authenticated rollover, and recovery readiness as primary workflows rather than
advanced footnotes.

### 23.5 Operational guidance

Document onboarding:

1. developer initializes identity;

2. developer sends public descriptor through an authenticated channel;

3. owner verifies the fingerprint, creates a registration challenge, and sends
   it to the developer;

4. developer returns the identity-generated proof and the owner verifies it;

5. owner previews and applies one atomic principal-add plus initial Development/
   Staging reader-set rotations;

6. owner exports transfer;

7. developer verifies genesis fingerprint and imports;

8. developer confirms `access list --me` contains Development/Staging and no
   Production name;

9. developer checks a caller-supplied Production reference and receives the same
   unavailable result as a nonexistent item.

Document offboarding:

1. owner dry-runs each item revoke or explicit revoke-all and reviews descriptor/
   body rotations;

2. owner confirms and Jury advances affected key epochs, creates fresh revision
   secrets/seal identifiers, and replaces all capsules;

3. owner removes the principal;

4. owner rotates external credentials that may have been learned;

5. owner exports and redistributes new state, then checks only the local export
   revision rather than assuming delivery;

6. online services revoke their own tokens independently.

Document key replacement as a fresh identity plus challenge/proof followed by
one atomic `principal replace`; never advise editing keys inside a registered
descriptor. Owner replacement requires a different remaining owner.

Document capacity operations:

1. monitor the public policy, proof, and encoded-size headroom;

2. dry-run rollover before the warning threshold becomes a hard-cap failure;

3. create the new lineage in an absent home and verify its signed source bridge;

4. create and verify a new owner backup;

5. distribute the new lineage and require its new genesis fingerprint;

6. retain the old lineage and backups according to policy because rollover does
   not erase or revoke them.

### 23.6 Hosted-provider guidance

Add a decision guide:

Use Jury v1 when:

- offline portability is required;
- direct human/machine membership is manageable;
- delayed file distribution is acceptable;
- cryptographic separation of current item state is the goal.

Use a central secrets manager instead when:

- revocation must be immediate without redistributing a file;
- SSO/SCIM lifecycle is mandatory;
- access must expire;
- authoritative centralized approval or audit is required;
- dynamic credentials or leasing are required;
- an authoritative latest state is required.

## 24. Implementation sequencing and delivery graph

The active graph is witnessed-first. Format and item work cannot freeze until
J19 supplies the reviewed direct/witnessed slot contract. Direct mode,
migration/recovery, process safety, the witness engine, and server adapters then
progress behind shared boundaries before J22 joins them into witnessed open.

No bead exists for writing this plan, reviewing it, or converting it to beads.

Every bead below owns a concrete independently verifiable outcome.

The tracker may use the six existing children of `jury-qv4` as delivery tracks;
the numbered outcomes below are their implementable descendants.

### 24.1 DAG

```text
J01A suite requirements -> J01B provider proof
J02 protected primitives ---------------------------+
J03 domain + adapter seam ----+
J01B provider proof ----------> J19A construction + threat model
J19A -> J19B protocol/state machines -> J19C vectors/retention proof
  -> J19D independent review -> J19 exact-revision machine gate

J01B + J02 + J19 -> J04 identity store
J01A + J03 + J19 -> J05 canonical format + direct/witnessed vectors
J03 + J05 -> J06 signed policy + access evaluator
J02 + J04 + J05 + J06 + J19 -> J07 direct/witnessed item envelopes
J02 + J04 + J07 -> J08 mode-neutral ItemAccessProvider + direct backend
J04 + J05 + J06 -> J09 local audit + checkpoints
J06 + J08 + J09 + J19 -> J10 witnessed-aware partial-unlock sessions
J07 + J10 -> J11 atomic item/policy mutations

J02 -> J12 neutral process execution extraction
J03 + J10 + J11 -> J13 native admin/read/inject CLI
J10 + J12 + J13 -> J14 exec/run pipeline

J05 + J06 + J07 + J09 + J10 -> J16 transfer and ancestry merge
J04 + J07 + J09 + J10 -> J17 backup, restore, recovery
J11 + J16 + J17 + J23 -> J18 capacity preflight + witnessed rollover

J04 + J06 + J19 -> J20 witness policy/replay/contribution engine
J20 -> J21 self-hostable juryd adapters
J10 + J13 + J14 + J19 + J21 + J23 -> J22 witnessed open + approval UX
J19 + J20 + J21 -> J23 receipts + witness operations

J10 + J13 + J16 + J17 + J18 + J22 + J23 -> J24 witnessed access TUI
J11 + J14 + J16 + J17 + J18 + J20 + J21 + J22 + J23 + J24
  -> J25 adversarial corpus + benchmarks
J18 + J22 + J23 + J24 + J25 -> J26 experimental witnessed release

Post-0.x only: J03 + J05 + J06 + J07 + J09 + J10 -> J15 compatibility
```

There are no dependency cycles.

J01A, J02, and J03 are the initial ready outcomes. J01B is blocked by J01A;
J19A is blocked by J01B and J03. J19A-J19D then feed the exact-revision J19
gate, which blocks the format and witnessed path.

J26 is the active release join and is not allowed to hide incomplete active
children. J19-J23 are mandatory release dependencies.

### 24.2 Track ownership

| Existing track | Concrete descendants |
| --- | --- |
| Cryptographic requirements | J01A, J01B |
| Portable vault and identity | J02-J11, J16-J18 |
| CLI and execution | J12-J14 |
| Witnessed authority and `juryd` | J19A-J19D, J19-J23 |
| Witnessed access TUI | J24 |
| Release | J25-J26 |

J15 is a standalone post-`0.x` compatibility outcome, not a descendant of the
active Jury release epic.

### 24.3 Jury Beads mapping

| Plan outcome | Bead |
| --- | --- |
| J01A | `jury-qv4.1.1` |
| J01B | `jury-qv4.1.2` |
| J02 | `jury-qv4.2.1` |
| J03 | `jury-qv4.2.2` |
| J04 | `jury-qv4.2.3` |
| J05 | `jury-qv4.2.4` |
| J06 | `jury-qv4.2.5` |
| J07 | `jury-qv4.2.6` |
| J08 | `jury-qv4.2.7` |
| J09 | `jury-qv4.2.8` |
| J10 | `jury-qv4.2.9` |
| J11 | `jury-qv4.2.10` |
| J12 | `jury-qv4.3.1` |
| J13 | `jury-qv4.3.2` |
| J14 | `jury-qv4.3.3` |
| J15 | `jury-qv4.2.11` |
| J16 | `jury-qv4.2.12` |
| J17 | `jury-qv4.2.13` |
| J18 | `jury-qv4.2.14` |
| J19A | `jury-qv4.4.6` |
| J19B | `jury-qv4.4.7` |
| J19C | `jury-qv4.4.8` |
| J19D | `jury-qv4.4.9` |
| J19 | `jury-qv4.4.1` |
| J20 | `jury-qv4.4.2` |
| J21 | `jury-qv4.4.3` |
| J22 | `jury-qv4.4.4` |
| J23 | `jury-qv4.4.5` |
| J24 | `jury-qv4.5.1` |
| J25 | `jury-qv4.6.1` |
| J26 | `jury-qv4.6.2` |

The three intended initial implementation tasks are J01A, J02, and J03. All
feature parents and tasks remain open until an implementation owner claims a
genuinely unblocked outcome; parent rollup state is not an implementation claim.

### 24.4 Task-specific Jig v2 baselines

The source baseline for every entry in this section is the sibling Jig
repository at commit `eed70cee337b0067ed92deb9fa05017b0b284605`.

The plan snapshot itself may be newer and uncommitted; code extraction always
uses the named Git commit unless the owning bead explicitly records and reviews
a newer source baseline.

These references are selective.

They do not make Jig v2 Jury's architecture, and they do not authorize a Jury
runtime dependency on a Jig crate.

#### J02 legacy baseline

Inspect and extract, where the component audit approves:

- `crates/jig-vault/src/secret.rs`;
- `crates/jig-vault/src/redact.rs`;
- `crates/jig-vault/src/exec_output.rs`;
- `crates/jig-vault/src/path_security.rs`;
- `crates/jig-vault/src/output.rs` and `output/unix/**`;
- the relevant unit tests embedded in those files.

Reuse non-growing secret buffers, zeroization, redacted formatting, bounded
streaming redaction, hardened handle/path checks, and atomic private output.

Replace Jig errors, homes, environment variables, URI types, crate names, and
vault-facade dependencies.

#### J09 legacy baseline

Inspect:

- `crates/jig-vault/src/audit.rs`;
- audit append/read primitives in `crates/jig-vault/src/store.rs`;
- audit failure cases in `vault_tests/management.rs`, `vault_tests/lifecycle.rs`,
  and `vault_tests/exec.rs`.

Port tamper, forged insertion, blank line, torn tail, missing log, append failure,
and value-leakage cases.

Replace the v2 DEK-derived audit key, global audit identity, and whole-vault
unlock assumptions with principal-local roots, checkpoints, and value-free
events.

#### J11 legacy baseline

Inspect behavioral tests and hardened write primitives in:

- `crates/jig-vault/src/vault_tests/management.rs`;
- `vault_tests/mutations.rs`;
- `vault_tests/import.rs`;
- `vault_tests/lifecycle.rs`;
- `crates/jig-vault/src/store.rs` and `store/existing.rs`.

Port collision, no-op, stale precondition, audit-before-save, atomic batch,
redaction downgrade, reserved-output, and publication-failure cases.

Replace `Vault`, `OpenVault`, the vault-wide envelope, and v2 mutation methods.

#### J12 legacy baseline

Inspect and either history-extract or replace:

- `crates/jig-owned-process/src/**`;
- `crates/jig-vault/src/exec_process.rs`;
- `crates/jig-vault/src/process_pipe.rs`;
- `crates/jig-vault/src/run/process.rs` and `run/process_unix.rs`;
- their process and platform tests.

Preserve process-group/job ownership, descendant cleanup, bounded capture,
signal/status semantics, pipe closure, timeout, and cancellation behavior.

Do not preserve the `jig-owned-process` package identity or dependency.

#### J13 legacy baseline

Inspect:

- `crates/jig-vault/src/template.rs`;
- `crates/jig-vault/src/output.rs`;
- `crates/jig-vault/src/vault_tests/reveal.rs` and `management.rs`;
- `crates/jig/src/command/vault.rs`;
- `crates/jig/src/cli/vault.rs`, `cli/command_conversion/vault.rs`, and
  `cli/output/vault.rs`;
- `crates/jig/src/runtime/vault.rs`, `runtime/vault/lifecycle.rs`, and
  `runtime/vault_env.rs`.

Reuse controlled-output safety, bounded template parsing, input ordering, safe
JSON/redaction behavior, and failure cases.

Replace command ownership, Jig home discovery, `jig://` domain storage,
`JIG_VAULT_*`, and any path that puts plaintext into Jig.

#### J14 legacy baseline

Inspect:

- `crates/jig-vault/src/exec.rs` and `exec_output.rs`;
- `exec_process.rs` and `process_pipe.rs`;
- `broker.rs` and `vault/brokered.rs`;
- `run.rs` and `run/**`;
- `vault_tests/exec.rs` and `run/tests/**`;
- `crates/jig/src/cli/vault_run.rs`, `cli/vault_run_tests.rs`, and
  `runtime/vault_env.rs`.

Reuse all-or-nothing reference resolution, no-child-on-failure, environment
stripping, streaming redaction, timeout, signal, exact status, output cap, and
process-tree failure cases.

Replace v2 unlocking, Jig reference types, and Jig-owned plaintext delivery.

#### J15 legacy baseline

Inspect as read-only compatibility input:

- `crates/jig-vault/src/format.rs`;
- `crypto.rs` and `aad.rs`;
- `vault/envelope.rs` and the minimum v1/v2 decode path;
- `audit.rs` and `store.rs`;
- `vault_tests/legacy.rs`;
- `crates/jig-vault/tests/fixtures/**` when present at the selected baseline.

Reuse only proven decoders, validation limits, audit verification, fixtures, and
failure cases.

Replace the writer, in-place migration, v2 audit append, vault ID preservation,
global unlock, and home mutation with an isolated reader and absent Jury target.

#### J17 legacy baseline

Inspect:

- `crates/jig-vault/src/backup.rs` and `backup/**`;
- `path_security.rs`, `output.rs`, and `store.rs`;
- `vault_tests/lifecycle.rs`;
- backup and restore controls exposed by the Jig CLI/TUI.

Reuse no-overwrite, private staging, tamper cleanup, permissions, symlink and
hard-link refusal, audit verification, publication-failure, and legacy backup
fixtures.

Replace the v2 backup payload, vault-wide passphrase/DEK recovery, single-target
transaction model, and any restore that mutates an existing destination.

#### J24 legacy baseline

Inspect the entire `crates/jig-vault-tui/src/**` history plus
`crates/jig/src/runtime/vault/tui.rs` and its tests.

Reuse generic line editing, bounded protected input, viewport/layout behavior,
terminal restoration, worker lifecycle, selection recovery, confirmation, and
deterministic buffer tests where their semantics remain valid.

Replace the v2 model, `Vault` facade, unlock state, Jig references, Jig runtime
adapter, and any UI state that assumes all item metadata is visible.

#### J25 legacy baseline

Inventory and classify every test under:

- `crates/jig-vault/src/vault_tests/**`;
- `crates/jig-vault/src/run/tests/**`;
- `crates/jig-vault/src/backup/tests.rs`;
- `crates/jig-vault/src/store/tests/**`;
- `crates/jig-vault-tui/src/tests.rs`;
- `crates/jig/src/cli/tests/vault_lifecycle.rs`;
- `crates/jig/src/runtime/vault/tui/tests/**`.

Each test receives one disposition: port unchanged in intent, adapt to Jury's
new oracle, supersede with a named stronger test, or reject with a rationale.

Never port a v2 expected value when the v2 security boundary is precisely what
Jury replaces.

### 24.5 Jig v3 retirement map

This table is the concrete disposition required before retiring the unshipped
Jig v3 epic. `Covered` means the complete behavior, negative cases, and release
obligations are owned by the named Jury or Jig delivery tasks, not merely
mentioned elsewhere in this plan. `Changed` records an intentional architectural
replacement. `Deferred` records an explicit Jury v1 non-goal rather than an
accidental omission.

| Jig v3 task | Disposition | Concrete owners | Rationale |
| --- | --- | --- | --- |
| B01 cryptographic provider | Covered | J01A, J01B, J02 | J01A freezes requirements and suite; J01B proves current providers; J02 owns protected secret-memory primitives. |
| B02 encrypted identities | Covered | J02, J04, J13, J24, J25 | Identity format, protected unlock, device protectors, operator UX, and conformance are independently owned. |
| B03 wire model and preimages | Changed | J05, J07, J19 | `jig-vault` v3 becomes bounded `jury-vault` v1 with tagged direct and witnessed slots. |
| B04 signed policy and access | Covered | J06, J11, J19, J20 | Offline policy replay remains; witnessed request policy adds a separate bounded decision engine. |
| B05 item envelopes and rekey | Covered | J07, J08, J11 | Item roots, derived keys, slots, proofs, rekeying, and guarded unwrapping remain first-class. |
| B06 audit and checkpoints | Covered | J09, J16, J17, J23 | Principal-local activity/checkpoints remain and are extended with transfer, recovery, and witness receipts. |
| B07 partial unlock | Changed | J08, J10, Jig D05 | Jury owns sessions and unwrapping; Jig delegates complete operations and never receives plaintext. |
| B08 atomic mutations | Covered | J11, J13, J24, J25 | Core authorization/publication, CLI/TUI workflows, cover reseals, and adversarial cases remain. |
| B09 v2-to-v3 migration | Changed | J15, Jig D06 | In-place migration is replaced by read-only Jig compatibility and copy-on-write migration to an absent Jury home. |
| B10 administration CLI | Covered | J04, J06, J11, J13, J24 | Identity, principal, access, protection, preview, status, and capacity workflows remain. |
| B11 list/read/inject | Changed | J03, J10, J13, Jig D04-D05 | Jury owns native selectors and plaintext operations; Jig only translates and delegates. |
| B12 exec/run | Changed | J12, J14, Jig D05 | Jury owns resolution, containment, redaction, and plaintext child delivery. |
| B13 1Password import | Deferred | Jury v1 non-goal | The importer is intentionally excluded from Jury v1 and may be reconsidered later. |
| B14 transfer and merge | Covered | J16 | Vault-only export, inspection, dry-run, ancestry merge, conflicts, and honest local status remain. |
| B15 backup and restore | Covered | J17 | Independent recovery credentials, absent-target restore, readiness, verification, and drills remain. |
| B16 access-aware TUI | Changed | J24, Jig D05 | Jury owns the CLI-backed direct/witnessed TUI; Jig replaces its in-process vault UI by delegation. |
| B17 config, status, contract, guidance | Changed | J13, J21, J23, J26, Jig D02-D09 | Jury owns native/server contracts and docs; Jig owns adapter discovery, rollout, deprecation, and removal. |
| B18 adversarial corpus and budgets | Covered | J25 | The corpus expands to witness, server, receipt, cancellation, and database boundaries. |
| B19 integration and release | Changed | J25, J26, Jig D07-D09 | Jury release assurance and Jig cutover/dogfood are separate, evidence-gated outcomes. |
| B20 capacity and rollover | Covered | J18 | Capacity preflight and signed new-lineage rollover remain, renamed for Jury v1. |

The Jig tracker may close B01-B20 and their parent as superseded only after the
live Jury Beads contain the task contracts below, the live dependency graph
matches section 24.1, and Jig D01 records this same mapping with concrete issue
IDs. Tracker records are closed, not physically deleted, so the original graph,
discussion, and source-plan provenance remain inspectable.

### J01A — Freeze core cryptographic requirements and the v1 suite

Outcome:

The repository contains a self-reviewed property matrix, alternative comparison,
explicit post-quantum and compliance decisions, and one exact provider-neutral
primitive suite and direct-slot construction before any provider is selected.

Scope:

- define required classical confidentiality/authenticity, recipient-compromise
  history exposure, nonce-misuse, key-binding/commitment, and failure behavior;
- decide whether stored recipient slots must resist harvest-now/decrypt-later
  attacks and separately whether signatures need post-quantum authenticity;
- compare classical RFC 9180 HPKE, pure ML-KEM HPKE, and
  X25519+ML-KEM-768 hybrid HPKE using exact key/ciphertext sizes, performance,
  portability, provider maturity, vector quality, and draft churn;
- compare AES-256-GCM-SIV, one-key/one-seal RFC 8439
  ChaCha20-Poly1305, and the exact expired XChaCha Internet-Draft profile for
  storage; do not equate larger nonces with misuse resistance;
- compare strict Ed25519 with a reviewed hybrid-signature alternative if PQ
  authenticity is required;
- freeze exact KEM/HPKE mode, AEADs, KDFs and contexts, hash/signature rules,
  Argon2id profiles, device-factor combiner, randomness treatment, encodings,
  limits, and error behavior;
- state that FIPS-validated deployment is a V1 non-goal and never infer a FIPS
  deployment claim from use of FIPS 203 ML-KEM;
- require one authenticated suite at lineage genesis, no negotiation or
  fallback, and authenticated re-encryption into a new lineage for migration;
- specify revision-scoped direct capsules plus descriptor/body secrets with
  fresh random `RevisionSealId` values; J19 owns the witnessed construction and
  may not weaken these suite, context, downgrade, or key-lifetime requirements.

Tests:

- independently recompute every size and security-property table entry from
  pinned primary specifications;
- demonstrate that every claimed property follows from the complete suite and
  that one weaker slot or fallback defeats the claim;
- specify positive, negative, fault, migration, and cross-provider vectors that
  J01B, J19, and J25 must realize;
- review nonce/key reuse, malformed-key/ciphertext, entropy failure, KDF
  exhaustion, and draft-version substitution cases at the construction level.

Acceptance:

- the matrix has no “broadly sound” or unstated property cells: each is yes, no,
  conditional with assumptions, or not required with rationale;
- HNDL resistance and PQ authenticity are explicit independent decisions;
- one exact suite and all constructions, contexts, encodings, and limits are
  frozen or J01A remains open;
- every RFC, FIPS, or draft dependency is named with exact status and revision;
- FIPS-validated deployment is explicitly out of scope;
- no algorithm negotiation, fallback, mixed active suites, or in-place suite
  mutation is permitted;
- no production provider dependency, adapter, or cryptographic implementation
  lands.

Dependencies: none.

Unblocks: J01B, J05.

### J01B — Select and prove the cryptographic provider set

Outcome:

The repository contains reproducible provider and wrapper evidence for exactly
the J01A-selected shared primitive suite and direct construction plus the
minimal direct-crypto gate manifest used as an input to J19.

Scope:

- inspect current upstream documentation, release metadata, and source only
  after J01A is accepted;
- record exact crates or implementations, source revisions and checksums,
  features, MSRV, licenses, unsafe-code posture, maintenance, and advisories;
- catalogue normative, official, and independent vectors with provenance and
  hashes;
- document actual zeroization, fallible entropy, allocation, error, and
  malformed-input behavior without extending guarantees by inference;
- define thin typed wrapper contracts and forbid raw provider calls outside
  those modules;
- record rejected alternatives and the anticipated minimal dependency tree;
- write `docs/security/jury-v0-direct-crypto-gate.toml`, binding the accepted
  suite, provider revisions, specification hashes, and vector hashes while
  stating that the result is experimental and not independently reviewed;
- run isolated upstream checks without linking a provider into a Jury product
  target.

Tests:

- run relevant provider suites at exact revisions;
- verify success vectors with at least two independent implementations;
- run cross-provider negative and semantic-differential vectors for malformed
  keys/ciphertexts/signatures, implicit rejection, canonical encodings, limits,
  and error behavior;
- inject entropy/provider failure and confirm no partial output or hidden panic;
- inspect and test zeroization on success, error, and cancellation boundaries;
- prove unsupported algorithms, unknown suites, and fallback attempts fail
  before private work.

Acceptance:

- every provider and wrapper claim has reproducible dated evidence;
- selected providers implement exactly one J01A suite with no extra runtime
  selection path;
- independent implementations agree on accepted outputs and rejection
  semantics, or every unavoidable difference is normalized and tested;
- the anticipated feature/dependency tree excludes unrelated plugin, SSH, PEM,
  legacy, and hazmat surfaces;
- no provider dependency, adapter, or cryptographic implementation lands before
  the J01A/J01B direct gate is accepted, and no witnessed implementation lands
  before J19's additional independent-review gate;
- the gate makes no certification or independent-review claim.

Dependencies: J01A.

Unblocks: J19.

### J02 — Extract protected bytes, redaction, and hardened filesystem primitives

Outcome:

Jury owns generic secret-memory and filesystem safety primitives with preserved
Jig history, sanitized fixtures, and no Jig runtime dependency.

Scope:

- execute the filtered-history workflow from section 0.19 in a disposable clone;
- import only reviewed whole files and their tests;
- rename APIs into neutral Jury language;
- preserve non-growing `SecretBytes` behavior;
- implement a page-dedicated non-growing `ProtectedMemory` owner for compact
  credentials, identity roots, optional item epoch and revision secrets, private
  keys, audit/RNG seeds,
  and provider outputs;
- implement Linux/macOS page locking, dump exclusion, guard pages, zeroize-before-
  unmap, and no-fork behavior where supported;
- disable ordinary process core dumps before private capture or unlock and expose
  one explicit fail-closed degraded-mode override that remains visible to callers;
- preserve zeroization, debug redaction, path alias checks, no-follow opens,
  private atomic output, permissions, parent sync, and failure cleanup;
- provide no-follow worktree-root and `.jury/vault.json` discovery/open
  primitives that treat repository contents as untrusted and never place
  plaintext staging files in the worktree;
- harden the separate platform state root and cross-worktree lock against
  symlink, hard-link, reparse-point, containment, and alias attacks;
- add explicit clock/randomness hooks where needed for later tests;
- remove Jig homes, environment variables, error types, and URI selectors;
- document platform guarantees and gaps.

Tests:

- zeroization and redacted `Debug`;
- allocation-growth refusal;
- protected-page rounding, guards, lock/dump/fork failure, zeroize-before-unmap,
  and core-suppression-before-callback tests on supported platforms;
- symlink, hard-link, reparse-point, and alias attacks;
- nested repository, linked-worktree `.git` file, malicious `.jury`, and
  worktree/state-root overlap cases;
- race replacement between validation and use;
- atomic output crash points;
- secret-free error snapshots;
- Linux, macOS, and Windows platform gates where supported.

Acceptance:

- `cargo tree` contains no Jig crate;
- imported file history resolves to original Jig commits;
- every reusable invariant has a ported test or an explicit rejection rationale;
- compact secrets cannot silently fall back to long-lived ordinary pageable
  Jury-owned allocations; degraded operation is explicit, stable, and tested;
- discovered repository paths fail closed before private work, and no plaintext
  or private local state is created below the worktree;
- generic fixtures contain no private names or paths.

Dependencies: none.

Unblocks: J04, J07, J08, J12.

### J03 — Implement native domain identifiers and the external adapter seam

Outcome:

Jury has bounded semantic domain types and no stored URI or Jig routing syntax.

Scope:

- implement `VaultId`, `PrincipalId`, `ItemId`, `ItemName`, `FieldName`,
  selectors, grants, roles, revisions, epochs, and safe display types;
- define canonical validation and size bounds;
- separate user input from confirmed catalog names;
- define a downstream adapter trait or CLI contract for external reference
  translation;
- add a Jig-reference adapter only in migration fixtures or the downstream Jig
  repository, not in native storage;
- model repository/global/explicit selection only as bounded storage context;
  Git paths, refs, object IDs, remotes, authors, and commit signatures never
  enter domain values or grant Jury authority;
- keep errors uniform for inaccessible and nonexistent names.

Tests:

- property tests for canonicalization and round trips;
- Unicode, normalization, separator, empty, oversized, and confusable cases;
- compile-time or dependency tests proving core types do not depend on Jig;
- fixtures proving `jig://` never appears in native serialized artifacts.
- fixtures proving Git routing and authorship never enter native serialized
  artifacts or authorization decisions.

Acceptance:

- native wire and domain types contain no `jig://`, project home, or Jig env;
- repository selection cannot change signed identity or make Git/PR identity a
  Jury principal;
- adapter input cannot alter signed cryptographic identity;
- public display types never accidentally confirm inaccessible names.

Dependencies: none.

Unblocks: J05, J06, J13, J15, J19.

### J04 — Deliver encrypted vault, approver, and witness identities

Outcome:

Vault principals, approvers, and witnesses have separately purposed encrypted
local identities outside vault artifacts, with typed private operations and no
raw-key escape hatch or implicit role reuse.

Scope:

- implement bounded identity format v1;
- after the full cryptography gate is accepted, implement the shared typed
  fallible `jury-core` provider adapters selected by J01B for the exact J01A
  suite; raw providers remain private to these modules;
- generate independent vault-principal recipient/signature, approver-signature,
  and witness signing/contribution key material required by J01A and J19;
- implement Argon2id profile validation before allocation;
- encrypt a random identity root and private payload with separate keys;
- support named and explicit-file selection;
- expose role-specific public descriptors and typed proof, sign,
  direct-decapsulation, and witnessed-contribution operations;
- implement the typed `IdentityProtector` boundary and versioned keychain,
  Secure Enclave P-256, TPM2 sealed-factor, and FIDO2 `hmac-secret` adapters;
- gate every advertised provider on direct-API, cancellation/timeout, temporary-
  buffer accounting, presence/verification, and real-device conformance;
- implement protection status, enrollment, rebind, removal, assurance reporting,
  explicit portable downgrade, and backup-based lost-device recovery with no
  passphrase-only bypass or cancellation fallback;
- implement passphrase change as resealing, not key replacement;
- keep identity homes disjoint from vault homes.

Tests:

- wrong passphrase and corrupted headers;
- all selected provider known-answer vectors, strict key/signature validation,
  suite-specific malformed/all-zero shared-secret rejection, injected
  entropy/provider failure, and no partial output or panic;
- exact UTF-8 passphrase bytes at 11/12/1,024/1,025-byte boundaries, no Unicode
  normalization or trimming, invalid UTF-8, NUL/CR/LF rejection, and identical
  prompt/environment/file-descriptor derivation;
- hostile KDF parameters before allocation;
- key/public descriptor correspondence;
- selector ambiguity and path attacks;
- portable and each available provider-backed round trip, provider/credential/
  challenge substitution, cancellation, timeout, lost-device, and no-fallback;
- enrollment/rebind/removal atomicity, old-method authorization, assurance
  reporting, and explicit downgrade confirmation;
- passphrase change preserving principal keys;
- principal replacement creating new keys;
- cross-role key reuse and vault-principal/approver/witness substitution
  rejection;
- secret-free logs/errors and protected-memory exits.

Acceptance:

- private keys cannot be returned through a public API;
- identity files never enter normal transfers;
- exact KDF profiles and downgrade rules are tested;
- passphrase encoding and length behavior is byte-exact across supported
  platforms and input sources;
- every advertised device provider passes deterministic protocol tests and gated
  real-hardware conformance; unsupported providers are reported unavailable and
  never silently substituted;
- public descriptor vectors are stable.
- approver and witness keys cannot be silently derived from or substituted for
  vault-principal keys.

Dependencies: J01B, J02, J19.

Unblocks: J07, J08, J09, J17, J20, J22, J23.

### J05 — Freeze the bounded direct/witnessed Jury vault format

Outcome:

`jury-vault` format v1 has bounded parse types, exact canonical preimages, and
independently generated positive and negative vectors.

Scope:

- implement minimal header discrimination and total-size limits;
- define `VaultFileV1`, header, genesis, journals, envelopes, direct and
  witnessed slots, revisions, tombstones, and migration/rollover attestations;
- define fresh 32-byte `RevisionSealId` fields for every descriptor/body seal;
- encode direct and witnessed capsules as revision scoped; an epoch root or
  reusable witness contribution is never serialized or released;
- encode exactly one authenticated suite at lineage genesis; reject per-slot or
  per-revision suite selection, negotiation, fallback, and mixed active suites;
- define authenticated suite migration only as decrypt-and-re-encrypt into a new
  lineage, with a signed statement binding both genesis IDs, old terminal
  revision, old/new suites, and canonical migrated-item digests;
- define exact byte layouts for every digest, signature, KDF context, HPKE
  `info`, and AAD;
- keep JSON as presentation storage while signing typed binary preimages;
- emit one bounded deterministic JSON representation for a given `VaultFileV1`
  so the committed `.jury/vault.json` is a byte-stable opaque artifact;
- keep identity, checkpoint, audit receipts, witness replay state, locks,
  transaction state, and every local path out of `VaultFileV1`;
- reject duplicate map keys, alternate encodings, oversized base64, and unknown
  versions before private work;
- reject Git conflict markers and truncated merge-driver output before private
  work;
- publish language-neutral vector files and schema documentation.

Tests:

- exact byte and hex vectors;
- independent encoder comparison;
- one-bit mutations;
- every count/length boundary;
- duplicate IDs, slots, nonces, revisions, and unknown tags;
- duplicate/reused revision seal identifiers, cross-revision capsule swaps,
  mixed-suite slots, fallback attempts, and migration-statement substitution;
- deterministic safe errors for malformed public input.
- byte-stable re-encoding, conflict-marker, and portable-artifact/local-state
  separation fixtures.

Acceptance:

- magic is `jury-vault` and version is `1`;
- no Jig format field is reused by implication;
- no plaintext private name appears in any vector artifact;
- `.jury/vault.json` contains the complete shared artifact and no
  installation-local state;
- direct slot encodings match the accepted J01A/J01B suite;
- witnessed slot encodings match the accepted J19 contract and no
  epoch root or reusable contribution field exists;
- suite migration preserves the old lineage unchanged and never creates a
  dual-suite lineage;
- unknown recipient slots fail closed.

Dependencies: J01A, J03, J19.

Unblocks: J06, J07, J09, J15, J16.

### J06 — Implement signed policy replay and exact access evaluation

Outcome:

Public policy can be replayed from genesis into one deterministic normalized
state with exact direct authorization plus witnessed membership, quorum,
workload, lifetime, and downgrade rules.

Scope:

- implement owner-signed genesis and policy revision verification;
- implement principal lifecycle, owner rules, exact item roles, tombstones,
  reader-set change, slot replacement, and principal replacement operations;
- model vault principals, approvers, and witnesses as distinct subject classes;
- bind each governed item to eligible approvers, eligible witnesses, approval
  quorum, witness quorum, allowed operations, request lifetime, and workload;
- count only distinct active same-role identities and reject unknown, revoked,
  duplicated, cross-role, zero, or over-capacity quorum configurations;
- make any usable direct slot explicitly unilateral and suppress the witnessed
  claim for that item;
- make membership, quorum, access-mode, and workload changes explicit policy
  revisions that invalidate incompatible pending authorization;
- validate historical authority at each sequence;
- reject illegal operation combinations and ambiguous forks;
- expose capability explanation without item-body decryption;
- keep item names absent from public policy.

Tests:

- role and owner matrices;
- missing, duplicated, reordered, and forged operations;
- sole-owner protections;
- exact reader-set change requirements;
- approver/witness membership, quorum, workload, and lifetime matrices;
- direct-slot claim suppression, implicit-downgrade rejection, and pending-
  request invalidation;
- principal replacement across all accessible items;
- rollback/fork fixtures and property-model comparison.

Acceptance:

- every accepted mutation has a unique normalized result;
- non-owner policy changes fail before key work;
- read and write authority are exact and deny by default;
- witnessed membership and both quorums are exact and deny by default;
- unknown, duplicated, revoked, or cross-role subjects and operations fail
  closed;
- policy status explains direct, witnessed-only, mixed/unilateral, and
  unsatisfiable-quorum states without revealing private item names.

Dependencies: J03, J05.

Unblocks: J07, J09, J10, J11, J13, J16, J20, and post-`0.x` J15.

### J07 — Implement direct/witnessed item envelopes and rekeying

Outcome:

Each item has a private descriptor/body, fresh revision seal identifiers and
secrets, algorithm-tagged direct and witnessed recipient paths, signed
revisions, and correct rekey behavior.

Scope:

- implement descriptor and body bucket encoding;
- implement typed descriptor/body revision-secret types;
- implement revision-scoped direct HPKE capsules through provider adapters;
- implement the J19-reviewed witnessed capsule construction without exposing an
  epoch root or reusable contribution;
- ensure both paths release only exact revision secrets and zeroize all
  intermediate state before calling item code;
- bind every seal and capsule to a fresh `RevisionSealId`, exact
  content role, revision, suite, vault, item, and epoch;
- implement signed item revisions and proof chains;
- implement authorized unchanged-body cover reseals as ordinary signed item
  revisions with fresh nonces and no public cover discriminator;
- increment epoch, rotate any construction-internal epoch secret, and reseal
  descriptor/body on effective reader-set changes;
- avoid epoch rotation on writer-only changes;
- implement item creation, rename, deletion, and tombstones.

Tests:

- authorized/unauthorized reader matrices;
- grant cannot decrypt pre-grant ciphertext;
- revoke cannot decrypt post-revoke ciphertext;
- retained old keys cannot open new epochs;
- nonce reuse and slot duplication rejection;
- revision seal reuse, cross-role/revision capsule swapping, mixed-suite, and
  fallback rejection;
- direct/witnessed downgrade, partial-quorum, replayed-contribution, and retained
  prior-revision state rejection;
- cover reseal preserves logical bytes and bucket, consumes proof capacity, and
  is publicly indistinguishable from an ordinary same-bucket revision except for
  the explicitly documented timing/activity leaks;
- bucket padding and malformed plaintext rejection.

Acceptance:

- no vault-wide DEK exists;
- private item names are absent from public state;
- every slot is tagged and authenticated;
- the common item consumer can receive only `ProtectedRevisionSecrets`;
- governed items can omit direct slots entirely; if any usable direct slot is
  present, status and receipts suppress the item-level quorum claim;
- witnessed material cannot yield an epoch root, reusable contribution, or a
  later revision secret;
- rekey operations are atomic or make no change.

Dependencies: J02, J04, J05, J06, J19.

Unblocks: J08, J11, J15, J16, J17.

### J08 — Implement the mode-neutral `ItemAccessProvider`

Outcome:

Direct and witnessed access share a stable guarded interface. J08 freezes that
interface and delivers the direct backend without exposing identity private
keys, decapsulation state, witness contributions, or item epoch secrets.

Scope:

- define sync core semantics and an async-compatible adapter boundary;
- model direct completion and asynchronous witnessed request completion without
  allowing callers to bypass either backend's authorization steps;
- validate public policy and exact slot bindings before decapsulation;
- call private identity operations internally;
- decapsulate only the authenticated revision secret, zeroize intermediate and
  optional epoch state, and pass `ProtectedRevisionSecrets` to the scoped
  consumer;
- zeroize on success, error, panic containment where possible, and cancellation;
- return stable value-free error kinds;
- reserve typed pending, approved, denied, expired, unavailable, stale, replay,
  and insufficient-quorum outcomes for the witnessed backend delivered by J22;
- expose mock unwrappers for tests without production key bypasses.

Tests:

- wrong principal, role, item, epoch, policy, slot, and suite;
- closure success and failure cleanup;
- compile-fail or API tests for raw-key escape;
- injected provider and entropy failures;
- epoch-root pre-callback destruction, revision-secret lifetime, and redacted
  debug checks.

Acceptance:

- CLI/TUI-facing APIs cannot request an identity private key;
- every provider can release only one selected descriptor/body revision to the
  scoped consumer;
- the public interface has no direct-only assumption or witness-material escape
  hatch;
- guard cleanup is observable through test instrumentation.

Dependencies: J02, J04, J07.

Unblocks: J10.

### J09 — Implement per-principal audit, checkpoints, and local receipts

Outcome:

Every identity has authenticated value-free local activity, rollback
checkpoints, and local operation receipts independent of shared item keys.

Scope:

- derive local audit/checkpoint roots from identity-local seed material;
- create platform-state paths keyed by vault ID, genesis fingerprint, and
  principal ID, never paths below the vault home or worktree;
- share retained state and a cross-process lock across clones and linked
  worktrees that select the same vault/genesis/principal tuple;
- authenticate event sequence and vault revision checkpoints;
- reject a behind or divergent Git checkout without lowering retained state;
  strict descendants may advance and independent-item branches route to J16;
- separate shared authenticity from local activity;
- define safe event schemas for direct and witnessed reads, request/decision
  transitions, writes, failures, transfers, backup, and witness operations;
- link witnessed entries to bounded request, decision, receipt, policy-revision,
  and revision-seal identifiers without storing manifests, contributions,
  reusable authorization material, private names, or values;
- expose selected-principal `vault audit verify` semantics, including clear
  labeling for migration-attested legacy archives;
- implement bounded verification and rollover.

Tests:

- edit, truncate, reorder, delete-tail, rollback, and wrong-identity cases;
- crash between intent, shared mutation, and checkpoint;
- audit path/permission attacks;
- clone/worktree concurrency, branch switching, old-commit checkout, state-root
  deletion, wrong-genesis reuse, and `JURY_STATE_HOME` containment attacks;
- scans proving no secret or private inaccessible name enters records;
- audit verification never claims another principal's activity or remote
  freshness and distinguishes current Jury verification from legacy attestation.

Acceptance:

- normal transfer excludes all local state;
- normal Git status/history contains no identity, checkpoint, audit, receipt,
  lock, or recovery transaction state;
- retained state detects conforming-client checkout rollback across clones and
  worktrees and never silently lowers its accepted ancestry;
- audit deletion is documented as detectable only with retained checkpoint;
- event reason codes are bounded and value-free.
- witnessed entries bind bounded request/decision/receipt identifiers without
  containing authorization material or private values.

Dependencies: J04, J05, J06.

Unblocks: J10, J16, J17, and post-`0.x` J15.

### J10 — Deliver witnessed-aware partial-unlock sessions and scoped snapshots

Outcome:

Opening a vault validates public state first, discovers only accessible item
names, and decrypts item bodies only after an explicit direct authorization or
a completed witnessed request for the exact operation.

Scope:

- implement parsed, public-validated, principal-session, witness-pending,
  approved, denied, expired, stale, unavailable, cancelled, and unlocked-item
  states;
- integrate `ItemAccessProvider` rather than identity keys;
- build accessible descriptor catalogs on demand;
- implement metadata-only snapshots and exact revision tokens;
- enforce uniform inaccessible/nonexistent errors;
- provide bounded multi-item preflight for explicit operations.
- bind session transitions to the exact request, manifest, revision tokens,
  policy checkpoint, and expiry; approval cannot broaden or refresh a request;
- ensure refresh, cancellation, lock, signal, or error wipes partial witness and
  revision material without turning a pending request into direct access.

Tests:

- mixed accessible/inaccessible items;
- body-decryption counters proving partial unlock;
- descriptor catalog lock/zeroization;
- stale revision and checkpoint conflicts;
- witnessed approval, denial, expiry, cancellation, stale checkpoint,
  insufficient quorum, and response-substitution transitions;
- snapshot, JSON, and debug leakage scans.

Acceptance:

- ordinary open decrypts no item body;
- inaccessible names never enter model state;
- direct and witnessed access use the same guarded session contract for
  descriptors and bodies;
- ordinary open and witness-pending states decrypt no item body.

Dependencies: J06, J08, J09, J19.

Unblocks: J11, J13, J14, J15, J16, J17, J24.

### J11 — Implement authorized atomic policy and item mutations

Outcome:

Field, item, batch, direct-access, witnessed-governance, and identity-lifecycle
mutations are authorized, preflighted, signed, audited, and atomically
published.

Scope:

- implement optimistic revision preconditions;
- mutate approver/witness membership, same-role replacement/rotation, access
  mode, both quorums, allowed operations, request lifetime, and workload limits;
- require witnessed-only transitions to prove that no usable direct slot
  remains and current membership can satisfy both quorums;
- treat introduction of any direct slot or weakened witnessed requirement as an
  explicit authenticated downgrade that suppresses the quorum claim and
  invalidates incompatible pending requests;
- determine every touched item before decryption;
- preflight all rotations, slots, signatures, bounds, and output size;
- append audit intent, publish one artifact, and advance checkpoint;
- under the shared cross-worktree lock, re-open and compare the current
  `.jury/vault.json` digest and ancestry to the loaded preview before replacing
  it; checkout, reset, merge, or another process changing the artifact returns a
  typed stale/conflict result;
- publish only encrypted shared bytes in the worktree, then update the separate
  platform-state audit/checkpoint with exact committed-primary recovery status;
- never invoke Git, stage, commit, or push as a side effect of a Jury mutation;
- preserve no-op and collision semantics;
- implement writer-authorized privacy cover preparation and publication as a
  normal unchanged-body revision with exact history/capacity preflight;
- produce dry-run previews identical to commit planning;
- emit redistribution and external-credential warnings.

Tests:

- every failure point before and after audit intent;
- stale preview and concurrent edit;
- Git checkout/reset and linked-worktree mutation between preview, lock, and
  publication;
- multi-item all-or-nothing behavior;
- reader/writer/owner authorization matrix;
- approver/witness membership, quorum, mode-transition, pending-request
  invalidation, and authenticated direct-downgrade matrices;
- cover authorization, same-bucket invariance, proof-cost, capacity, and
  redistribution-result cases;
- output publication and fsync faults;
- secret-free result and error contracts.

Acceptance:

- no partial reader-set change can publish;
- no partial witnessed-governance change can publish;
- witnessed-only mode cannot retain a usable direct slot or unsatisfiable
  quorum, and a direct downgrade cannot be implicit;
- dry-run writes no shared or local bytes;
- committed state always validates from scratch.
- a worktree mutation cannot overwrite a different Git or Jury ancestry, and a
  post-commit local-state failure is reported as committed rather than retried.

Dependencies: J07, J10.

Unblocks: J13, J18, J25.

### J12 — Extract or replace process-tree execution safely

Outcome:

Jury owns a neutral child-process containment layer with the hardened Jig
behavioral tests and no `jig-owned-process` dependency.

Scope:

- compare history extraction with a maintained general dependency;
- implement process group/job ownership, timeout, kill tree, signal forwarding,
  bounded capture, pipe closure, wait, and cleanup;
- preserve streaming redaction and independent output streams;
- support platform-specific capabilities explicitly;
- document unavoidable OS-owned secret copies.

Tests:

- descendant cleanup, double-fork or platform equivalent;
- timeout and cancellation races;
- output cap and redaction across chunk boundaries;
- signal exit status preservation;
- failed spawn and partial pipe setup;
- no Jig crate in dependency graph.

Acceptance:

- Jury never imports `jig-owned-process` at runtime;
- child cleanup tests pass on supported platforms;
- unsupported guarantees fail or degrade explicitly.

Dependencies: J02.

Unblocks: J14.

### J13 — Deliver native identity, admin, read, and inject CLI

Outcome:

The `jury` CLI supports native vault, identity, principal, access, field, read,
private-output, and template-injection workflows through stable core seams.

Scope:

- implement argument parsing and bounded protected input;
- implement human and stable JSON output;
- add identity init/list/status/public/prove/change;
- add identity protection status/enroll/rebind/remove with exact provider and
  assurance reporting, no fallback, and explicit portable downgrade gating;
- add vault init/status and item/field operations;
- implement section 0.8A precedence for `--home`, `--global`, absolute
  `JURY_HOME`, nearest Git worktree `.jury`, and the platform global default;
- make repository-local `jury init` create only encrypted
  `.jury/vault.json` plus `.jury/.gitattributes` that disables textual merge;
  V1 requires no authoritative `.jury/config.toml` and uses no clean/smudge
  filter or plaintext worktree file;
- expose stable public verification and value-free status for repo/global/
  explicit selection, first-use trust, stale checkout, and merge conflict;
- require explicit interactive genesis confirmation before first private use of
  a clone and an externally supplied expected genesis for non-interactive use;
- label direct, witnessed-only, and mixed-mode access per selected principal and
  never emit an item-level quorum claim for mixed mode;
- add role-specific create, inspect, rotate, replace, and protector commands for
  vault principals, approvers, and witnesses;
- add `policy require witnessed` with eligible approver/witness membership,
  approval quorum, witness quorum, allowed-operation, request-lifetime, and
  workload controls;
- require an authenticated acknowledgement for `policy allow direct` or any
  mutation that introduces a usable direct slot or weakens witnessed policy;
- add value-free policy status/explain output for mode, quorum satisfiability,
  pending-request invalidation, and direct-slot claim suppression;
- add read/private output and template injection;
- add `privacy cover --item`, `vault audit verify`, history/capacity status, and
  stable public validation output;
- strip every Jury and migration credential from child environments;
- never parse `jig://` in native commands.

Tests:

- interactive and non-interactive workflows;
- nested repositories, linked worktrees, explicit/global precedence, absent
  repo home init, malicious `.git`/`.jury` paths, and detached-home workflows;
- fresh-clone TOFU, externally pinned CI, whole-repository substitution, and
  rejection of a same-repository fingerprint as an independent trust anchor;
- exact JSON and exit contracts;
- uniform unavailable behavior;
- no output/JSON/log leakage;
- denied multi-reference injection creates no output;
- device-protector cancellation/loss never falls back; cover and audit commands
  reveal no inaccessible names and report exact committed/retryable state;
- mixed-slot fixtures prove status and JSON claims remain path-specific;
- role/membership/quorum/mode command matrices, impossible quorum rejection,
  and missing direct-downgrade acknowledgement;
- TTY and non-TTY safety rules.

Acceptance:

- selected-item operations do not decrypt unrelated bodies;
- policy previews are authenticated and commit-compatible;
- a fresh operator can configure witnessed-only access, both memberships, and
  both quorums entirely through native CLI commands;
- impossible quorums and implicit direct downgrades fail before mutation;
- native CLI help does not imply Jig ownership.
- inside a Git worktree the default shared artifact is the committed
  `.jury/vault.json`, while plaintext, identities, and local state never enter
  Git through a Jury command.

Dependencies: J03, J10, J11.

Unblocks: J14, J22, J24.

### J14 — Deliver transparent exec and brokered run

Outcome:

Jury can deliver selected values to child processes while preserving atomic
resolution, containment, cleanup, environment stripping, and redaction.

Scope:

- parse templates/dotenv before private capture;
- resolve all required fields at one authenticated revision;
- support environment, stdin, and explicitly controlled file sinks;
- start no child when any access or resolution fails;
- disable ordinary cores before private capture, keep compact parent secrets in
  protected no-fork pages, and ensure plaintext-delivery children inherit a zero
  core limit without inheriting protected parent mappings;
- integrate neutral process ownership;
- preserve exact child exit status;
- state that an authorized child may retain plaintext.

Tests:

- mixed allowed/denied references;
- no child marker on preflight failure;
- reserved environment stripping;
- process tree cleanup and signals;
- dump/lock setup failures start no child without the explicit degraded override;
- binary values and redaction boundaries;
- command digest normalization needed by witnessed operations.

Acceptance:

- secret values never enter argv or logs;
- failures are atomic before spawn;
- direct execution passes the complete process-containment contract.

Dependencies: J10, J12, J13.

Unblocks: J22, J25, J26.

### J15 — Deliver post-0.x read-only Jig compatibility and copy-on-write migration

Release status:

J15 is optional work after the witnessed-access `0.x` release. It is not a
child of the active release epic and does not block J17, J25, or J26.

Outcome:

Valid Jig v1/v2 vaults migrate to absent Jury homes without mutating the source,
and every destination is independently verifiable.

Scope:

- import legacy readers and audit verification with preserved history where
  appropriate;
- isolate legacy types from native Jury writers;
- implement explicit source/destination CLI;
- map canonical and legacy fields;
- create fresh Jury IDs, keys, genesis, audit, and checkpoint;
- when the explicit absent destination is a repository `.jury` home, publish
  only encrypted `vault.json` and public `.gitattributes` there; create the new
  checkpoint/audit under the platform state root and keep identity material
  outside both source and destination repositories;
- copy legacy audit evidence and bind its exact digest;
- write migration manifest, verify, retry, and rollback guidance;
- leave source bytes unchanged under all success/failure paths.

Tests:

- Jig v1 and v2 fixtures at bounds;
- wrong passphrase, invalid audit, malformed state, and races;
- source hash before/after every injected failure;
- absent/existing/aliased destination handling;
- staging recovery and fsync faults;
- repository-local destination, detached destination, Git-unavailable, and
  portable/local cross-directory publication cases;
- retained old-copy warning and credential rotation guidance.

Acceptance:

- source artifact and audit hashes are identical before and after;
- destination is `jury-vault` format v1 with new vault ID;
- repository-local migration leaves only the portable shared artifact and public
  integration metadata in Git;
- no dual-write or in-place option exists.

Dependencies: J03, J05, J06, J07, J09, J10.

Unblocks: post-`0.x` compatibility only.

### J16 — Implement transfer, inspection, and ancestry merge

Outcome:

Portable encrypted shared state can be exported, inspected, imported, and
merged when ancestry permits without carrying local identities or audit.

Scope:

- implement bounded transfer envelope and digest;
- implement public inspection and optional accessible-name projection;
- implement bounded public verify and value-free semantic diff over explicit
  artifact files without requiring an identity;
- implement ancestry-aware three-way merge over independently validated
  base/ours/theirs artifacts, suitable for explicit use or an opt-in Git merge
  driver, with no textual fallback;
- enforce genesis, policy, item-proof, and checkpoint relationships;
- permit strict descendants and independent-item merges only when signatures
  and ancestry prove safety;
- authenticate and merge witnessed membership, both quorums, access mode,
  workload rules, pending-request invalidation, and direct-slot claim
  suppression under those same ancestry rules;
- reject branches that conflict on witnessed governance, lower a quorum,
  introduce a direct slot, or revive a revoked approver/witness rather than
  selecting the weaker branch automatically;
- reject same-item forks without explicit recovery;
- record local export status without claiming delivery.

Tests:

- truncation, replacement, wrong genesis, rollback, and forks;
- Git conflict markers, malicious base selection, forged Git authorship or
  signed commits, missing merge driver, and merge-driver partial output;
- old-commit checkout and divergent-branch comparison against retained J09
  state, including fresh-clone trust and linked-worktree concurrency;
- independent-item merge and same-item conflict;
- direct-versus-witnessed policy forks, concurrent membership/quorum changes,
  direct-slot introduction, revoked actor resurrection, and stale cached quorum
  claims;
- inaccessible-name non-disclosure;
- no identity/audit/checkpoint/local receipt in transfer;
- atomic import and dry-run.

Acceptance:

- raw copy and transfer semantics are documented honestly;
- import cannot silently discard a valid local branch;
- Git diff/merge output is value-free by default, Git identity never grants Jury
  authority, and ordinary textual merge cannot produce an accepted artifact;
- merge never silently selects a direct downgrade, lower quorum, revived
  witness/approver, or stale quorum claim;
- export status never claims recipient delivery.

Dependencies: J05, J06, J07, J09, J10.

Unblocks: J18, J24, J25.

### J17 — Deliver owner backup, restore, and recovery drills

Outcome:

Owners can create independently protected recovery material for portable state,
all three local identity roles, and principal-local verification state. J23
separately owns replay-safe witness-service recovery.

Scope:

- implement bounded padded backup envelope;
- capture an independent backup passphrase;
- include the portable vault, explicitly selected vault-principal, approver, and
  witness-client identities, checkpoint, and necessary authenticated local
  evidence;
- report exactly which direct items, local roles, and checkpoints can recover;
  never imply that a client backup recovers juryd replay state, external
  anchors, witness availability, or quorum;
- revalidate witnessed topology, quorum satisfiability, checkpoint ancestry,
  and outstanding J23 witness recovery before private use, without adding a
  hidden direct slot;
- implement cross-directory recoverable restore transaction;
- restore a repository-local target as portable `.jury/vault.json` plus public
  integration metadata while restoring identity and authenticated local state
  only to their separate platform roots;
- preserve existing targets;
- support legacy backup restore followed by explicit migration;
- record drill success only after actual restored access verification.

Tests:

- wrong passphrase, hostile KDF, tamper, bucket, and padding failures;
- exact UTF-8 passphrase byte contract and 11/12/1,024/1,025-byte boundaries;
- witnessed-only recovery with available, unavailable, lost, and explicitly
  rotated witness sets;
- all three identity roles, impossible post-restore quorum, stale topology, and
  outstanding external witness recovery;
- identity/vault mismatch;
- publication faults at every transaction step;
- repository-local restore with Git present/absent and failures between
  portable, identity, and platform-state publication;
- existing and aliased targets;
- real drill and failed receipt recording;
- transfer/backup type confusion.

Acceptance:

- backup is clearly more sensitive than transfer;
- backup status states exactly which direct items, identity roles, and local
  verification state it can recover and never claims juryd or quorum recovery;
- restore never overwrites an existing identity or vault;
- restore never writes private identity or local rollback evidence into Git;
- recovery readiness distinguishes creation, verification, and real drill.

Dependencies: J04, J07, J09, J10.

Unblocks: J18, J24, J25.

### J18 — Implement capacity preflight and authenticated rollover

Outcome:

Every mutation predicts hard limits, and owners can create a fresh Jury-v1
lineage with a signed source bridge, fresh witnessed topology, and anchored
initial checkpoint before history caps are exhausted.

Scope:

- compute count and encoded-size results before mutation;
- report stable safe headroom and typed capacity errors;
- implement owner-only dry-run and absent-home rollover;
- generate new IDs, revision secrets/seal identifiers, capsules, ciphertext,
  and revision-one chains;
- bind a canonical bootstrap manifest into the source bridge;
- for governed items, bind the new policy, approver/witness membership, both
  quorums, suite, and revision-one seals; register fresh witness topology and
  establish the initial replay checkpoint/external anchor through J23 before
  declaring witnessed readiness;
- never reuse old approvals, receipts, witness contributions, revision secrets,
  or authorization transcripts in the new lineage;
- treat missing, stale, restored, or partially rotated witnesses as not ready
  and never fall back to direct access;
- reuse the absent-home rollover transaction for suite migration: validate the
  source under its authenticated suite, re-encrypt every active item under one
  supported destination suite, and bind old/new genesis IDs, suites, source
  terminal revision, and migrated-item digests; never negotiate or install both
  suites in one lineage;
- require new backup, fingerprint trust, and redistribution.
- for a repo-local source, produce a value-free adoption manifest for the
  separately created lineage; never invoke Git or replace the tracked source as
  part of rollover, and require explicit operator adoption plus new external
  genesis trust;
- warn that old Git objects and clones retain the complete old-lineage artifact
  and remain decryptable by retained old recipient keys.

Tests:

- every cap just below/at/above boundary;
- rollover while source is at cap;
- bridge and manifest mutation;
- old-contribution/transcript reuse, incomplete topology registration,
  checkpoint/anchor split writes, restored/rotated witnesses, impossible
  quorum, and direct-fallback attempts;
- suite-ID downgrade/fallback, mixed-lineage, partial re-encryption, old/new
  manifest substitution, and interrupted suite migration;
- destination path attacks and publication faults;
- old-lineage preservation and new-backup warning.
- repo-local adoption, unreachable/missing old-object evidence, force-push
  nonclaims, and external trust-pin update.

Acceptance:

- no in-place history pruning exists;
- rollover is available at hard cap;
- source is never replaced or deleted.
- new-lineage witnessed readiness requires registered topology plus a durable
  initial checkpoint and external anchor;
- old authorization material cannot authorize the new lineage, and incomplete
  witness recovery never creates a direct fallback;
- repo-local rollover never edits Git automatically and cannot claim that Git
  history, clones, or old recipient keys were erased;
- old retained artifacts remain governed by their old suite and are never
  described as retroactively HNDL protected.

Dependencies: J11, J16, J17, J23.

Unblocks: J24, J25, J26.

### J19A-J19D — Freeze and independently review the witnessed construction corpus

Work split:

- J19A selects the construction and freezes the threat model, trust boundaries,
  compromise assumptions, revocation limits, and endpoint-retention claim.
- J19B freezes canonical protocol-v1 schemas plus request, approval,
  contribution, replay, expiry, checkpoint, rotation, and recovery state
  machines.
- J19C publishes implementation-independent positive/negative vectors and the
  executable endpoint-retention model.
- J19D obtains independent cryptographic review of the exact J19A-J19C corpus
  and keeps the gate closed until every material remediation is reviewed.

These are separately schedulable delivery outcomes, not review ceremony. J19A-
J19C produce the product contracts consumed by implementations. J19D supplies
the external review required by the security boundary.

Outcome:

The repository contains a reviewed witnessed threat model, selected
distributed-decryption construction, authenticated approval and action-manifest
protocol, monotonic freshness and rollback-anchor design, bounded protocol-v1
schemas, downgrade rules, an endpoint-retention proof, and independent
deterministic vectors. This is the gate before production identity, item,
backup, or witnessed encryption implementation.

Scope:

- analyze endpoint, witness, quorum, retention, rotation, recovery, and
  collusion cases;
- compare standard threshold KEM/distributed-decryption and other reviewed
  candidates; select only a construction whose exact security model and
  implementation are independently reviewed, without calling coordination
  “threshold” by default;
- specify direct and witnessed-v1 slot fields needed by the final vault format;
- specify mixed-slot authorization, downgrade, status, receipt, and product-claim
  semantics so one direct slot defeats any item-level quorum claim;
- specify canonical requests, action manifests, approver descriptors and signed
  decisions, responses, receipts, policy checkpoints, state anchors, and error
  codes;
- specify `ApprovalTargetV1`, including owner-signed non-secret review labels,
  entitlement-bound private-name display, field/working-directory/output-sink
  openings, label rotation, and fail-closed human approval when any meaningful
  verified representation is unavailable;
- bind vault/item/epoch/content-role/revision/`RevisionSealId`/policy/principal/
  operation/workload/expiry/session;
- define one common validator that rejects every individually valid but
  semantically inconsistent request/action-manifest pair before display,
  automatic approval, approval signing, or witness counting;
- define independent approver and witness membership, key lifecycle, quorum,
  replay, and rotation;
- define first registration, strict-descendant checkpoint updates,
  witness-behind/stale/fork behavior, revocation propagation, and the exact limit
  of witnessed freshness;
- define an external rollback-anchor interface and at least one fully public,
  self-hostable production profile; a restored witness cannot contribute until
  its checkpoint and replay high-water marks are proven current enough;
- freeze the serialized database-commit, signed-candidate, external compare-and-
  swap, readback, response-release, and crash-reconciliation state machine;
- make every witnessed capsule and response revision scoped, never release or
  reconstruct an epoch root, and define what an authorized endpoint can retain;
- prove against the selected construction that a malicious endpoint retaining
  its long-term keys, all prior requests, approvals, witness responses,
  contributions, revision secrets, ciphertexts, and plaintext cannot open a
  later `RevisionSealId` without a fresh authorized quorum, absent a direct
  path or compromise threshold already excluded by the threat model;
- define exact action-manifest rendering and make opaque-digest-only interactive
  approval and opaque-target interactive approval invalid;
- produce `docs/security/jury-v1-crypto-gate.toml` plus a CI validator that binds
  accepted specifications, vectors, reviewed commit, review metadata, and
  finding dispositions and closes the gate after any bound hash changes;
- publish independent positive and negative vector corpus;
- obtain independent cryptographic review before implementation gate opens.

Tests/deliverables:

- exact language-neutral vectors;
- alternate-implementation verification;
- downgrade, request/approval replay, stale/fork/rollback, collusion, malicious
  endpoint, approval-rendering, and retention matrices;
- retained-endpoint vectors that authorize revision N, preserve all endpoint-
  visible state, then reject N+1 and prove the state cannot decrypt N+1;
- cross-revision, cross-role, and cross-seal capsule/response substitution plus
  repeated seal-identifier rejection;
- recovery, lost-witness, stale-database, missing/conflicting-anchor, and new-
  witness-identity scenarios;
- faults before/after database commit, anchor compare-and-swap, anchor readback,
  and response release, including the sole safe one-candidate reconciliation;
- proof that transport authentication cannot substitute for an approver
  signature;
- proof that an opaque selector or unauthenticated display label cannot produce
  an interactive approval;
- negative vectors changing each duplicated request/manifest field while both
  objects and their signatures remain individually valid;
- proof that no service has unilateral decryption under stated assumptions;
- proof that no witnessed transcript yields an epoch root or reusable
  contribution material.

Acceptance:

- no static share-release shortcut survives without an honest retention claim;
- the chosen construction is a reviewed distributed-decryption/threshold-KEM or
  equally analyzed scheme, not a bespoke static share/KDF composition;
- the endpoint-retention proof establishes fresh authorization for every new
  revision seal while explicitly allowing retention of an already released
  revision;
- exact nonclaims are prominent;
- every counted approval is a current approver signature over the exact request
  and verified action-manifest digest;
- old valid artifacts, stale witness databases, and unanchored restores cannot
  obtain contribution material after a durably propagated revocation;
- normal split-write crashes either reconcile the exact signed candidate before
  output or fail closed without allowing an old database to advance the anchor;
- direct and witnessed slot fields are final inputs to J05 and J07 rather than
  placeholder formats requiring later amendment;
- `docs/architecture.md` production-crypto gate opens only after independent
  review and disposition of every material finding;
- the machine gate rejects missing, stale, malformed, or hash-mismatched review
  evidence before a production cryptographic target can land.

Component dependencies:

- J19A: J01B, J03.
- J19B: J19A.
- J19C: J19B.
- J19D: J19C.

Unblocks: J19.

### J19 — Bind the independently reviewed witnessed construction gate

Outcome:

One machine-checked gate binds the exact J19A-J19D threat model, construction,
protocol corpus, conformance vectors, endpoint-retention proof, independent
review, remediations, and provider versions consumed by witnessed
implementation and J26.

Scope:

- emit a bounded gate manifest containing exact artifact revisions and hashes,
  suite/provider identifiers, reviewer and scope metadata, findings,
  remediations, and accepted assumptions;
- verify every referenced artifact and reviewed remediation before passing;
- fail closed when an artifact, provider version, vector, review scope, finding
  disposition, or implementation binding is absent, stale, or mismatched;
- invalidate the gate and require a new J19D review whenever a construction,
  preimage, state machine, vector, proof, provider, or material remediation
  changes;
- expose only scoped construction-review status and never imply whole-product
  certification or protection of real secrets.

Acceptance:

- the gate passes only for one exact corpus and implementation/provider binding;
- all material findings are resolved and their remediations independently
  reviewed;
- missing or stale independent review blocks witnessed cryptographic
  implementation and J26;
- output states the narrow review scope and retains the pre-alpha/no-real-
  secrets warning.

Dependencies: J19D.

Unblocks: J04, J05, J07, J10, J20, J22, J23.

### J20 — Implement witness policy, replay, expiry, and contribution engine

Outcome:

A transport-independent engine validates requests and approver decisions,
advances policy checkpoints monotonically, durably coordinates replay and state
anchors, evaluates policy, and emits one signed bounded witness decision.

Scope:

- consume J06 normalized witnessed policy for approver/witness membership, both
  quorums, allowed operations, request lifetime, workload limits, and direct-
  slot claim suppression;
- implement canonical request, action-manifest digest, approver-decision,
  checkpoint, anchor, response, and receipt-material verification;
- implement the common request/action-manifest semantic-equality validator and
  apply it before policy matching or approval counting;
- after J19 acceptance, implement any protocol-specific cryptographic adapters
  selected by the reviewed construction; raw providers remain private to those
  modules;
- inject clock, randomness, policy checkpoint, external anchor, key provider,
  and persistence;
- implement strict-descendant checkpoint advancement and exact stale,
  witness-behind, fork, and rollback outcomes;
- implement request reservation and idempotent decision transaction;
- implement the serialized signed-candidate/external-CAS/readback protocol and
  release no contribution or checkpoint acknowledgement before it completes;
- reserve and validate every counted approval identity/digest without extending
  its lifetime or accepting transport authentication as consent;
- enforce skew, not-before, expiry, freshness, membership, operation, and
  workload constraints;
- assemble only the approved role/revision/`RevisionSealId` contribution after
  reservation; never assemble or return an epoch root or reusable contribution;
- zeroize partial material;
- emit value-free decision and receipt data.

Tests:

- complete matrix in section 22.12;
- state-machine/property model for crashes and retries;
- fault injection at every database/anchor/output boundary, including exact
  candidate republish, already-published recovery, DB-behind, anchor-behind,
  divergent, and multiple-pending cases;
- fake clock rollback/forward jump;
- forged, stale, replayed, conflicting, wrong-manifest, and revoked approver
  decisions;
- individually valid request/manifest pairs with every duplicated field changed
  in turn;
- checkpoint gaps/forks, stale endpoint, witness-behind state, missing or
  conflicting external anchor, and recovered new-witness identity;
- replay compaction horizon;
- concurrent identical and conflicting request IDs;
- no contribution on deny/error;
- retained response/contribution/revision-secret attempts against every later
  seal in the same epoch.

Acceptance:

- at most one approval contribution is committed per request identity;
- retry cannot extend expiry;
- no contribution exists without the exact required current approver signatures
  and policy checkpoint or with any request/manifest semantic mismatch;
- output is usable only for the exact revision seal in the request and cannot be
  transformed into an epoch root or later-revision secret;
- checkpoint or replay rollback and unanchored recovery stop contribution
  service, while the sole signed one-candidate crash state reconciles without
  weakening the external predecessor check;
- core engine contains no HTTP or database-specific types.

Dependencies: J04, J06, J19.

Unblocks: J21, J23, J25.

### J21 — Deliver self-hostable `juryd` adapters

Outcome:

`juryd` exposes the public witness protocol with durable persistence, hardened
transport bounds, safe lifecycle, and reproducible self-host deployment.

Scope:

- choose and document transport and persistence adapters;
- implement TLS/auth integration boundaries without trusting transport alone;
- implement monotonic checkpoint persistence and the J19-selected public
  external rollback-anchor profile;
- implement authenticated compare-and-swap, exact readback, and the bounded
  startup reconciliation state machine without acknowledging unanchored state;
- enforce request/concurrency/rate bounds;
- implement atomic schema migration, backup, restore, replay durability, and
  fail-closed anchor comparison before contribution service starts;
- implement graceful shutdown and health endpoints with safe semantics;
- support file/software keys first and HSM/provider adapters through traits;
- publish container and service-manager examples.

Tests:

- conformance suite against real server processes;
- database/anchor crash/restart at each split-write boundary and backup/restore
  rollback;
- missing, older, newer, corrupted, and conflicting external rollback anchors;
- oversized/slow/malformed requests;
- rate-limit enumeration resistance;
- in-flight shutdown;
- same cryptographic behavior in self-host and managed configuration.

Acceptance:

- a fresh operator can build and run the public server;
- no proprietary service is required for correctness;
- startup and restore cannot serve contributions until checkpoint and replay
  high-water marks match a valid external rollback anchor or the sole exact
  signed next-candidate case is safely published and read back;
- health output contains no policy, item, or principal enumeration.

Dependencies: J20.

Unblocks: J22, J23, J25.

### J22 — Deliver witnessed open, approval, and execution UX

Outcome:

Users and machines can create, inspect, approve/deny, execute, cancel, and
observe witnessed requests through stable CLI contracts. The complete path from
format-v1 witnessed capsule to guarded read/inject/exec is operational.

Scope:

- implement request construction and client signatures;
- construct the canonical action manifest and bind its digest into every
  approval-capable request;
- verify its policy-authenticated `ApprovalTargetV1`; human approval requires an
  entitled private name or owner-signed non-secret review labels for every item,
  field, working directory, and output destination, while opaque selectors
  remain limited to explicitly typed automatic policy;
- run the common request/action-manifest consistency validator before rendering
  or signing any approval;
- implement a separately protected approver identity and strict signed
  `ApprovalDecisionV1`; never reuse a vault-principal or witness key implicitly;
- generate protected request-specific session keys;
- contact configured witnesses and validate responses;
- implement `WitnessedItemAccessProvider`, evaluate quorum, and call the common
  `ItemAccessProvider` revision-secret boundary without exposing contributions;
- connect J10's pending/approved/denied/expired states to real J20/J21 protocol
  responses and persist no secret-bearing session snapshot;
- expose human and JSON request/approval/status commands with complete verified
  manifest rendering and no digest-only approval path;
- make witnessed read/inject/exec the governed default while retaining an
  explicit direct mode whose unilateral status is visible;
- make expiry, denial, stale, replay, unavailable, and insufficient quorum
  distinct.

Tests:

- foreground automatic and asynchronous approval workflows;
- forged/replayed/revoked approval identities and wrong request, manifest,
  policy, witness set, key epoch, or expiry;
- manifest absence, one-bit changes, typed secret placeholders, lossy rendering,
  truncation at every supported terminal width, opaque targets, forged/stale
  review labels, opaque field/directory/sink commitments, and missing name
  entitlement;
- validly signed request/manifest pairs whose duplicated fields disagree;
- cancellation races;
- malicious response and wrong-session attacks;
- command digest changes;
- no child spawn before full authorization;
- no contribution in output, state snapshots, or logs.
- an end-to-end generic fixture that creates a witnessed-only item, requests its
  exact revision, obtains independent approvals and witness contributions,
  opens it through read/inject/exec, records the decision receipt, and rejects
  the next revision until a fresh quorum authorizes its new seal.

Acceptance:

- direct and witnessed modes share use-case APIs;
- a witnessed-only item can complete read, inject, and exec without any direct
  slot, raw key, epoch-root, or reusable-contribution path;
- request broadening always changes the digest;
- interactive approval signs only after complete verified action-manifest
  rendering with policy-authenticated meaningful target, field, working-
  directory, and output-destination displays; an opaque digest, target, or
  commitment alone can never be approved;
- every counted approval is a current independent approver signature, not a
  transport-authenticated action;
- receipt nonclaims appear in user documentation.

Dependencies: J10, J13, J14, J19, J21, J23.

Unblocks: J24, J25, J26.

### J23 — Deliver offline receipts and witness operations

Outcome:

Witness decisions produce offline-verifiable receipts, and operators can rotate,
back up, restore, and monitor witnesses without breaking protocol truth.

Scope:

- implement independent receipt parser/verifier;
- implement witness/approver descriptor and policy-checkpoint distribution with
  per-witness durable acknowledgement and no global-freshness claim;
- implement signing/contribution key rotation and retirement;
- implement replay/checkpoint database backup/restore and external state-anchor
  publication/recovery rules, including pending-candidate reconciliation and
  external-ahead/divergent fail-closed operations;
- implement safe health and audit export;
- define retention/compaction and transparency options;
- document customer-hosted plus managed-witness topologies.

Tests:

- receipt one-bit and field-substitution mutations;
- receipt verification for counted approver identities, decisions, manifest
  digest, checkpoint, and state-anchor generation;
- old/new witness key periods;
- restored stale replay DB failure and every database/anchor split-write crash;
- offline verification with no network/private key;
- topology tests proving one witness lacks unilateral access;
- value/private-name leakage scans.

Acceptance:

- receipts prove decisions only, not endpoint execution;
- rotation does not make old valid receipts unverifiable;
- policy status distinguishes proposed, partially propagated, and durably
  accepted witness checkpoints;
- recovery cannot silently reset replay or checkpoint safety and unanchored old
  witness identities cannot resume contribution service.

Dependencies: J19, J20, J21.

Unblocks: J24, J25, J26.

### J24 — Deliver the witnessed access-aware CLI-backed TUI

Outcome:

The Jury TUI supports witnessed requests, approvals, receipts, accessible-only
browsing, administration, and recovery without secret-bearing model state.

Scope:

- port reusable line editor, viewport, worker, and rendering behavior with
  history where appropriate;
- consume stable core/CLI backend contracts;
- show exact identity, roles, storage state, and disabled reasons;
- support administration, transfer, backup, rollover, and recovery tools;
- support identity KDF/protection status, provider enrollment/rebind/removal,
  privacy cover, local audit verification, migration recovery states, backup
  verify/drill/restore, principal replacement, and exact redistribution actions;
- render complete verified action manifests, witnessed request state, quorum
  progress, distinct deny/expiry/stale/unavailable failures, and receipt
  nonclaims without ever offering digest-only or opaque-target approval;
- display repo/global/explicit storage selection plus first-use, trusted,
  behind, divergent, and merge-conflict states from the common backend without
  treating Git status or authorship as authority;
- provide value-free Git diff/merge previews and never offer textual conflict
  editing inside the TUI;
- wipe protected state on lock/exit/error;
- support compact and wide terminal layouts.

Tests:

- deterministic buffer and interaction fixtures;
- inaccessible names and secret-value absence;
- device cancellation/no-fallback, protected-memory degradation, cover-history
  cost, audit tamper, and migration interruption states;
- fresh clone, old commit, divergent branch, same-item fork, policy fork, and
  missing semantic merge support at compact and wide sizes;
- cancellation and refresh failure;
- witnessed foreground/asynchronous approval, cancellation, expiry, stale
  checkpoint, manifest rendering, and no-child-before-authorization flows;
- terminal resize, signals, and lock cleanup;
- generic fixtures only.

Acceptance:

- no private key, revision secret, or field value enters Ratatui model;
- every mutation uses one backend authority path;
- Git-backed status and merge surfaces remain value-free for inaccessible items
  and cannot lower retained local ancestry;
- keyboard-only operation is complete.
- witnessed-only read/inject/exec and independent approval are keyboard-complete
  without a direct-slot fallback.

Dependencies: J10, J13, J16, J17, J18, J22, J23.

Unblocks: J25, J26.

### J25 — Complete the witnessed adversarial corpus and measured budgets

Outcome:

Jury has separately authored negative fixtures, fuzz/property targets,
failure-injection coverage, leak scans, and recorded performance/resource
measurements across the entire security boundary.

Scope:

- exercise format, crypto, identity, policy, item, transfer, backup,
  process, CLI, and TUI failure surfaces through executable tests;
- add coverage-guided fuzz targets for all untrusted parsers;
- add state-machine models for policy, mutations, replay, and recovery;
- inject filesystem, entropy, clock, network, database, process, and cancellation
  failures;
- model Git as an untrusted transport: whole-repository substitution, malicious
  `.git`/`.jury`, symlinked and linked worktrees, clone without local state,
  checkout/reset/force-push rollback, forged Git authorship/signatures, conflict
  markers, text merge, semantic merge partial output, and concurrent worktrees;
- prove repository-local workflows never place plaintext, identities,
  checkpoints, audit, receipts, locks, or recovery state in the Git worktree,
  index, objects, diffs, hooks, or filters;
- cover protected-memory/core-dump failure timing, device-provider conformance,
  privacy-cover history/capacity, and complete direct and witnessed end-to-end
  candidates;
- fuzz and model request/manifest consistency, approval counting, replay,
  witness checkpoint/anchor recovery, contribution assembly, receipt parsing,
  and direct-path downgrade reporting;
- run the complete corpus against at least two independent providers where the
  suite has more than one viable implementation, including cross-provider
  negative vectors and semantic-differential tests for malformed keys,
  ciphertexts, signatures, implicit rejection, canonical encoding, and limits;
- inject nonce/key reuse for every AEAD/KEM wrapper and demonstrate either the
  exact accepted misuse-resistance claim or fail-closed duplicate detection;
- exhaust every public KDF/Argon2 work, memory, lanes, length, and allocation
  limit before expensive work or allocation;
- measure all section 22.9 scenarios on documented machines;
- scan logs, errors, JSON, receipts, snapshots, fixtures, and crash artifacts.

Acceptance:

- every public parser has malformed-input coverage;
- every durable transaction has before/during/after crash tests;
- repo discovery, fresh-clone trust, Git rollback detection, and J16 three-way
  merge have independent negative/state-machine coverage;
- provider implementations agree on accepted outputs and normalized rejection
  semantics across the cross-provider corpus;
- nonce/key reuse faults and KDF resource exhaustion meet the exact J01A oracle;
- no guessed performance claim appears in release docs;
- unresolved high-severity security findings block J26.

Dependencies: J11, J14, J16, J17, J18, J20, J21, J22, J23, J24.

Unblocks: J26.

### J26 — Publish the experimental witnessed-access 0.x release

Outcome:

A fresh operator can verify, build, configure witnessed governance, self-host,
run, back up, and recover the experimental witnessed-access release while
understanding that Jury as a whole is pre-alpha and not suitable for real
secrets. J15 compatibility is post-`0.x` and is not advertised as shipped.

Scope:

- finalize license selection and add exact texts;
- publish format, direct/witnessed slot, protocol, receipt, and rollback-anchor
  specifications plus the vector corpus and exact J19 review scope;
- produce signed binaries, checksums, SBOM, provenance, and build instructions;
- document upgrades, rollback, backup, drills, and incident response;
- document and dogfood repo-local `.jury/vault.json` init, clone, external
  genesis trust, public verify, identity-scoped use, CI pinning, value-free diff,
  authenticated merge, detached `--home`, global mode, rollover adoption, and
  recovery;
- publish `.jury/.gitattributes` guidance, explicitly forbid clean/smudge and
  textual vault merging, and state that Git commits, PR approval, and signed Git
  history do not grant Jury authority;
- disclose permanent historical decryptability for retained direct-recipient
  keys plus public principal/grant, count, bucket, revision, and Git-timing
  metadata;
- document that direct slots are unilateral for their recipient, suppress the
  quorum claim for affected items, and are never an implicit fallback;
- dogfood a witnessed-only lifecycle across request creation, complete manifest
  rendering, independent approval, self-hosted witness contributions,
  read/inject/exec, receipt verification, revision change, denial/replay/stale
  failure, witness rotation, and recovery;
- document the exact J01A HNDL and PQ-authenticity decisions, that HNDL does not
  survive later private-key theft or protect already decrypted revisions, that
  re-encryption cannot revoke retained old-lineage copies, that FIPS-validated
  deployment is not claimed, and that suite migration creates a separately
  trusted lineage with no negotiation or fallback;
- publish the exact independent review performed for J19 without extending it
  to a whole-product assurance claim;
- self-review the exact candidate in a fresh pass and report it honestly as
  self-review; unresolved high-severity findings still block release;
- dogfood one generic owner/developer/machine lifecycle across identity
  protection, private-name grants, retained pre-grant ciphertext, direct
  execution, transfer, revocation, principal replacement, cover,
  backup verify/drill/restore, witnessed recovery, and rollover;
- verify source and binary version identity;
- add security reporting, embargo, and key-compromise procedures;
- retain the pre-alpha/no-real-secrets warning throughout `0.x`.

Acceptance:

- all active dependency leaves are complete with task-local test evidence;
- direct and witnessed release candidates pass the public conformance suite;
- the J19 machine gate binds an independent review of the exact witnessed
  construction and rejects any changed or undispositioned revision;
- no Jury Cargo package depends on Jig;
- documentation states endpoint-retention, offline-freshness, revocation, and
  the exact narrow scope of J19 independent review prominently;
- a fresh generic repository lifecycle proves committed ciphertext travels with
  code while every private and installation-local artifact remains outside Git;
- product, CLI, and release language claim witnessed authority only for items
  and deployments that satisfy the exact reviewed construction, policy,
  topology, checkpoint, and no-direct-slot assumptions;
- no product, CLI, or release language claims HNDL, PQ authenticity, FIPS
  validation, forward secrecy, or retroactive migration protection beyond the
  exact accepted suite evidence;
- the complete generic dogfood lifecycle and real witnessed recovery rehearsal
  are recorded against the exact self-reviewed release candidate;
- J15 compatibility is neither required nor advertised as included.

Dependencies: J18, J22, J23, J24, J25.

Unblocks: the experimental Jury `0.x` witnessed-access release.

## 25. Historical planning review record

This record explains prior decisions. It requires no new review rounds and is
not release evidence.

The retired planning workflow required at least four review rounds before Beads
conversion.

The rounds below were performed against this Jury document, not counted from the
nine Jig-focused reviews preserved in the source snapshot.

### Round 1 — Architecture and custody boundary

Findings:

- the mechanically adapted source still treated direct HPKE as the architecture;
- native types still inherited the Jig URI concept;
- the source implied a whole unlocked identity in every session;
- the witness service boundary was absent.

Revisions:

- added algorithm-tagged recipient slots;
- added `ItemKeyUnwrapper` semantics;
- made `jig://` downstream-only;
- separated `jury-core`, `jury-protocol`, adapters, and `juryd` responsibilities;
- stated endpoint-retention nonclaims.

Validation:

- obscure-task check used J08 and found enough interface/lifetime/test detail;
- dependency graph had no cycle;
- sampled decisions all include rationale;
- structural revision was large, requiring another round.

### Round 2 — Witness protocol and adversarial review

Findings:

- HPKE alone did not specify replay, message ordering, expiry, or downgrade
  protection;
- a static released witness share could be retained by the endpoint;
- receipts risked overstating endpoint execution;
- server crash and clock behavior were under-specified.

Revisions:

- bound request, response, session key, operation, workload, epoch, and policy;
- required durable replay reservation before contribution;
- made the contribution construction a reviewed protocol decision;
- added expiry/skew/clock rollback and transaction crash matrices;
- limited receipt claims to signed decisions.

Validation:

- obscure-task check used J20 and found implementable transaction semantics;
- graph remained acyclic;
- five sampled witness decisions had explicit rationale;
- changes were substantial but localized, requiring migration review.

### Round 3 — Migration, recovery, and provenance review

Findings:

- the source plan overwrote `vault.json` in place;
- passphrase compatibility blurred Jig source and Jury identity variables;
- anonymous copying would lose hardened component history;
- `jig-owned-process` could create a forbidden runtime dependency;
- legacy audit mutation conflicted with source immutability.

Revisions:

- made migration copy-on-write into an absent Jury home;
- gave the destination a fresh Jury vault identity;
- separated migration and identity credentials;
- preserved exact source audit bytes and moved intent into destination evidence;
- specified filtered-history extraction in a disposable clone;
- created the explicit process extraction/replacement outcome.

Validation:

- obscure-task check used J15 and found source/destination/recovery rules complete;
- graph remained acyclic;
- sampled migration choices had rationales;
- structural changes were now limited to one track.

### Round 4 — Delivery graph and steady-state review

Findings:

- the six original Jury issues were too broad;
- the earlier 20-task Jig graph omitted witness and server work;
- validation commands still named Jig product crates;
- release could appear complete without receipt and replay operations.

Revisions:

- decomposed delivery into 26 concrete outcomes with explicit edges;
- retained six issues as tracks rather than implementation tasks;
- added separate protocol, replay engine, server, CLI, receipt, and release joins;
- changed validation to Jury workspace and harness commands;
- made J26 depend on all security-critical leaves.

Validation:

- obscure-task check used J23 and found implementable inputs and acceptance;
- dependency graph had zero cycles and three intended roots;
- sampled architecture choices retained `why` paragraphs;
- final changes were wording and dependency polish rather than structural
  redesign, meeting the workflow's steady-state threshold.

### Round 5 — Live-Bead self-containment review

Findings:

- the 26 live task descriptions summarized outcomes but did not carry the full
  scope, tests, rationale, or governing security decisions;
- ten reuse-sensitive tasks named legacy baselines but had displaced their
  Jury-native implementation contract;
- no live task pointed an implementation agent to a complete dependency and
  evidence contract;
- protected memory, device protectors, cover reseals, and audit verification
  were present in the master design but not explicit enough in delivery tasks.

Revisions:

- gave every live task project boundary, rationale, required design contract,
  outcome, scope, tests where applicable, acceptance criteria, actual dependency
  IDs, legacy provenance, retirement provenance, and completion evidence;
- merged selective Jig-v2 baselines with rather than in place of the Jury task;
- assigned protected pages/core suppression to J02/J04/J14/J25;
- assigned the four device-protector families to J04/J13/J24/J25;
- assigned privacy cover to J07/J11/J13/J24/J25 and audit verification to
  J09/J13/J24;
- recorded 1Password import as an explicit post-v1 deferral.

Validation:

- all 26 live task descriptions contain the required self-containment headings;
- no task description depends on an unresolved numbered section in this plan;
- description lengths are bounded from roughly 3.4 to 5.3 KiB rather than being
  one-line summaries or copies of the complete master plan;
- obscure-task review used J20 and found the complete replay/expiry/crash matrix
  locally implementable.

### Round 6 — Semantic dependency review

Findings:

- J13 could complete mutation/admin CLI work before J11 mutations;
- J22 could complete witnessed exec before J14 execution;
- J24 exposed receipts without depending on J23;
- J25 claimed integrated CLI/TUI adversarial coverage without depending on J22
  or J24.

Revisions:

- added J11 → J13;
- added J14 → J22;
- added J23 → J24;
- added J22 and J24 → J25;
- synchronized both the textual DAG and each task's dependency declaration.

Validation:

- the live graph has 33 active nodes, 85 edges, and zero cycles;
- exact dependency comparison between all 26 task bodies and tracker records
  passes;
- `br ready --json` exposes only J01, J02, and J03 implementation tasks;
- J26 remains the single release join.

### Round 7 — Jig-v3 retirement and provenance review

Findings:

- a title-level B01-B20 mapping was insufficient to close the old tasks safely;
- deleting tracker records would erase useful design and dependency history;
- B13 needed an explicit disposition rather than an invented Jury owner;
- the release split needed both Jury assurance and Jig cutover owners.

Revisions:

- added the concrete B01-B20 map with live Jury and Jig issue IDs;
- placed the same mapping in the Jig cutover plan and D01 tracker contract;
- annotated every legacy child with its exact replacement owners;
- closed all 20 children and the parent as superseded rather than deleting them;
- preserved B13 as a post-v1 non-goal and preserved the exact source snapshot.

Validation:

- D01 is closed with its acceptance criteria satisfied;
- all 21 legacy tracker records are closed and retain original descriptions,
  concrete disposition notes, and unique provenance references;
- no active/deferred Jig-v3 implementation issue remains;
- the Jury provenance snapshot remains byte-identical to the Jig source plan and
  retains SHA-256
  `ed670ec63eaa9814ea0a01a0d4b2af6a65ccb68e68e307bac9109dd4286fb49a`.

### Round 8 — Steady-state synchronization review

Findings:

- the preceding rounds required structural contract and graph corrections;
- the final reread found one list-punctuation defect in J09 and five stale
  `Unblocks` summaries left by the new semantic dependency edges;
- no further task split, architecture change, ownership change, or dependency
  correction was needed.

Revisions:

- corrected the J09 test-list punctuation and synchronized J11, J14, J22, J23,
  and J24 `Unblocks` summaries;
- resynchronized all task bodies and acceptance fields from the final plan;
- left the three-root DAG and retirement map unchanged.

Validation:

- task-body, acceptance-field, and dependency synchronization checks pass for all
  26 Beads;
- Jury Beads lint reports zero issues and dependency-cycle checks report zero
  cycles;
- sampled rationales for identity, item encryption, migration, witnessed
  protocol, and release explain both the decision and rejected weaker boundary;
- this round produced marginal prose cleanup only, so the delivery graph is at
  steady state.

### Round 9 — Encryption, approval, and rollback-boundary review

Findings:

- J19 originally followed production format/item work, and ready J01 still
  allowed production provider adapters before the repository cryptography gate;
- approval lacked independent signed approver identities, exact meaningful
  human-review targets, and a request/manifest semantic-consistency invariant;
- witness freshness lacked monotonic policy checkpoints, an external rollback
  trust root, and a crash-consistent database/anchor publication protocol;
- backup and product language could overstate witnessed recovery or apply
  item-level quorum claims to direct or mixed-mode paths;
- XChaCha20-Poly1305 was described as standards-defined without disclosing its
  expired Internet-Draft status, and passphrase byte semantics were incomplete;
- live task test bodies had drifted from the authoritative plan despite matching
  acceptance fields and graph edges.

Revisions:

- made J19 depend only on pre-implementation J01 provider evidence and J03
  domain semantics, then made J04/J05 plus all production cryptography
  transitively depend on accepted J19 review;
- restricted J01 to provider research/contract evidence and assigned production
  adapters to post-gate J04/J07/J20 work;
- added signed approver decisions, `ActionManifestV1`,
  `ApprovalTargetV1`, strict duplicated-field equality, complete meaningful
  item/field/directory/sink review, and negative substitution vectors;
- added monotonic checkpoints, signed external state anchors, serialized signed
  candidates, external compare-and-swap/readback, bounded crash reconciliation,
  and fail-closed divergent/rolled-back recovery;
- made recovery and security claims path-specific for direct, witnessed-only,
  and mixed-mode slots and pinned exact passphrase and XChaCha contracts;
- required a hash-bound machine-validated J19 gate artifact and resynchronized
  every live task outcome, scope, test body, acceptance field, and edge summary.

Validation:

- independent read-only security-boundary and bypass reviews were reconciled;
- exact task-body, acceptance-field, dependency, and `Unblocks` comparison passes
  for all 26 Beads and all 85 blocking edges;
- `br dep cycles --json` reports zero cycles, while `br ready --json` exposes
  only J01, J02, and J03; J01 now explicitly forbids product cryptography;
- no cryptographic provider dependency exists and the absent J19 gate artifact
  correctly leaves this pre-alpha repository's implementation gate closed;
- formatting, warnings-denied workspace clippy, and all workspace tests pass.

### Round 10 — Cryptographic-property and retained-endpoint review

Findings:

- J01 conflated security requirements, suite selection, and current Rust
  provider due diligence, allowing provider availability to choose the protocol;
- “broadly sound” primitive names did not decide nonce misuse, key binding,
  HNDL confidentiality, PQ authenticity, standards maturity, or exact failure
  behavior;
- a witnessed endpoint that learned reusable epoch material could retain it and
  bypass fresh authorization for later revisions;
- FIPS 203 algorithm standardization had been confused with the separate and
  infeasible Jury deployment-validation question;
- suite fallback and in-place migration could silently destroy a PQ claim; and
- the adversarial corpus did not require provider-differential, reuse,
  resource-exhaustion, or retained-endpoint tests.

Revisions:

- split J01 into J01A property/suite selection and dependent J01B provider
  proof, with HNDL and PQ authenticity as separate explicit decisions;
- made FIPS-validated deployment a V1 non-goal while retaining FIPS 203 as the
  primary ML-KEM specification;
- required one authenticated suite per lineage, no negotiation or fallback, and
  authenticated re-encryption into a separately trusted lineage for migration;
- introduced fresh 32-byte `RevisionSealId` values, revision-scoped direct and
  witnessed capsules, and a common `ProtectedRevisionSecrets` boundary;
- required J19 to select an independently reviewed distributed-decryption or
  equivalent construction and prove that retained revision-N endpoint state
  cannot open revision N+1 without a fresh quorum;
- explicitly allowed an endpoint to retain and reopen an already released
  revision, because stronger erasure requires remote use or trusted execution;
- added the provider-differential, nonce/key-reuse, KDF-exhaustion, hybrid-
  fallback, and retained-witness-key matrices to J25; and
- extended rollover/release tasks with honest suite-migration and HNDL nonclaims.

Historical validation at that round (followed by a zero-budget cut that the
current witnessed-first scope has itself superseded):

- the pre-cut graph had 34 nodes and 27 concrete tasks with zero cycles;
- that intermediate cut deferred its J19-J23 witnessed path and independent-
  review gates;
- that intermediate release graph had 22 active tasks on the J26 dependency
  path;
- repetitive completion-evidence headings were removed from active tasks;
- `cargo fmt --all --check`, warnings-denied workspace clippy, and all workspace
  tests pass;
- the repository still contains no production cryptographic implementation or
  provider dependency; and
- the Jig wrapper checks could not run because no compatible Jig runtime is
  installed, so native Cargo and tracker validation are the recorded checks.

### Round 11 — Git-backed architecture and custody review

Findings:

- the portable artifact was already the shared source of truth, but native home
  discovery did not say whether it belonged beside the code;
- J09 incorrectly coupled installation-local checkpoint/audit/receipt state to
  the portable vault home;
- treating repo-local storage as an optional export mode would contradict the
  intended same-`vault.json` developer and CI workflow;
- Git routing still had to remain outside the cryptographic domain.

Revisions:

- made committed `.jury/vault.json` the native default inside a Git worktree;
- retained global and explicit detached homes for metadata-sensitive use;
- moved all authenticated local state to a platform state root keyed by vault
  ID, genesis fingerprint, and principal ID;
- kept identities under their independent platform data root;
- made Git an untrusted transport rather than an authority or format field.

Validation:

- the obscure-task check used J09 and found exact platform paths, overrides,
  containment rules, tuple keys, locking, rollback behavior, and deletion
  limitations locally implementable;
- the architecture preserves the existing artifact/identity/local-state custody
  split and introduces no runtime dependency on Jig or Git filters;
- sampled rationale for repo-local default, detached mode, XDG state, and
  routing exclusion is explicit in section 0.8A.

### Round 12 — Git substitution, freshness, and history review

Findings:

- a genesis fingerprint committed beside a substituted vault is not an
  independent trust anchor;
- fresh clones, old-commit checkout, force-push, linked worktrees, and concurrent
  branches needed explicit rollback semantics;
- Git signatures and pull-request approval could be mistaken for Jury writer or
  owner authority;
- historical repository objects make old direct-recipient ciphertext
  permanently recoverable to retained old keys.

Revisions:

- required interactive genesis confirmation or an externally supplied
  non-interactive pin before first private use;
- shared checkpoint/locking state across clones and worktrees for the same
  vault/genesis/principal tuple;
- made behind, divergent, wrong-genesis, policy-fork, and same-item-fork states
  fail closed without lowering retained state;
- explicitly separated Git identity/review state from Jury authorization and
  added history/metadata nonclaims to release work.

Validation:

- the obscure-task check used J13 and found deterministic precedence, init,
  first-use, CI, detached-home, and failure behavior without an unresolved human
  choice;
- J25 now owns whole-repository substitution, stale pin, rollback, worktree,
  conflict-marker, and leakage adversarial cases;
- no new dependency edge was needed because J09 already blocks J10/J16 and J25
  already joins the relevant implementation leaves.

### Round 13 — Git diff, merge, mutation, and recovery review

Findings:

- ordinary textual merge cannot preserve signed policy/item ancestry;
- a Git merge base is untrusted input and a merge commit proves no Jury
  authority;
- mutation must detect checkout/reset/concurrent-worktree replacement between
  preview and publication;
- migration, restore, and rollover span the committed artifact and separate
  identity/state roots without cross-root atomicity.

Revisions:

- made `vault.json` deterministic and conflict-marker rejecting while retaining
  typed binary signing preimages;
- assigned public verification, value-free semantic diff, and independently
  validated base/ours/theirs merge to J16;
- assigned digest/ancestry recheck and committed-primary recovery reporting to
  J11;
- extended J15/J17/J18 with repository-local publication, explicit adoption,
  no implicit Git operations, and old-history warnings;
- assigned storage/merge state presentation to J24.

Validation:

- the obscure-task check used J18 and found source preservation, absent new
  lineage, adoption manifest, external trust, backup, Git-side-effect, and
  historical-decryptability behavior locally implementable;
- the dependency DAG remains unchanged: J11/J16/J17 already block J18, and J24
  already depends on J13/J16/J17/J18;
- no clean/smudge path, plaintext worktree, text-merge fallback, or implicit
  stage/commit/push behavior remains.

### Round 14 — Git-backed steady-state and Beads conversion review

Findings:

- the preceding rounds fit existing concrete delivery owners and did not
  justify a Git-planning, review, or conversion bead;
- the final reread found one direct conflict: J09's old
  `<vault-home>/local/...` required-design line had to be replaced rather than
  merely amended;
- no further task split, dependency, priority, ownership, or architecture change
  was needed.

Revisions:

- replaced the conflicting J09 path contract;
- synchronized Git-backed amendments and acceptance criteria into the epic,
  portable track, and J02/J03/J05/J09/J11/J13/J15/J16/J17/J18/J24/J25/J26;
- added a `git-backed` label to those 15 tracker records;
- left the 34-node, 86-edge graph unchanged.

Validation:

- all 15 selected records contain exactly one Git-backed amendment and the old
  J09 required path is absent;
- `br dep cycles --json` reports zero cycles;
- `br ready --json` exposes J02 and J03 while claimed J01A remains in progress;
- `bv --robot-plan` retains one connected graph with 10 actionable and 24
  dependency-blocked records;
- `br sync --flush-only` reports no dirty issues after automatic export;
- `git diff --check` passes;
- `scripts/jig check contract` remains unavailable because no contract-
  compatible Jig binary is installed; it made no repository mutation.

## 26. Completion criteria for this plan

The witnessed-first plan is ready for implementation when:

- all 30 active outcomes exist in Beads with the same dependency direction:
  J01A, J01B, J02-J14, J16-J26, and J19A-J19D; J19-J23 are mandatory release
  work and J15 is explicitly post-`0.x`;
- `br ready --json` exposes only genuinely unblocked outcomes;
- `bv --robot-plan` shows no cycles or orphan implementation leaves;
- the exact source snapshot and digest remain preserved;
- `docs/jig-cutover-plan.md` owns downstream integration;
- repository checks pass;
- no tracker issue exists solely to plan, review, or convert this document.

Implementation completion requires J26 to satisfy both the J01A/J01B shared and
direct gate and J19's independently reviewed witnessed-construction gate. The
pre-alpha/no-real-secrets warning remains after completion: J19 review is scoped
to its exact construction and does not certify the whole `0.x` product.
