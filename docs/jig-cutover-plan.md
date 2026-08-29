# Jig-to-Jury cutover plan

Status: downstream integration plan; no implementation has started.

Plan date: 2026-08-28.

Owning product after cutover: Jury.

Downstream consumer: Jig.

Related Jury plan: `docs/jury-v1-master-plan.md`.

Legacy implementation: Jig vault format v2 and its CLI/TUI.

Unshipped design source: the former Jig vault format-v3 security-scopes plan.

## 1. Executive decision

Jig vault v2 remains the legacy source until a user explicitly migrates.

The unshipped Jig v3 design becomes Jury vault format v1.

Jig does not implement and ship a separate v3 artifact first.

Jig becomes a downstream adapter to the standalone `jury` product.

The adapter delegates complete secret-consuming operations so that Jig does not
receive plaintext values, item keys, identity private keys, or witness
contributions.

The migration is copy-on-write into an absent Jury home.

The Jig source remains untouched and available for rollback until the operator
deliberately retires it.

There are no dual writes.

Jury never acquires a runtime dependency on Jig.

## 2. Why delegation owns the security boundary

A library adapter inside Jig would pull Jury's identity, cryptographic, and
plaintext lifetime into the Jig process.

That would recreate the architecture Jury was split out to avoid.

A local RPC that returns values would have the same custody problem with more
framing.

The initial integration therefore delegates the entire operation to `jury`.

For a simple vault command, Jig replaces itself with the Jury process where the
platform permits.

For inject and exec workflows, Jury resolves the values and owns the output or
child-process sink.

Jig supplies only a bounded value-free operation manifest and public adapter
context.

This preserves one secret-handling implementation and makes CLI compatibility a
downstream concern rather than a cryptographic type.

## 3. Non-negotiable invariants

- Jury has no Cargo, protocol, environment, or home-resolution dependency on
  Jig.
- Jig never receives an identity private key.
- Jig never receives an item root or derived key.
- Jig never receives a witness contribution.
- Jig never logs or parses plaintext returned from Jury.
- `jig://` is translated only at the adapter boundary.
- Jury artifacts never store `jig://`.
- A Jig v1/v2 source is never overwritten during migration.
- Jury and Jig v2 are never written in the same logical operation.
- Failure before Jury process replacement/spawn starts no secret-consuming
  operation.
- Failure after Jury commits is reported as committed Jury state even when Jig
  cannot refresh its presentation.
- An old Jig binary remains able to use the unchanged Jig v2 source during an
  intentional rollback window.
- Cutover documentation never claims that a Jury migration revoked old copies.

## 4. Version vocabulary

| Term | Meaning |
| --- | --- |
| Jig v1 | historical Jig vault input format |
| Jig v2 | current legacy Jig vault input/write format |
| Jig v3 | unshipped design; never a released migration hop |
| Jury v1 | `jury-vault` portable artifact format version 1 |
| Jury protocol v1 | witnessed request/response/receipt family |
| Jig adapter v1 | downstream command and selector translation contract |

Help, errors, migration manifests, and support documentation use these qualified
terms.

No output says merely “v1” or “v2” when both products could be meant.

## 5. Product ownership after cutover

Jury owns:

- identity creation and unlock;
- artifact parsing and validation;
- item discovery and access;
- policy, grants, rekeying, and revocation;
- private output and template injection;
- child-process secret delivery and cleanup;
- direct and witnessed key unwrapping;
- approvals and receipts;
- transfer, backup, restore, recovery, and rollover;
- Jury TUI;
- Jig-vault import.

Jig owns:

- discovering project intent to use a vault;
- translating `jig://ITEM/FIELD` into Jury selectors;
- mapping legacy command spelling to supported Jury operations;
- resolving an approved Jury executable;
- checking adapter/protocol compatibility before delegation;
- presenting value-free setup and migration guidance;
- its own non-secret project/runtime behavior;
- the staged removal of its v2 implementation.

Jig does not own a second Jury client implementation.

## 6. Executable discovery and trust

Executing whichever `jury` happens to appear first on `PATH` is too weak for
unattended security-sensitive use.

The adapter supports these resolution modes in order:

1. explicit command option for the current invocation;
2. explicit Jig configuration containing an absolute Jury executable path;
3. a platform installation record written by a verified installer;
4. interactive development fallback to `PATH` with a visible warning;
5. a missing-dependency error with install and verification instructions.

The production modes require an absolute regular executable path under hardened
file checks.

The adapter runs a value-free Jury capability handshake before the first
protected command.

The handshake reports:

- Jury product version;
- adapter-contract versions;
- supported artifact and protocol versions;
- build identity or release digest when available;
- supported operation families;
- platform capability flags.

Jig rejects an incompatible or ambiguous executable before passphrase capture.

The handshake contains no home path, item name, identity name, or secret.

## 7. Adapter contract

The preferred adapter is a process-exec contract, not a Rust ABI.

Jig creates a bounded canonical manifest only when argument translation is more
complex than direct argv mapping.

The manifest may contain:

- adapter schema version;
- requested Jury operation;
- absolute Jury home selected by explicit Jig context;
- typed item and field selectors translated from caller input;
- non-secret output mode;
- child executable and arguments for Jury-owned exec;
- public command/workload digest inputs;
- TTY and JSON mode flags;
- correlation ID generated from randomness.

The manifest must not contain:

- secret values;
- passphrases;
- identity private material;
- witness contributions;
- authentication tokens;
- inherited full environment;
- raw Jig configuration;
- relative home paths;
- repository names in receipts;
- unbounded strings.

Jury validates the manifest independently.

Jig validation is usability, not a trust boundary.

## 8. Reference translation

Jig parses its existing `jig://ITEM/FIELD` syntax through Jig-owned domain types.

The adapter emits separate bounded item and field selector fields.

It never emits the URI string as Jury storage or protocol input.

Example:

```text
jig://ExampleItem/EXAMPLE_FIELD
  -> JigReference { item, field }
  -> JuryAdapterManifest { item: "ExampleItem", field: "EXAMPLE_FIELD" }
```

Jury applies its own canonical validation.

If Jury rejects a name that Jig historically accepted, the adapter fails with a
migration/translation error and does not guess, truncate, normalize, or route to
another item.

Unrepresentable legacy secrets remain accessible only through Jury's explicit
owner-only legacy compartment after migration.

## 9. Command mapping

The exact names freeze only after Jury J13 and J14 stabilize.

The compatibility intent is:

| Jig surface | Jury-owned operation |
| --- | --- |
| `jig vault status` | public Jury status or migration-needed status |
| `jig vault field list` | Jury accessible field list |
| `jig vault read` | Jury controlled read sink |
| `jig vault inject` | Jury template injection sink |
| `jig vault exec` | Jury resolves values and spawns child |
| Jig brokered run | Jury resolves named values and spawns child |
| `jig vault backup` | Jury owner backup family |
| `jig vault tui` | replace process with Jury TUI |
| Jig v2 migration | `jury migrate jig-vault` |

Commands with no safe Jury equivalent return a stable unsupported error and a
native Jury next step.

The adapter does not emulate them by decrypting values in Jig.

## 10. Home selection

Jig project/global/explicit home concepts do not become Jury domain types.

Jury independently owns its native repository/global/explicit selection. A
native Git worktree may therefore contain the committed portable artifact at
`.jury/vault.json`; that repository location remains storage context and never
enters Jury's cryptographic domain.

During transition, Jig maps its selected context to one explicit absolute Jury
home and passes that path through the adapter contract. When that context uses
the native repository-local artifact, Jig passes the absolute `.jury` home
rather than reimplementing or weakening Jury's discovery and trust rules.

The mapping is stored in Jig configuration as public integration metadata.

It is not embedded in the Jury artifact.

The mapping record contains:

- adapter schema;
- absolute Jury home or platform-safe installation identifier;
- expected Jury vault ID and genesis fingerprint;
- migration ID when applicable;
- cutover state;
- last verified Jury build/capability identity;
- no passphrase, key, item list, or receipt.

Jig refuses a mapped home whose current vault ID/genesis differs from the pinned
record until the operator explicitly accepts a legitimate rollover or restore.

## 11. Migration workflow

The operator performs:

```console
jury migrate jig-vault --from /absolute/jig-v2/home --to /absolute/absent/jury/home
jury migrate verify --home /absolute/absent/jury/home --against /absolute/jig-v2/home
jig vault jury link --home /absolute/absent/jury/home --dry-run
jig vault jury link --home /absolute/absent/jury/home
```

The real command spellings may change, but the state transition does not.

Before link, Jig shows:

- exact source product/format;
- source remains unchanged;
- Jury destination vault ID/genesis fingerprint;
- mapped project/global scope;
- commands that will delegate;
- commands still using Jig v2;
- no-dual-write rule;
- rollback steps;
- warning to rotate external credentials when old copies had broader access.

Link writes only Jig's public adapter mapping.

It does not mutate either vault.

## 12. Cutover states

Jig models the transition explicitly:

`LegacyV2`

Jig v2 remains the source of truth and current legacy commands work.

`JuryPrepared`

A Jury destination exists and verifies, but Jig still uses v2.

`JuryLinked`

Protected operations delegate to Jury; Jig v2 remains untouched for rollback
but receives no writes.

`JuryDefault`

New Jig integrations create/link Jury only; existing unlinked v2 homes still
work in maintenance mode.

`LegacyReadOnly`

Jig can inspect and guide migration from v2 but refuses v2 mutations.

`LegacyRemoved`

The shipped Jig product no longer includes the v2 writer; a separately versioned
import tool or older supported binary is required for legacy handling.

Every state is explicit in status and JSON output.

## 13. Rollout phases

### Phase 0 — Freeze and inventory

- freeze new v2 feature development;
- continue critical correctness and security fixes;
- inventory every caller of `jig-vault` and `jig-vault-tui`;
- inventory every `jig://`, `JIG_VAULT_*`, home, TUI, process, and output
  assumption;
- map every former Jig v3 bead to Jury or this cutover;
- do not close the v3 epic as superseded until mapping is complete.

Exit:

Every legacy responsibility has one owner and no proposed Jury code depends on
Jig.

### Phase 1 — Stabilize public Jury contracts

- complete Jury direct-mode vertical slice;
- freeze adapter capability handshake;
- freeze native selector and operation manifest schemas;
- prove private output and exec end to end;
- publish compatibility/version policy.

Exit:

Jig can delegate a generic fixture operation without plaintext entering Jig.

### Phase 2 — Add dormant Jig adapter

- implement executable discovery and trust checks;
- implement value-free capability/status commands;
- implement selector translation;
- add dry-run command mapping;
- ship disabled by default;
- retain all v2 behavior.

Exit:

Adapter contract tests pass while no production operation routes to Jury.

### Phase 3 — Migration preview and opt-in linking

- expose Jury migration preview from Jig help/status;
- link only already verified Jury destinations;
- require explicit opt-in per Jig scope;
- delegate read, inject, exec, backup, and TUI as each mapping passes tests;
- keep v2 source immutable after link;
- make unlink/rollback explicit.

Exit:

Dogfood projects use `JuryLinked` with recorded recovery rehearsal.

### Phase 4 — Jury default for new integrations

- new Jig vault initialization invokes or guides Jury;
- do not create v2 for new scopes;
- existing unlinked v2 scopes remain legacy;
- add clear migration health and support telemetry only when value-free and
  opt-in;
- publish operator playbooks.

Exit:

Fresh Jig users never need to learn the v2 envelope.

### Phase 5 — Make v2 write path read-only

- announce deprecation and minimum support window;
- refuse new v2 writes in the current Jig release;
- retain inspect, backup verification, and migration guidance;
- preserve a tested older-binary rollback playbook;
- do not auto-migrate on first command.

Exit:

Supported users have completed migration/recovery rehearsals and remaining v2
usage is understood.

### Phase 6 — Remove v2 runtime ownership

- remove Jig's v2 writer and TUI integration;
- retain only the minimum explicit compatibility launcher or external importer;
- remove unused `JIG_VAULT_*` variables after their deprecation window;
- remove the `jig-vault` runtime crate only after reverse dependencies are zero;
- preserve source history and migration fixtures in reachable Git history;
- close the old v3 epic as superseded with exact Jury/cutover issue links.

Exit:

Jig has no secret custody beyond invoking Jury, and Jury still has no Jig
dependency.

## 14. Rollback

Before `JuryLinked`, rollback means discarding an incomplete absent destination
or leaving it unlinked.

After `JuryLinked`, rollback means:

1. stop Jury-backed writes;
2. unlink the public Jig mapping;
3. select the unchanged Jig v2 source with a supported legacy binary;
4. acknowledge that Jury-only changes made after migration are absent from v2;
5. choose one source of truth before any further mutation.

There is no reverse synchronization.

There is no automatic Jury-to-Jig-v2 down-migration.

If external credentials were rotated after Jury cutover, old v2 values may no
longer work; that is expected and must not trigger unsafe dual writes.

## 15. Failure semantics

- incompatible Jury executable: fail before private capture;
- missing Jury executable: return install/verification guidance;
- invalid adapter manifest: fail before private capture;
- Jury authentication/access denial: preserve Jury's stable safe error kind;
- Jury committed mutation followed by Jig presentation failure: report
  committed and require status refresh;
- Jury child exec failure: preserve exact child/spawn status from Jury;
- adapter cancellation before process replacement: no Jury operation;
- adapter cancellation after delegation: Jury owns cancellation and receipt
  semantics;
- mapped vault fingerprint mismatch: stop and require explicit relink/rollover
  verification;
- Jig v2 source changes after migration: status warns of divergent independent
  states and refuses merge.

## 16. Test matrix

Contract tests cover:

- exact capability handshake versions;
- supported and unsupported operation mapping;
- trusted absolute binary selection;
- PATH ambiguity and executable replacement;
- manifest bounds and canonicalization;
- every `jig://` parse edge;
- no URI in Jury artifact/protocol fixtures;
- no secret returned to Jig memory, JSON, logs, or snapshots;
- direct process replacement and fallback spawn/wait;
- exact child status;
- signal forwarding and terminal restoration;
- migration dry-run and link with generic fixtures;
- source hashes unchanged;
- link fingerprint mismatch;
- each cutover state and JSON representation;
- rollback with Jury-only mutations;
- no-dual-write enforcement;
- missing/old/new Jury binary;
- direct and witnessed Jury operations;
- backup and recovery guidance;
- Jig v2 old-copy credential-rotation warning;
- platform path and executable security.

Dependency tests assert:

- Jury Cargo metadata contains no Jig package;
- Jig adapter does not link `jury-core` by default;
- `jig-vault` reverse dependencies decrease according to the phase;
- `jig-owned-process` never enters Jury.

## 17. Delivery outcomes

The cutover implementation graph is:

```text
D01 inventory + responsibility map
  -> D02 Jury/Jig adapter contract
D02 -> D03 executable discovery + capability handshake
D02 -> D04 selector + operation translation
D03 + D04 -> D05 dormant delegation adapter
Jury migration ready + D05 -> D06 opt-in migration/link/rollback
D06 -> D07 new-integration default
D07 + support-window evidence -> D08 v2 read-only transition
D08 + zero reverse dependencies -> D09 legacy runtime removal
```

### D01 — Map every legacy responsibility

Deliver a source-backed inventory of Jig vault/TUI callers, commands, homes,
environment variables, process sinks, fixtures, v3 design outcomes, and their
Jury or cutover owners.

Acceptance: no responsibility is unmapped; the old v3 epic remains open until
the map has concrete issue links.

Dependencies: none.

### D02 — Freeze the adapter contract

Deliver versioned capability, selector, operation-manifest, error, status, and
process-exec contracts with cross-repository fixtures.

Acceptance: an independent fake Jury executable passes and fails the same
contract suite deterministically; no secret field exists in the manifest.

Dependencies: D01 and stable Jury J13/J14 surfaces.

### D03 — Implement trusted Jury executable discovery

Deliver absolute-path configuration, install-record discovery, interactive PATH
fallback warning, capability handshake, version checks, and replacement-race
defense.

Acceptance: incompatible/ambiguous executables fail before credential capture.

Dependencies: D02.

### D04 — Implement Jig reference and operation translation

Deliver exact `jig://` parsing, native Jury selectors, command mappings, bounded
manifests, and unsupported-operation errors.

Acceptance: translation never changes Jury cryptographic identifiers or emits a
URI into native Jury storage/protocol fixtures.

Dependencies: D02.

### D05 — Add dormant no-plaintext delegation

Deliver the disabled-by-default adapter for status, read, inject, exec, backup,
and TUI replacement with value-free contract tests.

Acceptance: instrumentation proves Jig never receives protected values or key
material; existing v2 behavior remains unchanged while disabled.

Dependencies: D03, D04.

### D06 — Deliver opt-in migration, link, and rollback

Deliver migration preview, verified destination linking, explicit cutover state,
no-dual-write enforcement, unlink, and rollback guidance.

Acceptance: source hashes remain unchanged, Jury-only writes never reach v2,
and rollback states data divergence honestly.

Dependencies: D05 and Jury J15.

### D07 — Make Jury the default for new Jig integrations

Deliver Jury-first initialization/linking and keep existing unlinked v2 scopes
in maintenance mode.

Acceptance: fresh generic fixtures create no Jig v2 artifact; documented install
and recovery paths pass.

Dependencies: D06 plus dogfood evidence.

### D08 — Transition Jig v2 to read-only

Deliver deprecation enforcement, inspect/verify/migrate-only legacy commands,
support-window communication, and tested old-binary rollback.

Acceptance: current Jig cannot mutate v2, and no automatic migration occurs.

Dependencies: D07 plus support-window evidence.

### D09 — Remove legacy runtime ownership

Deliver removal of v2 writer/TUI/runtime dependencies, retain explicit importer
guidance, remove expired environment contracts, and close the old v3 epic with
links.

Acceptance: Jig has no in-process secret custody for Jury-backed workflows,
Jury has no Jig dependency, and Git history remains reachable.

Dependencies: D08 and zero supported reverse dependencies.

## 18. Beads ownership

The D-series belongs in the Jig tracker because those outcomes mutate Jig.

The cutover epic is `jig-sh-z3u`.

The concrete mapping is:

| Outcome | Bead |
| --- | --- |
| D01 | `jig-sh-z3u.1` |
| D02 | `jig-sh-z3u.2` |
| D03 | `jig-sh-z3u.3` |
| D04 | `jig-sh-z3u.4` |
| D05 | `jig-sh-z3u.5` |
| D06 | `jig-sh-z3u.6` |
| D07 | `jig-sh-z3u.7` |
| D08 | `jig-sh-z3u.8` |
| D09 | `jig-sh-z3u.9` |

They are not children of the Jury implementation epic.

The completed Jig-v3 retirement map is:

| Legacy Jig task | Jury owners | Jig cutover owners | Disposition |
| --- | --- | --- | --- |
| B01 | `jury-qv4.1.1`, `jury-qv4.2.1` | — | Provider proof and protected primitives |
| B02 | `jury-qv4.2.1`, `jury-qv4.2.3`, `jury-qv4.3.2`, `jury-qv4.5.1`, `jury-qv4.6.1` | — | Identity, device protection, UX, conformance |
| B03 | `jury-qv4.2.4`, `jury-qv4.2.6`, `jury-qv4.4.1` | — | Jury-v1 format plus direct/witnessed slots |
| B04 | `jury-qv4.2.5`, `jury-qv4.2.10`, `jury-qv4.4.1`, `jury-qv4.4.2` | — | Offline and witnessed policy enforcement |
| B05 | `jury-qv4.2.6`, `jury-qv4.2.7`, `jury-qv4.2.10` | — | Envelopes, guarded unwrap, atomic rekey |
| B06 | `jury-qv4.2.8`, `jury-qv4.2.12`, `jury-qv4.2.13`, `jury-qv4.4.5` | — | Audit, checkpoints, export/recovery/witness receipts |
| B07 | `jury-qv4.2.7`, `jury-qv4.2.9` | `jig-sh-z3u.5` | Jury partial unlock; no-plaintext Jig delegation |
| B08 | `jury-qv4.2.10`, `jury-qv4.3.2`, `jury-qv4.5.1`, `jury-qv4.6.1` | — | Mutations, cover, CLI/TUI, adversarial tests |
| B09 | `jury-qv4.2.11` | `jig-sh-z3u.6` | Copy-on-write migration and opt-in link/rollback |
| B10 | `jury-qv4.2.3`, `jury-qv4.2.5`, `jury-qv4.2.10`, `jury-qv4.3.2`, `jury-qv4.5.1` | — | Native identity/access administration |
| B11 | `jury-qv4.2.2`, `jury-qv4.2.9`, `jury-qv4.3.2` | `jig-sh-z3u.4`, `jig-sh-z3u.5` | Native read/inject plus adapter translation/delegation |
| B12 | `jury-qv4.3.1`, `jury-qv4.3.3` | `jig-sh-z3u.5` | Jury-owned execution and child plaintext delivery |
| B13 | — | — | Explicitly deferred beyond Jury v1; no v1 importer |
| B14 | `jury-qv4.2.12` | — | Transfer, inspection, ancestry merge |
| B15 | `jury-qv4.2.13` | — | Backup, restore, readiness, drills |
| B16 | `jury-qv4.5.1` | `jig-sh-z3u.5` | Jury TUI and Jig delegation replacement |
| B17 | `jury-qv4.3.2`, `jury-qv4.4.3`, `jury-qv4.4.5`, `jury-qv4.6.2` | `jig-sh-z3u.2`–`jig-sh-z3u.9` | Native/server contract plus staged Jig cutover |
| B18 | `jury-qv4.6.1` | — | Expanded adversarial corpus and measured budgets |
| B19 | `jury-qv4.6.1`, `jury-qv4.6.2` | `jig-sh-z3u.7`–`jig-sh-z3u.9` | Jury assurance/release plus Jig dogfood/removal |
| B20 | `jury-qv4.2.14` | — | Capacity preflight and signed Jury-v1 rollover |

Every named Jury task contains its outcome, rationale, exact design contract,
scope, required tests, acceptance criteria, live dependencies, legacy baseline
where applicable, and Jig-v3 retirement provenance. B13 is not silently lost:
the Jury master plan records 1Password import as a v1 non-goal.

The Jury tracker owns J01-J26.

Cross-repository blocking relationships are recorded by external references and
mirrored notes because each Beads database is repository-local.

Do not create beads for authoring or reviewing this cutover plan.

The old Jig v3 tasks may be closed as superseded after this table, the matching
D01 tracker description, and the self-contained Jury Beads are synchronized and
validated. Close rather than physically delete them so their original graph and
description history remain inspectable.

## 19. Completion criteria

The cutover is complete only when:

- new Jig integrations use Jury by default;
- migrated sources were never overwritten;
- no supported workflow dual-writes Jig v2 and Jury;
- Jig never receives Jury plaintext or key material;
- Jury has no Jig runtime dependency;
- v2 retirement followed a published support window;
- migration and recovery were rehearsed with generic fixtures;
- every old v3 issue has a concrete disposition;
- adapter and version compatibility tests pass on supported platforms;
- operators can still explain and verify rollback limitations.
