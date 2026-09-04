# J17 owner backup, restore, and recovery drills

This plan delivers `jury-qv4.2.13`. Its concrete consumer is the native Jury CLI and the J25 adversarial corpus that J17 unblocks. The observed defect is that the repository has no owner-recovery artifact, no absent-target restore transaction, and no honest recovery-readiness command. Close this plan after all J17 acceptance criteria and repository gates pass; retain only the repository's append-only Jig receipts.

## Progress

- [x] Read the J17 bead, `docs/jury-v1-master-plan.md` sections 18 and J17, `docs/architecture.md`, and the frozen suite backup domains.
- [x] Confirm J01A/J01B are already closed and the direct cryptographic gate artifacts exist.
- [x] Claim `jury-qv4.2.13` and start this Jig work session from commit `cb69f838140d36e57a43c8c2c74941a2cf44da52`.
- [x] Add the bounded padded backup wire envelope and hostile-header validation.
- [x] Add core-only recovery payload creation/opening, identity resealing, role/topology/direct-slot checks, and recovery summaries.
- [x] Add Linux hardened create/verify/status/restore/drill CLI transactions and failure reporting.
- [x] Add unit, integration, and failure-injection coverage, then run format, clippy, tests, work gates, and requirement audit.

## Surprises & Discoveries

- J09 already implemented authenticated backup, verification, and drill receipt record types even though no command records them yet.
- A Jury identity contains one role-specific principal, so J17 must explicitly select supporting approver and witness-client identities rather than treating the owner identity as all three roles.
- The frozen backup target is an exact total envelope bucket. A binary envelope avoids base64/JSON expansion ambiguity and permits validation of KDF and bucket fields before passphrase capture or allocation.
- Recovery coverage must fit the existing fixed 106-byte local receipt entry. The backup entry's existing digest slot now commits a canonical coverage record; the frozen receipt MAC preimage and vector remain unchanged.
- Testing the restore transaction at its actual publication boundaries requires real Argon2/open/reseal work. The focused failure matrix is intentionally slower than a serialization-only state-machine test because it proves exact-output reconciliation.

## Decision Log

- Keep the public wire codec in `jury-protocol`, recovery cryptography and private identity payload handling in `jury-core`, hardened path publication in `jury-filesystem`, and prompts/output in `jury`.
- Use a fixed canonical public header followed by AEAD ciphertext whose total file length is exactly 4, 8, 16, 32, or 64 MiB. Bind the header digest and bucket to AAD and require zero padding after the length-delimited private payload.
- Store canonical recovery payloads, not copies of independently passphrase-encrypted live identity files. Restore reseals each recovered identity under a newly captured credential.
- Treat witnessed readiness as a reported and enforced local precondition. Client backup does not claim to recover witness replay databases, external anchors, witness availability, or quorum.
- Preserve every target. A partial cross-directory commit remains explicit committed state with a durable transaction marker and a safe retry path.
- Keep the J01A receipt entry byte layout unchanged; authenticate J17 status metadata through a kind-specific digest committed by that existing entry.

## Outcomes & Retrospective

Delivered an exact-bucket encrypted backup envelope, core recovery archive validation,
fresh identity resealing, authenticated recovery coverage receipts, hardened owner-only
publication, and native `backup create`, `verify`, `status`, `restore`, and `drill`
commands. Restore now validates every installed identity and state artifact by readback,
and its durable marker permits an exact retry after each injected cross-directory
publication failure without replacing existing targets.

The native CLI test proves that create, verify, status, drill, and repository restore
preserve the source vault and recover a direct item through the restored identity. Unit
coverage additionally proves all three local roles, hostile headers, exact buckets,
tamper/wrong-passphrase refusal, policy and checkpoint mismatch refusal, and every
restore publication boundary. Baseline-linked work gates passed under batch receipt
`receipt_01M1P4KRAA7S309KBC51WKEFZB`; a prior whole-workspace attempt encountered one
scheduler-sensitive failure in an unchanged `jury-process` escaped-pipe test, which
passed on exact rerun and in the final complete gate run.

Remaining nonclaims are explicit: the archive does not recover witness replay
databases, external anchors, service availability, quorum, or deployment readiness.
Jury remains a pre-alpha scaffold and this work does not claim that it protects
secrets or has received independent security review.

## Context and orientation

`jury-protocol` owns versioned bounded wire types. `jury-core/src/identity.rs` is the only module that can reach protected private identity payloads. `jury-core/src/local_state.rs` authenticates audit/checkpoint/receipt files. `jury-filesystem` owns no-follow, owner-only, atomic publication primitives. `jury/src/cli` owns argument parsing, credential capture, path selection, and stable human/JSON output.

J17 must not add a direct slot or alter `vault.json`. It packages the exact portable artifact and authenticated local evidence, reports which direct items and local roles are recoverable, and reports witnessed dependencies without claiming external recovery. Restore targets must be absent and separate from Git except for repository `.jury/vault.json` and `.gitattributes`.

## Plan of work

1. Define and test the exact backup header/envelope parser. Reject wrong magic/version, unknown or altered KDF tuples, impossible ciphertext lengths, noncanonical buckets, oversize input, and transfer/backup confusion before private work.
2. Define a bounded private payload containing the exact vault bytes, selected role recovery payloads, owner audit/checkpoint/receipts, and public policy catalog. Validate all cross-links, owner status, direct-slot recoverability, witnessed-only absence of direct slots, policy topology, and checkpoint ancestry before sealing and after opening.
3. Add identity recovery exports that stay inside `jury-core`, and reseal the same role keys/local seed to a fresh portable identity file without exposing those bytes through public adapters.
4. Add CLI arguments, independent credential sources, hardened backup output/input, authenticated receipt updates, readiness status, absent-target restore, repository metadata publication, transaction markers, and drills through the real restore path.
5. Exercise role coverage, passphrase bounds, hostile/tampered envelopes, exact buckets/padding, identity/vault mismatch, direct/witnessed invariants, existing/aliased targets, Git separation, publication failures, real access drills, and committed-but-unrecorded receipt outcomes.

## Concrete steps

Run focused package tests after each layer. Run `scripts/jig work check`, `scripts/jig check fmt`, `scripts/jig check clippy`, and `scripts/jig check test` after integration. Use `scripts/jig work evidence` and `scripts/jig work gates` to connect final evidence to this plan. Review `git diff` before closing the bead.

## Validation and acceptance

Evidence must prove every bullet under the J17 scope/tests/acceptance section. Tests must compare the vault before/after create, verify, drill, and restore to prove the artifact and access-mode/direct-slot/quorum-claim state are unchanged. Native CLI tests must inspect filesystem locations and failure outcomes rather than relying only on core unit tests.

## Idempotence and recovery

Create/restore/drill use absent targets and are safe to retry before publication. Once any target publishes, never overwrite or automatically delete it. The transaction marker records only public identifiers, target paths, payload digest, and publication state. A later retry validates already-published bytes exactly before continuing; mismatches fail closed.

## Interfaces and dependencies

Use only existing pinned cryptographic providers and protected-memory APIs. No Jury runtime dependency on Jig is permitted. No real names, credentials, secrets, or private operational details may enter source, tests, errors, output, plans, or receipts.
