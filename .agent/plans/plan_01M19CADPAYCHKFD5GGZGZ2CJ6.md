# Freeze the J01A provider-neutral cryptographic suite

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current. Maintain it according to `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

Jury is pre-alpha and must not accept cryptographic implementation merely because a library exposes convenient primitives. This work produces `docs/security/jury-v1-suite.md`, a provider-neutral specification that freezes one exact shared/direct suite, its security and non-security claims, every shared/direct cryptographic preimage, its limits and failures, and the vector obligations consumed by J01B and J05. A maintainer can observe completion by verifying all primary-source hashes and generated preimage vectors, confirming that the live J01A acceptance criteria map to sections of the artifact, and running the repository gates successfully. This plan is consumed by J01A (`jury-qv4.1.1`), gates J01B/J03/J05, addresses cryptographic drift and ambiguous-composition defects, and is closed when J01A is accepted.

## Progress

- [x] (2026-08-30 13:03Z) Committed contract baseline `c17021c` and pinned the long-term HPKE comparison pair.
- [x] (2026-08-30 13:03Z) Verified J01A is the graph-selected actionable P0 task and moved it to `in_progress`.
- [x] (2026-08-30 13:08Z) Inventoried J01A-owned constructions, limits, and J01B/J03/J05/J19/J25 consumers against the architecture and master plan.
- [x] (2026-08-30 13:12Z) Recomputed sizes, identifiers, draft compatibility, and security notions from 25 exact source artifacts.
- [x] (2026-08-30 13:15Z) Selected suite `0x0001`, recorded rejected alternatives, and reduced unsupported application properties to explicit nonclaims.
- [x] (2026-08-30 13:23Z) Defined 46 byte-exact JCE1 preimages and a deterministic public vector corpus with positive direct, registration, identity-mode, genesis-attestation, AEAD, Argon2id, signature, MAC, and negative fixtures.
- [x] (2026-08-30 13:27Z) Recomputed the corpus with independent temporary implementations. Did not add a permanent self-checking validator before production builders exist; J01B/J05 are the concrete consumers that must add byte-for-byte tests.
- [x] (2026-08-30 13:30Z) Mapped every J01A criterion, completed the fresh solo/cross-implementation rerun, passed all Jig gates, and recorded the author-distinct verification request/blocker on the task.
- [ ] Close J01A only if every acceptance criterion is met; otherwise leave it open with exact blockers.

## Surprises & Discoveries

- Observation: `draft-ietf-hpke-pq-05` normatively cites HPKE core `-03`, but its test-vector procedure uses `EncapDerand`, which exists only in core `-04`.
  Evidence: the pinned archive texts hash to `c3afa3981c7e2aacac4912a8b58eca14a92a10c66c4fd4e9ff078195a1ac9c5d` and `7c3090db36136e58242216c04bcc744f297800a4a615680930c5a4e3ae7cd733`; `rg EncapDerand` finds the definition only in core `-04`.
- Observation: concrete-hybrid-kems `-03` still cites generic hybrid-kems `-09`, while PQ `-05` cites `-12`; `-12` repairs missing returns, tuple ordering, and combiner variable names.
  Evidence: exact generic-framework hashes and the `-09` to `-12` semantic delta are recorded in section 2 of the suite artifact.
- Observation: the pinned hybrid KEM defines public-key serialization/deserialization as fixed-length identity operations. Adding independent X25519 canonicality or low-order rejection would change the KEM.
  Evidence: PQ `-05` section 4 and concrete-hybrid/X-Wing pseudocode; the suite now requires the pinned component behavior without an extra validity oracle.
- Observation: including the normalized policy-state hash in direct-slot AAD creates a cycle because normalized state contains the completed slot ciphertext.
  Evidence: recomputing the first complete fixture had no topological order. The final AAD binds slot algorithm/access mode while the outer owner signature jointly binds the complete slot and independently computed resulting state hash.
- Observation: a suite-migration statement that includes the destination genesis fingerprint cannot itself be embedded in that genesis.
  Evidence: doing so makes the genesis fingerprint depend on itself. The final contract keeps that statement outside genesis and permits only cycle-free legacy-migration or rollover source attestations inside genesis.

## Decision Log

- Decision: Use exact HPKE core `draft-ietf-hpke-hpke-04` plus PQ profile `draft-ietf-hpke-pq-05` as the comparison baseline.
  Rationale: core `-04` supplies the vector interface used by PQ `-05`, corrects DHKEM sizes, adds edge vectors, and is farther along the standards track. The stale `-03` bibliography entry is recorded rather than silently followed.
  Date/Author: 2026-08-30 / Codex, confirmed by operator request for the best long-term option.
- Decision: J01A contains no production provider dependency or cryptographic adapter.
  Rationale: provider selection and implementation proof belong to J01B; separating the property contract prevents provider availability from selecting security behavior.
  Date/Author: 2026-08-30 / Codex, from the live J01A contract.
- Decision: Suite `0x0001` uses MLKEM768-X25519, Base-mode HPKE, HKDF-SHA256, and ChaCha20-Poly1305 for direct slots; AES-256-GCM-SIV for stored seals; strict Ed25519, SHA-256, HMAC-SHA-256, and the frozen Argon2id profiles.
  Rationale: retained slots require HNDL confidentiality, the hybrid preserves a classical hedge, misuse-resistant storage limits nonce-reuse damage, and PQ authenticity remains an explicit non-goal until a stable hybrid-signature application profile exists.
  Date/Author: 2026-08-30 / Codex, following the operator's long-term-option direction.
- Decision: Do not commit a standalone vector validator in J01A.
  Rationale: before production preimage builders exist, a repository validator would only recompute its own fixtures and risk proof-class inflation. The corpus was cross-checked with separate Ruby/OpenSSL, Rust X-Wing, Rust AES-GCM-SIV, and system libargon2 implementations; J01B/J05 must add the lasting consumer tests.
  Date/Author: 2026-08-30 / Codex, applying the repository's honest-work rule.

## Outcomes & Retrospective

The suite artifact and corpus now exist. All 25 source hashes, 46 preimage hashes, seven HKDF outputs, three HMACs, twelve Ed25519 signatures, the official and three Jury HPKE schedules/ciphertexts, three X-Wing encapsulation/decapsulation pairs, both AES-GCM-SIV seals, and both Argon2id profiles have been rerun locally with cross-implementations. The exact diff and acceptance mapping were reviewed, and all Jig gates pass. The candidate remains uncommitted and J01A cannot close without the required author-distinct reproducibility verifier at an exact revision; solo cross-checking is not that verification.

## Context and Orientation

The repository root is `/home/aa/Documents/jury`. `docs/architecture.md` defines the implementation gates and ownership boundaries. `docs/jury-v1-master-plan.md` contains the detailed J01A task contract and the exact HPKE draft pins. `.beads/issues.jsonl` mirrors the live Beads tracker; mutate it only through `br` and then run `br sync --flush-only`. `docs/security/jury-v1-suite.md` is the primary deliverable and `docs/security/vectors/jury-v1-suite.json` is its frozen language-neutral corpus.

“Provider-neutral” means the artifact specifies algorithms, bytes, limits, errors, and required security behavior without selecting a Rust crate. A “preimage” is the exact byte sequence passed to a hash, signature, MAC, KDF, or AEAD associated-data input. A “suite” is the inseparable set of KEM, HPKE mode, KDF, AEAD, storage AEAD, MAC, signature, password KDF, contexts, limits, and encodings. “HNDL” means harvest-now/decrypt-later resistance: stored ciphertext remains confidential against an attacker who records it now and later gains a quantum computer. Jury makes no production-security, FIPS-validation, certification, or independent-review claim.

## Plan of Work

First inventory the owning documents with `rg` and trace each J01A reference into J01B, J03, J05, J07-J09, J17, J19, and J25. Build an acceptance map before selecting algorithms so no field or consumer is omitted.

Next retrieve exact primary specifications into a temporary directory, hash the exact bytes, and independently recompute algorithm identifiers, key and ciphertext sizes, nonce/tag sizes, KDF constraints, Argon2id profiles, and signature encodings. Pin mutable analyses and drafts by exact revision and content hash. Separate primitive guarantees from Jury composition arguments and record unsupported properties as unproven and unclaimed.

Then write `docs/security/jury-v1-suite.md`. Choose exactly one genesis suite with no negotiation or fallback. Specify classical and post-quantum confidentiality separately from authenticity, the direct-slot outer sender-authentication composition, revision-scoped secret lifetimes, randomness and identifier rules, side-channel requirements, failure taxonomy, and migration through a new authenticated lineage.

Define a canonical encoding shared by all J01A preimages. Every field must state its byte width or length prefix, order, integer endianness, domain prefix, suite identifier, and whether it is secret. Use native 32-byte `VaultId`, `PrincipalId`, and `ItemId` values, never their hexadecimal JSON representation. Publish deterministic non-secret fixture vectors using names such as `ExampleVault`, `ExamplePrincipal`, and `ExampleSecret`; do not include real identifiers or credentials.

Validate with independent temporary implementations now. Add lasting executable checks only with the J01B/J05 production builders they consume; a J01A-only script that recomputes its own golden fixtures is not product evidence. Negative fixtures demonstrate field-order, identifier-text, label, suite-ID, algorithm, length, and strict-signature substitutions, while fault and cross-provider obligations remain explicit for their owning implementation gates.

Finally map each live acceptance criterion to a document section and executable check, rerun all verification from a clean state, review the diff for security-claim inflation, and record that solo reruns and automated checks are not independent cryptographic review. Close J01A only after an author-distinct verifier cites the exact revision and reruns the specified calculations; if no such verifier is available, leave J01A open and state that blocker.

## Concrete Steps

Run all commands from `/home/aa/Documents/jury`.

    rg -n "J01A|suite|preimage|HPKE|Argon2|RevisionSealId|MAC|direct slot" docs crates .beads/issues.jsonl

Expect a complete ownership inventory without production provider code in scope.

    mkdir -p /tmp/jury-j01a-specs
    curl -fSLo /tmp/jury-j01a-specs/<name> <immutable-primary-source-url>
    sha256sum /tmp/jury-j01a-specs/*

Do not copy source documents into the repository. Record exact URLs, revisions, hashes, and the derived facts in `docs/security/jury-v1-suite.md`.

Use `apply_patch` to create and revise repository files. If a validator is added, keep its inputs declarative and its output deterministic. Run its positive and negative cases directly, then run:

    scripts/jig check contract
    scripts/jig check fmt
    scripts/jig check clippy
    scripts/jig check test
    git diff --check

Expect every command to exit zero. Preserve stderr in evidence. Run `scripts/jig work evidence` and `scripts/jig work gates` as required by the active plan before finishing.

## Validation and Acceptance

The artifact is accepted only when a reader can reconstruct every J01A-owned cryptographic input byte-for-byte without choosing an unstated convention. Every security-property matrix cell is `yes`, `no`, `conditional`, or `not required`, with a notion, attacker, assumptions, exact analysis, and composition rationale for every `yes` or `conditional`. HNDL confidentiality and PQ authenticity are distinct decisions. The selected HPKE core, KEM, mode, KDF, AEAD, and outer authentication are compatible as a unit. There is one genesis suite, no negotiation or fallback, and migration changes lineage and suite identifier.

Executable checks must reproduce all declared source hashes and fixture preimages, accept canonical native identifiers, reject text substitutions and malformed encodings, and fail on a one-byte change to a domain label, field, limit, or pinned source hash. J01B and J05 must be able to bind these exact artifacts without redefining them. The repository contract, formatter, Clippy, and test suite must pass.

## Idempotence and Recovery

Specification downloads go only to a uniquely named temporary directory and may be repeated. All repository edits are additive or patch-based. Never regenerate a golden file merely to make a failing check pass; independently recompute the expected bytes and investigate the mismatch. Tracker changes use only `br`; rerun `br sync --flush-only` after mutation. If research invalidates a selected primitive, update the Decision Log and all affected vectors before proceeding. Do not close J01A to bypass an unavailable verifier.

## Artifacts and Notes

Baseline commit: `c17021c` (`docs: freeze cryptographic contract baseline`). Primary outputs: `docs/security/jury-v1-suite.md` and `docs/security/vectors/jury-v1-suite.json` (SHA-256 `204ff421daa6b56f4b8481291988a0eea9628e016833483720d72d81ccfb7486`). Any executable drift validator must name J01B/J05 as consumers and ambiguous-preimage/specification-drift as its defect class.

## Interfaces and Dependencies

J01A depends on no implementation task. J01B consumes the suite and selects providers. J03 consumes identifier-generation and native-byte encoding rules. J05 embeds, but cannot redefine, shared/direct preimages. J19 owns witnessed constructions and may not weaken J01A suite, context, downgrade, or key-lifetime invariants. J25 later consumes positive, negative, fault, migration, and cross-provider vectors. No Jury runtime package may depend on Jig or on a cryptographic provider as part of J01A.

Revision note: Initial plan created on 2026-08-30 from baseline `c17021c` to implement the newly accepted long-term draft pairing and the complete J01A contract.

Revision note: Updated on 2026-08-30 after implementation to record suite decisions, cycle/failure discoveries, the no-self-certification validator decision, exact corpus evidence, and the remaining gate/verifier work.
