# Implement J02 protected primitives

Consumer: J02 (`jury-qv4.2.1`) and downstream J03/J04/J07/J08/J12 callers.
Gated feature: protected byte lifetimes, bounded redaction, hardened
repository/state paths, atomic private publication, process core suppression,
and fallible entropy. Observed defect classes: pageable secret fallback, value
leakage, path traversal/alias/race attacks, partial entropy return, and
non-provenanced legacy extraction. Deletion condition: close this work record
after exact-source ancestry, the complete J02 acceptance contract, and required
repository gates are verified.

This ExecPlan is a living document. Maintain `Progress`, `Surprises &
Discoveries`, `Decision Log`, and `Outcomes & Retrospective` while implementing
it, as required by `.agent/PLANS.md`.

## Purpose / Big Picture

Jury is a pre-alpha scaffold and does not protect real secrets. J02 establishes
the reusable non-cryptographic safety boundaries that later identity, item,
process, and storage work must use. After this work, a caller can allocate a
compact secret directly in page-dedicated guarded memory, require or explicitly
acknowledge runtime protection controls, generate bytes through a fallible
entropy seam without receiving partial output, redact bounded output across
chunk boundaries, suppress ordinary process core dumps before capture, and open
or publish through capability-held filesystem objects that reject aliases,
links, and stale identities.

The implementation must not add a Jig runtime dependency or production
cryptography. It must preserve the selected Jig components' Git history, retain
`unsafe_code = "forbid"` in every Jury-owned crate, use generic fixtures, and
keep all error text free of secret values.

## Progress

- [x] (2026-08-30) Read root and crate guidance, the complete J02 bead, the J02
  master-plan section, and the architecture security boundary.
- [x] (2026-08-30) Verified sibling `../jig-sh` contains canonical source commit
  `eed70cee337b0067ed92deb9fa05017b0b284605` and all eight reviewed files.
- [x] (2026-08-30) Reviewed the whole-file allowlist and prepared disposable
  filtered history at `/tmp/jury-j02-filter.JxmZ7U/source`; the filtered head is
  `7a6d648316afb5706d39b63b763f122528a426ce` and 35 original commits map to
  retained filtered commits.
- [x] (2026-08-30) Claimed `jury-qv4.2.1`, flushed tracker state, and opened Jig
  plan `plan_01M19EH7DR0GMWRVREGEJG5A7M` at baseline
  `76bf6c87cb31cfe5400870d35e858adb14a42b52`.
- [x] (2026-08-30) Audited current protected-memory candidates. Only
  `sanitization` 2.0.3 exposes the complete required guarded-mapping contract
  through a safe caller API; it requires raising the recorded workspace MSRV
  from Rust 1.85 to Rust 1.90.
- [x] (2026-08-30) Verified packaged `sanitization` 2.0.3 checksum
  `75e43f2762b31232062e8ba7bfbdfcbd33c80c43bf7a306a7e195c3c4f734e0f`,
  matched its complete `src/` tree to tag `v2.0.3` at source commit
  `ffcb211cd931c6966b2e767ce5edffa4b47c4f07`, and ran its Linux unit suites:
  150/150 selected-feature tests and 196/196 all-feature tests passed on Rust
  1.97.1 in disposable targets.
- [x] (2026-08-30) Installed Rust 1.90.0 and compiled/ran a disposable
  `#![forbid(unsafe_code)]` probe using the proposed exact dependency versions.
  A strict Linux protection request achieved required memory lock, dump
  exclusion, no-fork, guard pages, and canaries; capability no-follow opens and
  handle metadata compiled and ran under the same floor.
- [x] (2026-08-30) Matched `cap-std`/`cap-fs-ext`/`cap-tempfile` 4.0.3 package
  source to Bytecode Alliance commit
  `b7acf8e8807fe3fab991884d2208b7e03d35a409`; the all-feature upstream suites
  passed, including 15 `cap-primitives` and 14 `cap-tempfile` tests.
- [ ] Obtain explicit authority to create the required provenance merge and
  ordinary reviewable commits in Jury.
- [ ] Merge filtered history with explicit provenance, move approved files, and
  decouple them into Jury-owned crates.
- [ ] Implement protected memory, non-growing bytes, redaction, entropy, and
  pre-capture process protection.
- [ ] Implement capability-based repository/state discovery, locks, reads, and
  atomic output.
- [ ] Add platform documentation, provider/provenance evidence, and the complete
  adversarial test matrix.
- [ ] Run focused tests, exact-provider checks, MSRV/current toolchain checks,
  Jig gates, ancestry checks, and the final requirement-by-requirement audit.

## Surprises & Discoveries

- The exact baseline merge commit does not touch any selected file. Therefore
  `git filter-repo` prunes it and maps that commit to zero; the filtered tip maps
  from original commit `68856a09f5e976f499d86a8b86159ae57b62a393`.
  Preserve the complete filter-repo commit map and exact baseline in the
  provenance record rather than claiming the rewritten hash is the baseline.
- The legacy `output/unix.rs` contains direct `libc` unsafe calls and performs
  several path-based validate-then-use operations. Its invariants and negative
  tests are useful, but the implementation cannot enter a Jury crate unchanged
  because Jury retains `unsafe_code = "forbid"` and J02 requires handle-based
  validation.
- `shrouded` 0.2.0 has guards and Rust 1.77 support but lacks fork exclusion and
  documents ordinary allocation fallback. `memsafe` 1.0.2 supports Rust 1.85
  and fork wiping but has no surrounding guard pages. Neither meets J02's full
  contract. `sanitization` 2.0.3 has required/optional protection requests,
  reports, guards, page rounding, locking, dump/fork controls, canaries, direct
  fallible filling, and zeroize-before-unmap, but declares Rust 1.90.
- The existing workspace already has a separate open J01A plan. Jig permits a
  second work plan, so J02 has its own exact baseline and receipts without
  rewriting J01A's record.
- The provider's packaged source is byte-identical to the tagged repository
  `src/` tree. Its all-feature suite exercises explicit cleanup retry,
  normalization-before-unmap, release/unmap failure, required protection before
  fill, guarded logical bounds, injected CSPRNG failure, and fork-child wiping.
  These are provider-level evidence only; Jury still needs wrapper tests and
  must not describe the provider's repository-authored review record as
  independent security review.
- `cap-tempfile` 4.0.3's default-feature library tests do not compile because
  test code imports `cap_std::fs_utf8` without enabling that feature. The
  all-feature suite passes and the product API compiled in the MSRV probe, but
  J02 does not need the crate's replace-only publication API. Reject it and
  create a bounded random same-directory temporary through `cap-std` instead;
  this removes a dependency and avoids laundering an upstream test gap.

## Decision Log

- Decision: create `jury-protected` and `jury-filesystem` instead of putting OS
  details into `jury-core`.
  Rationale: `jury-core` must remain independent of storage and process details,
  while J03 needs the entropy seam without inheriting capability-filesystem
  dependencies. Two narrow crates keep that dependency edge explicit.
  Date/Author: 2026-08-30 / Codex.
- Decision: pin `sanitization = "=2.0.3"` with only the exact mapped-memory
  features needed by Jury and raise `workspace.package.rust-version` to 1.90.
  Rationale: no Rust-1.85-compatible candidate found during the current source
  audit satisfies guards, locking, dump exclusion, fork exclusion,
  zeroize-before-unmap, fallible construction, and an entirely safe downstream
  API. Silently using a partial provider would violate J02. The installed
  current toolchain is Rust 1.97.1; acceptance must additionally compile the
  workspace under 1.90.
  Date/Author: 2026-08-30 / Codex.
- Decision: require mapping and guard-page setup in every mode. The single
  emergency override may relax runtime lock/dump/fork controls only where the
  provider reports the exact degraded state; it may never use an ordinary heap
  fallback.
  Rationale: this preserves the acceptance rule that compact secrets cannot
  silently become long-lived pageable allocations while making degradation
  explicit and stable for API, JSON, and TUI consumers.
  Date/Author: 2026-08-30 / Codex.
- Decision: use pinned Bytecode Alliance `cap-std` and `cap-fs-ext` 4.0.3 APIs
  for capability-relative traversal and publication, plus provider-reported
  `(device, inode, link count)` identity. Do not use `cap-tempfile`; create the
  private same-directory temporary with `create_new`, a bounded random public
  filename, and explicit owner-only mode through the held parent capability.
  Rationale: these crates expose no-follow handle operations and cross-platform
  metadata through safe APIs. Jury-owned code can retain the workspace unsafe
  lint while avoiding the legacy path-only race pattern.
  Date/Author: 2026-08-30 / Codex.
- Decision: keep `SecretBytes` distinct from `ProtectedMemory` and document it
  as a transient, non-growing, zeroizing buffer, not a locked-memory type.
  Rationale: legacy redaction and bounded payload paths need grow-refusal and
  zeroization, while compact keys, roots, credentials, and seeds must use the
  stronger page-dedicated owner. Naming the distinction prevents proof-class
  inflation.
  Date/Author: 2026-08-30 / Codex.

## Outcomes & Retrospective

Not complete. Fill this section with shipped crate/API boundaries, exact
provider and source revisions, platform gaps, ancestry evidence, gate receipts,
and anything deliberately rejected. Do not claim independent verification; a
solo rerun is only solo verification.

## Context and Orientation

Repository-wide guidance is in `AGENTS.md`, crate guidance in
`crates/AGENTS.md`, and implementation constraints in
`docs/architecture.md`. The authoritative task contract is the
`jury-qv4.2.1` bead and `docs/jury-v1-master-plan.md` section `J02 — Extract
protected bytes, redaction, and hardened filesystem primitives`.

The current implementation is a five-crate scaffold. `jury-core` owns domain
types; `jury-protocol` owns public wire contracts; `jury` and `jury-tui` own
presentation; and `jury-witness` owns the future service boundary. No existing
crate owns generic protected memory or hardened storage. All workspace crates
inherit `unsafe_code = "forbid"` from the root `Cargo.toml` and also state the
lint in their crate roots.

The canonical extraction source is `https://github.com/bpcakes/jig-sh.git` at
`eed70cee337b0067ed92deb9fa05017b0b284605`. A verified sibling may provide
objects. The whole-file allowlist is:

- `crates/jig-vault/src/secret.rs`;
- `crates/jig-vault/src/redact.rs`;
- `crates/jig-vault/src/exec_output.rs`;
- `crates/jig-vault/src/path_security.rs`;
- `crates/jig-vault/src/output.rs`;
- `crates/jig-vault/src/output/unix.rs`;
- `crates/jig-vault/src/output/unix/error.rs`;
- `crates/jig-vault/src/output/unix/macos_path_tests.rs`.

The filtered tree temporarily names these under `jury-legacy-components/`.
Move memory/redaction files into `crates/jury-protected/` and filesystem files
into `crates/jury-filesystem/`; do not compile or retain the temporary tree.

## Requirements and proof map

1. Exact extraction and ancestry. Prove with the canonical baseline object,
   selected blob SHA-256 manifest, filter-repo commit map, temporary merge
   commit, `git log --follow`, and absence of the temporary remote after the
   move/decouple commits.
2. No Jig runtime dependency or unsafe Jury code. Prove with `cargo tree
   --workspace`, `rg` for Jig package names in manifests, and Clippy/build under
   the workspace lint.
3. Non-growing redacted bytes. Prove capacity refusal, retained capacity after
   truncate/clear, eager zeroization through an injectable test allocator/probe
   where possible, and value-free `Debug`/errors.
4. Protected compact memory. Prove direct in-mapping initialization, maximum and
   page rounding, required guards/locking/dump/fork states on supported hosts,
   no ordinary fallback, partial-fill cleanup, integrity errors, and the pinned
   provider's exact-source cleanup/failure tests.
5. Core suppression and visible degradation. Prove the real Unix subprocess
   has `RLIMIT_CORE=0` before its private callback and fake suppressors establish
   ordering/failure behavior. Serialize strict/degraded status to JSON and
   render the same degraded fact in `jury-tui` state.
6. Bounded redaction. Prove raw and encoded forms, binary values, leftmost-longest
   overlap, every chunk split, independent stdout/stderr state, pattern/count/
   memory limits, no growth beyond the constructed pending capacity, and
   redacted debug/errors.
7. Fallible entropy. Prove `OsRandom` fills an already protected destination,
   injected partial-write failure returns one typed value-free error and no
   `ProtectedMemory`, and the public trait is usable by `jury-core` without Jig.
8. Hardened repository/state paths. Prove no-follow component traversal,
   symlink/reparse and hard-link rejection, handle identity checks, nested repo
   and linked-worktree `.git` handling, malicious `.jury`, containment and
   state/worktree overlap rejection, and replacement between preview/open/use.
9. Private atomic output. Prove owner-only creation, file and parent sync,
   no-clobber/replace policy, exact precondition identity, all injected crash
   points, identity-safe cleanup, and an explicit published-but-parent-unsynced
   outcome. Only encrypted shared artifact bytes may target the worktree;
   plaintext/private state APIs accept only the platform state-root capability.
10. Platform truth. Prove Linux behavior locally; compile/test platform-gated
    macOS and Windows branches in CI or record unsupported controls as explicit
    gaps. Documentation must repeat pre-alpha/no-real-secrets and may not imply
    independent review.

## Plan of Work

### Phase 1: preserve source history

Recreate the disposable clone if `/tmp/jury-j02-filter.JxmZ7U` disappears. Clone
from canonical remote or the verified sibling, detach at the exact baseline,
verify each selected blob, then run `git filter-repo` only inside that clone with
one `--path` and `--path-rename` per allowlisted file/tree. Save the commit map
and blob manifest before adding the clone as temporary remote
`j02-filtered-source`.

After explicit Git commit authority is received, first commit the J02 tracker,
Jig plan, and provenance preparation without mixing unrelated work. Merge the
filtered head with `--allow-unrelated-histories --no-ff` and a message naming the
canonical URL, exact baseline, allowlist, and filter operation. In following
ordinary commits, move the files into their owning crates, replace Jig-specific
types and unsafe/path-only operations, preserve or port approved tests, and
delete `jury-legacy-components`. Remove the temporary remote. Do not commit or
push unrelated work.

### Phase 2: `jury-protected`

Create the crate, its nearest `AGENTS.md`, and modules `secret`, `memory`,
`randomness`, `redact`, `streaming_redaction`, and `process_protection`.

`SecretBytes` owns a `Zeroizing<Vec<u8>>`, refuses any extension above its
initial allocation capacity, clears removed capacity before truncation, clears
on drop, and redacts `Debug`. It must not implement `Clone`, `Display`, serde,
or implicit conversions that copy bytes.

`ProtectedMemory` privately wraps the pinned provider's guarded dynamic owner.
Its constructor accepts a public maximum and an initializer closure that writes
directly into the protected mapping and returns initialized length. Keep a
Jury-owned logical capacity because the provider rounds writable space to a
page. Expose bytes only to scoped callbacks, never as an owned `Vec`, string,
serde value, or public provider guard. Wrap provider errors into stable
value-free Jury error kinds. Public `ProtectionPolicy` has exactly `Strict` and
`EmergencyAllowDegraded`; public serializable `ProtectionStatus` lists every
requested and achieved control.

Pin `sanitization` exactly and default-disable features. Enable only the
reviewed guarded/memory-lock/canary/fork profile features. Record crate checksum,
source revision, license, MSRV, unsafe posture, maintenance evidence, relevant
source files/tests, and explicit nonclaims in
`docs/security/protected-primitives.md`. Raise and verify the workspace Rust
floor rather than using an incompatible transitive graph.

`RandomSource::fill` takes a caller-owned destination and returns a value-free
error. `OsRandom` delegates to pinned `getrandom` without fallback. A helper
constructs `ProtectedMemory` first and asks the source to fill that mapping;
failure destroys partial bytes and returns no owner.

Redaction ports the selected files with Jury-neutral errors and markers. Pattern
generation is bounded before matcher allocation. Streaming instances share only
the immutable automaton and own separate, preallocated overlap state.

Process protection uses a safe `rlimit` API on Unix and a typed platform result
elsewhere. Strict capture aborts before invoking its callback if suppression or
required memory controls fail. Emergency mode invokes the callback only after a
serializable degraded status has been constructed. No error contains captured
bytes or passphrases.

### Phase 3: `jury-filesystem`

Create the crate, its nearest `AGENTS.md`, and modules `capability`,
`repository`, `state_root`, `lock`, and `private_output`. Depend on
`jury-protected` only where a secret-bearing write needs scoped byte access.

Open a trusted platform root capability and walk every untrusted component with
no-follow directory/file operations. Retain capabilities and provider metadata
rather than returning canonical strings as authority. Normalize only the
documented macOS root aliases after verifying their actual targets. Reject NUL,
relative traversal, unsupported prefixes, links, reparse points, wrong file
types, multi-link files, and identity changes. Errors expose operation and kind,
not private paths by default.

Repository discovery ascends syntactically but opens each candidate from a
trusted root. A `.git` directory is accepted only through a no-follow directory
handle. A linked-worktree `.git` file is opened no-follow, must be single-link
and bounded, and may name only a separately hardened Git directory; it never
acts as a trust anchor. Prefer the nearest marker for nested repositories.
Open `.jury` and `vault.json` from retained worktree capabilities and reject a
malicious existing `.jury` before any private callback.

The platform state root is opened or created owner-only through the same
capability discipline. Compare handle identities to every retained worktree and
reject equality, ancestor/descendant containment, and aliases. Cross-worktree
locks live only below that state root and are keyed later by public identifiers;
J02 supplies the safe lock primitive without inventing domain IDs.

Private publication creates an owner-only same-directory temporary through a
held parent capability, writes from a scoped callback, syncs the file, rechecks
destination and temporary identities, publishes atomically according to
create/replace/exact-precondition policy, then syncs the parent. A failure
injector names crash stages for deterministic tests. Cleanup removes only the
created identity. An error after namespace publication reports that publication
may be durable only after recovery; it must not claim rollback.

### Phase 4: integration and documentation

Expose the entropy trait to `jury-core` through a dependency that does not
expose filesystem or provider internals. Add a minimal TUI protection-state
model/rendering function whose input is the public Jury status, with a test that
degraded mode stays visible. Do not add vault commands or claim the product is
implemented.

Update `Cargo.toml`, `Cargo.lock`, `agent-map.md`, and crate guides. Add
`docs/provenance/j02-legacy-components.md` with exact source/blob/filter mapping
and rejection rationales for invariants that could not be reused. Add
`docs/security/protected-primitives.md` with provider evidence, platform table,
runtime override semantics, core-dump limitations, hibernation/privileged-read/
register-copy nonclaims, and the pre-alpha/no-real-secrets warning.

## Concrete Steps

1. Receive commit authority; inspect `git status` and exact HEAD again.
2. Commit the current J02 work record/tracker state if necessary, merge the
   filtered source, and verify the merge before any source moves.
3. Scaffold the two crates and ownership guides; update workspace/agent map.
4. Move the allowlisted source, then decouple memory/redaction and filesystem
   sides in small compiling commits.
5. Add pinned dependencies and provider/provenance records; prove Rust 1.90.
6. Implement and test `SecretBytes`, `ProtectedMemory`, entropy, redaction, and
   process protection.
7. Implement and test capability traversal, repository/state discovery, locks,
   and publication.
8. Add JSON/TUI status visibility and platform documentation.
9. Run focused and upstream provider tests, then all Jig gates and ancestry/
   dependency searches.
10. Audit every numbered proof-map item; only then close/sync J02 and finish the
    Jig work record.

## Validation and Acceptance

Run focused crate tests during development. Before completion run, without
silencing stderr:

    cargo test -p jury-protected --all-targets
    cargo test -p jury-filesystem --all-targets
    cargo test -p jury-core --all-targets
    cargo test -p jury-tui --all-targets
    cargo tree --workspace --locked
    cargo +1.90.0 check --workspace --all-targets --locked
    scripts/jig check fmt
    scripts/jig check clippy
    scripts/jig check test
    scripts/jig check contract
    cargo run -p jury -- --help
    cargo run -p jury-witness --bin juryd -- --help

Run the pinned provider's relevant exact-source tests with the selected feature
set and record their revision/checksum and command in evidence. On Linux, run
real subprocess tests for core suppression, guard faults where the provider
supports them, `MADV_DONTDUMP`, fork exclusion, permissions, links, nested and
linked worktrees, replacement hooks, and every publication failure stage.
Compile platform-gated macOS/Windows code where target toolchains are available;
record missing execution honestly rather than treating cross-compilation as a
runtime test.

For ancestry, verify every installed legacy-derived file with `git log
--follow`, check original-to-filtered rows for each retained source-changing
commit, confirm current content descended through the merge, and confirm
`j02-filtered-source` is absent from `git remote -v`. `cargo tree` and all
workspace manifests must contain no Jig crate or path dependency.

Finally run `scripts/jig work check`, attach gate receipts with `scripts/jig work
evidence`, run `scripts/jig work gates`, review the generated diff for stale
plans/policy, and call `scripts/jig work finish` only after the code and tests
are genuinely complete. Close the bead with `br close ... --reason="Completed"`
and `br sync --flush-only` only after this audit passes.

## Idempotence and Recovery

The extraction clone is disposable. If missing or suspect, create a new
`mktemp -d`, re-clone, detach, re-hash, and re-filter; never repair it from build
output or a plan snapshot. Do not rerun the unrelated-history merge after its
merge commit exists. Source moves and decoupling should be ordinary commits so
they can be inspected or reverted individually without rewriting the imported
history.

Every filesystem test owns a unique temporary directory. Failure injection must
leave either the old destination, the complete new destination with an explicit
post-publication outcome, or no destination; rerunning a test must not depend on
stale paths. Provider protection setup is fail-closed by default. Never work
around a host lock limit by changing tests to degraded mode; use the explicit
emergency policy only in tests whose subject is degraded visibility.

If no safe provider can pass its exact required controls at the recorded MSRV,
stop J02. Do not add an unsafe Jury leaf, weaken the workspace lint, widen
tolerances, suppress tests, or claim a partial memory wrapper satisfies the
contract. An unsafe leaf requires the separate operator-approved architecture
and threat-model scope named by the bead.

## Interfaces and Dependencies

Expected public seams (names may change only with a recorded rationale):

    jury_protected::SecretBytes
    jury_protected::ProtectedMemory
    jury_protected::ProtectionPolicy::{Strict, EmergencyAllowDegraded}
    jury_protected::ProtectionStatus
    jury_protected::RandomSource
    jury_protected::OsRandom
    jury_protected::Redactor
    jury_protected::StreamingRedactor
    jury_protected::capture_after_process_protection

    jury_filesystem::RepositoryLocation
    jury_filesystem::HardenedStateRoot
    jury_filesystem::PrivateFilePrecondition
    jury_filesystem::PreparedPrivateFile
    jury_filesystem::PublicationPolicy
    jury_filesystem::PublicationOutcome

Pin security-boundary dependencies exactly in manifests. Keep provider types,
raw handles, third-party errors, OS flags, and capability implementation types
private. The only dependency from `jury-core` is the narrow `jury-protected`
entropy seam; `jury-core` must not depend on `jury-filesystem`. `jury-filesystem`
may depend on `jury-protected`, but neither crate depends on Jig, CLI/TUI,
protocol, witness transport, or cryptographic providers.
