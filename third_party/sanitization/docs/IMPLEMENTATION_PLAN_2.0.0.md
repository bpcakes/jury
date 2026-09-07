# Sanitization 2.0.0 Commit Implementation Plan

Status: active development plan

This document converts the 2.0 architecture roadmap into bounded implementation
commits. It replaces alpha, beta, and release-candidate tags as development
checkpoints.

There are no intermediate 2.0 version tags or crates.io releases. Each
checkpoint ends at a reviewed commit, receives its own pentest or targeted
security review, and must be accepted by the project owner before work starts
on the next checkpoint. Development findings are temporary working material;
only the completed release receives a permanent pentest report and the
`v2.0.0` tag.

The architecture and security requirements remain normative in
[`ROADMAP_2.0.0.md`](ROADMAP_2.0.0.md). This document defines implementation
order, commit boundaries, verification, and review handoff.

## Commit Discipline

Each checkpoint uses a symbolic identifier such as `CP-04`. The identifier is
not a Git tag or version. Record the actual full commit hashes when the
checkpoint is implemented.

The normal flow is:

1. Record the current branch tip as the checkpoint base.
2. Implement only the current checkpoint.
3. Run the checkpoint verification and the repository-wide required checks.
4. Create one implementation commit with the checkpoint identifier in the
   commit message.
5. Stop implementation.
6. Pentest the range from the checkpoint base through the new implementation
   commit.
7. Put temporary findings in root `PENTEST.md`.
8. Fix findings in one or more checkpoint-scoped remediation commits.
9. Delete `PENTEST.md` and rerun the entire checkpoint review range.
10. Stop when the project owner confirms that the retest is sufficient.
11. Start the next checkpoint from the accepted branch tip after CI is green.

If a checkpoint no longer fits in one coherent implementation commit, stop
before editing production code and split it in this plan. Do not stack multiple
planned implementation commits behind one later review merely to preserve the
original numbering.

The review range is:

```text
git diff <checkpoint-base-commit>..<reviewed-through-commit>
```

If remediation commits are needed, the reviewed-through commit is the last
remediation commit. The complete range is retested; the review does not inspect
only the final patch. The exact range is communicated in the development
conversation and does not require permanent repository metadata.

## Development Pentest Material

Development findings use the ignored root file:

```text
PENTEST.md
```

The file is never committed. It is deleted after remediation and a clean
retest. Development reviews may be repeated as often as needed without
creating repository artifacts or release-like acceptance commits.

The final `v2.0.0` review is different: it must produce
`security/pentest/v2.0.0.md`, committed alone through the normal release gate.

## Version And Tag Policy

- Do not create alpha, beta, RC, or checkpoint tags.
- Do not publish checkpoint packages.
- Do not bump workspace packages for every checkpoint.
- Keep checkpoint identity in commit messages and this planning register.
- Perform the coordinated workspace bump to `2.0.0` only in `CP-23`.
- Create and push `v2.0.0` only after the final report-only release commit.
- Continue using the 1.2.x line separately for eligible non-breaking
  backports.

## Required Checkpoint Baseline

Every implementation and remediation stop must run the applicable subset of:

- `scripts/checks.sh`;
- `scripts/verify-codegen.sh`;
- `scripts/verify-derive-failures.sh`;
- `scripts/verify-leakage-smoke.sh`;
- `scripts/verify-loom.sh`;
- `scripts/verify-kani.sh`;
- `scripts/verify-miri.sh`;
- `scripts/verify-evidence.py`;
- workspace package-list checks;
- target-specific native checks required by the checkpoint.

The checkpoint may add stronger commands. A narrow checkpoint may skip an
unrelated expensive native job when the review handoff explains why it is
unrelated. The final evidence checkpoints run the complete matrix.

## Checkpoint Register

Update this table when a checkpoint starts and after the project owner accepts
its retest.

| Checkpoint | Status |
|---|---|
| `CP-00` | Accepted |
| `CP-01` | Accepted |
| `CP-02` | Accepted |
| `CP-03` | Accepted |
| `CP-04` | Accepted |
| `CP-05` | Accepted |
| `CP-06` | Accepted |
| `CP-07` | Accepted |
| `CP-08` | Accepted |
| `CP-09` | Accepted |
| `CP-10` | Accepted |
| `CP-11` | Accepted |
| `CP-12` | Accepted |
| `CP-13` | Accepted |
| `CP-14` | Accepted |
| `CP-15` | Accepted |
| `CP-16` | Accepted |
| `CP-17` | Accepted |
| `CP-18` | Accepted |
| `CP-19` | Accepted |
| `CP-20` | Accepted |
| `CP-21` | Accepted |
| `CP-22` | Accepted |
| `CP-23` | Pentest |

Allowed status values are `Planned`, `Implementing`, `Pentest`, `Remediating`,
`Retest`, `Accepted`, and `Deferred`. `Deferred` is valid only for an optional
additive checkpoint and requires the rationale and removed or reduced stable
claim to be recorded in the roadmap or implementation plan.

## Commit Sequence

### `CP-00`: Development Workflow And Baseline

Recommended commit message:

```text
CP-00 establish sanitization 2.0 development workflow
```

Goal: establish the development branch, review boundaries, and frozen baseline
before behavioral work starts.

Deliverables:

- capture the 1.2.5 public API, feature matrix, package contents, unsafe-block
  inventory, codegen samples, and current target evidence;
- disposition every 1.2.x backport candidate as a separate patch-release task
  or a documented non-breaking defer;
- keep temporary `PENTEST.md` input ignored;
- document the commit-range review workflow.

Pentest focus:

- ambiguous base/head ranges;
- review handoffs that omit remediation commits;
- accidental mixing of multiple roadmap checkpoints.

Exit criteria:

- the review boundary and exact commit range are unambiguous;
- the baseline artifacts are reproducible;
- temporary findings are removed after accepted retest;
- CI is green before CP-01 starts.

### `CP-01`: Behavior-Preserving Module Split

Recommended commit message:

```text
CP-01 split sanitization internals into auditable modules
```

Goal: separate the large core implementation before changing behavior.

Deliverables:

- create `wipe_backend`, `owned`, `ct`, `mapped`, `platform`, `canary`, and
  `interop` modules;
- split target-family platform code where useful;
- preserve public paths, cfg behavior, feature behavior, unsafe invariants, and
  target support;
- compare API snapshots, package lists, codegen, tests, and unsafe inventory
  against `CP-00`;
- pin the complete Rust source snapshot reviewed for CP-01 and enforce that
  historical snapshot from the repository-wide check path.

Pentest focus:

- cfg items lost or exposed during moves;
- changed visibility;
- changed drop order;
- accidental codegen changes in wipe and CT paths;
- platform implementations selected on the wrong target.

Exit criteria:

- no intentional API or behavior change;
- baseline comparisons explain every mechanical difference;
- the complete reviewed Rust source matches the pinned CP-01 digest;
- temporary findings are removed after accepted retest and CI is green.

### `CP-02`: Sanitization And Storage Contracts

Recommended commit message:

```text
CP-02 add sanitization storage contracts
```

Goal: make current-value sanitization and storage stability separate,
enforceable concepts.

Deliverables:

- make the `SecureSanitize` implementer contract normative;
- add `StableSharedSecretStorage`;
- add `StableMutableSecretStorage`;
- cover inherent methods, trait methods, interior mutation, returned guards,
  callbacks, deferred cleanup, and destructors;
- add audited built-in implementations;
- add tuple implementations to the selected arity;
- add manual-implementation guidance, compile-pass examples, and negative
  documentation tests;
- decide whether a conservative assertion derive belongs in 2.0.

Pentest focus:

- incorrect blanket implementations;
- interior-mutability escapes;
- downstream false assumptions;
- trait combinations that permit storage release without clearing;
- tuple cleanup order and padding claims.

Exit criteria:

- generic guarantees are explicitly conditional on correct implementations;
- no stability trait is marked unsafe unless memory safety begins to depend on
  it;
- temporary findings are removed after accepted retest and CI is green.

### `CP-03`: Restrict Generic `Secret<T>` Exposure

Recommended commit message:

```text
CP-03 restrict generic secret exposure
```

Goal: prevent generic exposure from reaching storage-unstable safe operations.

Deliverables:

- require shared stability for `with_secret`;
- require mutable stability for `with_secret_mut`;
- remove unrestricted shared and mutable exposure;
- add compile-fail coverage for `Vec`, `String`, and interior-mutable
  reallocating types;
- add migration diagnostics and examples;
- preserve ownership and drop sanitization for non-stable `T`.

Pentest focus:

- alternate methods or trait paths that recover unrestricted access;
- escaping borrows;
- interior-mutability bypasses;
- accidental `Deref`, `AsRef`, ordinary equality, cloning, or value-printing
  debug implementations.

Exit criteria:

- storage-unstable types can be owned and cleared but not generically exposed;
- stable user types can opt in explicitly;
- the complete hosted Linux, Windows, Apple, Android, BSD, WASM, and embedded
  checkpoint matrix is green; locally skipped non-host targets do not satisfy
  this criterion;
- temporary findings are removed after accepted retest and CI is green.

### `CP-04`: Direct Fixed-Secret Exposure

Recommended commit message:

```text
CP-04 make fixed secret exposure direct
```

Goal: remove unnecessary full-size temporary arrays from the normal fixed
secret path.

Deliverables:

- make direct borrowing the normal `SecretBytes<N>` exposure behavior;
- add explicitly named copy exposure;
- apply the same policy to fixed locked, pooled, expiring, split, and guarded
  wrappers where valid;
- add unwind cleanup for copy exposure;
- add codegen checks proving the direct path does not construct a full-size
  copy;
- document abort, register, stack-frame, and caller-copy limits.

Pentest focus:

- hidden compiler or helper copies;
- borrow escape;
- temporary cleanup on normal return and unwind;
- double clearing or use after move;
- integrity checks occurring before exposure.

Exit criteria:

- direct exposure has no reviewed full-size temporary;
- copy exposure is visibly named and documented;
- temporary findings are removed after accepted retest and CI is green.

### `CP-05`: Fixed Allocation And Aggregate Guidance

Recommended commit message:

```text
CP-05 add fixed allocation secret storage
```

Goal: provide a stable runtime-length allocation and correct aggregate
guidance.

Deliverables:

- implement `SecretBoxBytes` if retained for 2.0;
- provide zeroed, boxed, slice, closure, replacement, clear, drop, CT equality,
  serde, and interop paths;
- ensure replacement stages the new value before clearing and releasing the
  old allocation;
- document `SecretBoxBytes`, managed-growth byte/text types, and mapped types
  as distinct choices;
- tighten generic `Vec<T>`, array, slice, and box documentation;
- add performance checks for accidental per-byte fencing.

Pentest focus:

- allocation replacement ordering;
- hidden reallocations;
- serde intermediate buffers;
- capacity versus length wiping;
- consuming APIs and double cleanup.

Exit criteria:

- fixed allocation cannot grow;
- managed growth never releases old storage uncleared;
- temporary findings are removed after accepted retest and CI is green.

### `CP-06`: CT Declassification And Naming Repair

Recommended commit message:

```text
CP-06 repair data oblivious declassification
```

Goal: remove ordinary-control-flow bypasses from CT control values.

Deliverables:

- remove ordinary equality and unrestricted raw extraction from `Choice`;
- require reason-bearing declassification;
- repair `CtOrdering` and masks;
- keep normalized-state invariant checks;
- rename `strict-ct` to `strict-compare`;
- document the exact primitive and target scope of strict comparison;
- add repository checks for unauthorized raw extraction.

Pentest focus:

- alternate extraction paths;
- invalid normalized states;
- secret-dependent branches or memory access;
- feature-name overclaiming;
- debug and formatting leaks.

Exit criteria:

- every public branch boundary is searchable through explicit
  declassification;
- codegen and leakage smoke tests pass;
- an independent CT review is scheduled after `CP-07`;
- temporary findings are removed after accepted retest and CI is green.

### `CP-07`: Secret CT Ownership

Recommended commit message:

```text
CP-07 add clear on drop ct secret state
```

Goal: give secret-derived CT values explicit ownership and cleanup semantics.

Deliverables:

- replace generic `ct::Secret<T>` with `SecretIndex` and `SecretScalar<T>`;
- make both redacted, non-copying, and clear-on-drop;
- add consuming reason-bearing declassification;
- add explicit `PublicValue<T>` and `SecretValue<T>` classification;
- redesign secret-bearing CT option/result containers;
- clear dummy and unselected secret values;
- cover panic, mapping, selection, zero-sized, drop-bearing, and
  move-without-double-cleanup paths.

Pentest focus:

- secret state surviving drop or declassification;
- double drop and double cleanup;
- panic-unwind ownership;
- selected and unselected value confusion;
- public metadata forced through fake secret traits;
- CT regressions.

Exit criteria:

- Miri and panic probes cover every ownership transition;
- focused independent review of `CP-06..CP-07` is PASS;
- temporary findings are removed after the focused independent retest is
  accepted and CI is green.

### `CP-08`: Fail-Closed Derives

Recommended commit message:

```text
CP-08 make sanitization derives fail closed
```

Goal: prevent derives from silently accepting unsafe aggregate behavior.

Deliverables:

- reject enum derives unconditionally because inactive variant storage is
  unreachable to generated safe code;
- require a non-empty reason for every skipped field;
- preserve generic-bound correctness;
- reject unions;
- add tuple struct, renamed crate, generic, enum-rejection, skip, and diagnostic
  tests;
- ensure generated drop implementations have correct bounds.

Pentest focus:

- inactive enum storage;
- skipped secret fields;
- malformed or bypassed helper attributes;
- generic bounds that omit cleanup;
- crate-path substitution and macro hygiene.

Exit criteria:

- unsupported forms fail at compile time with actionable diagnostics;
- the derive pass/fail suite and Miri pass;
- temporary findings are removed after accepted retest and CI is green.

### `CP-09`: Complete ArrayVec Backing Cleanup

Recommended commit message:

```text
CP-09 clear historical arrayvec storage
```

Goal: clear historical inline storage without raw-zeroing live values.

Deliverables:

- sanitize and drop all live elements;
- clear complete post-drop `MaybeUninit<T>` backing storage;
- handle zero-sized types and overflow;
- add an audited unsafe helper only if the stable `arrayvec` API supports the
  required invariant;
- otherwise remove unsupported generic ownership conversion and provide the
  documented narrower API;
- test push, pop, truncate, clear, reuse, and historical spare bytes.

Pentest focus:

- live values overwritten before `Drop`;
- incomplete inline-region coverage;
- invalid assumptions about `ArrayVec` layout or API stability;
- zero-sized and drop-bearing types.

Exit criteria:

- full backing coverage is demonstrated or the claim/API is removed;
- Miri passes;
- temporary findings are removed after accepted retest and CI is green.

### `CP-10`: Canonical Wipe Backend And Fence Policy

Recommended commit message:

```text
CP-10 consolidate wipe backends and naming
```

Goal: establish one clear safe wipe API and one audited internal backend
architecture.

Deliverables:

- expose the canonical safe `sanitization::wipe` module;
- rename the private implementation to `wipe_backend`;
- remove obsolete best-effort, volatile-alias, and misleading unsafe names;
- remove the no-op compatibility feature;
- add the sealed internal erasure backend abstraction;
- benchmark and review compiler versus hardware fence requirements;
- retain 1.x ordering if reduced fencing is not proven;
- keep multi-pass clearing documented as compliance behavior.

Pentest focus:

- paths that no longer reach volatile stores;
- missing ordering barriers;
- public unsafe exposure;
- feature combinations selecting a weaker backend;
- benchmark-driven weakening without evidence.

Exit criteria:

- all public wipe paths reach the reviewed backend;
- any fence change has codegen, target documentation, native evidence, and
  external review;
- temporary findings are removed after accepted retest and CI is green.

### `CP-11`: Cache And Register Hardening

Recommended commit message:

```text
CP-11 harden cache and register controls
```

Goal: make optional cache and register controls capability-aware and honestly
scoped.

Deliverables:

- check x86 cache-flush capability and reported line size;
- provide structured unsupported and failure results;
- always wipe even when eviction is unavailable;
- retain overflow-safe range handling and completion fences;
- refresh x86 and AArch64 register-scrub codegen and documentation;
- document unhandled architectural, ABI-preserved, kernel-saved, and
  microarchitectural state.

Pentest focus:

- illegal instructions;
- incorrect cache-line arithmetic;
- false complete-register claims;
- Windows ABI preservation;
- feature fallback that skips wiping.

Exit criteria:

- unsupported hardware fails or falls back as documented;
- native and codegen evidence covers supported paths;
- temporary findings are removed after accepted retest and CI is green.

### `CP-12`: Protection Request And Runtime Report

Recommended commit message:

```text
CP-12 add explicit memory protection policy
```

Goal: separate requested controls, requirement policy, compiled capability,
and achieved runtime state.

Deliverables:

- add `Requirement`;
- add `ProtectionRequest`;
- add `ProtectionReport`;
- make required failures roll back and return an error;
- permit preferred failures only with an explicit reduced report;
- include partial reports and rollback outcomes in errors;
- include non-secret operational metadata such as mapped and locked bytes;
- update named feature profiles so they request rather than imply controls.

Pentest focus:

- reports marking failed controls established;
- successful constructors after required failure;
- rollback failure suppression;
- sensitive data in errors or reports;
- Cargo features mistaken for runtime success.

Exit criteria:

- every constructor outcome is unambiguous;
- state-transition Kani tests cover request/report logic;
- temporary findings are removed after accepted retest and CI is green.

### `CP-13`: Fork Policy And Checked Integrity

Recommended commit message:

```text
CP-13 make fork and integrity policy explicit
```

Goal: make fork inheritance and canary behavior checked, target-specific, and
non-panicking by default.

Deliverables:

- add explicit inherit, exclude, and wipe-child fork policy;
- implement Linux `MADV_DONTFORK` and `MADV_WIPEONFORK` where available;
- report exact non-Linux behavior;
- make checked canary exposure, mutation, replacement, copy, and comparison
  the normal APIs;
- retain panic helpers only under explicit names;
- clear corrupted secret state before returning;
- preserve deterministic versus random canary claims.

Pentest focus:

- forked child exposure;
- unsupported policy reported as established;
- partial canary comparison leaks;
- corruption paths that return secret data;
- clear-through-shared-reference invariants.

Exit criteria:

- native child-process tests pass where supported;
- integrity errors do not expose partial canary state;
- temporary findings are removed after accepted retest and CI is green.

### `CP-14`: Consume-Once Secret Semantics

Recommended commit message:

```text
CP-14 finalize consume once secret ownership
```

Goal: make one-access secret semantics precise across success, error, panic,
and concurrency.

Deliverables:

- rename or redesign `ReadOnceSecret<T>` as `ConsumeOnceSecret<T>`;
- define whether ownership is moved or scoped;
- prevent a second consumer under races;
- clear unreturned state on failure or panic;
- model atomic transitions with Loom;
- document register, moved-value, and caller-copy limits.

Pentest focus:

- double consumption;
- races between consumers;
- panic before state transition completion;
- leaked unconsumed value;
- incorrect `Send` or `Sync`.

Exit criteria:

- Loom and Miri pass;
- the public name matches actual semantics;
- temporary findings are removed after accepted retest and CI is green.

### `CP-15`: Secure Arena Evolution

Recommended commit message:

```text
CP-15 harden secure arena allocation
```

Goal: improve locked allocation efficiency without introducing stale-handle or
reuse bugs.

Deliverables:

- add generation counters for reusable slots;
- review fixed and variable-size allocation strategy;
- clear before release and before generation reuse;
- report locked-byte efficiency and quota pressure;
- add fault injection and concurrency models;
- defer variable-size allocation if fragmentation and metadata secrecy cannot
  be bounded convincingly.

Pentest focus:

- stale slot handles;
- ABA and double release;
- overlapping allocation;
- metadata corruption;
- uncleared reuse;
- lock-quota accounting.

Exit criteria:

- included arena behavior has Loom/native evidence;
- deferred behavior is removed from stable claims;
- temporary findings are removed after accepted retest and CI is green.

### `CP-16`: Page-Sealed Fixed Secrets

Recommended commit message:

```text
CP-16 add reviewed page sealed secrets
```

Goal: evaluate page-protected fixed secrets without weakening existing mapped
storage.

Deliverables:

- prototype `SealedSecretBytes<N>`;
- keep storage inaccessible outside a scoped access window;
- restore protection on success and unwind;
- define failure behavior when resealing fails;
- keep sanitization fallible rather than implementing infallible clear traits;
- test nested access rejection, signal/error behavior, and drop cleanup;
- defer the type entirely if external unsafe review or target semantics are
  incomplete.

Pentest focus:

- pages left writable;
- unwind paths;
- nested access;
- races and incorrect `Sync`;
- signal-handler and callback reentry;
- failed reseal handling.

Exit criteria:

- external unsafe review passes, or the feature is explicitly deferred from
  2.0 stable;
- the `CP-16` PASS/defer report is committed alone.

### `CP-17`: Experimental Representation And Target Backends

Recommended commit message:

```text
CP-17 constrain experimental erasure extensions
```

Goal: decide and bound the remaining experimental unsafe extension points.

Deliverables:

- evaluate built-in-only `ZeroValidPlainData`;
- require `Copy`, no `Drop`, no pointers/references/provenance, no ownership,
  no interior mutability, and valid all-zero representation;
- evaluate an unsafe target-provided erasure backend for DMA, non-coherent RAM,
  persistent memory, or device-specific cache maintenance;
- keep ordinary RAM, MMIO, DMA, and persistent-memory contracts distinct;
- add Miri and compile-fail coverage;
- defer either extension if a precise stable contract is not available.

Pentest focus:

- invalid all-zero representations;
- pointer provenance destruction;
- raw-zeroing drop-bearing values;
- backends applied to the wrong memory category;
- safe APIs relying on untrusted target implementations for memory safety.

Exit criteria:

- only reviewed built-in representation implementations are stable;
- target backends remain experimental and unsafe if retained;
- the `CP-17` PASS/defer report is committed alone.

### `CP-18`: Feature Profiles And Companion Architecture

Recommended commit message:

```text
CP-18 finalize sanitization feature profiles
```

Goal: make feature sets express compiled capability without overstating
runtime guarantees.

Deliverables:

- finalize named profiles;
- fail known-incompatible strict target/profile combinations at compile time;
- keep WASM compatibility explicitly reduced-guarantee;
- review derive, arrayvec, bytes, and crypto-interop companion boundaries;
- keep optional third-party dependencies out of the default core graph;
- update feature matrix tests and package metadata.

Pentest focus:

- feature combinations that silently weaken a strict profile;
- default dependency regressions;
- no_std and no-alloc regressions;
- companion crates duplicating clearing logic;
- WASM APIs implying unavailable platform protection.

Exit criteria:

- every profile maps to a documented request policy;
- default core remains no_std and dependency-free;
- temporary findings are removed after accepted retest and CI is green.

### `CP-19`: Verification Infrastructure Expansion

Recommended commit message:

```text
CP-19 expand sanitization verification tooling
```

Goal: build the release evidence machinery before collecting final evidence.

Deliverables:

- add path-specific codegen harnesses;
- add the optimization, LTO, panic, compiler, and target codegen matrix;
- add a quarantining allocator;
- add fuzzing and fault injection;
- add ASan, TSan, and UBSan jobs where supported;
- expand Miri, Kani, and Loom coverage;
- add crash/core-dump marker probes where permitted;
- keep tooling dependencies unpublished and outside runtime graphs.

Pentest focus:

- evidence scripts producing false PASS results;
- broad artifact greps that miss the actual public path;
- fault injection that leaves resources established;
- test-only dependencies entering published crates;
- sanitizer exclusions hiding unsafe modules.

Exit criteria:

- tooling fails closed under seeded negative tests;
- each security claim has a named harness;
- temporary findings are removed after accepted retest and CI is green.

### `CP-20`: Target, Timing, And Performance Evidence

Recommended commit message:

```text
CP-20 collect sanitization 2.0 target evidence
```

Goal: collect the exact minimum evidence matrix against the API intended for
release.

Deliverables:

- Tier A x86_64 Linux evidence;
- Tier B native AArch64 Linux, Windows x86_64, and macOS AArch64 evidence;
- compile-only BSD, Android, iOS, embedded ARM, and embedded RISC-V evidence;
- Tier C WASM compatibility evidence;
- multi-seed dudect-style timing runs for every claimed CT primitive;
- default and strict-comparison timing evidence;
- performance baselines and regression thresholds;
- dated target manifests with compiler, feature, and runner metadata.

Pentest focus:

- claims exceeding collected evidence;
- stale or mismatched compiler/commit metadata;
- one-off timing passes presented as guarantees;
- target tiers that imply native testing where only cross-compilation occurred;
- performance changes hiding repeated fences or early exits.

Exit criteria:

- every target and primitive claim maps to current evidence;
- unexplained timing or performance outliers are resolved or claims are
  downgraded;
- temporary evidence-review findings are removed after accepted retest and CI
  is green.

### `CP-21`: Documentation And Downstream Migration

Recommended commit message:

```text
CP-21 document and exercise sanitization 2.0 migration
```

Goal: make the breaking model usable by real downstream projects before API
freeze.

Deliverables:

- complete README and rustdoc updates;
- complete guarantees, non-guarantees, threat model, safety, barriers, targets,
  evidence, leakage, storage-contract, and protection-report documentation;
- add `MIGRATION_2.0.md`;
- document every removed 1.x API and replacement;
- migrate representative cryptographic consumers;
- test generic bounds, derive diagnostics, errors, feature profiles, and
  companion crates from downstream builds;
- snapshot the public API for freeze.

Pentest focus:

- examples using weaker or obsolete paths;
- undocumented breaking behavior;
- docs implying absolute constant time or process-memory secrecy;
- migration copies that create new secret remnants;
- downstream feature combinations missing from workspace tests.

Exit criteria:

- real consumers compile and pass their security tests;
- no removed API lacks a migration example;
- temporary migration-review findings are removed after accepted retest and CI
  is green.

### `CP-22`: API Freeze And Independent Close-Out

Recommended commit message:

```text
CP-22 freeze sanitization 2.0 api
```

Goal: close the complete implementation range before release metadata work.

Deliverables:

- prohibit new major concepts;
- run semver and public-API comparison against 1.2.5 and the `CP-21` snapshot;
- run full independent audit/pentest across `CP-00..CP-22`;
- remediate every finding;
- rerun all native, codegen, Miri, Kani, Loom, sanitizer, timing, package, and
  downstream gates;
- classify any deferred additive feature explicitly.

Pentest focus:

- cross-workstream interactions;
- incomplete migration;
- inconsistent feature/profile behavior;
- stale evidence after remediation;
- unresolved security-model or production-readiness blockers.

Exit criteria:

- no open critical, high, or medium finding;
- no low finding contradicts a guarantee;
- API is frozen;
- the independent close-out is accepted by the project owner and its findings
  are incorporated into the final `v2.0.0` pentest scope.

### `CP-23`: Final 2.0.0 Release Preparation

Recommended commit message:

```text
CP-23 prepare sanitization 2.0.0 release
```

Goal: perform only coordinated release metadata and final documentation work.

Deliverables:

- bump every publishing workspace crate to `2.0.0`;
- update internal dependency versions;
- update README examples and crates.io references;
- add complete 2.0.0 release notes;
- update changelog, release matrix, and release script order;
- validate package contents from generated crate archives;
- run the release script in check/dry-run mode;
- collect a final regression review of the metadata-only range after `CP-22`.

Pentest focus:

- wrong crate versions or dependency ranges;
- missing sister crates;
- package contents differing from reviewed workspace contents;
- stale documentation;
- release script publishing in the wrong order;
- accidental code changes after API freeze.

Exit criteria:

- the implementation commit contains no unreviewed functional change;
- all crates package correctly as `2.0.0`;
- full CI and release gates pass;
- temporary metadata-review findings are removed after accepted retest and CI
  is green.

## Final Release Commit And Tag

After `CP-23` is accepted:

1. Create `security/pentest/v2.0.0.md` reviewing the exact `CP-23` accepted
   implementation state.
2. Commit only that final report.
3. Run full CI, CodeQL, package, evidence, and release-readiness gates.
4. Confirm the release script publishes every changed crate in dependency
   order.
5. Create a signed `v2.0.0` tag at the final report-only commit.
6. Push only when explicitly requested.
7. Publish crates using the reviewed release script.

No functional remediation belongs in the final report commit. Any finding
reopens `CP-23`, requires a remediation commit, a clean retest, and a new final
report-only commit.

## Roadmap Coverage Matrix

| Roadmap area | Commit checkpoints |
|---|---|
| Workstream 0: module split | `CP-01` |
| Workstream 1: contracts and generic ownership | `CP-02`, `CP-03` |
| Workstream 2: exposure and copy reduction | `CP-04`, `CP-05` |
| Workstream 3: aggregates and representations | `CP-02`, `CP-05`, `CP-09`, `CP-17` |
| Workstream 4: data-oblivious API | `CP-06`, `CP-07`, `CP-20` |
| Workstream 5: derive behavior | `CP-08` |
| Workstream 6: ArrayVec | `CP-09` |
| Workstream 7: wipe backend | `CP-10`, `CP-17` |
| Workstream 8: cache and registers | `CP-11`, `CP-20` |
| Workstream 9: native protection | `CP-12`, `CP-13`, `CP-15`, `CP-16` |
| Workstream 10: one-access secrets | `CP-14` |
| Workstream 11: features and crates | `CP-18`, `CP-23` |
| Workstream 12: verification and evidence | `CP-00`, `CP-19`, `CP-20`, `CP-22` |
| Workstream 13: documentation | `CP-21`, `CP-23` |
| Security-model release blockers | `CP-01` through `CP-13`, as applicable |
| Production-readiness blockers | `CP-19` through `CP-23` |
| Optional additive decisions | `CP-05`, `CP-14` through `CP-17` |
| 1.2.x backport decisions | tracked separately before the affected 2.0 checkpoint |

## Completeness Rule

A roadmap item may leave this plan only through one of three outcomes:

1. implemented and accepted in its assigned checkpoint;
2. explicitly deferred with rationale, removed stable claims, and a named
   future issue or roadmap entry;
3. rejected because its security contract cannot be made credible.

Silently omitting an item is not an accepted outcome. Before `CP-22`, compare
the implementation against this matrix and the complete stable-scope lists in
`ROADMAP_2.0.0.md`.
