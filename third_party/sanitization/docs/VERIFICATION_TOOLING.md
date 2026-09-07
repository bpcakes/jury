# Verification Tooling

CP-19 adds evidence machinery. It does not promote target tiers or replace an
independent review. CP-20 uses these harnesses to collect dated target evidence.

The machine-readable registry is `docs/verification-harnesses.json`.

## Declassification And Export Review Gate

`scripts/lint-declassification-reasons.py` lexes every tracked Rust source and
checks method-style and UFCS calls to CT declassification methods, calls to the
high-level `declassified_*` CT boundaries, and the core fixed-secret `export_*`
methods. Consumer boundaries must provide a direct string literal with enough
context to identify a public, test, verification, wire, return, or reporting
boundary. The gate rejects dynamic and macro-generated reasons, short generic
labels, and placeholder words such as `todo`, `fixme`, and `tbd`.

The core CT and owned-secret implementations have a narrow allowlist for
forwarding a public method's already-supplied `reason` argument to nested
owners. No consumer source is allowed to forward a dynamic reason. Both the
lint and its negative fixtures run in `scripts/checks.sh`.

This is intentionally a source-review aid, not authorization machinery. It
cannot determine whether a convincing sentence states a valid disclosure
policy, detect a declassification method hidden behind a function pointer, or
prove that a reviewer examined the boundary. High-assurance review must still
search for declassification and export calls and assess each reason against
application policy.

## High-Assurance Storage Policy Gate

`scripts/lint-storage-policies.py` lets downstream applications designate
sensitive Rust roots, private policy files, and the only files permitted to
implement storage-stability markers. It rejects direct generic `Secret<T>`
usage, marker implementations outside that explicit list, and policy types
broader than private or `pub(crate)`. It also rejects `mem::forget`,
`Box::leak`, and `ManuallyDrop` in sensitive roots so reviewed owners cannot
bypass destructor cleanup through ordinary source.
`scripts/test-storage-policy-lint.py` provides positive and fail-closed
fixtures, and `scripts/checks.sh` runs both the fixtures and the compile-checked
policy example.

The lint is deliberately dependency-free and lexical. It complements the
compiler-enforced `AllowlistedSecret` policy but cannot prove marker semantics
or fully interpret generated Rust. Downstream repository review must control
the scanned roots, exemptions, generated source, and policy-file ownership.

## Fail-Closed Initialization Gate

`scripts/lint-fail-closed-initialization.py` rejects `try_*` results discarded
through `drop(...)`, `.ok()`, or an unhandled underscore binding, and calls to
the lossy pool `allocate()` helper in production roots. This keeps allocation,
CSPRNG, generator, length, and integrity failures observable rather than
collapsing them into ignored results or apparent exhaustion. Rust's `Result`
is already `must_use`; the source gate addresses explicit warning-suppression
forms that `must_use` cannot prevent. The core check excludes the crate's
fault-injection test module; downstream projects should point it at every
production source root that can initialize hardened storage.

`scripts/test-fail-closed-initialization-lint.py` verifies accepted checked
propagation and fail-closed behavior for both prohibited forms. The gate is
lexical and conservative, so human review remains responsible for aliases,
re-exports, macro expansion, data flow after an ordinary named binding, and
unsafe or generated code. An AST-aware compiler plugin may complement this
gate downstream, but is not required by the dependency-free core workflow.

## Path-Specific Codegen

`tools/direct-exposure-codegen` exports named downstream functions for:

- direct and copied fixed-secret exposure;
- `SecretBoxBytes`, `SecretVec`, and `SecretString` clearing;
- locked, guarded, pooled, and sealed clearing;
- derive-generated struct cleanup and reviewed manual enum cleanup;
- tuple and `sanitization-arrayvec` cleanup;
- CT equality, ordering, conditional copy/swap, and oblivious lookup.

`scripts/verify-codegen-artifact.py` extracts each exact function body from
LLVM IR. It does not accept a matching symbol elsewhere in the artifact as
evidence for the public path.

`scripts/verify-codegen-matrix.sh` covers:

| Variant | Optimization | LTO | Codegen units | Panic |
| --- | --- | --- | --- | --- |
| `opt2-many-unwind` | 2 | off | 16 | unwind |
| `opt3-one-unwind` | 3 | off | 1 | unwind |
| `opts-thin-unwind` | s | Thin | 1 | unwind |
| `optz-fat-abort` | z | Fat | 1 | abort |

Compiler and target expansion belongs to CP-20 because those runs need dated
runner metadata.

## CP-20 Target Evidence

`.github/workflows/cp20-evidence.yml` produces per-commit artifacts in three
separate classes:

- native functional, codegen, and relative-performance evidence on x86_64
  Linux, AArch64 Linux, x86_64 Windows, and AArch64 macOS;
- multi-seed default and `strict-compare` leakage evidence on x86_64 Linux,
  AArch64 Linux, and AArch64 macOS;
- explicitly compile-only manifests for BSD, Android, iOS, embedded ARM,
  embedded RISC-V, and Tier C WASM targets.

`scripts/capture-target-evidence.py` rejects a native label unless the target
triple equals the active rustc host triple. Each manifest records the UTC
date, commit, dirty state, compiler, runner, feature set, evidence class, and
workflow URL. `scripts/verify-target-evidence.py` validates those manifests
and rejects dirty, failed, mismatched, unhashed, or incomplete evidence.

`scripts/collect-leakage-evidence.py` requires at least three distinct seeds
for both the default and strict-comparison variants. Every raw report is
hashed into its summary. A failed primary run triggers exactly two fresh
same-seed confirmations for diagnosis, but the primary failure always fails
the release gate. Confirmation results never erase or accept a threshold
excursion. This provides repeated target-specific evidence for review; it does
not convert statistical evidence into a universal timing guarantee.

`tools/performance-baseline` uses relative thresholds rather than absolute
nanosecond limits. It detects pathological large-wipe scaling and ensures the
specialized bulk wipe and `SecretBytes` paths remain materially separate from
the intentionally slower per-element generic-array path. Performance evidence
cannot authorize weakening fence policy by itself.

## Allocation Quarantine And Fault Models

`tools/lifecycle-probes` installs a test-only allocator that delays
deallocation. This keeps released blocks allocated and readable so tests can
search them for full secret markers after `SecretVec` growth and drop.

This allocator deliberately leaks quarantined test allocations. It must never
be used in production and is excluded from the publishable workspace.

The same tool enumerates required setup failures for mapping, dump exclusion,
fork policy, locking, protection, random generation, and cache policy. This is
a deterministic state-transition model. It verifies rollback expectations but
does not replace native syscall-failure tests.

## Fuzzing

The unpublished `fuzz` package contains:

- `owned_lifecycle`: growth, replacement, bounded serde input, UTF-8
  conversion, and acknowledged enum transitions;
- `ct_primitives`: equality, ordering, conditional copy/swap, and oblivious
  lookup functional stress.

CI runs short smoke campaigns. Longer, seeded campaigns and retained corpora
belong to release evidence rather than ordinary unit testing.

## Sanitizers

`.github/workflows/security-evidence.yml` runs x86_64 Linux AddressSanitizer and
ThreadSanitizer jobs through `scripts/verify-sanitizer.sh`.

Rust nightly currently exposes ASan and TSan modes used here. The project does
not claim a general Rust UBSan job: rustc does not currently provide a
corresponding supported `-Zsanitizer=undefined` workflow. Miri, Kani, native
tests, and explicit arithmetic checks cover different portions of that space,
but are not described as UBSan.

Sanitizer success is evidence only for the compiled target and feature set. It
does not exercise unsupported targets or prove syscall semantics.

## Formal And Concurrency Checks

Miri additionally covers `sanitization-bytes`, the crypto companion paths, and
the fixed, dynamic, text, and pooled native locked-container lifecycle through
a core-unit-test-only `cfg(all(miri, test))` aligned-allocation model. The model
verifies complete clearing before deallocation but does not execute or validate
OS syscalls, page permissions, locking, dump/fork policy, or CSPRNG behavior.
Downstream Miri execution of mapped constructors remains unsupported. Portable
comparison code is selected under Miri even in downstream builds and has a
dedicated integration test.
Kani includes complete fixed-secret replacement in addition to clearing,
comparison, capacity, and protection-report properties.

The Miri workflow runs the core all-feature lifecycle suite as library unit
tests so the private model is available. Derive integration tests and companion
crate tests run with portable comparison features; their dependency build does
not receive the core crate's `cfg(test)`, so executing native comparison
assembly there would be unsupported by Miri.

`scripts/verify-miri-test-gates.py` rejects production source gates where
`miri` can change protection behavior without `test`, verifies every mapped
simulator has the native `not(all(miri, test))` complement, compiles a normal
release library with a manually supplied `--cfg miri`, and verifies that a
release build forging both `cfg(miri)` and `cfg(test)` is rejected. Comparison
is the deliberate exception: Miri always selects the portable implementation,
which provides interpreter compatibility without simulating an OS protection.
The release helper also refuses ambient Rust flags and records those channels
in evidence. These checks assume a trusted compiler invocation.

The Loom model covers:

- competing consume-once accessors;
- pool allocation, clearing, generation, and reuse.

The unpublished Loom harness hand-mirrors the production atomic orderings; it
does not compile the production types under `loom`, so ordering changes require
an explicit synchronized review of the harness. `SealedSecretBytes` ordinary
reentry is prevented by `&mut self` and its lifetime-bound access guard rather
than an atomic state machine, and is therefore outside Loom's scope.

Kani is not concurrency evidence. Loom models atomics but not kernel behavior.

## Core-Dump Marker Probe

`scripts/verify-core-dump-probe.sh` is opt-in because hosted CI commonly pipes
or suppresses core dumps. On a permitted Linux runner with a relative
`core_pattern`, set:

```bash
SANITIZATION_RUN_CORE_DUMP_PROBE=1 scripts/verify-core-dump-probe.sh
```

The probe derives a process-specific marker directly into locked storage,
aborts, and searches the resulting core file. A missing core file is a failure
when the probe was explicitly requested.

## Fail-Closed Tests

`scripts/test-verification-fail-closed.py` seeds malformed evidence and an
incomplete LLVM artifact. Both validators must reject those fixtures.

`scripts/test-declassification-reasons.py` separately proves that placeholder,
generic, dynamic, macro-generated, UFCS, and high-level helper reasons fail
closed while meaningful literal boundaries remain accepted.

`scripts/verify-verification-harnesses.py` also ensures:

- harness names are unique;
- referenced scripts exist;
- every tool and fuzz package is `publish = false`;
- tooling has not entered the publishable workspace.

## Release Package Archives

`scripts/verify-release-packages.py` packages the complete workspace together
so not-yet-published internal 2.0 dependencies resolve without weakening their
crates.io version requirements. It then inspects each generated `.crate`
archive and requires:

- all five packages use the coordinated release version;
- normalized internal dependencies require that same version and contain no
  local path;
- every packaged source, test, example, original manifest, and README matches
  the reviewed workspace bytes;
- no unexpected files, symbolic links, parent paths, repository tooling,
  security reports, or temporary pentest input enter an archive.

The verifier does not replace Cargo's build verification during publication.
It proves that the archive contents handed to that later step match the
reviewed release tree.
