# Deliver J14 transparent exec and brokered run

This ExecPlan is a living document and must be maintained in accordance with
`.agent/PLANS.md`. It completes Beads task `jury-qv4.3.3` from Git baseline
`3571ff806b4f7666318a81247c923554e6cb3f6d`. The current working tree already
contains the completed but uncommitted J13 implementation, so every J14 edit
must preserve and build on those changes. This plan is the only new process
artifact: its concrete consumer is the native Linux `jury` execution feature,
it gates J22 witnessed execution and J25 adversarial assurance, it addresses
pre-spawn authorization and descendant-leak defects, and it is deleted or
archived when the bead closes.

## Purpose / Big Picture

After J14, a Linux operator can run a command with selected Jury fields
delivered through environment variables, standard input, or anonymous
file-descriptor-backed paths. `jury exec` is the transparent form: it inherits
ordinary environment and stdin unless explicitly replaced and streams the
child's redacted stdout and stderr. `jury run` is the brokered form: it begins
with a cleared environment, accepts only explicit field mappings, uses bounded
captured output and a timeout, and returns a stable result. Both forms resolve
and authorize every field against one already authenticated vault revision
before any child starts, supervise the whole Linux process group, and preserve
the direct child's exact code or signal.

The user-visible proof is an end-to-end fixture in
`crates/jury/tests/native_cli/` that creates generic fields, runs child and
grandchild probes, and observes exact delivery, redaction, status, timeout,
signal, no-child-before-authorization, zero core limit, and file-descriptor
hygiene behavior. Jury remains externally unreviewed pre-alpha and unsuitable
for real secrets; an authorized child can retain plaintext.

## Progress

- [x] (2026-09-01 07:07Z) Verify `jury-qv4.3.3` is dependency-ready, claim it,
  and start a Jig work session at the exact repository baseline.
- [x] (2026-09-01 07:09Z) Read `AGENTS.md`, `agent-map.md`, the crate guides,
  `.agent/PLANS.md`, the J14 master-plan sections, current J12/J13 APIs, and
  verify every named legacy source path at pinned Jig commit
  `eed70cee337b0067ed92deb9fa05017b0b284605`.
- [x] (2026-09-01 07:34Z) Add the neutral protected-stdin and unbounded-streaming
  supervision extension to `jury-process`; all 33 process tests pass without
  weakening cleanup, output, timeout, cancellation, or signal contracts.
- [x] (2026-09-01 07:41Z) Add the bounded execution manifest, restricted dotenv/reference parser,
  executable/working-directory pinning, protected value resolution, anonymous
  file delivery, child descriptor scrub, and command digest implementation.
- [x] (2026-09-01 07:41Z) Add `jury exec` and `jury run` parsing, dispatch, stable outputs/errors,
  exact process status propagation, and local audit outcomes.
- [x] (2026-09-01 08:02Z) Port the hostile and end-to-end cases required by
  J14. The expanded native CLI scenario passed binary delivery, mixed-denial
  no-spawn, reserved-env and descriptor stripping, redaction/persistence scans,
  output caps, timeout cleanup, real-signal cleanup, and exact statuses.
- [x] (2026-09-01 09:04Z) Audit every J14 bead and master-plan requirement,
  update the pre-alpha documentation, inspect the final diff, and run fresh
  plan-scoped gates. Batch `receipt_01M1E2YV0P38J61HVG7H3WT489` executed all
  five checks with no reuse and no failures.
- [x] (2026-09-01 09:21Z) Close `jury-qv4.3.3` as completed, flush the
  beads_rust tracker export, and refresh the final closed-tracker gate evidence
  as batch `receipt_01M1E3Y01XNJVDS08G4KFRB3TX`. Finish the Jig work session
  without committing or pushing.

## Surprises & Discoveries

- Observation: J12 already proves Linux process-group ownership, descendant
  termination, bounded drains, redaction, cancellation, and synthetic signal
  forwarding, but its output API closes a piped stdin and requires an overall
  deadline. J14 therefore needs a narrow neutral extension, not a second
  process owner.
  Evidence: `crates/jury-process/src/process.rs` routes all output runs through
  `spawn_owned_process`, `OwnedProcessOutputDrains`, and
  `finish_owned_process_wait`.
- Observation: J13 resolves bodies through `ItemAccessProvider`, but returns
  `ItemStateV1` heap values. J14 must finish all item/field preflight first,
  copy only selected values into page-dedicated `ProtectedMemory`, clear the
  decrypted bodies, build redaction, and only then spawn.
  Evidence: `crates/jury/src/cli/context.rs::open_item_body` and
  `crates/jury-protocol/src/vault_v1/plaintext.rs::ItemStateV1::clear_sensitive`.
- Observation: inherited non-close-on-exec descriptors are outside Rust
  `Command`'s default hygiene. The safe `close_fds` 0.3.2 API can mark every
  unapproved descriptor close-on-exec inside a short helper process before the
  helper replaces itself with the pinned executable; this keeps Jury source
  under `unsafe_code = "forbid"`.
  Evidence: the crate exposes safe `CloseFdsBuilder::cloexecfrom`, while its
  direct close operation is intentionally unsafe.
- Observation: J13's protected-memory helper allocated exactly the input
  length, but `ProtectedMemory` correctly rejects a zero-capacity mapping.
  Empty literal execution values therefore exposed a pre-existing adapter edge
  case before spawn.
  Evidence: `crates/jury/src/cli/support.rs::protect` now allocates a minimum
  one-byte page-backed capacity while retaining a logical length of zero.
- Observation: restricted public env files pass through the hardened public
  file reader, so a test-created file retains a private `0600` umask mode and
  is intentionally rejected until it is made checkout-like `0644`.
  Evidence: the first end-to-end run failed before spawn with
  `filesystem-error`; after setting only the fixture's public mode, the same
  scenario passed through exact exit code 37 and brokered delivery.
- Observation: Jury's dependency-boundary test rejects external product routing
  literals in production source, and the repository rule forbids a Jig runtime
  dependency. The initial inherited-environment filter included `JIG_*`; the
  correct fix was to remove all Jig recognition rather than weaken or evade the
  boundary test. Transparent execution strips only Jury-owned `JURY_*` names.
  Evidence: `cargo test -p jury-core --test dependency_boundary` and the final
  contract gate pass with no Jig crate or routing literal in production code.
- Observation: the first integrated execution corpus pushed
  `crates/jury/tests/native_cli.rs` over the hard Rust file-size gate. The
  cohesive J14 helpers and scenarios now live in
  `crates/jury/tests/native_cli/execution.rs`; no limit, assertion, or test was
  weakened.
  Evidence: final `jig.rust_file_loc` receipt
  `receipt_01M1E2GH4WXQV59X7DKDVGPGT3` passes; the root scenario file is 787
  lines and the execution module is 467 lines.
- Observation: reopening the hidden descriptor-scrubbing helper through
  Jury's filesystem pathname would leave a pathname-replacement race. The
  Linux adapter now re-enters the already-running image through
  `/proc/self/exe`, which is consistent with its existing procfs requirement
  for pinned targets and anonymous-file delivery.
  Evidence: the post-change unit suite and a direct helper smoke test preserve
  the pinned `/tmp` working directory and exact exit code 37; the fresh full
  gate batch passes.

## Decision Log

- Decision: Keep transparent exec and brokered run as distinct CLI and process
  contracts.
  Rationale: Transparent exec must preserve inherited stdin/environment and raw
  streaming, while brokered run must clear the environment, bound capture, and
  enforce timeout; collapsing them would weaken one contract or overconstrain
  the other.
  Date/Author: 2026-09-01 / Codex.
- Decision: Resolve all distinct item names from one parsed vault/context and
  open each selected body at most once before constructing any `Command`.
  Rationale: This is the current mode-neutral `ItemAccessProvider` seam and
  gives no-child-on-any-failure behavior without duplicating direct-versus-
  witnessed policy logic. J22 can later supply a witnessed provider without
  changing the delivery layer.
  Date/Author: 2026-09-01 / Codex.
- Decision: Use Linux anonymous `memfd` objects for controlled file delivery,
  exposed to the child as `/proc/self/fd/N`, rather than persistent temporary
  plaintext files.
  Rationale: J14's active platform is Linux; anonymous descriptors provide a
  bounded explicit sink, support binary fields, leave no named plaintext file,
  and can be sealed read-only before spawn. The authorized child may still copy
  or retain their contents, which output and documentation must state.
  Date/Author: 2026-09-01 / Codex.
- Decision: Resolve the executable and working directory before private
  capture, hold an opened executable descriptor across the helper, and digest
  canonical executable identity, exact argument bytes, working directory,
  mapping names/modes, and non-secret placeholders only.
  Rationale: This validates paths early, avoids PATH or filesystem replacement
  between authorization and spawn, keeps secrets out of the digest, and gives
  J22 a stable command-normalization input while explicitly retaining Linux's
  weaker script/interpreter semantics.
  Date/Author: 2026-09-01 / Codex.
- Decision: Pin the canonical working directory with an inherited descriptor,
  then make that descriptor close-on-exec after the trusted helper uses
  `/proc/self/fd/N` for its final `chdir`.
  Rationale: Reopening a canonical path after authorization leaves a rename or
  replacement race. The descriptor binds the directory inode while avoiding a
  descriptor leak into the authorized target.
  Date/Author: 2026-09-01 / Codex.
- Decision: Canonically sort environment and file destinations and include the
  broker timeout plus output-retention limit in the execution digest.
  Rationale: Mapping order is not child-visible behavior, while timeout and
  retained-output bounds are security-relevant action dimensions that J22 must
  not accidentally authorize interchangeably.
  Date/Author: 2026-09-01 / Codex.

## Outcomes & Retrospective

The J14 implementation is complete and its code evidence is green. Transparent
`jury exec` atomically resolves exact placeholders, inherits ordinary
environment/stdin while removing `JURY_*`, optionally supplies protected stdin
and sealed anonymous files, streams independently redacted stdout/stderr, and
mirrors the target status. Brokered `jury run` starts from its bounded allowlist,
accepts only explicit field mappings, supplies EOF or protected stdin, captures
separately capped redacted output under an explicit timeout, and mirrors the
target status. Both use the J12 process-group owner and the same direct
`ItemAccessProvider` seam that J22 can later place behind witnessed authority.

Runtime evidence covers mixed accessible/missing references with no child
marker, invalid binary environment delivery with no child, reserved environment
and unrelated-descriptor stripping, binary stdin and sealed-file delivery,
concealed raw output redaction, exact exit 37, output truncation, zero inherited
core limit, timeout cleanup, real SIGTERM status 143, child/grandchild absence,
and recursive persistence scans. Process-level tests additionally cover stdin
refusal, cancellation, output failure/overflow, cleanup races, binary-safe
capture, split-boundary redaction, and independent stream state. The final
plan-scoped batch is `receipt_01M1E2YV0P38J61HVG7H3WT489`: contract
`receipt_01M1E2GGVCDKYAZC6Y86S07FR5`, file LOC
`receipt_01M1E2GH4WXQV59X7DKDVGPGT3`, format
`receipt_01M1E2GHR05JPE2Z3X8NSMWKV1`, clippy
`receipt_01M1E2GKCYMWHDRYASZTZSDX7W`, and full workspace tests
`receipt_01M1E2YQG3RS2SR2EASANFDTQT`.

After tracker closure, the complete gate set was executed once more so the
finished work is tied to the exported closed-bead state. Final batch
`receipt_01M1E3Y01XNJVDS08G4KFRB3TX` passed contract
`receipt_01M1E3FNE1PW91KWG1KX1D5TNF`, file LOC
`receipt_01M1E3FNQ4RH5095KJ7KW4BS2F`, format
`receipt_01M1E3FPAVZ88Y8ZWWB7XCQE1M`, clippy
`receipt_01M1E3FPMF6CYNKGX7Y3QGKMXJ`, and full workspace tests
`receipt_01M1E3XWVVNHQ38364XTRQJPSX`, with zero reused or failed checks.

Bead `jury-qv4.3.3` closed as completed at 2026-09-01 09:05Z and the tracker
export was flushed before final Jig closure. Jury is still an externally
unreviewed pre-alpha scaffold that does not protect secrets. J14 is direct
execution only: witnessed authorization remains J22, the executable identity
is intentionally weaker than content-stable identity, an authorized child can
retain plaintext, a process that deliberately escapes the owned group is
outside the guarantee, and uncatchable parent termination is an OS limit. No
commit or push was made.

## Context and Orientation

`crates/jury/src/cli.rs` defines the native Clap grammar and imports bounded
adapter helpers. `crates/jury/src/cli/dispatch.rs` selects a command handler.
`crates/jury/src/cli/context.rs` authenticates the selected vault and identity,
checks the local rollback checkpoint, discovers descriptors visible to that
identity, and opens an exact item body through the direct implementation of
`jury_core::access_provider::ItemAccessProvider`. That trait is called
mode-neutral because its caller sees the same exact revision and protected
consumer boundary whether authority is direct today or witnessed in J22.

`crates/jury-process/src/process.rs` is the neutral J12 process owner. On Linux
it creates a new process group, keeps the direct child unreaped while signaling
the pinned group, terminates every descendant, proves the group quiescent, then
reaps the leader. Its output drains are nonblocking and bounded. A process
observer receives already-redacted chunks and can request cancellation or one
forwarded signal. J14 must compose this owner rather than calling
`std::process::Command::status`, `output`, or `wait` directly.

A transparent execution is `jury exec --env-file FILE -- COMMAND [ARG...]`.
The restricted dotenv file is bounded UTF-8 with exact `NAME=VALUE` lines. A
value that is exactly `{{Item.Field}}` is a Jury field placeholder; a literal
uses the restricted quoting and escaping rules described in the parser module.
No interpolation, command substitution, NUL, duplicate variable, invalid name,
or `JURY_` destination is accepted. The transparent child inherits ordinary
environment and stdin, except that every inherited `JURY_` variable is removed
and explicit bindings override non-reserved names. Optional `--stdin
Item.Field` replaces inherited stdin. `--file NAME=Item.Field` adds an explicit
anonymous file path through that environment name. `--json` is rejected because
stdout and stderr are the child's raw streaming protocol.

A brokered execution is `jury run --env NAME=Item.Field --file
NAME=Item.Field --stdin Item.Field --timeout SECONDS -- COMMAND [ARG...]`.
It accepts no literal secret input, starts from an empty environment, restores
only a minimal non-secret execution allowlist such as `PATH`, `HOME`, and
`LANG`, and rejects secret mappings to every preserved or `JURY_` name. With no
stdin mapping the child receives EOF. It captures at most the public configured
stdout/stderr limits, redacts concealed values across chunk boundaries, times
out and kills the complete group, and reports exact code/signal plus truncation.

An execution manifest means the bounded, secret-free description of the exact
action. It contains the opened executable identity, argument bytes, canonical
working directory, destination variable names, typed field placeholders,
stdin mode, file modes, output contract, and platform assurance. Its SHA-256
digest is not authorization by itself; direct J14 uses it for audit and tests,
and J22 later binds it into witnessed authorization.

The pinned legacy source at
`../jig-sh@eed70cee337b0067ed92deb9fa05017b0b284605` is behavior provenance
only. J14 reuses all-or-nothing resolution, restricted dotenv parsing,
credential stripping, streaming independent redaction, bounded broker output,
timeout, signal/status, cleanup, and hostile tests. It does not import Jig
types, runtime dependencies, v2 unlocking, `jig://` references, or plaintext
delivery.

## Plan of Work

First extend `jury-process` with one execution-options API that can accept
optional protected stdin, an optional overall deadline, existing output limits
and redaction, and an observer. Its supervision loop nonblockingly advances
stdin alongside stdout/stderr so a child that refuses input cannot deadlock the
parent. It must close stdin after the final byte, discard remaining input on
every failure, terminate the process group before reaping, and return the exact
existing output/status type. Existing public functions remain wrappers so J12
callers and tests retain behavior.

Next add `crates/jury/src/cli/execution_commands.rs` for the bounded execution
contract, Linux delivery primitives, parsing, and orchestration. Keeping these
crate-private types beside the native adapter avoids claiming a stable library
API before J22 supplies its witnessed manifest types. The public preflight resolves the working directory and
executable before identity unlock. The private preflight builds an accessible
catalog, rejects any missing item before opening bodies, opens each body once,
validates every field, copies selected values into protected pages, clears body
state, constructs redaction only from concealed fields, creates and seals
anonymous file descriptors, and builds environment or stdin delivery. No
`Command` exists before this function succeeds.

The spawned command is a hidden internal Jury helper whose argv contains only
the secret-free pinned action. The helper marks every descriptor at or above
three close-on-exec except the pinned executable and explicitly mapped memfds,
then replaces itself with the pinned executable. The parent adds environment
values only after authorization, clears or filters the inherited environment
according to exec/run mode, and streams or captures through `jury-process`.
Signal-hook's nonblocking pending iterator feeds J12's existing observer signal
seam. Terminal state remains owned by the existing passphrase echo guard; the
process command adds no terminal mode changes.

Finally wire Clap, dispatch, outputs, error classes, and audit. A denied or
failed preflight records a value-free local `ExecuteOrInject` outcome when an
authenticated context exists and never names a guessed inaccessible item. A
spawned execution records the exact manifest operation ID and success,
cancellation, timeout, or process failure without values, argv, paths, or
captured bytes. Child nonzero exit is an execution result, not a Jury failure;
`jury exec` exits with the portable child status while `jury run` emits its
stable bounded result and mirrors that status.

## Concrete Steps

All commands run from `/home/aa/Documents/jury`.

Implement and exercise the process extension first:

    cargo test -p jury-process --all-targets

Expect all existing J12 tests plus new stdin progress, stdin refusal, streaming,
timeout, cancellation, and exact-status tests to pass. No existing public J12
test may be removed or weakened.

Then implement the execution contract and parser, followed by focused CLI
tests:

    cargo test -p jury --test native_cli \
      fresh_repository_identity_vault_and_public_status_flow -- --nocapture
    cargo test -p jury --all-targets

Expected fixtures include `ExampleVault`, `ExamplePrincipal`, and
`ExampleSecret` only. Before successful implementation, the parser has no
`exec` or `run` subcommand. After implementation, `jury exec --help` describes
raw streaming and `jury run --help` describes bounded brokered output; both
repeat the pre-alpha warning through root help.

Run the repository contract after focused tests:

    scripts/jig work check
    scripts/jig check fmt
    scripts/jig check clippy
    scripts/jig check test
    scripts/jig check contract

Inspect `git diff --check`, `git diff --stat`, and the complete J14 diff. Record
the final receipt IDs in this plan. Do not regenerate expected output or widen
limits merely to make tests pass. Do not commit or push unless the operator
explicitly asks.

## Validation and Acceptance

Acceptance requires direct runtime evidence, not only compilation. A successful
transparent case must deliver accessible text and concealed fields through
multiple channels, inherit a benign environment variable and stdin when not
overridden, replace stdin when requested, stream arbitrary binary stdout
unchanged, redact concealed raw and encoded values split across chunk
boundaries independently on stdout and stderr, and return the child's exact
nonzero code or conventional signal code.

A successful brokered case must deliver UTF-8 environment values, binary stdin,
and sealed anonymous-file bytes, prove that ambient and all `JURY_` variables
are absent, prove an unrelated deliberately non-close-on-exec descriptor is not
visible after the helper exec, return bounded stdout/stderr with truncation or
typed overflow behavior, and kill a child plus grandchild on timeout or signal.
The child must observe `RLIMIT_CORE` soft and hard limits of zero. A fork probe
must not find the parent's protected mapping; the existing `jury-protected`
provider tests remain the authoritative mapping-control evidence.

For atomic failure, a request containing one accessible and one denied or
missing reference must return the same value-free unavailable error, create no
marker, produce no child output or controlled file, and never reveal the
guessed selector or any selected value. Invalid dotenv, variable names,
duplicate/conflicting destinations, executable, working directory, JSON/raw
mode, timeout, NUL/UTF-8 environment value, redaction limit, memory protection,
and memfd setup failures must all occur before spawn. Strict protection failure
has no ordinary heap fallback; only the existing explicit
`--allow-degraded-protection` policy may proceed with a visible degraded fact.

The dependency graph must contain no Jig crate. README and help must say that
Jury is pre-alpha, does not protect secrets, and that an authorized child may
retain plaintext. Completion additionally requires a requirement-by-
requirement audit of the J14 bead and master-plan section, with every item tied
to a test or direct command observation.

## Idempotence and Recovery

All parser, preflight, digest, and failed-resolution operations are read-only
apart from bounded local audit outcomes. Retrying them does not create a child
or shared artifact. Anonymous memfds have no filesystem name and close when
the parent and child release them. J12 terminates and proves the owned group on
every supervised return path, including timeout, cancellation, output,
signal-forwarding, and cleanup failures. Uncatchable parent termination remains
an operating-system limit and is not presented as a cleanup guarantee.

The worktree is intentionally dirty with completed J13 changes. Never reset,
checkout, or rewrite those changes. If a J14 test exposes a J13 defect, make the
smallest behavior-preserving correction and record it in Surprises &
Discoveries. Jig state files are append-only. Tracker mutations use `br` only
and are flushed with `br sync --flush-only`. If validation stops midway, resume
from this plan and `scripts/jig work status`; do not create a replacement plan
or restart the bead.

## Artifacts and Notes

Exact legacy object availability was proven before implementation:

    git -C ../jig-sh cat-file -e \
      eed70cee337b0067ed92deb9fa05017b0b284605:crates/jig-vault/src/exec.rs
    # exit 0; every J14-named path was checked the same way

Current J12 and J13 evidence at plan creation was green in the preceding work
session, but J14 completion requires fresh gates over the combined tree.

Final fresh evidence over the combined tree:

    scripts/jig work check --plan-id plan_01M1DX02GWZF3HX8CZTSNJ4RAM
    # passed; batch receipt_01M1E2YV0P38J61HVG7H3WT489

All five configured checks executed rather than reusing prior receipts. The
workspace test receipt includes 18 Jury library tests, four native CLI tests,
82 jury-core tests, 33 jury-process tests, 27 jury-protected tests, remaining
workspace suites, and doc tests with zero failures.

Final evidence after the completed bead export:

    scripts/jig work check --plan-id plan_01M1DX02GWZF3HX8CZTSNJ4RAM
    # passed; batch receipt_01M1E3Y01XNJVDS08G4KFRB3TX

## Interfaces and Dependencies

`jury-process` must retain all current public wrappers. Add one options-based
entrypoint whose inputs name optional deadline, protected stdin, output limits,
overflow policy, redaction, and observer; its result remains
`OwnedProcessTreeOutput` and its errors remain value-free
`OwnedProcessTreeError` variants, with a specific stdin-delivery class if
needed. Output callbacks receive post-redaction bytes only.

`crates/jury/src/cli/execution_commands.rs` defines bounded manifest and
delivery types with custom value-free `Debug`. Required conceptual types are `ExecutionMode`
(`Transparent` or `Brokered`), `FieldReference` (typed item plus field),
`EnvironmentBinding`, `FileBinding`, `StdinBinding`, `NormalizedCommand`,
`ExecutionManifest`, `ProtectedFieldValue`, and `ExecutionOutcome`. Exact names
may change while implementing, but every final type must keep secret bytes out
of Serde, errors, digests, and `Debug`.

Linux delivery uses pinned `rustix` for memfd creation, permissions, seals, and
descriptor flags; `close_fds = 0.3.2` for safe descriptor close-on-exec
scrubbing in the helper; and `signal-hook = 0.4.4` for pending Unix signals.
`jury` adds a path dependency on `jury-process`. All third-party versions are
exactly pinned. No Jig crate or runtime enters any Cargo manifest.

Plan revision note (2026-09-01): replaced the initial one-line Jig work-plan
placeholder with the complete J14 implementation and verification contract
after reading the repository spec, current code, and exact pinned legacy
sources.

Plan revision note (2026-09-01 07:48Z): recorded the implemented API locations,
focused test evidence, hardened-public-file and empty-value discoveries, and
the explicit uncatchable-parent-termination limit before the adversarial CLI
run.

Plan revision note (2026-09-01 08:05Z): recorded the green hostile CLI corpus,
descriptor-pinned working directory, canonical mapping order, and digest-bound
broker timeout/output limits before repository-wide gates.

Plan revision note (2026-09-01 09:04Z): recorded the dependency-boundary and
file-size discoveries, hardened the helper re-entry against pathname
replacement through `/proc/self/exe`, audited J14 requirement evidence and
non-guarantees, and attached the fresh all-executed final gate receipts before
tracker and work-session closure.

Plan revision note (2026-09-01 09:05Z): recorded the completed and flushed J14
bead before refreshing the tracker-sensitive gate evidence and closing the Jig
work session.

Plan revision note (2026-09-01 09:21Z): attached the all-executed, all-passing
gate batch over the final closed-bead export before Jig plan closure.
