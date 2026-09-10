# M04: native macOS process containment

Consumer: M05/M07 native launch implementers and managed child execution.
This recovery plan gates M04 against missed group members, stale numeric
signaling, erased primary failures and late cleanup proofs. Keep it until
acceptance evidence is complete, then archive it. Baseline: `6881359`.
Task: `jury-qv4.3.4`, activated by the operator on 2026-09-10.

## Progress

- [x] Research Darwin snapshot completeness and native wait ownership.
- [x] Replace count-then-allocate membership with a checked fixed-capacity query.
- [x] Require fresh wait ownership before direct-child fallback signaling.
- [x] Preserve the primary operation error alongside failed cleanup.
- [x] Add native wait, descendant-handshake, churn and malformed-response tests.
- [x] Pass local arm64 process tests, provider tests and Clippy, including
  provider Rust 1.90 tests/Clippy; logs are listed below.
- [x] Pass required workspace verification on the final implementation.
- [x] Finish fresh Claude Opus and Cursor xhigh review of the complete diff.
- [x] Validate the follow-up native churn-during-proof regression and rerun
  Claude Opus/Codex review until no actionable findings remain.
- [x] Complete requested local combined-failure and CLI/audit classification
  checks, then refresh workspace validation for those additions.
- [x] Observe current macOS 26.6.2 Apple Silicon tests.
- [x] Observe minimum-version macOS 15 Apple Silicon tests.
- [x] Observe Linux regression execution.
- [x] Record final evidence, close the task and finish this plan only when
  those acceptance requirements pass.

## Surprises & Discoveries

`libproc` 0.14.11 sizes from the system process count, allocates and fills a
vector, but exposes no completeness flag. No false sole-leader result was
reproduced; this is an allocation and completeness-contract deficiency.
XNU commit `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` scans live and zombie lists
under the process-list lock. Its supplied capacity bounds the native result
allocation. Two PID slots suffice for the sole-member question: an exact
leader singleton is complete; a full buffer cannot prove quiescence. Source
links and limitations are in `third_party/darwin-process-info/README.md`.

A direct fallback checked cached group ownership without a fresh wait
observation. Another wait consumer could already have released that identity.
An ECHILD observation must revoke numeric signaling before either fallback or
group signaling. Existing group signaling already made this observation. A
non-consuming native wait error must still permit best-effort direct-child
cleanup; the regression proves the live child exits before group cleanup runs.

Cleanup errors replaced the primary timeout/cancellation/output classification.
Final drain errors could also replace an earlier operation or cleanup failure.
The compound error now retains the original cause while classifying cleanup
failure as failure, including when cancellation initiated cleanup.

A zero-timeout EOF test was racy because a concurrent fork could temporarily
inherit its pipe writer. Its replacement uses an explicitly shut-down real
Unix socket, preserving zero timeout, exact byte/redaction and EOF assertions.
Native subprocess pipe tests remain in the suite.

The first comprehensive review (Claude Opus, Cursor xhigh, frozen fingerprint
`7bc6496da6de365a85466b5bf1c0b99f80667fdf6b35490b1236591c372e0a2d`) found two
accepted low-severity issues from Claude: Darwin wrapper errors map to zero,
and non-ECHILD wait errors must retain direct fallback. Both are fixed and
have regressions. Cursor's claim that a supplied buffer returns the full
required byte size was rejected against pinned XNU source and a passing native
three-member test. The source returns copied bytes, so oversized responses stay
invalid. Runner-label questions were resolved against GitHub's official runner
reference. Tracker activation wording was reconciled without closing the task.
The second same-scope review of
`8db473942174495c5027763a8ee3136460f46641761881c3f4b065aeec21583e` identified a
valid non-leader singleton aborting retries (Claude low/Cursor medium, accepted
as medium). It is fixed: valid other members return non-quiescent, with a native
leader-leaves-group regression and an injected deadline/re-signal regression.
Claude also identified stale inventory wording (fixed) and a churn timing
window. Its wrong-exit-status claim was unsupported because cancellation is
checked before exit, but churn could finish by itself before cleanup. A bounded
wall-clock churn loop and explicit churn-ended failure marker now prevent that
proof-class inflation. Cursor's claim that no stable member was spawned was
rejected against the common fixture setup, which spawns and acknowledges it
before the churn branch.
The third review of fingerprint
`0ff4b024bc53da68881f943ce4c49e7b58183524913b8924cdebf4a63f90e686` produced a
Claude report with no containment-code defects, but a stale fuzz lockfile and
a fixture expiry gap. Cursor was cancelled after the required fixes were known;
its adapter reached terminal exit 143 before any replacement invocation. That
round is a single-reviewer result, not a completed merged review.

Locked fuzz metadata resolution reproduced the dependency failure. QA-21 had
previously closed for an earlier lock update; M03 introduced a later missing
provider edge, and M04 replaces that edge. The refresh changes only the
provider package/edge and removes libproc, with no unrelated version upgrades.
The unchanged `bash scripts/check-j25-fuzz-smoke` passes on arm64 macOS with
CI-pinned nightly-2026-08-25 and cargo-fuzz 0.13.2: five seed tests plus all four
10-second bounded targets (protocol, witness, core_artifacts, input_boundaries).
This is a local macOS fuzz run, not Linux evidence or an exhaustive fuzz claim.

Members now publish an expiry marker before failing their bounded release wait.
The containment assertion rejects it. A native expiry regression deliberately
waits for that failure and confirms it cannot masquerade as successful cleanup.
The fourth fresh review of fingerprint
`731366e010e576eded0c4ef08f9f2cb74d78624d24811da133c4cfda681dca38` completed
with both reviewers; the fingerprint matched after completion. Claude used
restricted filesystem access and default configuration. Claude's remaining
low finding concerns fixture deadline margins on slow CI hosts; retain this
as a validation risk pending those runs, with no observed failure justifying
timeout widening. Cursor's high finding claimed Bash printf did not flush
before publishing readiness. Apple's Bash 3.2 source explicitly calls
`fflush(stdout)` in PRETURN, contradicting that premise and agreeing with the
passing native test on /bin/sh 3.2.57. No source change is warranted for that
finding. Primary source:
https://github.com/apple-oss-distributions/bash/blob/main/bash-3.2/builtins/printf.def
`.agent` is excluded by `6881359:.reviewignore`; no explicit exclusions apply.

The supplementary Rosetta process test attempt exited 101 before tests ran:
the x86_64 build script could not load the installed arm64-only Xcode libclang.
Log: `/tmp/jury-m04-rosetta-process.log`. This supplies no Intel execution
evidence. Intel acceptance was subsequently removed from scope by the operator.

## Decision Log

- On 2026-09-10 the operator removed Intel Mac support from Jury's product
  scope. macOS development, native CI, artifacts and acceptance now target
  Apple Silicon only. This supersedes earlier Intel requirements in historical
  plans and review reports; it does not establish a passing run on any host.
- Additional local verification requested: exercise real stdin setup refusal,
  injected output setup failure after actual pipe acquisition, and injected
  cleanup confirmation failure after real group termination. Keep both success
  and failure controls, verify leader SIGKILL/reaping before fallback, and
  extend the real-pipe final-drain test to a compound cleanup failure. Use two
  private operation parameters instead of unsafe descriptor corruption or
  global test switches. The public supervisor still supplies the same functions.
- Move unchanged CLI error mapping and audit classification out of the
  Linux-only launch module into one private module compiled on Linux or in
  tests. Test the production classifications on this Mac without claiming
  full native CLI child execution or persisted audit integration.

- Follow-up Claude/Codex review found one accepted low test defect: the
  in-group churn producer dies before proof. This is fixture topology and
  synchronization design, not an established production containment defect.
  Keep cancellation-under-spawn coverage and add a controller outside the
  group, with prestarted children joining between real signal/proof calls.
  Use the existing confirmation loop and extract its unchanged Darwin proof
  closure into one private function shared with the test, avoiding a second
  proof implementation or a new public test hook. Require actual SIGKILL exit
  status before RAII fallback and verify the proof streak resets on growth.
  Apple XNU setpgid at the pinned commit permits self-joining an existing
  same-session group and rejects changing an already-execed child from its
  parent; the fixture therefore calls setpgid on itself after a handshake.
- Open questions researched: GitHub officially lists macos-26-intel; generic
  CLI mapping avoids falsely promising successful termination on compound
  failure; empty groups and unreaped nonleader zombies remain conservative
  Darwin failures. Document these existing availability differences without
  changing the sole-leader contract. Primary setpgid source:
  https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_prot.c

- Consolidate native ABI queries in the maintained `darwin-process-info`
  provider, formerly `libproc-region`; no unsafe code enters Jury crates.
- Only an exact leader singleton establishes sole membership. Saturation or
  a valid non-leader singleton keeps retrying; duplicate, empty or malformed
  observations fail. The caller separately owns unconsumed wait
  status, observes leader exit and requires consecutive proofs before reaping.
- Check absolute deadlines before/after provider calls. A synchronous kernel
  allocation, lock wait or scan is not preemptible; do not claim otherwise.
- Keep public macOS platform status provisional until final integration and
  release; local tests and workflow configuration do not establish full support.
- Prepare explicit macOS 15/26 Apple Silicon CI lanes. GitHub runner
  labels were checked against its official documentation on 2026-09-10.
- No source commit or push is implied by this task. New files are staged so
  Jig's file-budget check has stable index authority; implementation remains
  uncommitted. CI publication remains an operator question.

## Outcomes & Retrospective

M04 acceptance is complete. Implementation commit
`362b209a01a933a470893161b0d1c381aec13ee4` passed all 18 executable PR checks;
one optional external check was skipped. PR #1 remains a draft, unmerged:
https://github.com/bpcakes/jury/pull/1
The native Darwin run is
https://github.com/bpcakes/jury/actions/runs/34501541365
Its logs establish native arm64 macOS 15.7.9 (24G830) and 26.6.2 (25G83),
with ten provider, 54 process, eight running-image and 76 CLI unit tests
passing on each current-toolchain lane. The running-image parent intentionally
ignores one subprocess helper entrypoint. Rust 1.90 provider tests and Clippy
also passed on macOS 15.7.9. The PR test-merge commit
`11580e179dcd5718d93dac40ca7ad38d38ebed2e` has tree
`18d3174d1e20ed3da09b56194d895d268a162738`, identical to the implementation
commit's tree. Logs are retained at `/tmp/jury-m04-ci-macos15-current.log`,
`/tmp/jury-m04-ci-macos26-current.log` and
`/tmp/jury-m04-ci-macos15-msrv.log`. Native Linux evidence follows below.
These observed results supersede the earlier unavailable-host/CI blockers
recorded in this recovery history. Apple Silicon containment acceptance is
complete; full native CLI launch/delivery and release acceptance remain M05-M10.
The final closure work check passed all configured targets under receipt
`receipt_01M262XA2ETN42CGFTZKV0Q4E1`; gates were fresh and `work finish`
closed this plan with outcome `success`. The task is closed as Completed.

Native Linux verification passed on 2026-09-10 using the operator-provided
host in an isolated temporary source directory. The 811-file working-source
snapshot excluded only tracker/agent metadata; per-file hashes, symlink targets
and executable bits matched on transfer and after tests, and still matched the
local source afterwards. Archive SHA256:
`593e48a3d1ff2049d856674226946342994f70618141a79d47fcd30a14df3ef4`.
Environment: Linux 7.1.9-arch1-2 x86_64, Rust 1.98.1, core limit zero,
MEMLOCK soft/hard 8192 KiB, test optimization level 1 with ordinary parallel
tests and unchanged assertions. No system resource-limit changes were needed.

`cargo +1.98.1 test -p jury-process --all-targets --locked` and the same
command on Rust 1.90.0 each passed 50 unit tests and seven running-image tests;
one subprocess helper was intentionally ignored by the parent runner.
Workspace Clippy passed with all targets/features, locked dependencies,
warnings denied and `clippy::mod_module_files` denied. The full locked workspace
test/doctest run passed, including 79 CLI unit and 33 CLI integration tests.
No source fixes were required. Logs retained locally:
`/tmp/jury-m04-linux-native-process.log`,
`/tmp/jury-m04-linux-native-process-msrv.log`,
`/tmp/jury-m04-linux-native-clippy.log`, and
`/tmp/jury-m04-linux-native-workspace-test.log`.
These are native Cargo results, not remote Jig receipts. The earlier failed
Docker attempts below are historical and no longer block Linux acceptance.
M04 remains open only for the required macOS 15 Apple Silicon containment run;
the operator was asked whether a host is available. Current macOS and Linux
passes do not establish the minimum macOS version.

The operator's Apple Silicon-only scope revision is applied to the README,
architecture/filesystem/provider docs, macOS implementation plan, native CI and
all 11 macOS tracker records. Issue statuses are unchanged; historical Intel
measurements remain history. The workflow now expands to macOS 15 with Rust
1.90.0/1.98.1 and macOS 26 with Rust 1.98.1, all Apple Silicon. YAML matrix
inspection, the existing CI action-pin checker, stale requirement scans and
diff whitespace checks pass. Fresh workspace Clippy, formatting, tests,
contract and file-budget checks pass under validation receipt
`receipt_01M260X2Y67HXKRRGT1HE3ABY1`; evidence and gates are fresh.
Log: `/tmp/jury-apple-silicon-scope-work-check.log`. No runtime code changed
for this scope revision. Earlier review fingerprints describe the earlier
scope, not this subsequent docs/CI/tracker change. Native minimum/current OS
acceptance on Apple Silicon and Linux execution remain required for M04.

Additional local checks now exercise four setup/cleanup combinations and two
final-drain/cleanup combinations through the common supervision function.
Stdin refusal is native missing-pipe behavior; output setup failure is injected
after real pipe acquisition, and cleanup confirmation failure is injected after
real group termination. Assertions require explicit cleanup, reaped SIGKILL
status and preserved typed primary causes. CLI classification tests cover
compound timeout/cancellation/stdin/output failures plus normal success,
timeout and cancellation controls. These are shared production-function tests,
not end-to-end macOS child-execution or persisted audit evidence.
Focused checks, Rust 1.90 process tests and work-check pass. Logs:
`/tmp/jury-m04-combined-failures.log`, `/tmp/jury-m04-execution-outcome.log`,
`/tmp/jury-m04-extra-clippy.log`, `/tmp/jury-m04-extra-msrv.log`, and
`/tmp/jury-m04-extra-work-check.log`. Latest validation receipt:
`receipt_01M25YZ2VJAWD4FH6ZRJHHNH2A`; its test receipt:
`receipt_01M25YZ2J4GEAAQ98A67WFG578`. The final explicit workspace test passed
with output at `/tmp/jury-m04-extra-final-test.log`; gates remain fresh.
Fresh Claude Opus/Codex review completed with no actionable findings against
complete fingerprint
`5e8161f4f148342264eb4346de04c3f3fbd6e31dc2ddb71ed0645e0936aabffe`.
The parent rechecked that same complete fingerprint after both frozen reports.
Claude used Opus, restricted filesystem access and default configuration;
Codex performed a source review and did not run tests in this round. The local
execution results above belong to the parent. The trusted exclusion remains
`.agent` from `688135927e5b1ccfbf97e2e964d0f9d5f796457e:.reviewignore`, with no
explicit exclusions.

Claude's runner-label and renamed-required-check questions were already resolved
by the official runner reference and read-only repository rules checks. Invalid
Darwin snapshots intentionally end confirmation with an error after the current
group signal; only still-owned direct-child fallback follows. Retrying that
query until the deadline could improve best-effort cleanup availability, but
would not establish quiescence and is not a reproduced regression. Departed
leaders and externally retained zombies remain the documented conservative
availability difference from Linux, not an identical-parity claim.

Remaining coverage gaps from this review include normal exit followed by cleanup
failure, signal-forwarding/output-limit compound failures, persisted CLI audit
wiring, real-pipe zero-budget EOF, and actual native kernel query failures.
Injected decoder errors and mapping tests do not prove those paths. Native
minimum-version Apple Silicon macOS and Linux execution remain outstanding; M04 stays
open. Current local process counts are 54 unit tests and eight integration
tests, with one subprocess helper intentionally ignored by the parent runner.

Earlier churn-only implementation and local workspace validation passed. Its work-check
test receipt is `receipt_01M25XJH4JWADQBGQCMA1E1X6B`; the work-check
validation receipt is `receipt_01M25XJHDF4EWPPFSRH3CK66BE`. The final explicit
`scripts/jig check test` passed on that source
(`/tmp/jury-m04-proof-budget-final-test.log`). Process tests also
pass on Rust 1.90. M04 remains open;
current local evidence is macOS 26.6.2 arm64, not minimum OS proof.
Detached descendants remain outside the process-group guarantee. No security
certification or independent review is claimed.

The native proof-churn regression passes on current Rust and Rust 1.90.
It observes [true, false, false, true, true] from the production proof function,
and verifies all four injected native members died from SIGKILL before fallback.
Temporary mutations omitting repeated loop signals, retaining stale proofs,
and suppressing the native group kill were each rejected by the new test;
all mutations were restored before validation and review. Their expected-failure
logs are `/tmp/jury-m04-proof-mutant-resignal.log`,
`/tmp/jury-m04-proof-mutant-reset.log`, and
`/tmp/jury-m04-proof-mutant-native-signal.log`.
Follow-up logs: `/tmp/jury-m04-proof-churn.log`,
`/tmp/jury-m04-proof-churn-clippy.log`, `/tmp/jury-m04-proof-msrv.log`, and
`/tmp/jury-m04-proof-work-check.log`. Current native process counts are 53 unit
and eight running-image tests, plus the ignored subprocess helper entrypoint.
Fresh Claude Opus/Codex review ran against complete fingerprint
`1732aac2ecf89b7d9a6c382729596875a2523ab3df081f38346be1d5fdc2731a`.
That round completed with Codex finding none and Claude identifying a low
fixture-budget coupling issue. The controlled test now has a five-second
coordination deadline because its callback also waits for external joins and
reaps fixtures; this is not evidence of the production 500 ms bound. That
production timeout and the explicit late-proof rejection tests are unchanged.
Joining helpers have a separate bounded pre-join lifetime so preparation does
not race the coordination budget. No scheduling failure was observed locally;
the change separates test coordination from the production latency contract,
rather than claiming a reproduced native CI failure.
Read-only GitHub checks found main unprotected and no repository rulesets, so
no stale required-check name needs migration. The pinned research revision is
Apple's xnu-12377.1.9, while the observed local kernel is xnu-12377.161.14;
source inspection is not claimed as exact shipped-kernel equivalence. Native
Apple Silicon supported-version acceptance remains required. Tracker deferral text is
dated scope provenance followed by the explicit 2026-09-10 activation.
The budget follow-up passes work-check and Rust 1.90 process tests, with logs
`/tmp/jury-m04-proof-budget-work-check.log` and
`/tmp/jury-m04-proof-budget-msrv.log`. The final context-free Claude Opus/Codex
review completed with no actionable findings from either reviewer against
complete fingerprint
`4c53a5cee2f369ad1d7544038e0050a4f0f6c3d00bbb8f38b720919ac1404d1d`.
The parent rechecked the identical complete fingerprint after both reports.
Claude used restricted filesystem access and default config; Codex reran the
53 process unit, eight running-image and ten provider tests successfully.
The trusted exclusion remains `.agent` from `6881359:.reviewignore`, with no
explicit exclusions. Fresh work evidence and gates pass.

Final review questions were adjudicated against existing contracts and primary
source: in the pinned XNU revision, forkproc sets group membership under
proc_list_lock before pinsertchild later publishes allproc membership. Group
replacement takes the same lock. The fork path also terminates a child when
its parent has begun exiting or its forking thread is inactive. Sources:
https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_fork.c
and the linked kern_proc.c above. The leader-escape fixture deliberately joins
the outer test group to retain the same session; cleanup only targets the
original pinned group or the owned child, never that outer group. Production
500 ms behavior on minimum-version Apple Silicon macOS is still an unmeasured acceptance requirement,
not established by widening the separate test coordination budget.

## Context and work remaining

`crates/jury-process/src/process.rs` owns lifecycle and cleanup;
`process/error.rs` preserves failure classification; `src/unix.rs` delegates
macOS membership to `third_party/darwin-process-info/src/groups.rs`.
`process/tests/native_containment.rs` covers ownership, failures and deadlines;
`native_churn.rs` uses real children with ready/release handshakes and a
positive control before checking absence of a survival marker. Each of eight
fresh cancellation groups has an acknowledged stable descendant and real churn.
Provider malformed-response tests are synthetic and are not native evidence.

Run from the repository root:

    cargo test -p jury-process --all-targets --locked
    cargo +1.90.0 test --manifest-path third_party/darwin-process-info/Cargo.toml --locked
    cargo +1.90.0 clippy --manifest-path third_party/darwin-process-info/Cargo.toml --all-targets --locked -- -D warnings
    cargo fmt --manifest-path third_party/darwin-process-info/Cargo.toml -- --check
    scripts/jig work check --plan-id plan_01M25NJ23YMHZ050J0GSR4C07Q
    scripts/jig check test
    scripts/jig work evidence --plan-id plan_01M25NJ23YMHZ050J0GSR4C07Q
    scripts/jig work gates --plan-id plan_01M25NJ23YMHZ050J0GSR4C07Q

Focused passes: `/tmp/jury-m04-final-process.log`,
`/tmp/jury-m04-final-clippy.log`, `/tmp/jury-m04-provider.log`,
`/tmp/jury-m04-msrv-test.log`, `/tmp/jury-m04-msrv-clippy.log`,
`/tmp/jury-m04-process-msrv.log`. Final workspace logs:
`/tmp/jury-m04-lock-expiry-workspace-test.log`,
`/tmp/jury-m04-lock-expiry-work-check.log`,
`/tmp/jury-m04-edge-provider-msrv.log`,
`/tmp/jury-m04-edge-provider-msrv-clippy.log`,
`/tmp/jury-m04-edge-provider-clippy.log`, and
`/tmp/jury-m04-lock-expiry-process-msrv.log`. Fuzz output is retained in
`/tmp/jury-m04-fuzz-smoke.log`; original locked-resolution failure is retained
in `/tmp/jury-m04-fuzz-metadata-error.log`.
Post-fix counts: 52 process/unit tests, eight running-image tests (one helper
entrypoint ignored in the parent and exercised by subprocess tests), and ten
provider tests. The three-member native case passes, then observes two members
and finally the still-live lone leader, which separately requires exit proof.
An intermediate test command exited successfully but Jig correctly marked
its receipt stale after a source whitespace edit; the final runs above were
made with the source frozen. Docker listed containers but both inspection
of the prior Jury container and starting a fresh `jury-m04-linux` container
stalled; the fresh startup was stopped after 20 seconds. No Linux execution
evidence was produced. Do not restart unrelated host services.
A later recheck returned Linux/aarch64 from Docker and successfully ran the
Rust 1.97 compiler probe. Actual regression startup still stalled: the
bind-mounted attempt never created a container, and copy-based and bare
containers remained Created with Running=false and Pid=0. Their clients were
stopped and the two created task containers removed; no tests ran. A source
archive is available at `/tmp/jury-m04-linux-source.tar` for a future copy-based
run. GitHub's latest observed completed checks belong to `e3996aa`, not this
uncommitted M04 patch. CI publication approval remains unanswered.
Early failures are retained in `/tmp/jury-m04-query-tests.log` (EOF race) and
`/tmp/jury-m04-clippy.log` (new tests used forbidden unwraps, subsequently fixed).
Required gate receipts belong to this plan under `.agent/state/`.

Acceptance requires observed passing native process suites on Apple Silicon
minimum/current macOS versions, plus Linux execution. The
workflow `.github/workflows/darwin-process-info.yml` prepares those macOS
lanes; do not substitute configuration or Rosetta for native run evidence.
No persisted runtime data or public protocol migration is involved. To recover,
inspect the diff against the baseline and the existing test logs before reruns;
poll live test sessions to completion. Preserve other work and append-only
Jig state. Do not close the task or plan while required host evidence is absent.
