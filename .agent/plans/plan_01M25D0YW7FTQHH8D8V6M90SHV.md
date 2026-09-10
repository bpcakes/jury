# Resolve macOS review notices and coverage gaps

Consumer: maintainers integrating the native macOS cutover. This work gates the
observed missing provider attribution and untested executable-replacement and
final-output-drain boundaries. Retain this minimal research/recovery record
through integration, then archive it; it is not security certification.
Baseline: e3996aaf032135df5fbd60776b444f94739b362f plus the existing uncommitted
macOS changes. Preserve that work and do not commit or push.

## Progress

- Researched every review open question before choosing changes.
- Added central provider attribution and an explicit MIT build-script notice.
- Added atomic rename-over refusal, ad hoc hardened-runtime image capture,
  final-poll redaction, XDG traversal and interior-dot selection regressions.
- Added Intel/Apple Silicon and Rust 1.90 provider CI with a 30-minute timeout.
- Focused native regressions, provider Rust 1.90 tests/Clippy and release-script
  tests pass. All required native workspace gates pass.

## Surprises & Discoveries

The checked-in provider LICENSE is byte-identical to both the cached libproc
0.14.11 LICENSE and the license fetched from the pinned upstream commit:
https://github.com/andrewdavidmackenzie/libproc-rs/blob/9c5b669ca414918eadc81e70ec654505a0c8a93f/LICENSE
The root NOTICE omission is integration documentation debt, not a provider API
defect. The Linux collector deliberately collects the provider compiled into
Linux binaries; libproc-region is macOS-only. Source archives already retain
its local LICENSE. NOTICE now makes the platform distinction explicit.

Installed br is 0.5.7. Source inspection of sync_comments_for_import_in_tx and
insert_comment_for_import at
https://github.com/Dicklesworthstone/beads_rust/blob/v0.5.7/src/storage/sqlite.rs
shows per-issue replacement and global-ID collision reallocation. A real br
experiment in disposable databases found an additional final-verification
constraint: deliberately colliding source comment IDs cause SYNC_CONFLICT and
rollback, despite insertion-time remapping. Changing source_repo_path alone
succeeds. Crucially, replaying this repository's exact HEAD export and then its
working export in a fresh disposable br database succeeds, with all current
comment payloads preserved. The current export has no duplicate global IDs or
comment payloads and retains every upstream comment. Do not rewrite real
tracker IDs or claim arbitrary collisions are supported. No actual tracker
mutations were needed.

Linux CLI gates use Ubuntu hosted runners, whose official inventory includes
GCC/Clang: https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md
The pinned release builder compiles x86_64-unknown-linux-gnu; the native_cli
candidate suite runs on the release validation host, not inside the build-only
container. It needs /usr/bin/cc, /bin/cp and a loader-injectable dynamically
linked test executable. docs/linux-release.md now states these prerequisites.
The fixture already fails if its real loader barrier cannot execute. This is
source/environment research, not a fresh Linux execution result.

Apple documents that Hardened Runtime blocks DYLD environment injection:
https://developer.apple.com/videos/play/wwdc2019/703/
The provider API itself does not use injection. The new native subprocess
regression captures real kernel image metadata from a locally ad hoc signed
Hardened Runtime executable without exception entitlements; it passes on this
arm64 host. This is not Developer ID or notarization proof. M10 still requires
final signed-distribution validation and actual signing inputs. No operator
input is needed for this fix; no signing credentials were accessed.

GitHub supports macos-15 for arm64 and macos-15-intel for x86_64:
https://docs.github.com/en/actions/reference/runners/github-hosted-runners
The workflow now covers both and provider Rust 1.90, separately from the
workspace's pinned Rust 1.98.1. Local Rust 1.90 provider tests and Clippy pass;
Intel hosted execution remains pending CI.

## Decision Log

- Preserve the small kernel-identity provider abstraction. No production
  behavior bug was established by these review questions.
- A missing timeout is resolved with 30-minute jobs, matching existing test
  command bounds. Provider tests remain explicit because it is intentionally
  an isolated workspace; both toolchain matrix entries run them.
- Atomic rename-over is different from rename-away plus replacement: it unlinks
  the running vnode and must be refused. The native regression observes that
  refusal. Same-vnode content mutation is outside RunningImage's documented
  metadata-snapshot contract; do not fake an immutability test.
- Linux descriptive paths still canonicalize the procfs target. Add a Linux
  assertion comparing the ordinary result with canonicalize(/proc/self/exe).
  Replacement/deletion refusal is intentional; descriptor serialization did
  not change, and this is not a migration of persisted manifests.
- restore --state-out has separate direct_utf8_path validation and hardened
  capability/overlap validation before private input. Bypassing environment
  selection is intentional for an explicit target, not a validation bypass.
- Interior dots are normalized by Rust Path components, including the home
  checks. The selector's preserved OsStr spelling grants no filesystem
  authority. Pin selection behavior without changing compatibility.
- Native witnessed fixtures explicitly use emergency protection. Full strict
  lifecycle, persistent juryd/TLS and child-execution coverage remain the
  existing M04-M10 work; do not relabel these tests as proof of that scope.

## Outcomes & Retrospective

Completed: all required gates are fresh and pass; final scripts/jig check test
passed (api:test, 35.6 seconds). Provider tests and Clippy pass on Rust 1.90 and
1.98.1. Focused running-image tests passed 8 cases (one subprocess entry point
is intentionally invoked through its parent test), including real hardened
signing and atomic replacement. Final-poll tests passed 2 cases; native path
tests passed 5. Release-script tests passed 20 with one existing opt-in case
skipped. git diff --check HEAD passes. Linux and hosted Intel execution were
not run in this turn; the added Intel workflow awaits CI. Full strict witnessed
lifecycle and signed/notarized distribution remain existing M08/M10 acceptance,
not evidence supplied by this patch. No operator input is required for the
current fix. No application commit or push was made; staged prior work and
new unstaged changes are retained.

## Validation and recovery

Run provider tests and Clippy on Rust 1.90 and the current toolchain, workspace
formatting, focused filesystem/process regressions, python3
scripts/test-linux-release.py, and scripts/jig work check for this plan. Finish
backend verification with scripts/jig check test. Check git diff --check HEAD.
All test fixtures use generic data. Disposable tracker databases are removed.
The existing recovery stash and preexisting edits are untouched.
