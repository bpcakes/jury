# M02 native filesystem publication and validation

Consumer: native filesystem implementer. Feature: M02 safe macOS publication.
Observed defects: native create-new refusal, metadata validation after exposure,
and missing ACL checks. Supersede this task-local plan when implementation,
acceptance and review results are integrated into docs/macos-support-plan.md;
keep history in Git. The Beads owner is jury-2bg.2.

## Progress

- [x] Audit current code, M01 status, pinned rustix source and published ACL APIs.
- [x] Activate M02 under the explicit operator request and update its contract.
- [x] Implement descriptor ACL checks, validation before exposure, native no-replace
  publication, APFS refusal and native file/parent full-sync.
- [x] Run all filesystem tests on native case-sensitive and case-insensitive APFS.
- [x] Pass native filesystem Clippy and Linux filesystem tests/Clippy.
- [x] Complete three comprehensive review/fix rounds before committing.
- [x] Commit M02, review that commit, and record the clean result in Beads.

## Surprises & Discoveries

M01 is closed with its changes already staged. Those existing changes remain
separate from M02. Five historical native unit failures now all reach publication
and return Unsupported. Once publication works, a Linux-only resolver expectation
is also reached on Darwin; that test now asserts each platform's actual contract.
The native full workspace still fails at Linux memfd imports owned by M03.

## Decision Log

Use calcifer-macos-acl 0.1.0 for borrowed-descriptor reads; reject any nonempty
extended ACL without account lookup or ACL mutation. Use rustix 1.1.4's Darwin
RENAME_EXCL mapping and F_FULLFSYNC. Darwin publication accepts APFS only.
Keep Linux sync behavior and existing portable bytes unchanged. Native tests
prove observed calls, concurrency and process restart, not power-loss survival.

## Outcomes & Retrospective

Native filesystem validation currently passes 61 tests plus one deliberately
ignored subprocess probe invoked by its owning crash test. Both APFS case modes
were exercised on owned 128 MiB disk images, then detached. The Linux filesystem
suite and Clippy pass. Comprehensive reviews are complete. Full exact-commit Linux workspace tests pass. HFS+ refusal passed through the owning native image runner. No native release/minimum-OS/Intel or independent-review claim is made.

## Validation and recovery

Run cargo test --locked -p jury-filesystem --all-targets -- --test-threads=1 and
cargo clippy --locked -p jury-filesystem --all-targets -- -D warnings. For APFS
volumes, set TMPDIR to an owned directory on the mounted image and
JURY_M02_CASE_MODE to sensitive or insensitive; run the same full crate suite.
Run scripts/jig work check/evidence/gates/finish for this plan, and finish backend
verification with scripts/jig check test. Native workspace memfd failures remain
explicit M03 prerequisites; run full Linux workspace gates as regression evidence.
Run direct/witness gate verifiers without changing their accepted inputs.

Prepared-file failures clean only the identity still owned by the held descriptor.
A post-rename parent-sync failure remains PublishedButParentUnsynced. Quarantine
cleanup/retry semantics remain covered by the existing state-root tests.

## Review evidence

Pre-commit round 1: Codex completed with stable full scope fingerprint
3489a0b6929d230075ea10fb6ac684d908b1398c54ed16ddd81be3c0816eda15.
Fixed its two findings: cleanup now identifies the still-held temporary inode
when ACL changes alter ctime, and destination ACL opens are nonblocking with
post-open type/identity validation. Added refusal cleanup and bounded FIFO tests.
Claude failed without a review. This is single-reviewer evidence.

Pre-commit round 2: Codex completed with stable full scope fingerprint
76403c66a172fd20e023c27db4de124eb22ccd656342c798d917940b19c6d291.
Fixed its lock-cleanup finding using the retained lock guard on every failure;
added replacement-preservation and original-lock retry tests. Claude failed;
its exact provider response reported the weekly quota exhausted until September 9.
No external review or independent security review is claimed.

Pre-commit round 3: Codex completed with no actionable findings and stable full
scope fingerprint 0036041315a4a52c3bcb3a361ccd37630b3f3e92e19afd893d4d16f676c12046.
The suggested retained-parent ACL regression was also added and passed.
Committed only M02 as 9323a5562e11be5e7af86ea202d2fc038561e516. Existing M01
source and dependency changes remain staged. The exact commit tree passed
Linux filesystem Clippy/tests independently of those staged changes. Native
strict tests used the staged M01 prerequisite, as documented.

Final immutable commit review: Codex found no actionable findings. Before/after
fingerprint 317ac145cc69f70fd587e8d8583a9075ef0835933971f39b2f2a15fef3591287
was complete with a clean checkout. Claude remained unavailable due to quota.
The result is recorded on jury-2bg.2; no empty/speculative finding ticket was
created. Full exact-commit Linux workspace tests subsequently passed.

Final regression disposition: scripts/jig check test passed on the exact
9323a55 commit in an init-enabled Linux container (exit 0, 471.2 seconds).
The first diagnostic container without init failed two CLI cases (broken pipe
and process-lifecycle assertion). The later serial diagnostic against staged
M01 was deliberately stopped (exit 143) once the exact-commit run advanced past
those cases; it is not counted as a pass. The immutable-commit result is the
full workspace evidence. Nine Linux release packaging tests passed under
Python 3.13; older Python lacked tarfile's data-filter API, and native macOS
hit an existing Linux-release test path-alias limitation.

The task is closed in Beads with the clean final review recorded. Root Jig plan
closure remains blocked by its mixed staged baseline and broader native CLI
portability failure; the work finish command refused, and no gate or receipt
was altered to force closure. Product implementation, native filesystem
acceptance, exact-commit Linux regression and requested reviews are complete.
