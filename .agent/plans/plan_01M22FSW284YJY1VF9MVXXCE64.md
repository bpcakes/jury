# Fix M03 macOS review findings

Consumer: native CLI users and maintainers. This work fixes witnessed injection failing at Linux renderer identification, lost root-selection diagnostics, and repository-sensitive default-root tests. The implementation and regression tests supersede this plan after the checks pass. Baseline: `9c48e9610a1584696196afe76da1f15050baacd1`, with the staged M03 implementation retained.

## Progress

- [x] Inspect review findings and the relevant native CLI boundaries.
- [x] Map identity/state selection failures to actionable value-free CLI errors.
- [x] Isolate default-root discovery from TMPDIR repositories; strengthen preflight with initialized state and internal-helper assertions.
- [x] Reuse existing witness-engine/approval fixtures in a macOS regression target.
- [x] Fix native renderer identification and prove successful witnessed injection.
- [x] Run native workspace gates and targeted Linux regressions; close the issue after finishing this plan.

## Surprises & Discoveries

The existing witnessed test combined read/inject, child execution, and rollover. Shared fixtures are extracted so the native injection regression can execute without skipping assertions in the Linux workflow. These fixtures use real CLI and witness-engine operations with in-memory witness persistence and explicitly degraded protection; they are not native juryd durability/TLS or full strict-lifecycle evidence.

## Decision Log

- Preserve Linux renderer descriptor bytes and the existing authenticated template manifest. Renderer path reporting is distinct from executable launch; no child launch is added.
- Preserve empty JURY_HOME fallback while diagnosing invalid identity/state overrides.
- Hidden terminal field entry and physical witness database paths remain documented limitations; this patch does not activate M04-M10.
- Keep all staged M03 changes and avoid commits/pushes.

## Outcomes & Retrospective

The regression first failed with `invalid-template`, then completed witnessed read/inject and receipt verification after the renderer fix. Native CLI unit tests (69), all three basic lifecycle/preflight/diagnostic tests, and the macOS witnessed target pass. The explicit TMPDIR-inside-Git unit and CLI tests pass. Linux CLI unit tests and all 25 native CLI integration tests pass, including the unchanged child-execution and rollover scenarios; Linux Clippy passes. Native workspace tests, formatting, Clippy, contract, file-budget, and all six required work gates pass with fresh evidence. The final standalone `scripts/jig check test` passes. Test commands use optimization level 1 with the same assertions, debug assertions, and test selection. Direct/witness gate verifiers accept the unchanged bound inputs.

The first Linux compile exposed a shared-fixture visibility mistake; retaining its original lexical scope fixed it. Clippy required splitting preflight assertions into a shared helper. A work check run during that fixture edit was correctly rejected for scope drift; the final stable run supersedes it. Jig rejected partial staging and ignored an alternate index, so already-staged files were updated to their repaired versions; new files remain unstaged and no commit was made.

## Validation and acceptance

Run the macOS witnessed regression against the old implementation to establish the failure, then after the fix require output and verified receipts. Run default-root tests with TMPDIR inside an owned Git repository. Run formatting, Clippy, full native workspace tests, and required Jig work gates. Run the shared Linux CLI suite in the existing Rust 1.97 Linux container environment with explicit memory-lock/core limits. Track this work as `jury-8u6`; close only after checks pass.
