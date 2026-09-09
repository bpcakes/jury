# Repair container documentation and review regression coverage

Consumer: Linux 0.0.1 maintainer. This plan gates the container distribution
fixes and regression coverage for overwrite help, health JSON and SBOM archive
refusal. Observed defects: CI skips the actual image check, and packaged README
links refer to absent files. Retain only while this work needs recovery or review.
Baseline: a91220ab136461ccdc22d0ea327bf488314bb685, with the preceding fixes staged.

## Progress

- [x] Reproduce the missing image links with a regression against the old image.
- [x] Package the three canonical documents with repository links for unbundled
  references; enable the real image test in Security invariants CI.
- [x] Add actual CLI help and HTTP readiness-body assertions. Extract the SBOM
  installer into a module and test checksum, malformed-archive, traversal,
  absolute-path, symlink, hardlink, FIFO and device rejection before any writes.
- [x] Validate targeted Rust tests, a fresh image and all 17 release-helper tests.
- [x] Reproduce a complete local release candidate; the two clean builds produce
  matching binaries, live owner-change checks pass, and the real SBOM tool builds.
- [x] Run full workspace tests, formatting, Clippy and file-budget checks.
- [x] Stage the final tracker export, record all required gates, and run
  scripts/jig check test. The complete work-check rerun also passed.

## Surprises & Discoveries

Following every README link recursively would ship source and planning records.
References outside the three canonical documents instead point to the public
source repository; canonical prose remains unchanged. The old image fails the
new local-link check. The pinned builder uses Python without extraction filters;
explicit archive validation remains mandatory on all supported interpreters.
The exact health assertions exposed a test-helper mismatch: rollover used a
readiness helper to poll liveness. Separate ready/live wrappers preserve exact
JSON assertions. Both supported Python extraction paths pass refusal tests.

## Decision Log

Preserve the authorized banner/JSON cutover. Verify actual image contents in CI,
not Dockerfile text. Keep private-deployment compatibility outside this local
fix; no new wire-format change is introduced. Tests use synthetic input only.

## Outcomes & Retrospective

Implementation and functional validation pass. The local unsigned candidate is
target/linux-release/0.0.1-review-coverage; its final source/artifact consistency
check passed. All 14 generated repository file links exist on public main at
the baseline commit. The required Rust tests also passed with optimization
level 1, debug assertions and overflow checks enabled. Initial work-check
recording refused a partially staged tracker export; native check attachment
also hit a run-plan context error. Staging the closed tracker item and using
the documented work-check path resolved the bookkeeping without changing any
checks or application inputs. All required checks pass. The issue is closed.
Commands used include the targeted cargo tests, docker build followed by
JURYD_TEST_IMAGE=juryd:review-coverage python3 scripts/test-linux-release.py,
scripts/build-linux-release build --output target/linux-release/0.0.1-review-coverage
--allow-dirty, and scripts/jig work check/evidence/gates/finish for this plan.
A failed candidate is not releasable; fix the cause and use a fresh output path.
The candidate remains unsigned and unpublished. Issue jury-qv4.6.7 is complete.
