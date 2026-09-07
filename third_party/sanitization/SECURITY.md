# Security Policy

Security fixes are developed against the current `main` branch and, when
applicable, backported to the latest published stable release line. The current
development line targets `2.x`; older tagged release documentation remains
historical.

Do not publish exploitable details publicly before a fix is available. Report
security issues privately through a
[GitHub Security Advisory](https://github.com/valkyoth/sanitization/security/advisories/new).
Do not use a public issue for an undisclosed vulnerability.

Security-sensitive changes should include:

- tests for default, feature-matrix, target-matrix, WASM compatibility, and
  all-features builds through `scripts/checks.sh`;
- advisory checks for every lockfile and the source, license, wildcard, and
  duplicate-version policy in `scripts/verify-dependency-policy.sh`;
- release-codegen inspection for volatile wipe visibility;
- bounded Kani harnesses when `cargo-kani` is installed or via the Kani
  workflow;
- Miri verification on nightly for default, `alloc`, and all-features builds;
- `docs/SAFETY.md` updates for unsafe code;
- `docs/THREAT_MODEL.md` updates for guarantee or scope changes.

## GitHub Security Defaults

Enable GitHub CodeQL default setup in the repository security settings. Keep the
checked-in CI workflow separate from CodeQL so GitHub owns SARIF upload
permissions and there is no competing advanced CodeQL workflow in this repo.

The active default-branch ruleset requires a pull request, one approving
review, code-owner review, approval after the last push, and clean CodeQL
results for actors without an explicit administrative bypass. Dependabot is not
a bypass actor, and each configured update root requests review from the
repository owner. Dependency updates must still receive human diff review.
