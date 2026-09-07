# Release 2.0.1

Version 2.0.1 is a documentation and packaging correctness release for the 2.0
line. It does not change the runtime API or security implementation.

## Fixed

- Changed the core package README's migration-guide URL from a repository-local
  path to an absolute GitHub URL. The relative path worked on GitHub but pointed
  at the wrong location when crates.io rendered the packaged README.
- Corrected every other repository-document link in that README for the same
  package-rendering context, including feature, advanced-usage, protection,
  target, threat-model, evidence, and security references.
- Added release-archive validation that fails when a packaged README contains a
  relative link to a repository-only documentation directory.

## Release Coordination

- All five publishable crates are versioned `2.0.1`.
- Internal workspace dependencies require the matching `2.0.1` release, with
  `sanitization` continuing to exact-pin `sanitization-derive`.
- The release script publishes `sanitization-derive`, `sanitization`,
  `sanitization-arrayvec`, `sanitization-bytes`, and
  `sanitization-crypto-interop` in dependency order.

Users already on 2.0.0 receive the same runtime behavior. The patch ensures
that documentation links shown on crates.io lead to the reviewed repository
documents.
