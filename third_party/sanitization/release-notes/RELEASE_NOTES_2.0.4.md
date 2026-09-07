# sanitization 2.0.4

This maintenance release updates the supported toolchain and dependency set
without changing the public API or the Rust `1.90.0` MSRV.

## Maintenance updates

- Release development is pinned to Rust `1.98.1`, and the compatibility matrix
  now checks Rust `1.90.0` through `1.98.1`.
- `syn` is updated to `3.0.4` and BLAKE3 to `1.8.7`; compatible transitive
  dependencies and standalone-tool lockfiles are refreshed.
- The SHA-pinned `Swatinem/rust-cache` action is updated to `2.9.2`. The
  repository now pins the signed commit referenced by the annotated release
  tag. Checkout, artifact upload, and Kani action pins were reviewed and remain
  current.
- Mapped growth and staged replacement preserve established preferred
  controls. If a control accepted for the current storage cannot be
  re-established, replacement fails before the old value or report changes.
- Multi-seed timing evidence treats every primary threshold excursion as
  release-blocking. Exactly two fresh same-seed confirmations are retained for
  diagnosis but cannot convert the failure into accepted evidence; the Welch
  threshold is unchanged.
- The performance baseline keeps detailed measurements in its structured JSON
  artifact but no longer prints the complete report to CI logs. Console output
  now contains only a fixed pass/fail status, resolving the CodeQL
  cleartext-logging alert without reducing retained benchmark evidence.

All five workspace crates are released together at `2.0.4`, with the derive
crate exact-pinned to the matching runtime version.
