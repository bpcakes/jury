# CP-21 Public API Candidate

`cp21-public-api.json` freezes the source-level API candidate after downstream
migration work. It records workspace package metadata, feature maps, normal
dependencies, package include lists, public source declarations, and hashes of
every publishable crate manifest and Rust source file.

The recorded workspace package version remains `1.2.5` by design. The 2.0
development checkpoints preserve release metadata until CP-23 performs the
reviewed version and publication transition.

The snapshot is historical and must not be regenerated after CP-21. Its exact
SHA-256 is pinned by `scripts/verify-2.0-api-freeze.py`. The exact manifest
hashes intentionally predate CP-22's reviewed `syn` 2.0.119 pin.
To reproduce the original capture at CP-21, check out commit
`082d1e19fb5473e565b31c24e1c743f4c88d7470` and run:

```bash
scripts/capture-2.0-api.py
```

For current-tree freeze verification, use the separately named rolling source
inventory and semantic API checks instead:

```bash
scripts/capture-2.0-api.py --check
scripts/verify-2.0-api-freeze.py
scripts/capture-2.0-public-api.py
```

`current-source-api.json` is regenerated after reviewed pre-release changes.
It is deliberately not presented as the historical CP-21 artifact.

This snapshot is deliberately not presented as a semantic Rust API model. It
can detect any source or manifest change and gives CP-22 a fixed candidate to
compare, but line-based declaration collection cannot fully understand
re-exports, cfg evaluation, macro expansion, or generic compatibility. CP-22
must run `cargo-semver-checks` and rustdoc/public-API comparison before freeze.
