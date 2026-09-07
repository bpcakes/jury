# Sanitization 1.2.5 Baseline For 2.0

Status: frozen comparison baseline

Baseline tag: `v1.2.5`

Baseline commit: `d41204551c840e086b2a7d53c83514633e604e82`

2.0 planning base: `62411d236f651159f82b4db6422f242488a9e94c`

This baseline records the state from which the breaking 2.0 work begins. It is
not a security certification for 1.2.5 and does not replace the permanent
1.2.5 pentest report.

The machine-readable snapshot is
[`baseline-1.2.5.json`](baseline-1.2.5.json).

## Captured Surface

The snapshot records:

- workspace version, edition, resolver, MSRV, members, features, and direct
  dependency names;
- crates.io package file lists for all five published workspace crates;
- 617 source-level public declarations;
- 125 source lines containing an unsafe boundary or unsafe declaration;
- SHA-256 hashes for 27 source, manifest, lock, and toolchain files;
- hashes for the permanent guarantees, non-guarantees, safety, threat-model,
  target, barrier, leakage, and evidence documents;
- release LLVM IR and assembly observations for the wipe and native CT paths;
- the rustc host and installed target set used for the one-time codegen
  capture.

The public declaration list is deliberately called a source-level inventory.
It is not equivalent to `cargo-semver-checks` or a rustdoc semantic API model.
`CP-21` and `CP-22` add the release API snapshots and semver review needed for
the final 2.0 surface.

## Codegen Capture

The one-time capture used:

- Rust `1.97.0`;
- LLVM `22.1.6`;
- host `x86_64-unknown-linux-gnu`;
- release mode with all features through `scripts/verify-codegen.sh`.

It recorded:

- the volatile wipe symbol;
- volatile zero-byte stores;
- native conditional-copy, conditional-swap, and slice-selection symbols;
- the optimizer barrier and mask-generation patterns;
- x86_64 comparison, cache-flush, and cache-fence samples;
- absence of `memcmp` and `bcmp` in the checked IR and assembly.

The recorded artifact hashes are compiler- and host-specific. Later
before/after codegen comparisons must compare observations and reviewed
functions under the documented compiler matrix rather than treating one binary
hash as portable evidence.

## Reproduction

The capture command is:

```bash
scripts/capture-2.0-baseline.py
```

Capture intentionally fails after production source diverges from `v1.2.5`.
This prevents a later tree from silently replacing the historical baseline.

The stable tagged-source sections remain independently verifiable after 2.0
development starts:

```bash
scripts/capture-2.0-baseline.py --check
```

That check reconstructs manifests, features, package contents, public source
declarations, unsafe sites, file hashes, and evidence-document hashes directly
from the immutable `v1.2.5` Git tag. It validates the recorded codegen metadata
against a pinned canonical SHA-256 digest without pretending that old
host-specific artifacts should be rebuilt byte-for-byte by every future
compiler.

## Use During 2.0

- `CP-01` compares the behavior-preserving module split against this baseline.
- `CP-04`, `CP-06`, `CP-07`, `CP-10`, and `CP-11` compare changed public and
  codegen paths against this baseline.
- `CP-18` checks default dependencies, feature profiles, and package
  boundaries.
- `CP-21` records the intended 2.0 public API.
- `CP-22` performs the final semantic API and full-range review.

Any unexplained baseline difference is a checkpoint finding, not routine
generated-file churn.
