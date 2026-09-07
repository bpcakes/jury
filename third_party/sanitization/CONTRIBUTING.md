# Contributing

This fork is maintained in Jury's `third_party/sanitization` workspace. Read
`AGENTS.md` for monorepo ownership, commands, and safety boundaries. Submit
provider and Jury integration changes together. The upstream commands below
are provider tooling; its nested GitHub workflows are retained reference files
and are not Jury CI jobs.

Security-sensitive changes should keep unsafe code isolated behind the crate
root `#![deny(unsafe_code)]` policy and documented in `docs/SAFETY.md`.

From the Jury root, run:

```bash
cargo fmt --manifest-path third_party/sanitization/Cargo.toml --all -- --check
cargo test --manifest-path third_party/sanitization/Cargo.toml --locked --workspace
cargo test --manifest-path third_party/sanitization/Cargo.toml --locked -p sanitization --no-default-features --features std,profile-guarded-native,require-fork-exclusion
cargo test -p jury-protected --locked
```

The imported `scripts/checks.sh` also runs upstream release-history and evidence
checks that assume the original standalone Git repository and tags. It is
retained for reference, not the monorepo acceptance command. Use additional
focused provider checks when relevant; do not regenerate upstream evidence to
claim that it verifies the imported or subsequently modified source.

Changes to `wipe`, `unsafe_wipe`, platform memory backends, comparison
assembly, cache flushing, or guarded mappings must update `docs/SAFETY.md`. Changes
that alter guarantees, limits, or supported attacker models must update
`docs/THREAT_MODEL.md`.
