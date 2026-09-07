# Maintained sanitization provider

## Purpose

Own the maintained guarded-memory provider used by Jury. This is editable
monorepo source, imported from the operator-owned fork; it is not a generated
Cargo vendor cache. Jury remains pre-alpha and unsuitable for real secrets.

## Key entrypoints

- `Cargo.toml`: separate workspace, original licensing, import ancestry
- `crates/sanitization/src/lib.rs`: safe public provider API
- `crates/sanitization/src/mapped/`: guarded mappings and native controls
- `crates/sanitization/src/mapped/native_tests.rs`: failure and native oracles
- `docs/SAFETY.md`: unsafe implementation invariants
- `../../crates/jury-protected`: Jury's safe integration and status policy

## Edit here for X

Develop native provider changes here and their Jury integration in the same
change. Keep tests beside the owning implementation. Update `docs/SAFETY.md`
for changes to unsafe memory operations, and `docs/THREAT_MODEL.md` when their
guarantees change. Preserve the upstream notices verbatim. The workspace
metadata records the original import; do not relabel later edits as that revision.

## Invariants

- Keep this workspace separate from Jury's root workspace. Its MIT OR Apache-2.0
  terms and narrowly scoped native unsafe implementation remain its own.
- Do not weaken Jury crates' `unsafe_code = "forbid"` policy.
- This tree is explicitly excluded from Jury's file-size cap. Its compilation,
  formatting, Clippy, and tests remain required; use the monorepo workflow.
- Do not add production cryptographic algorithms or change crypto boundaries
  without Jury's applicable gates. Imported optional modules are not newly
  approved Jury features.
- No secrets in logs, diagnostics, or fixtures. Use generic synthetic inputs.
- Upstream documents and evidence are historical provider material, not a
  certification of Jury or proof of subsequent changes.
- Check upstream advisories and the maintained delta when updating the
  provider; ordinary registry auditing does not cover the path dependency.
- Do not publish provider crates or run upstream release scripts as part of
  local development. Monorepo CI lives in `../../.github/workflows`.

## Common commands

From the Jury root:

```sh
cargo test --manifest-path third_party/sanitization/Cargo.toml --locked -p sanitization --no-default-features --features std,profile-guarded-native,require-fork-exclusion
cargo test --manifest-path third_party/sanitization/Cargo.toml --locked --workspace
cargo test -p jury-protected --locked
cargo fmt --manifest-path third_party/sanitization/Cargo.toml --all -- --check
```

Native tests require working guarded mappings and an adequate memory-lock
limit (Linux CI uses 64 MiB). Failures remain failures; do not skip controls
because a host cannot establish them. Root `cargo test --workspace` does not
run this separate workspace's tests, so CI runs both explicitly.
