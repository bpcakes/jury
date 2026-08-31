# Witness-v1 conformance corpus

## Purpose

This standalone crate owns the public J19C vectors and bounded model. It is not
a Jury runtime dependency and contains only deterministic generic fixtures.

## Key entrypoints

- `src/lib.rs` builds and consumes the corpus and runs the bounded model.
- `src/bin/generate.rs` emits the deterministic corpus.
- `alternate_runner.py` independently consumes the JSON cases with Python's
  standard library.
- `vectors.json` is the checked-in language-neutral corpus.

## Invariants

- Keep the crate outside the root Cargo workspace and all product dependency
  graphs.
- Never replace a mismatching checked-in vector during a test run.
- Keep fixture material public, deterministic, and generically named.
- Do not describe model exhaustion as a formal proof or external review.

## Common commands

- `cargo test --manifest-path conformance/witness-v1/Cargo.toml --locked`
- `python3 conformance/witness-v1/alternate_runner.py conformance/witness-v1/vectors.json`
- `cargo run --manifest-path conformance/witness-v1/Cargo.toml --locked --bin generate -- --check`
