#!/usr/bin/env bash
set -euo pipefail

cargo fmt --manifest-path tools/consume-once-loom/Cargo.toml --check
cargo clippy --manifest-path tools/consume-once-loom/Cargo.toml --all-targets -- -D warnings
cargo test --release --manifest-path tools/consume-once-loom/Cargo.toml
