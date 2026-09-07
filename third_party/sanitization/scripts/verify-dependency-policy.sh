#!/usr/bin/env bash
set -euo pipefail

if ! cargo deny --version >/dev/null 2>&1; then
    printf '%s\n' 'cargo-deny 0.20.2 is required; install it with:' >&2
    printf '%s\n' 'cargo install cargo-deny --version 0.20.2 --locked' >&2
    exit 1
fi

expected_version='cargo-deny 0.20.2'
actual_version="$(cargo deny --version)"
if [ "$actual_version" != "$expected_version" ]; then
    printf 'expected %s, found %s\n' "$expected_version" "$actual_version" >&2
    exit 1
fi

manifests=(
    Cargo.toml
    fuzz/Cargo.toml
    tools/consume-once-loom/Cargo.toml
    tools/core-dump-probe/Cargo.toml
    tools/ct-leakage/Cargo.toml
    tools/direct-exposure-codegen/Cargo.toml
    tools/downstream-migration/Cargo.toml
    tools/lifecycle-probes/Cargo.toml
    tools/performance-baseline/Cargo.toml
)

for manifest in "${manifests[@]}"; do
    config='deny.toml'
    if [ "$manifest" = 'fuzz/Cargo.toml' ]; then
        config='fuzz/deny.toml'
    fi

    cargo deny \
        --config "$config" \
        --manifest-path "$manifest" \
        --locked \
        check \
        --allow license-not-encountered \
        --allow license-exception-not-encountered \
        bans licenses sources
done

printf 'dependency policy verified across %s Cargo graphs\n' "${#manifests[@]}"
