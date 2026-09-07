#!/usr/bin/env bash
set -euo pipefail

toolchains=(
    1.90.0
    1.91.0
    1.92.0
    1.93.0
    1.94.0
    1.95.0
    1.96.0
    1.96.1
    1.97.0
    1.97.1
    1.98.0
    1.98.1
)

for toolchain in "${toolchains[@]}"; do
    if ! rustup toolchain list | grep -Eq "^${toolchain}(-|$)"; then
        rustup toolchain install "$toolchain" --profile minimal
    fi

    cargo "+$toolchain" check --workspace --all-features
done
