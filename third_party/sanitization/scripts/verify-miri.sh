#!/usr/bin/env bash
set -euo pipefail

toolchain="${MIRI_TOOLCHAIN:-nightly}"

if ! cargo +"${toolchain}" miri --version >/dev/null 2>&1; then
    echo "cargo miri is unavailable for toolchain '${toolchain}'" >&2
    echo "install it with: rustup +${toolchain} component add miri" >&2
    exit 1
fi

cargo +"${toolchain}" miri test -p sanitization --no-default-features
cargo +"${toolchain}" miri test -p sanitization --features alloc
cargo +"${toolchain}" miri test -p sanitization --all-features --lib
cargo +"${toolchain}" miri test -p sanitization --test miri_downstream
cargo +"${toolchain}" miri test -p sanitization \
    --no-default-features \
    --features derive \
    --test derive
cargo +"${toolchain}" miri test -p sanitization-arrayvec
cargo +"${toolchain}" miri test -p sanitization-bytes
cargo +"${toolchain}" miri test -p sanitization-crypto-interop \
    --no-default-features \
    --features sha2,blake3,hmac-sha2
