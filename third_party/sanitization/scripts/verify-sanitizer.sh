#!/usr/bin/env bash
set -euo pipefail

sanitizer="${1:-}"
case "${sanitizer}" in
    address|thread) ;;
    *)
        echo "usage: verify-sanitizer.sh address|thread" >&2
        exit 2
        ;;
esac

toolchain="${SANITIZER_TOOLCHAIN:-nightly}"
target="${SANITIZER_TARGET:-x86_64-unknown-linux-gnu}"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
    echo "${sanitizer} sanitizer verification currently requires x86_64 Linux" >&2
    exit 1
fi

export RUSTFLAGS="-Zsanitizer=${sanitizer}"
export RUSTDOCFLAGS="-Zsanitizer=${sanitizer}"

cargo +"${toolchain}" test \
    -Zbuild-std \
    --target "${target}" \
    -p sanitization \
    --all-features \
    --lib \
    -- \
    --test-threads=1
