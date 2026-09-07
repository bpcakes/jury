#!/usr/bin/env sh
set -eu

uses_lines="$(grep -REn '^[[:space:]]*uses:' .github/workflows || true)"
invalid="$(
    printf '%s\n' "$uses_lines" \
        | grep -Ev ':[[:space:]]*uses: [^@[:space:]]+@[0-9a-f]{40}([[:space:]]+#.*)?$' \
        || true
)"

if [ -n "$invalid" ]; then
    echo "GitHub Actions must be pinned to immutable full commit SHAs:" >&2
    printf '%s\n' "$invalid" >&2
    exit 1
fi

echo "GitHub Action SHA pins verified"
