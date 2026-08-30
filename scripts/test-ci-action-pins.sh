#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
CHECKER="$REPO_ROOT/scripts/check-ci-action-pins.sh"
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT

mkdir -p "$TEST_ROOT/good/local-action" "$TEST_ROOT/bad" "$TEST_ROOT/multiple" "$TEST_ROOT/local-bad/wrapper"

cat >"$TEST_ROOT/good/workflow.yml" <<'YAML'
jobs:
  test:
    steps:
      - uses : actions/example@0123456789abcdef0123456789abcdef01234567
      - "uses": "actions/quoted@89abcdef0123456789abcdef0123456789abcdef"
      - uses: docker://ghcr.io/example/action@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      - uses: ./local-action
      - run: echo 'actions/example@v1 is documentation, not an action invocation'
YAML

cat >"$TEST_ROOT/good/local-action/action.yml" <<'YAML'
name: Local pinned wrapper
runs:
  using: composite
  steps:
    - uses: actions/nested@fedcba9876543210fedcba9876543210fedcba98
YAML

cat >"$TEST_ROOT/multiple/workflow.yml" <<'YAML'
jobs: {}
---
jobs:
  hidden:
    uses: actions/example@v1
YAML

cat >"$TEST_ROOT/bad/workflow.yml" <<'YAML'
jobs:
  test:
    steps:
      - uses : actions/example@v1
      - "uses": actions/quoted@v2
      - "\u0075ses": "actions\u002fescaped\u0040main"
      - uses: docker://ghcr.io/example/action:latest
YAML

cat >"$TEST_ROOT/local-bad/workflow.yml" <<'YAML'
jobs:
  test:
    steps:
      - uses: ./wrapper
YAML

cat >"$TEST_ROOT/local-bad/wrapper/action.yml" <<'YAML'
name: Local mutable wrapper
runs:
  using: composite
  steps:
    - uses: actions/nested@v1
YAML

bash "$CHECKER" "$TEST_ROOT/good" "$TEST_ROOT/good"
if bash "$CHECKER" "$TEST_ROOT/bad" "$TEST_ROOT/bad" >"$TEST_ROOT/bad.out" 2>"$TEST_ROOT/bad.err"; then
  echo "Mutable action tag was accepted" >&2
  exit 1
fi
grep -Fq 'actions/example@v1' "$TEST_ROOT/bad.err"
grep -Fq 'actions/quoted@v2' "$TEST_ROOT/bad.err"
grep -Fq 'actions/escaped@main' "$TEST_ROOT/bad.err"
grep -Fq 'docker://ghcr.io/example/action:latest' "$TEST_ROOT/bad.err"

if bash "$CHECKER" "$TEST_ROOT/local-bad" "$TEST_ROOT/local-bad" >"$TEST_ROOT/local-bad.out" 2>"$TEST_ROOT/local-bad.err"; then
  echo "Mutable action in a local wrapper was accepted" >&2
  exit 1
fi
grep -Fq 'actions/nested@v1' "$TEST_ROOT/local-bad.err"

if bash "$CHECKER" "$TEST_ROOT/multiple" "$TEST_ROOT/multiple" >"$TEST_ROOT/multiple.out" 2>"$TEST_ROOT/multiple.err"; then
  echo "Multiple YAML documents were accepted" >&2
  exit 1
fi
grep -Fq 'exactly one YAML document is required' "$TEST_ROOT/multiple.err"

bash "$CHECKER" "$REPO_ROOT/.github/workflows" "$REPO_ROOT"
