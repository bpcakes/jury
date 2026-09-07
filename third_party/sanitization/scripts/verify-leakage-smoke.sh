#!/usr/bin/env bash
set -euo pipefail

output="${TMPDIR:-/tmp}/sanitization-ct-leakage-smoke.json"
portable_output="${TMPDIR:-/tmp}/sanitization-ct-leakage-portable-smoke.json"
multi_output="${TMPDIR:-/tmp}/sanitization-ct-leakage-multi-smoke"

cargo check --manifest-path tools/ct-leakage/Cargo.toml
cargo check --manifest-path tools/ct-leakage/Cargo.toml --no-default-features
cargo check --manifest-path tools/ct-leakage/Cargo.toml --features asm-compare
cargo check --manifest-path tools/ct-leakage/Cargo.toml --features strict-compare
cargo run --release --manifest-path tools/ct-leakage/Cargo.toml -- \
    --samples 20 \
    --inner 2 \
    --warmup 2 \
    --threshold 1000000 \
    --output "$output" >/dev/null
python3 -m json.tool "$output" >/dev/null
python3 -c 'import json, sys; report = json.load(open(sys.argv[1], encoding="utf-8")); assert report["environment"]["features"] == "asm-compare"' \
    "$output"

cargo run --release --manifest-path tools/ct-leakage/Cargo.toml --no-default-features -- \
    --samples 20 \
    --inner 2 \
    --warmup 2 \
    --threshold 1000000 \
    --output "$portable_output" >/dev/null
python3 -c 'import json, sys; report = json.load(open(sys.argv[1], encoding="utf-8")); assert report["environment"]["features"] == "portable-fallback"' \
    "$portable_output"

python3 scripts/collect-leakage-evidence.py \
    $'\u00a0--output-dir' "$multi_output" \
    $'\u00a0--samples' 20 \
    $'\u00a0--inner' 2 \
    $'\u00a0--warmup' 2 \
    $'\u00a0--threshold' 1000000000 >/dev/null
python3 -c 'import json, sys; report = json.load(open(sys.argv[1], encoding="utf-8")); assert report["schema_version"] == 2; assert report["passed"] is True; assert report["minimum_confirmation_runs"] == 2; assert report["config"]["confirmation_runs"] == 2; assert report["required_variants"] == ["default-compare", "strict-compare"]; assert len(report["runs"]) == 6; assert all(run["passed"] is True and run["primary_passed"] is True and run["confirmation_required"] is False and run["confirmations_passed"] is None and len(run["attempts"]) == 1 for run in report["runs"])' \
    "$multi_output/summary.json"

printf 'ct leakage smoke check passed: %s\n' "$output"
