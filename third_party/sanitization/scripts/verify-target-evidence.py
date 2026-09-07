#!/usr/bin/env python3
"""Fail closed when CP-20 target, timing, or performance evidence is malformed."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


REQUIRED_VARIANTS = {"default-compare", "strict-compare"}
REQUIRED_CASES = {
    "ct_choice_boolean_ops",
    "ct_eq_fixed_16_first_diff",
    "ct_eq_fixed_32_first_diff",
    "ct_eq_fixed_32_last_diff",
    "ct_eq_fixed_64_last_diff",
    "ct_eq_public_len_64_first_diff",
    "secret_bytes_eq_32_first_diff",
    "ct_cmp_fixed_32_first_diff",
    "ct_u64_ordering_equal_vs_different",
    "ct_u64_select_choice",
    "ct_option_unwrap_choice",
    "ct_result_unwrap_choice",
    "ct_conditional_copy_64_choice",
    "ct_conditional_swap_64_choice",
    "ct_select_slice_64_choice",
    "ct_oblivious_lookup_16_index",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"verify-target-evidence: {message}", file=sys.stderr)
    raise SystemExit(1)


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} must contain an object")
    return value


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        fail(result.stderr.strip() or "cannot determine the current git commit")
    return result.stdout.strip()


def verify_timestamp(value: object, *, path: Path, field: str) -> None:
    if not isinstance(value, str):
        fail(f"{path} is missing {field}")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        fail(f"{path} has malformed {field}")


def verify_commit(value: object, *, path: Path, expected_commit: str) -> None:
    if not isinstance(value, str) or not GIT_COMMIT.fullmatch(value):
        fail(f"{path} has malformed git_commit")
    if value != expected_commit:
        fail(f"{path} was produced for {value}, expected {expected_commit}")


def verify_manifest(path: Path, expected_commit: str) -> None:
    data = load(path)
    if data.get("schema_version") != 1 or data.get("tool") != "sanitization-target-manifest":
        fail(f"{path} has the wrong target-manifest schema")
    if data.get("status") != "passed" or data.get("git_dirty") is not False:
        fail(f"{path} is not clean passing evidence")
    verify_timestamp(data.get("generated_at_utc"), path=path, field="generated_at_utc")
    verify_commit(data.get("git_commit"), path=path, expected_commit=expected_commit)
    kind = data.get("evidence_kind")
    native = data.get("native")
    target = data.get("target")
    host = data.get("host")
    if kind == "native-functional" and (native is not True or target != host):
        fail(f"{path} falsely labels cross-target evidence as native")
    if kind in {"compile-only", "wasm-compatibility"} and native is not False:
        fail(f"{path} compile evidence must not be native")
    if kind == "wasm-compatibility" and (
        not isinstance(target, str) or not target.startswith("wasm32-") or data.get("tier") != "C"
    ):
        fail(f"{path} has invalid WASM classification")
    if data.get("tier") not in {"A", "B", "B/C", "C"}:
        fail(f"{path} has an invalid target tier")
    if not isinstance(data.get("completed_checks"), list) or not data["completed_checks"]:
        fail(f"{path} has no completed checks")
    for key in ("target", "host", "features", "rustc", "workflow_run"):
        if not isinstance(data.get(key), str) or not data[key]:
            fail(f"{path} is missing {key}")
    runner = data.get("runner")
    if not isinstance(runner, dict) or not all(
        isinstance(runner.get(key), str) and runner[key]
        for key in ("name", "os", "arch", "image", "platform")
    ):
        fail(f"{path} has incomplete runner metadata")


def verify_leakage(path: Path, expected_commit: str) -> None:
    summary = load(path)
    if summary.get("schema_version") != 2 or summary.get("tool") != "sanitization-multi-seed-leakage":
        fail(f"{path} has the wrong leakage-summary schema")
    if summary.get("passed") is not True or summary.get("git_dirty") is not False:
        fail(f"{path} is not clean passing leakage evidence")
    verify_timestamp(summary.get("generated_at_utc"), path=path, field="generated_at_utc")
    verify_commit(summary.get("git_commit"), path=path, expected_commit=expected_commit)
    if set(summary.get("required_variants", [])) != REQUIRED_VARIANTS:
        fail(f"{path} does not require default and strict variants")
    if set(summary.get("required_cases", [])) != REQUIRED_CASES:
        fail(f"{path} does not cover the required primitive cases")
    if summary.get("minimum_distinct_seeds") != 3:
        fail(f"{path} has an invalid minimum seed policy")
    minimum_confirmations = summary.get("minimum_confirmation_runs")
    config = summary.get("config")
    if (
        minimum_confirmations != 2
        or not isinstance(config, dict)
        or config.get("confirmation_runs") != 2
    ):
        fail(f"{path} has an invalid confirmation policy")
    runs = summary.get("runs")
    if not isinstance(runs, list):
        fail(f"{path} has no leakage runs")
    commit = summary.get("git_commit")
    variants = {run.get("variant") for run in runs if isinstance(run, dict)}
    if variants != REQUIRED_VARIANTS:
        fail(f"{path} contains an unexpected leakage variant")
    seen_reports: set[Path] = set()
    for variant in REQUIRED_VARIANTS:
        variant_runs = [run for run in runs if isinstance(run, dict) and run.get("variant") == variant]
        seeds = {run.get("seed") for run in variant_runs}
        if len(seeds) < 3 or len(seeds) != len(variant_runs):
            fail(f"{path} requires at least three distinct {variant} seeds")
        for run in variant_runs:
            seed = run.get("seed")
            attempts = run.get("attempts")
            if not isinstance(seed, int) or not isinstance(attempts, list) or not attempts:
                fail(f"{path} contains malformed {variant} attempts")
            attempt_results: list[bool] = []
            for index, attempt in enumerate(attempts, start=1):
                if not isinstance(attempt, dict) or attempt.get("attempt") != index:
                    fail(f"{path} contains unordered {variant} attempts")
                if not SHA256.fullmatch(str(attempt.get("sha256", ""))):
                    fail(f"{path} contains an unhashed {variant} attempt")
                report_path = (path.parent / str(attempt.get("report", ""))).resolve()
                if not report_path.is_relative_to(path.parent.resolve()):
                    fail(f"{path} contains an out-of-tree leakage report")
                if report_path in seen_reports:
                    fail(f"{path} reuses a leakage report: {report_path}")
                seen_reports.add(report_path)
                if not report_path.is_file() or digest(report_path) != attempt["sha256"]:
                    fail(f"{path} report digest mismatch: {report_path}")
                report = load(report_path)
                report_passed = report.get("passed") is True
                process_exit_code = attempt.get("process_exit_code")
                attempt_passed = process_exit_code == 0 and report_passed
                if attempt.get("passed") is not attempt_passed:
                    fail(f"{report_path} attempt result is inconsistent")
                if attempt.get("report_passed") is not report_passed:
                    fail(f"{report_path} report result is inconsistent")
                attempt_results.append(attempt_passed)
                if report.get("seed") != seed:
                    fail(f"{report_path} seed mismatch")
                verify_timestamp(
                    report.get("generated_at_utc"),
                    path=report_path,
                    field="generated_at_utc",
                )
                environment = report.get("environment")
                if not isinstance(environment, dict) or environment.get("git_commit") != commit:
                    fail(f"{report_path} commit mismatch")
                expected_features = (
                    "asm-compare"
                    if variant == "default-compare"
                    else "asm-compare,strict-compare"
                )
                if environment.get("features") != expected_features:
                    fail(f"{report_path} feature mismatch")
                if report.get("config") != {
                    "samples": config.get("samples"),
                    "inner": config.get("inner"),
                    "warmup": config.get("warmup"),
                    "threshold": config.get("threshold"),
                }:
                    fail(f"{report_path} run configuration mismatch")
                for key in ("target", "profile", "rustc", "workflow_run"):
                    if not isinstance(environment.get(key), str) or not environment[key]:
                        fail(f"{report_path} is missing environment.{key}")
                cases = report.get("cases", [])
                names = {
                    case.get("name")
                    for case in cases
                    if isinstance(case, dict)
                }
                if names != REQUIRED_CASES or len(cases) != len(REQUIRED_CASES):
                    fail(f"{report_path} case coverage mismatch")

            primary_passed = attempt_results[0]
            primary = attempts[0]
            confirmation_required = (
                primary.get("process_exit_code") == 1
                and primary.get("report_passed") is False
            )
            if run.get("primary_passed") is not primary_passed:
                fail(f"{path} misstates the {variant} primary result")
            if run.get("confirmation_required") is not confirmation_required:
                fail(f"{path} misstates the {variant} confirmation requirement")
            if run.get("passed") is not primary_passed:
                fail(f"{path} misstates release acceptance for the {variant} primary")
            if primary_passed:
                if run.get("confirmations_passed") is not None:
                    fail(f"{path} invents a {variant} confirmation result")
                if len(attempt_results) != 1:
                    fail(f"{path} contains unnecessary {variant} confirmation runs")
            else:
                if not confirmation_required:
                    fail(f"{path} contains a release-blocking operational failure")
                if len(attempt_results) != 1 + minimum_confirmations:
                    fail(f"{path} has incomplete {variant} diagnostic confirmations")
                confirmations_passed = all(attempt_results[1:])
                if run.get("confirmations_passed") is not confirmations_passed:
                    fail(f"{path} misstates the {variant} confirmation result")
                fail(f"{path} contains a release-blocking {variant} primary excursion")


def verify_performance(path: Path, expected_commit: str, allow_dirty: bool) -> None:
    data = load(path)
    if data.get("schema_version") != 1 or data.get("tool") != "sanitization-performance-baseline":
        fail(f"{path} has the wrong performance schema")
    if data.get("passed") is not True:
        fail(f"{path} reports a performance regression")
    verify_commit(data.get("git_commit"), path=path, expected_commit=expected_commit)
    if not allow_dirty and data.get("git_dirty") is not False:
        fail(f"{path} is not clean performance evidence")
    if not isinstance(data.get("generated_at_unix"), int) or data["generated_at_unix"] <= 0:
        fail(f"{path} has an invalid generation timestamp")
    for key in ("target", "rustc", "runner", "workflow_run"):
        if not isinstance(data.get(key), str) or not data[key]:
            fail(f"{path} is missing {key}")
    ratios = data.get("ratios")
    thresholds = data.get("thresholds")
    if not isinstance(ratios, dict) or not isinstance(thresholds, dict):
        fail(f"{path} lacks ratios or thresholds")
    pairs = (
        ("wipe_scaling", "max_wipe_scaling"),
        ("specialized_to_generic", "max_specialized_to_generic"),
        ("secret_bytes_to_generic", "max_secret_bytes_to_generic"),
    )
    for ratio_name, threshold_name in pairs:
        ratio = ratios.get(ratio_name)
        threshold = thresholds.get(threshold_name)
        if not isinstance(ratio, (int, float)) or not isinstance(threshold, (int, float)):
            fail(f"{path} lacks numeric {ratio_name}/{threshold_name}")
        if ratio > threshold:
            fail(f"{path} exceeds {threshold_name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, action="append", default=[])
    parser.add_argument("--leakage-summary", type=Path, action="append", default=[])
    parser.add_argument("--performance", type=Path, action="append", default=[])
    parser.add_argument("--expected-commit")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="permit dirty performance smoke reports; never use for release evidence",
    )
    args = parser.parse_args()
    if not (args.manifest or args.leakage_summary or args.performance):
        fail("at least one evidence path is required")
    expected_commit = args.expected_commit or current_commit()
    if not GIT_COMMIT.fullmatch(expected_commit):
        fail("--expected-commit must be a full lowercase git commit")
    for path in args.manifest:
        verify_manifest(path, expected_commit)
    for path in args.leakage_summary:
        verify_leakage(path, expected_commit)
    for path in args.performance:
        verify_performance(path, expected_commit, args.allow_dirty)
    print("CP-20 target evidence validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
