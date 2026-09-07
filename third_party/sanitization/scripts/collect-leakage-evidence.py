#!/usr/bin/env python3
"""Collect reproducible multi-seed default and strict CT leakage evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tools" / "ct-leakage" / "Cargo.toml"
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
VARIANTS = {
    "default-compare": (None, "asm-compare"),
    "strict-compare": ("strict-compare", "asm-compare,strict-compare"),
}
DEFAULT_SEEDS = [
    0x243F6A8885A308D3,
    0x13198A2E03707344,
    0xA4093822299F31D0,
]
MINIMUM_CONFIRMATION_RUNS = 2


def fail(message: str) -> None:
    print(f"collect-leakage-evidence: {message}", file=sys.stderr)
    raise SystemExit(1)


def git_output(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, text=True, capture_output=True, check=False
    )
    if result.returncode != 0:
        fail(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_seeds(value: str) -> list[int]:
    try:
        seeds = [int(item.strip(), 0) for item in value.split(",") if item.strip()]
    except ValueError as error:
        raise argparse.ArgumentTypeError("seeds must be comma-separated integers") from error
    if len(seeds) < 3 or len(set(seeds)) != len(seeds):
        raise argparse.ArgumentTypeError("at least three distinct seeds are required")
    if any(seed < 0 or seed > (1 << 64) - 1 for seed in seeds):
        raise argparse.ArgumentTypeError("seeds must fit in u64")
    return seeds


def validate_report(
    report: dict[str, object], *, seed: int, commit: str, expected_features: str
) -> None:
    if report.get("schema_version") != 1 or report.get("tool") != "ct-leakage":
        fail("leakage report schema or tool name is invalid")
    if report.get("seed") != seed:
        fail(f"leakage report seed mismatch: expected {seed}")
    environment = report.get("environment")
    if not isinstance(environment, dict):
        fail("leakage report environment is missing")
    if environment.get("git_commit") != commit:
        fail("leakage report commit does not match the collected checkout")
    if environment.get("features") != expected_features:
        fail(f"leakage report feature mismatch for {expected_features}")
    cases = report.get("cases")
    if not isinstance(cases, list):
        fail("leakage report cases are missing")
    names = {case.get("name") for case in cases if isinstance(case, dict)}
    if names != REQUIRED_CASES:
        missing = sorted(REQUIRED_CASES - names)
        extra = sorted(name for name in names - REQUIRED_CASES if isinstance(name, str))
        fail(f"leakage case mismatch; missing={missing}, extra={extra}")


def failed_cases(report: dict[str, object]) -> list[dict[str, object]]:
    cases = report.get("cases")
    if not isinstance(cases, list):
        return []
    return [
        {
            "name": case.get("name"),
            "welch_t_abs": case.get("welch_t_abs"),
            "threshold": case.get("threshold"),
        }
        for case in cases
        if isinstance(case, dict) and case.get("passed") is not True
    ]


def normalize_cli_args(arguments: list[str]) -> list[str]:
    """Remove formatting whitespace commonly introduced when commands are copied."""
    return [argument.strip().strip("\ufeff").strip() for argument in arguments]


def evaluate_attempts(
    attempts: list[dict[str, object]],
) -> tuple[bool, bool, bool | None]:
    """Return release acceptance, confirmation need, and diagnostic result."""
    primary = attempts[0]
    primary_passed = primary["passed"] is True
    confirmation_required = (
        primary["process_exit_code"] == 1 and primary["report_passed"] is False
    )
    confirmations_passed = (
        all(attempt["passed"] is True for attempt in attempts[1:])
        if confirmation_required and len(attempts) > 1
        else None
    )
    return primary_passed, confirmation_required, confirmations_passed


def collect_attempt(
    *,
    variant: str,
    feature: str | None,
    expected_features: str,
    seed: int,
    attempt: int,
    output_dir: Path,
    commit: str,
    samples: int,
    inner: int,
    warmup: int,
    threshold: float,
) -> dict[str, object]:
    variant_dir = output_dir / variant
    variant_dir.mkdir(parents=True, exist_ok=True)
    suffix = "" if attempt == 1 else f"-confirmation-{attempt - 1}"
    report_path = variant_dir / f"seed-{seed}{suffix}.json"
    command = [
        "cargo",
        "run",
        "--quiet",
        "--release",
        "--manifest-path",
        str(MANIFEST),
    ]
    if feature is not None:
        command.extend(["--features", feature])
    command.extend(
        [
            "--",
            "--seed",
            str(seed),
            "--samples",
            str(samples),
            "--inner",
            str(inner),
            "--warmup",
            str(warmup),
            "--threshold",
            str(threshold),
            "--output",
            str(report_path),
        ]
    )
    result = subprocess.run(
        command, cwd=ROOT, text=True, capture_output=True, check=False
    )
    if not report_path.is_file():
        fail(result.stderr.strip() or f"{variant} seed {seed} produced no report")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    validate_report(
        report,
        seed=seed,
        commit=commit,
        expected_features=expected_features,
    )
    cases = report["cases"]
    report_passed = report.get("passed") is True
    return {
        "attempt": attempt,
        "passed": result.returncode == 0 and report_passed,
        "report_passed": report_passed,
        "max_welch_t_abs": max(float(case["welch_t_abs"]) for case in cases),
        "process_exit_code": result.returncode,
        "failed_cases": failed_cases(report),
        "report": str(report_path.relative_to(output_dir)),
        "sha256": sha256(report_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=50_000)
    parser.add_argument("--inner", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=1_000)
    parser.add_argument("--threshold", type=float, default=4.5)
    parser.add_argument(
        "--confirmation-runs",
        type=int,
        default=MINIMUM_CONFIRMATION_RUNS,
        help="fresh same-seed runs required after a primary statistical excursion",
    )
    parser.add_argument(
        "--seeds",
        type=parse_seeds,
        default=DEFAULT_SEEDS,
        help="comma-separated decimal or 0x-prefixed u64 values",
    )
    args = parser.parse_args(normalize_cli_args(sys.argv[1:]))
    if args.confirmation_runs != MINIMUM_CONFIRMATION_RUNS:
        fail(
            "confirmation-runs must be exactly "
            f"{MINIMUM_CONFIRMATION_RUNS} for release evidence"
        )
    if args.samples < 2 or args.inner < 1 or args.warmup < 0 or args.threshold <= 0:
        fail(
            "samples, inner, warmup, and threshold must describe a valid evidence run"
        )

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    commit = git_output("rev-parse", "HEAD")
    runs: list[dict[str, object]] = []

    for variant, (feature, expected_features) in VARIANTS.items():
        for seed in args.seeds:
            attempts = [
                collect_attempt(
                    variant=variant,
                    feature=feature,
                    expected_features=expected_features,
                    seed=seed,
                    attempt=1,
                    output_dir=output_dir,
                    commit=commit,
                    samples=args.samples,
                    inner=args.inner,
                    warmup=args.warmup,
                    threshold=args.threshold,
                )
            ]
            primary_passed, confirmation_required, _ = evaluate_attempts(attempts)
            if confirmation_required:
                for confirmation in range(1, args.confirmation_runs + 1):
                    attempts.append(
                        collect_attempt(
                            variant=variant,
                            feature=feature,
                            expected_features=expected_features,
                            seed=seed,
                            attempt=confirmation + 1,
                            output_dir=output_dir,
                            commit=commit,
                            samples=args.samples,
                            inner=args.inner,
                            warmup=args.warmup,
                            threshold=args.threshold,
                        )
                    )
            accepted, _, confirmations_passed = evaluate_attempts(attempts)
            runs.append(
                {
                    "variant": variant,
                    "seed": seed,
                    "passed": accepted,
                    "primary_passed": primary_passed,
                    "confirmation_required": confirmation_required,
                    "confirmations_passed": confirmations_passed,
                    "attempts": attempts,
                }
            )

    passed = all(run["passed"] is True for run in runs)
    summary = {
        "schema_version": 2,
        "tool": "sanitization-multi-seed-leakage",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": commit,
        "git_dirty": bool(git_output("status", "--short")),
        "passed": passed,
        "minimum_distinct_seeds": 3,
        "minimum_confirmation_runs": MINIMUM_CONFIRMATION_RUNS,
        "required_variants": sorted(VARIANTS),
        "required_cases": sorted(REQUIRED_CASES),
        "config": {
            "samples": args.samples,
            "inner": args.inner,
            "warmup": args.warmup,
            "threshold": args.threshold,
            "confirmation_runs": args.confirmation_runs,
        },
        "runs": runs,
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(summary_path)
    for run in runs:
        if run["confirmation_required"] is True:
            result = "passed" if run["confirmations_passed"] is True else "failed"
            print(
                "collect-leakage-evidence: primary excursion is release-blocking; "
                f"{args.confirmation_runs} diagnostic confirmations {result} "
                f"variant={run['variant']} seed={run['seed']}",
                file=sys.stderr,
            )
    if not passed:
        for run in runs:
            if run["passed"] is True:
                continue
            for attempt in run["attempts"]:
                if attempt["passed"] is True:
                    continue
                print(
                    "collect-leakage-evidence: "
                    f"FAILED variant={run['variant']} seed={run['seed']} "
                    f"attempt={attempt['attempt']} "
                    f"exit={attempt['process_exit_code']} "
                    f"max_welch_t_abs={attempt['max_welch_t_abs']:.6f}",
                    file=sys.stderr,
                )
                for case in attempt["failed_cases"]:
                    print(
                        "collect-leakage-evidence:   "
                        f"case={case['name']} "
                        f"welch_t_abs={float(case['welch_t_abs']):.6f} "
                        f"threshold={float(case['threshold']):.6f}",
                        file=sys.stderr,
                    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
