#!/usr/bin/env python3
"""Regression checks for fail-closed leakage-evidence acceptance policy."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "scripts" / "collect-leakage-evidence.py"
VERIFIER = ROOT / "scripts" / "verify-target-evidence.py"


spec = importlib.util.spec_from_file_location("collect_leakage_evidence", COLLECTOR)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load leakage collector")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


passing = {
    "passed": True,
    "process_exit_code": 0,
    "report_passed": True,
}
excursion = {
    "passed": False,
    "process_exit_code": 1,
    "report_passed": False,
}

accepted, confirmation_required, confirmations_passed = collector.evaluate_attempts(
    [passing]
)
assert accepted is True
assert confirmation_required is False
assert confirmations_passed is None

accepted, confirmation_required, confirmations_passed = collector.evaluate_attempts(
    [excursion, passing, passing]
)
assert accepted is False
assert confirmation_required is True
assert confirmations_passed is True

accepted, confirmation_required, confirmations_passed = collector.evaluate_attempts(
    [excursion, passing, excursion]
)
assert accepted is False
assert confirmation_required is True
assert confirmations_passed is False

with tempfile.TemporaryDirectory(prefix="sanitization-leakage-policy-") as directory:
    temp = Path(directory)
    result = subprocess.run(
        [
            "python3",
            str(COLLECTOR),
            "--output-dir",
            str(temp / "collector-output"),
            "--confirmation-runs",
            "3",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "confirmation-runs must be exactly 2" in result.stderr

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    config = {
        "samples": 50_000,
        "inner": 200,
        "warmup": 1_000,
        "threshold": 4.5,
        "confirmation_runs": 2,
    }

    def write_report(
        variant: str, seed: int, attempt: int, passed: bool
    ) -> dict[str, object]:
        suffix = "" if attempt == 1 else f"-confirmation-{attempt - 1}"
        relative = Path(variant) / f"seed-{seed}{suffix}.json"
        path = temp / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        cases = [
            {
                "name": name,
                "passed": passed or index != 0,
                "welch_t_abs": 1.0 if passed or index != 0 else 5.0,
                "threshold": 4.5,
            }
            for index, name in enumerate(sorted(collector.REQUIRED_CASES))
        ]
        report = {
            "schema_version": 1,
            "tool": "ct-leakage",
            "generated_at_utc": "2026-09-04T00:00:00Z",
            "passed": passed,
            "seed": seed,
            "config": {key: config[key] for key in ("samples", "inner", "warmup", "threshold")},
            "environment": {
                "git_commit": commit,
                "features": collector.VARIANTS[variant][1],
                "target": "x86_64-unknown-linux-gnu",
                "profile": "release",
                "rustc": "fixture",
                "workflow_run": "fixture",
            },
            "cases": cases,
        }
        path.write_text(json.dumps(report), encoding="utf-8")
        return {
            "attempt": attempt,
            "passed": passed,
            "report_passed": passed,
            "max_welch_t_abs": 1.0 if passed else 5.0,
            "process_exit_code": 0 if passed else 1,
            "failed_cases": [] if passed else [cases[0]],
            "report": str(relative),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    runs = []
    for variant in sorted(collector.VARIANTS):
        for seed in collector.DEFAULT_SEEDS:
            if variant == "default-compare" and seed == collector.DEFAULT_SEEDS[0]:
                attempts = [
                    write_report(variant, seed, 1, False),
                    write_report(variant, seed, 2, True),
                    write_report(variant, seed, 3, True),
                ]
                runs.append(
                    {
                        "variant": variant,
                        "seed": seed,
                        "passed": True,
                        "primary_passed": False,
                        "confirmation_required": True,
                        "confirmations_passed": True,
                        "attempts": attempts,
                    }
                )
            else:
                runs.append(
                    {
                        "variant": variant,
                        "seed": seed,
                        "passed": True,
                        "primary_passed": True,
                        "confirmation_required": False,
                        "confirmations_passed": None,
                        "attempts": [write_report(variant, seed, 1, True)],
                    }
                )

    summary = {
        "schema_version": 2,
        "tool": "sanitization-multi-seed-leakage",
        "generated_at_utc": "2026-09-04T00:00:00Z",
        "git_commit": commit,
        "git_dirty": False,
        "passed": True,
        "minimum_distinct_seeds": 3,
        "minimum_confirmation_runs": 2,
        "required_variants": sorted(collector.VARIANTS),
        "required_cases": sorted(collector.REQUIRED_CASES),
        "config": config,
        "runs": runs,
    }
    summary_path = temp / "summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    result = subprocess.run(
        [
            "python3",
            str(VERIFIER),
            "--leakage-summary",
            str(summary_path),
            "--expected-commit",
            commit,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "misstates release acceptance" in result.stderr

    summary["config"]["confirmation_runs"] = 3
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    result = subprocess.run(
        [
            "python3",
            str(VERIFIER),
            "--leakage-summary",
            str(summary_path),
            "--expected-commit",
            commit,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "invalid confirmation policy" in result.stderr

print("leakage evidence policy rejects retry-based acceptance and variable confirmations")
