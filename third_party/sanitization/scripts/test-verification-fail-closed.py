#!/usr/bin/env python3
"""Seed negative artifacts and require verification tooling to reject them."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )


def expect_failure(command: list[str], label: str, cwd: Path = ROOT) -> None:
    result = run(command, cwd)
    if result.returncode == 0:
        raise SystemExit(f"negative verification fixture unexpectedly passed: {label}")


with tempfile.TemporaryDirectory(prefix="sanitization-negative-evidence-") as directory:
    temp = Path(directory)
    commit = run(["git", "rev-parse", "HEAD"]).stdout.strip()

    invalid_evidence = json.loads(
        (ROOT / "docs" / "ct-evidence.json").read_text(encoding="utf-8")
    )
    invalid_evidence.pop("claim")
    evidence_path = temp / "ct-evidence.json"
    evidence_path.write_text(json.dumps(invalid_evidence), encoding="utf-8")
    expect_failure(
        [
            "python3",
            str(ROOT / "scripts" / "verify-evidence.py"),
            str(evidence_path),
        ],
        "missing evidence claim",
    )

    tampered_cp21 = temp / "cp21-public-api.json"
    tampered_cp21.write_bytes(
        (ROOT / "docs" / "baselines" / "2.0" / "cp21-public-api.json").read_bytes()
        + b"\n"
    )
    expect_failure(
        [
            "python3",
            str(ROOT / "scripts" / "verify-2.0-api-freeze.py"),
            "--cp21",
            str(tampered_cp21),
        ],
        "tampered immutable CP-21 source inventory",
    )

    stale_current = json.loads(
        (
            ROOT / "docs" / "baselines" / "2.0" / "current-source-api.json"
        ).read_text(encoding="utf-8")
    )
    source_path = next(iter(stale_current["source_hashes"]))
    stale_current["source_hashes"][source_path] = "00" * 32
    stale_current_path = (
        temp / "docs" / "baselines" / "2.0" / "current-source-api.json"
    )
    stale_current_path.parent.mkdir(parents=True)
    stale_current_path.write_text(json.dumps(stale_current), encoding="utf-8")
    expect_failure(
        [
            "python3",
            str(ROOT / "scripts" / "verify-2.0-api-freeze.py"),
            "--current",
            "docs/baselines/2.0/current-source-api.json",
        ],
        "caller-relative tampered current source hash inventory",
        cwd=temp,
    )

    invalid_ir = temp / "invalid.ll"
    invalid_ir.write_text(
        "define void @cp04_direct_exposure() {\n  ret void\n}\n",
        encoding="utf-8",
    )
    expect_failure(
        [
            "python3",
            str(ROOT / "scripts" / "verify-codegen-artifact.py"),
            str(invalid_ir),
        ],
        "missing path-specific probes",
    )

    false_native = {
        "schema_version": 1,
        "tool": "sanitization-target-manifest",
        "generated_at_utc": "2026-07-19T00:00:00Z",
        "status": "passed",
        "git_commit": commit,
        "git_dirty": False,
        "target": "aarch64-unknown-linux-gnu",
        "host": "x86_64-unknown-linux-gnu",
        "native": True,
        "tier": "B",
        "evidence_kind": "native-functional",
        "features": "fixture",
        "completed_checks": ["fixture"],
        "rustc": "fixture",
        "workflow_run": "fixture",
    }
    false_native_path = temp / "false-native.json"
    false_native_path.write_text(json.dumps(false_native), encoding="utf-8")
    expect_failure(
        [
            "python3",
            str(ROOT / "scripts" / "verify-target-evidence.py"),
            "--manifest",
            str(false_native_path),
        ],
        "cross-target result labeled native",
    )

    failed_performance = {
        "schema_version": 1,
        "tool": "sanitization-performance-baseline",
        "passed": False,
        "ratios": {
            "wipe_scaling": 200.0,
            "specialized_to_generic": 1.0,
            "secret_bytes_to_generic": 1.0,
        },
        "thresholds": {
            "max_wipe_scaling": 128.0,
            "max_specialized_to_generic": 0.5,
            "max_secret_bytes_to_generic": 0.5,
        },
    }
    failed_performance_path = temp / "failed-performance.json"
    failed_performance_path.write_text(
        json.dumps(failed_performance), encoding="utf-8"
    )
    expect_failure(
        [
            "python3",
            str(ROOT / "scripts" / "verify-target-evidence.py"),
            "--performance",
            str(failed_performance_path),
        ],
        "failed performance baseline",
    )

    passing_performance = {
        "schema_version": 1,
        "tool": "sanitization-performance-baseline",
        "generated_at_unix": 1,
        "git_commit": "0" * 40,
        "git_dirty": False,
        "target": "x86_64-unknown-linux-gnu",
        "rustc": "fixture",
        "runner": "fixture",
        "workflow_run": "fixture",
        "passed": True,
        "ratios": {
            "wipe_scaling": 1.0,
            "specialized_to_generic": 0.1,
            "secret_bytes_to_generic": 0.1,
        },
        "thresholds": {
            "max_wipe_scaling": 128.0,
            "max_specialized_to_generic": 0.5,
            "max_secret_bytes_to_generic": 0.5,
        },
    }
    mismatched_performance_path = temp / "mismatched-performance.json"
    mismatched_performance_path.write_text(
        json.dumps(passing_performance), encoding="utf-8"
    )
    expect_failure(
        [
            "python3",
            str(ROOT / "scripts" / "verify-target-evidence.py"),
            "--performance",
            str(mismatched_performance_path),
        ],
        "performance report for another commit",
    )

    passing_performance["git_commit"] = commit
    passing_performance["git_dirty"] = True
    dirty_performance_path = temp / "dirty-performance.json"
    dirty_performance_path.write_text(
        json.dumps(passing_performance), encoding="utf-8"
    )
    expect_failure(
        [
            "python3",
            str(ROOT / "scripts" / "verify-target-evidence.py"),
            "--performance",
            str(dirty_performance_path),
        ],
        "dirty performance evidence without a smoke override",
    )

print("verification tooling rejected seeded negative fixtures")
