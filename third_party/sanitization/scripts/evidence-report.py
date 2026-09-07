#!/usr/bin/env python3
"""Emit local release-evidence metadata as JSON.

This script does not certify a release. It captures the local toolchain,
repository, and installed-target context that `docs/EVIDENCE.md`,
`docs/TARGETS.md`, and `docs/ct-evidence.json` require release candidates to
cite.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str]) -> tuple[int, str, str]:
    process = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return process.returncode, process.stdout.strip(), process.stderr.strip()


def command_output(command: list[str]) -> str | None:
    if shutil.which(command[0]) is None:
        return None
    code, stdout, stderr = run(command)
    if code != 0:
        return stderr or stdout or f"command exited with status {code}"
    return stdout


def rustc_version() -> dict[str, str]:
    output = command_output(["rustc", "-vV"])
    if output is None:
        return {"available": "false"}

    parsed: dict[str, str] = {"available": "true"}
    for line in output.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            parsed[key.strip().replace(" ", "_")] = value.strip()
        elif line.startswith("rustc "):
            parsed["version"] = line
    return parsed


def git_metadata() -> dict[str, str]:
    metadata: dict[str, str] = {}
    for key, command in {
        "commit": ["git", "rev-parse", "HEAD"],
        "branch": ["git", "branch", "--show-current"],
        "status": ["git", "status", "--short"],
    }.items():
        metadata[key] = command_output(command) or ""
    metadata["dirty"] = "true" if metadata["status"] else "false"
    return metadata


def installed_targets() -> list[str]:
    output = command_output(["rustup", "target", "list", "--installed"])
    if output is None:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def optional_tool(command: list[str]) -> dict[str, Any]:
    if shutil.which(command[0]) is None:
        return {"available": False}
    code, stdout, stderr = run(command)
    return {
        "available": code == 0,
        "command": " ".join(command),
        "output": stdout or stderr,
    }


def main() -> int:
    report = {
        "schema_version": 1,
        "repository": "sanitization",
        "git": git_metadata(),
        "rustc": rustc_version(),
        "installed_targets": installed_targets(),
        "build_environment": {
            "RUSTFLAGS": os.environ.get("RUSTFLAGS", ""),
            "CARGO_ENCODED_RUSTFLAGS": os.environ.get("CARGO_ENCODED_RUSTFLAGS", ""),
        },
        "tools": {
            "cargo_kani": optional_tool(["cargo", "kani", "--version"]),
            "cargo_miri": optional_tool(["cargo", "+nightly", "miri", "--version"]),
        },
        "recommended_checks": [
            "scripts/checks.sh",
            "scripts/verify-codegen.sh",
            "scripts/verify-codegen-matrix.sh",
            "scripts/verify-derive-failures.sh",
            "scripts/verify-migration-2.0.py",
            "scripts/verify-downstream-migration.py",
            "scripts/verify-leakage-smoke.sh",
            "scripts/collect-leakage-evidence.py",
            "scripts/verify-target-evidence.py",
            "scripts/verify-loom.sh",
            "scripts/verify-kani.sh",
            "scripts/verify-miri.sh",
            "scripts/verify-miri-test-gates.py",
            "scripts/verify-verification-harnesses.py",
            "scripts/test-verification-fail-closed.py",
            "scripts/verify-evidence.py",
            "scripts/verify-2.0-api-freeze.py",
            "scripts/capture-2.0-public-api.py",
        ],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
