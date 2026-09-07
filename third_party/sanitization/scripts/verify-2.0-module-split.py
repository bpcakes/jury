#!/usr/bin/env python3
"""Verify the exact Rust source snapshot reviewed for CP-01."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CP01_REVIEWED_COMMIT = "049cdc626bd1a4295bf23fd0133b32d6955f9881"
EXPECTED_SOURCE_SHA256 = (
    "df37c4d9e38ee8904830d404446400907415e4e5994848e110c7bd4ad033a5ce"
)


def fail(message: str) -> None:
    print(f"verify-2.0-module-split: {message}", file=sys.stderr)
    raise SystemExit(1)


def git_output(*args: str) -> str:
    process = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        fail(f"git {' '.join(args)} failed: {process.stderr.strip()}")
    return process.stdout


def git_bytes(*args: str) -> bytes:
    process = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        fail(
            f"git {' '.join(args)} failed: "
            f"{process.stderr.decode(errors='replace').strip()}"
        )
    return process.stdout


def source_digest(commit: str) -> str:
    paths = sorted(
        path
        for path in git_output(
            "ls-tree",
            "-r",
            "--name-only",
            commit,
            "--",
            "crates/sanitization/src",
        ).splitlines()
        if path.endswith(".rs")
    )
    if not paths:
        fail(f"reviewed commit has no sanitization Rust source: {commit}")

    aggregate = hashlib.sha256()
    for path in paths:
        contents = git_bytes("show", f"{commit}:{path}")
        file_digest = hashlib.sha256(contents).hexdigest()
        aggregate.update(f"{file_digest}  {path}\n".encode())
    return aggregate.hexdigest()


def main() -> None:
    actual = source_digest(CP01_REVIEWED_COMMIT)
    if actual != EXPECTED_SOURCE_SHA256:
        fail(
            f"reviewed Rust source digest changed for {CP01_REVIEWED_COMMIT}; "
            f"expected={EXPECTED_SOURCE_SHA256}, actual={actual}"
        )

    print(f"verified CP-01 exact Rust source snapshot at {CP01_REVIEWED_COMMIT}")


if __name__ == "__main__":
    main()
