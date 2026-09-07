#!/usr/bin/env python3
"""Fixture tests for the latest stable Rust release gate."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-latest-rust.py"


def write_toolchain(path: Path, version: str) -> None:
    path.write_text(
        f'[toolchain]\nchannel = "{version}"\nprofile = "minimal"\n',
        encoding="utf-8",
    )


def write_manifest(path: Path, version: str) -> None:
    path.write_text(
        f'manifest-version = "2"\n[pkg.rust]\n'
        f'version = "{version} (fixture 2026-09-04)"\n',
        encoding="utf-8",
    )


def run_check(toolchain: Path, manifest: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CHECKER),
            "--toolchain-file",
            str(toolchain),
            "--manifest-file",
            str(manifest),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        toolchain = root / "rust-toolchain.toml"
        manifest = root / "channel-rust-stable.toml"

        write_toolchain(toolchain, "1.98.1")
        write_manifest(manifest, "1.98.1")
        result = run_check(toolchain, manifest)
        require(result.returncode == 0, result.stderr)
        require("matches official stable 1.98.1" in result.stdout, result.stdout)

        write_toolchain(toolchain, "1.98.0")
        result = run_check(toolchain, manifest)
        require(result.returncode == 1, result.stdout)
        require("pins 1.98.0, official stable is 1.98.1" in result.stderr, result.stderr)

        write_toolchain(toolchain, "stable")
        result = run_check(toolchain, manifest)
        require(result.returncode == 1, result.stdout)
        require("must pin an exact stable patch version" in result.stderr, result.stderr)

        write_toolchain(toolchain, "1.98.1")
        manifest.write_text("[pkg.cargo]\nversion = 1\n", encoding="utf-8")
        result = run_check(toolchain, manifest)
        require(result.returncode == 1, result.stdout)
        require("stable Rust manifest is malformed" in result.stderr, result.stderr)

    print("latest Rust release gate fixture tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
