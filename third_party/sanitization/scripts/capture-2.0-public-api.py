#!/usr/bin/env python3
"""Capture or verify rustdoc-derived current 2.0 public API snapshots."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "baselines" / "2.0" / "public-api"
METADATA = OUTPUT / "metadata.json"
SOURCE_CHECKPOINT = "docs/baselines/2.0/current-source-api.json"
PACKAGES = (
    "sanitization",
    "sanitization-derive",
    "sanitization-arrayvec",
    "sanitization-bytes",
    "sanitization-crypto-interop",
)


def fail(message: str) -> None:
    print(f"capture-2.0-public-api: {message}", file=sys.stderr)
    raise SystemExit(1)


def capture(command: list[str]) -> str:
    process = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        fail(f"{' '.join(command)} failed: {process.stderr.strip()}")
    return process.stdout.strip() + "\n"


parser = argparse.ArgumentParser()
parser.add_argument("--write", action="store_true")
arguments = parser.parse_args()

tool_version = capture(["cargo", "public-api", "--version"]).strip()
if tool_version != "cargo-public-api 0.52.0":
    fail(f"expected cargo-public-api 0.52.0, found {tool_version}")

snapshots: dict[str, str] = {}
for package in PACKAGES:
    snapshots[package] = capture(
        [
            "cargo",
            "public-api",
            "-p",
            package,
            "--all-features",
            "-sss",
            "--color",
            "never",
        ]
    )

metadata = {
    "schema_version": 1,
    "checkpoint": "2.0-current",
    "source_checkpoint": SOURCE_CHECKPOINT,
    "tool": tool_version,
    "rustc": capture(["rustc", "--version"]).strip(),
    "packages": {
        package: {
            "file": f"{package}.txt",
            "sha256": hashlib.sha256(snapshot.encode("utf-8")).hexdigest(),
            "lines": len(snapshot.splitlines()),
        }
        for package, snapshot in snapshots.items()
    },
}

if arguments.write:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for package, snapshot in snapshots.items():
        (OUTPUT / f"{package}.txt").write_text(snapshot, encoding="utf-8")
    METADATA.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote semantic public API snapshots for {len(PACKAGES)} packages")
else:
    if not METADATA.is_file():
        fail(f"missing {METADATA.relative_to(ROOT)}")
    recorded = json.loads(METADATA.read_text(encoding="utf-8"))
    if recorded != metadata:
        fail("public API metadata differs from the current 2.0 semantic snapshot")
    for package, snapshot in snapshots.items():
        path = OUTPUT / f"{package}.txt"
        if not path.is_file() or path.read_text(encoding="utf-8") != snapshot:
            fail(f"public API changed for {package}")
    print(f"verified semantic public API snapshots for {len(PACKAGES)} packages")
