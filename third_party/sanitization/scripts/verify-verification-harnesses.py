#!/usr/bin/env python3
"""Validate the CP-19 harness registry and unpublished-tool boundary."""

from __future__ import annotations

import json
import shlex
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "docs" / "verification-harnesses.json"


def fail(message: str) -> None:
    print(f"verification harness registry failed: {message}", file=sys.stderr)
    raise SystemExit(1)


data = json.loads(REGISTRY.read_text(encoding="utf-8"))
if data.get("schema_version") != 1:
    fail("schema_version must be 1")

harnesses = data.get("harnesses")
if not isinstance(harnesses, list) or not harnesses:
    fail("harnesses must be a non-empty list")

names: set[str] = set()
for index, harness in enumerate(harnesses):
    if not isinstance(harness, dict):
        fail(f"harnesses[{index}] must be an object")
    for key in ("name", "claim", "command"):
        value = harness.get(key)
        if not isinstance(value, str) or not value.strip():
            fail(f"harnesses[{index}].{key} must be a non-empty string")
    name = harness["name"]
    if name in names:
        fail(f"duplicate harness name: {name}")
    names.add(name)

    command = harness["command"]
    tokens = shlex.split(command)
    script_tokens = [token for token in tokens if token.startswith("scripts/")]
    for script in script_tokens:
        path = ROOT / script
        if not path.is_file():
            fail(f"{name} references missing script {script}")

workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
members = set(workspace["workspace"]["members"])
for path in sorted((ROOT / "tools").glob("*/Cargo.toml")):
    manifest = tomllib.loads(path.read_text(encoding="utf-8"))
    package = manifest.get("package", {})
    if package.get("publish") is not False:
        fail(f"{path.parent.name} must set publish = false")
    relative = str(path.parent.relative_to(ROOT))
    if relative in members:
        fail(f"unpublished tool {relative} entered the publishable workspace")

fuzz_manifest = tomllib.loads((ROOT / "fuzz" / "Cargo.toml").read_text(encoding="utf-8"))
if fuzz_manifest.get("package", {}).get("publish") is not False:
    fail("fuzz package must set publish = false")
if "fuzz" in members:
    fail("fuzz package entered the publishable workspace")

print("verification harness registry and unpublished tooling boundary verified")
