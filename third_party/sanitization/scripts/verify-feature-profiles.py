#!/usr/bin/env python3
"""Verify named profiles and companion-crate architecture."""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "crates" / "sanitization"

EXPECTED_PROFILES = {
    "profile-hardened-native": [
        "memory-lock",
        "random-canary",
        "strict-canary-check",
        "strict-compare",
    ],
    "profile-guarded-native": [
        "profile-hardened-native",
        "guard-pages",
    ],
    "profile-hardened-linux": [
        "profile-hardened-native",
        "require-fork-exclusion",
    ],
}

COMPANIONS = {
    "sanitization-arrayvec": "companion",
    "sanitization-bytes": "companion",
    "sanitization-crypto-interop": "companion",
    "sanitization-derive": "proc-macro",
}

MINIMUM_COMPANION_DEPENDENCIES = {
    ("sanitization-bytes", "bytes"): "1.12.1",
}

FORBIDDEN_WIPE_PRIMITIVES = (
    "write_volatile",
    "compiler_fence",
    "atomic::fence",
)


def fail(message: str) -> None:
    print(f"feature profile verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_manifest(crate: str) -> dict:
    path = ROOT / "crates" / crate / "Cargo.toml"
    with path.open("rb") as handle:
        return tomllib.load(handle)


core = load_manifest("sanitization")
with (ROOT / "Cargo.toml").open("rb") as handle:
    workspace_version = tomllib.load(handle)["workspace"]["package"]["version"]
features = core.get("features", {})
if features.get("default") != ["asm-compare"]:
    fail("sanitization default features must contain only asm-compare")

crypto_interop = load_manifest("sanitization-crypto-interop")
crypto_features = crypto_interop.get("features", {})
if crypto_features.get("default") != ["asm-compare"]:
    fail("sanitization-crypto-interop must forward asm-compare by default")
if crypto_features.get("asm-compare") != ["sanitization/asm-compare"]:
    fail("sanitization-crypto-interop asm-compare forwarding changed")

for profile, expected in EXPECTED_PROFILES.items():
    if features.get(profile) != expected:
        fail(f"{profile} must expand exactly to {expected!r}")

for dependency, specification in core.get("dependencies", {}).items():
    if not isinstance(specification, dict) or not specification.get("optional", False):
        fail(f"default core dependency {dependency!r} is not optional")

derive_dependency = core.get("dependencies", {}).get("sanitization-derive")
expected_derive_version = f"={workspace_version}"
if (
    not isinstance(derive_dependency, dict)
    or derive_dependency.get("version") != expected_derive_version
):
    fail(
        "sanitization must exact-pin sanitization-derive to the workspace "
        f"version {expected_derive_version!r}"
    )

core_metadata = core.get("package", {}).get("metadata", {}).get("sanitization", {})
if core_metadata.get("role") != "core":
    fail("core package metadata does not identify the core role")
if core_metadata.get("clearing-owner") != "sanitization":
    fail("core package metadata does not identify the clearing owner")

tree = subprocess.run(
    [
        "cargo",
        "tree",
        "-p",
        "sanitization",
        "--no-default-features",
        "--edges",
        "normal",
        "--prefix",
        "none",
        "--depth",
        "1",
    ],
    cwd=ROOT,
    check=True,
    capture_output=True,
    text=True,
).stdout.splitlines()
tree = [line for line in tree if line.strip()]
if len(tree) != 1 or not tree[0].startswith("sanitization "):
    fail(f"no-default-features core dependency graph is not empty: {tree!r}")

for crate, expected_role in COMPANIONS.items():
    manifest = load_manifest(crate)
    metadata = manifest.get("package", {}).get("metadata", {}).get("sanitization", {})
    if metadata.get("role") != expected_role:
        fail(f"{crate} package metadata role must be {expected_role!r}")

    dependencies = manifest.get("dependencies", {})
    for (dependency_crate, dependency), minimum in MINIMUM_COMPANION_DEPENDENCIES.items():
        if crate != dependency_crate:
            continue
        specification = dependencies.get(dependency)
        if not isinstance(specification, dict) or specification.get("version") != minimum:
            fail(
                f"{crate} must require {dependency} >= {minimum} through its "
                "published caret requirement"
            )

    if crate == "sanitization-derive":
        if "sanitization" in dependencies:
            fail("sanitization-derive must not depend on the runtime crate")
    else:
        core_dependency = dependencies.get("sanitization")
        if not isinstance(core_dependency, dict):
            fail(f"{crate} must declare a structured sanitization dependency")
        if core_dependency.get("default-features") is not False:
            fail(f"{crate} must disable sanitization default features")
        if metadata.get("clearing-owner") != "sanitization":
            fail(f"{crate} must identify sanitization as its clearing owner")

    for source in (ROOT / "crates" / crate / "src").rglob("*.rs"):
        text = source.read_text(encoding="utf-8")
        for primitive in FORBIDDEN_WIPE_PRIMITIVES:
            if primitive in text:
                fail(f"{crate} duplicates core wipe primitive {primitive!r} in {source}")

readme = (ROOT / "README.md").read_text(encoding="utf-8")
profile_doc = (ROOT / "docs" / "FEATURE_PROFILES.md").read_text(encoding="utf-8")
for profile in EXPECTED_PROFILES:
    if profile not in readme or profile not in profile_doc:
        fail(f"{profile} is missing from README or feature-profile documentation")

print("feature profiles and companion boundaries verified")
