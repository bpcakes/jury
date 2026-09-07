#!/usr/bin/env python3
"""Shared source-level API inventory generation for 2.0 verification."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DECLARATION = re.compile(
    r"^\s*pub\s+(?:unsafe\s+)?(?:const\s+)?(?:async\s+)?"
    r"(?:fn|struct|enum|trait|type|const|static|mod|use)\b"
)
MACRO_NAME = re.compile(r"^\s*macro_rules!\s+([A-Za-z_][A-Za-z0-9_]*)")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_paths() -> list[Path]:
    paths = [ROOT / "Cargo.toml"]
    for crate in sorted((ROOT / "crates").iterdir()):
        if not crate.is_dir():
            continue
        manifest = crate / "Cargo.toml"
        if manifest.is_file():
            paths.append(manifest)
        paths.extend(sorted((crate / "src").rglob("*.rs")))
    return paths


def public_inventory(paths: list[Path]) -> list[str]:
    declarations: list[str] = []
    for path in paths:
        if path.suffix != ".rs":
            continue
        relative = path.relative_to(ROOT)
        macro_pending = False
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            normalized = " ".join(line.strip().split())
            if "#[macro_export]" in line:
                macro_pending = True
            elif macro_pending:
                macro = MACRO_NAME.match(line)
                if macro:
                    declarations.append(
                        f"{relative}:{line_number}:macro_rules! {macro.group(1)}"
                    )
                    macro_pending = False
                elif normalized and not normalized.startswith("#["):
                    macro_pending = False
            if PUBLIC_DECLARATION.match(line):
                declarations.append(f"{relative}:{line_number}:{normalized}")
    return sorted(declarations)


def package_snapshot(member: str) -> dict[str, Any]:
    manifest_path = ROOT / member / "Cargo.toml"
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    package = manifest["package"]
    return {
        "name": package["name"],
        "manifest": str(manifest_path.relative_to(ROOT)),
        "features": manifest.get("features", {}),
        "dependencies": sorted(manifest.get("dependencies", {})),
        "include": package.get("include", []),
    }


def snapshot() -> dict[str, Any]:
    root_manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    workspace = root_manifest["workspace"]
    package = workspace["package"]
    paths = source_paths()
    return {
        "schema_version": 1,
        "checkpoint": "2.0-current",
        "status": "release-candidate-current",
        "historical_baseline": "docs/baselines/2.0/cp21-public-api.json",
        "scope": "source-level declarations, manifests, features, and source hashes",
        "semantic_check": "CP-22 cargo-semver-checks and rustdoc API comparison",
        "workspace": {
            "version": package["version"],
            "edition": package["edition"],
            "rust_version": package["rust-version"],
            "members": workspace["members"],
            "packages": [package_snapshot(member) for member in workspace["members"]],
        },
        "source_hashes": {
            str(path.relative_to(ROOT)): sha256(path) for path in paths
        },
        "public_declarations": public_inventory(paths),
    }
