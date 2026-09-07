#!/usr/bin/env python3
"""Build and inspect every publishable sanitization crate archive."""

from __future__ import annotations

import argparse
import json
import subprocess
import tarfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIRS = {
    "sanitization-derive": ROOT / "crates" / "sanitization-derive",
    "sanitization": ROOT / "crates" / "sanitization",
    "sanitization-arrayvec": ROOT / "crates" / "sanitization-arrayvec",
    "sanitization-bytes": ROOT / "crates" / "sanitization-bytes",
    "sanitization-crypto-interop": ROOT / "crates" / "sanitization-crypto-interop",
}
INTERNAL_PACKAGES = frozenset(PACKAGE_DIRS)
ALLOWED_GENERATED_FILES = {
    ".cargo_vcs_info.json",
    "Cargo.lock",
    "Cargo.toml",
}
FORBIDDEN_PARTS = {
    ".github",
    "docs",
    "release-notes",
    "scripts",
    "security",
    "tools",
    "PENTEST.md",
}
REPOSITORY_ONLY_README_LINKS = (
    "](docs/",
    "](release-notes/",
    "](security/",
    "](SECURITY.md",
)


def fail(message: str) -> None:
    raise RuntimeError(message)


def metadata() -> dict[str, Any]:
    output = subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        text=True,
    )
    return json.loads(output)


def expected_files(package_dir: Path, manifest: dict[str, Any]) -> dict[str, Path]:
    expected = {"Cargo.toml.orig": package_dir / "Cargo.toml"}
    readme = manifest["package"].get("readme")
    if isinstance(readme, str):
        expected["README.md"] = (package_dir / readme).resolve()

    for directory in ("src", "tests", "examples"):
        root = package_dir / directory
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.rs")):
            expected[path.relative_to(package_dir).as_posix()] = path
    return expected


def normalized_dependency_version(
    dependencies: dict[str, Any], dependency: str
) -> str | None:
    value = dependencies.get(dependency)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        version = value.get("version")
        return version if isinstance(version, str) else None
    return None


def verify_archive(package: str, version: str, package_dir: Path) -> None:
    archive = ROOT / "target" / "package" / f"{package}-{version}.crate"
    if not archive.is_file():
        fail(f"missing generated archive: {archive.relative_to(ROOT)}")

    source_manifest = tomllib.loads(
        (package_dir / "Cargo.toml").read_text(encoding="utf-8")
    )
    expected = expected_files(package_dir, source_manifest)
    prefix = f"{package}-{version}/"

    with tarfile.open(archive, mode="r:gz") as package_archive:
        members = package_archive.getmembers()
        regular_files: dict[str, tarfile.TarInfo] = {}
        for member in members:
            if member.isdir():
                continue
            if not member.isfile():
                fail(f"{archive.name} contains a non-regular entry: {member.name}")
            if not member.name.startswith(prefix):
                fail(f"{archive.name} contains an entry outside {prefix}: {member.name}")
            relative = member.name.removeprefix(prefix)
            path = PurePosixPath(relative)
            if path.is_absolute() or ".." in path.parts:
                fail(f"{archive.name} contains an unsafe path: {relative}")
            if FORBIDDEN_PARTS.intersection(path.parts):
                fail(f"{archive.name} contains forbidden release content: {relative}")
            regular_files[relative] = member

        missing = sorted(set(expected).difference(regular_files))
        if missing:
            fail(f"{archive.name} is missing reviewed files: {missing}")
        unexpected = sorted(
            set(regular_files).difference(expected).difference(ALLOWED_GENERATED_FILES)
        )
        if unexpected:
            fail(f"{archive.name} contains unexpected files: {unexpected}")

        for relative, source in expected.items():
            archived = package_archive.extractfile(regular_files[relative])
            if archived is None or archived.read() != source.read_bytes():
                fail(f"{archive.name} content differs from workspace file: {relative}")

        readme_member = regular_files.get("README.md")
        if readme_member is not None:
            archived_readme = package_archive.extractfile(readme_member)
            if archived_readme is None:
                fail(f"{archive.name} has no readable README.md")
            readme = archived_readme.read().decode("utf-8")
            for relative_link in REPOSITORY_ONLY_README_LINKS:
                if relative_link in readme:
                    fail(
                        f"{archive.name} README contains repository-only relative "
                        f"link prefix {relative_link!r}"
                    )

        normalized_file = package_archive.extractfile(regular_files["Cargo.toml"])
        if normalized_file is None:
            fail(f"{archive.name} has no readable normalized Cargo.toml")
        normalized = tomllib.loads(normalized_file.read().decode("utf-8"))

    if normalized["package"].get("name") != package:
        fail(f"{archive.name} normalized package name is incorrect")
    if normalized["package"].get("version") != version:
        fail(f"{archive.name} normalized package version is incorrect")

    dependencies = normalized.get("dependencies", {})
    if not isinstance(dependencies, dict):
        fail(f"{archive.name} normalized dependencies are malformed")
    for dependency in INTERNAL_PACKAGES.intersection(dependencies):
        dependency_spec = dependencies[dependency]
        if isinstance(dependency_spec, dict) and "path" in dependency_spec:
            fail(f"{archive.name} retained local path for {dependency}")
        expected_requirement = (
            f"={version}"
            if package == "sanitization" and dependency == "sanitization-derive"
            else version
        )
        if normalized_dependency_version(dependencies, dependency) != expected_requirement:
            fail(
                f"{archive.name} does not require {dependency} with reviewed "
                f"release requirement {expected_requirement}"
            )

    print(f"verified {archive.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate and inspect every publishable crate archive."
    )
    parser.add_argument(
        "--version",
        help="Expected package version. Defaults to the common workspace version.",
    )
    args = parser.parse_args()

    packages = {
        package["name"]: package["version"] for package in metadata()["packages"]
    }
    if set(packages) != set(PACKAGE_DIRS):
        fail("workspace publishable package set differs from the release package set")

    versions = set(packages.values())
    if args.version is None:
        if len(versions) != 1:
            fail(f"workspace packages do not share one version: {sorted(versions)}")
        version = versions.pop()
    else:
        version = args.version

    for package in PACKAGE_DIRS:
        if packages[package] != version:
            fail(
                f"{package} is version {packages[package]}, expected {version}"
            )

    subprocess.run(
        [
            "cargo",
            "package",
            "--workspace",
            "--allow-dirty",
            "--no-verify",
        ],
        cwd=ROOT,
        check=True,
    )

    for package, package_dir in PACKAGE_DIRS.items():
        verify_archive(package, version, package_dir)

    print(f"all {len(PACKAGE_DIRS)} release archives verified for {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
