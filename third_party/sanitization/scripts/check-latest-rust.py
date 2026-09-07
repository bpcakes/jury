#!/usr/bin/env python3
"""Verify that the repository pins the latest official stable Rust release."""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - release host guard.
    print("Python 3.11+ is required because this script uses tomllib.", file=sys.stderr)
    raise


ROOT = Path(__file__).resolve().parents[1]
STABLE_MANIFEST_URL = "https://static.rust-lang.org/dist/channel-rust-stable.toml"
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def load_toml(path: Path) -> dict[str, object]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def pinned_version(toolchain_file: Path) -> str:
    manifest = load_toml(toolchain_file)
    try:
        channel = manifest["toolchain"]["channel"]  # type: ignore[index]
    except (KeyError, TypeError) as error:
        raise ValueError(f"{toolchain_file} has no toolchain.channel") from error

    if not isinstance(channel, str) or VERSION_PATTERN.fullmatch(channel) is None:
        raise ValueError(
            f"{toolchain_file} must pin an exact stable patch version, got {channel!r}"
        )
    return channel


def stable_manifest_bytes(manifest_file: Path | None) -> bytes:
    if manifest_file is not None:
        return manifest_file.read_bytes()

    request = urllib.request.Request(
        STABLE_MANIFEST_URL,
        headers={"User-Agent": "sanitization-release-gate/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except (OSError, urllib.error.URLError) as error:
        raise RuntimeError(
            f"could not fetch the official stable Rust manifest: {error}"
        ) from error


def latest_stable_version(manifest_bytes: bytes) -> str:
    try:
        manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
        release = manifest["pkg"]["rust"]["version"]
    except (KeyError, TypeError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError("official stable Rust manifest is malformed") from error

    if not isinstance(release, str):
        raise ValueError("official stable Rust manifest has a non-string Rust version")

    version = release.split(maxsplit=1)[0]
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError(f"official stable Rust version is malformed: {release!r}")
    return version


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare rust-toolchain.toml with Rust's official stable channel manifest."
        )
    )
    parser.add_argument(
        "--toolchain-file",
        type=Path,
        default=ROOT / "rust-toolchain.toml",
        help="Toolchain file to inspect. Defaults to the repository pin.",
    )
    parser.add_argument(
        "--manifest-file",
        type=Path,
        help="Read a local stable manifest instead of fetching the official URL.",
    )
    args = parser.parse_args()

    try:
        pinned = pinned_version(args.toolchain_file)
        latest = latest_stable_version(stable_manifest_bytes(args.manifest_file))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"latest Rust check failed: {error}", file=sys.stderr)
        return 1

    if pinned != latest:
        print(
            "latest Rust check failed: "
            f"rust-toolchain.toml pins {pinned}, official stable is {latest}",
            file=sys.stderr,
        )
        return 1

    print(f"latest Rust check: pinned {pinned} matches official stable {latest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
