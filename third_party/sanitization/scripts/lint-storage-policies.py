#!/usr/bin/env python3
"""Enforce application-owned storage policy boundaries in sensitive Rust code."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


MARKER_IMPL = re.compile(
    r"\bimpl\b(?:(?!\bimpl\b)[\s\S]){0,768}?"
    r"\b(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*"
    r"Stable(?:Shared|Mutable)SecretStorage\b(?:(?!\{)[\s\S])*?\{"
)
GENERIC_SECRET = re.compile(r"\bSecret\s*(?:<|::|\bas\b)")
POLICY_DECLARATION = re.compile(
    r"define_secret_storage_policy\s*!\s*\{\s*"
    r"(?:(?:#\s*\[[^\]]*\]\s*)*)"
    r"(?P<visibility>pub(?:\s*\([^)]*\))?\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{",
    re.MULTILINE,
)
LIFECYCLE_ESCAPES = (
    ("forget", re.compile(r"\bforget\s*\(")),
    ("Box::leak", re.compile(r"\bBox\s*::\s*leak\s*\(")),
    ("ManuallyDrop", re.compile(r"\bManuallyDrop\b")),
)

SKIPPED_DIRECTORIES = {".git", "target", "vendor"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "reject direct Secret<T>, unapproved storage-marker impls, and "
            "public policy types in designated high-assurance Rust sources"
        )
    )
    parser.add_argument(
        "--root",
        action="append",
        required=True,
        type=Path,
        help="sensitive Rust file or directory to scan (repeatable)",
    )
    parser.add_argument(
        "--allow-marker-file",
        action="append",
        default=[],
        type=Path,
        help="reviewed file allowed to implement a storage marker (repeatable)",
    )
    parser.add_argument(
        "--allow-generic-secret-file",
        action="append",
        default=[],
        type=Path,
        help="reviewed file allowed to use direct Secret<T> (repeatable)",
    )
    parser.add_argument(
        "--policy-file",
        action="append",
        default=[],
        type=Path,
        help="file whose storage policies must be private or pub(crate) (repeatable)",
    )
    return parser.parse_args()


def normalized(path: Path) -> Path:
    return path.resolve()


def rust_files(roots: list[Path]) -> list[Path]:
    found: set[Path] = set()
    for root in roots:
        if not root.exists():
            raise ValueError(f"scan root does not exist: {root}")
        if root.is_file():
            if root.suffix != ".rs":
                raise ValueError(f"scan root is not a Rust source: {root}")
            found.add(normalized(root))
            continue
        for path in root.rglob("*.rs"):
            if any(part in SKIPPED_DIRECTORIES for part in path.parts):
                continue
            found.add(normalized(path))
    return sorted(found)


def strip_comments_and_literals(source: str) -> str:
    """Replace comments and literals with spaces while preserving newlines."""

    output = list(source)
    index = 0
    length = len(source)

    def blank(start: int, end: int) -> None:
        for offset in range(start, end):
            if output[offset] != "\n":
                output[offset] = " "

    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            if end == -1:
                end = length
            blank(index, end)
            index = end
            continue

        if source.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if source.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif source.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            blank(index, cursor)
            index = cursor
            continue

        raw = re.match(r"r(#+)?\"", source[index:])
        if raw:
            hashes = raw.group(1) or ""
            terminator = '"' + hashes
            start_content = index + raw.end()
            end = source.find(terminator, start_content)
            end = length if end == -1 else end + len(terminator)
            blank(index, end)
            index = end
            continue

        if source[index] == "'":
            character = re.match(r"'(?:\\.|[^\\'\n])'", source[index:])
            if character:
                end = index + character.end()
                blank(index, end)
                index = end
                continue

        if source[index] == '"':
            quote = source[index]
            cursor = index + 1
            while cursor < length:
                if source[cursor] == "\\":
                    cursor += 2
                    continue
                cursor += 1
                if source[cursor - 1] == quote:
                    break
            blank(index, min(cursor, length))
            index = cursor
            continue

        index += 1

    return "".join(output)


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def relative(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def main() -> int:
    args = parse_args()
    try:
        files = rust_files(args.root)
    except ValueError as error:
        print(f"storage-policy lint: {error}", file=sys.stderr)
        return 2

    allowed_markers = {normalized(path) for path in args.allow_marker_file}
    allowed_generic = {normalized(path) for path in args.allow_generic_secret_file}
    policy_files = {normalized(path) for path in args.policy_file}
    scanned = set(files)

    for path in allowed_markers | allowed_generic | policy_files:
        if not path.exists():
            print(f"storage-policy lint: configured file does not exist: {path}", file=sys.stderr)
            return 2
    if not policy_files:
        print("storage-policy lint: at least one --policy-file is required", file=sys.stderr)
        return 2
    if not policy_files.issubset(scanned):
        missing = ", ".join(relative(path) for path in sorted(policy_files - scanned))
        print(f"storage-policy lint: policy file is outside scanned roots: {missing}", file=sys.stderr)
        return 2
    exemptions = allowed_markers | allowed_generic
    if not exemptions.issubset(scanned):
        missing = ", ".join(relative(path) for path in sorted(exemptions - scanned))
        print(f"storage-policy lint: exempted file is outside scanned roots: {missing}", file=sys.stderr)
        return 2

    failures: list[str] = []
    policy_count = 0

    for path in files:
        source = path.read_text(encoding="utf-8")
        stripped = strip_comments_and_literals(source)

        if path not in allowed_markers:
            for match in MARKER_IMPL.finditer(stripped):
                failures.append(
                    f"{relative(path)}:{line_number(stripped, match.start())}: "
                    "storage marker implementation is outside --allow-marker-file"
                )

        if path not in allowed_generic:
            for match in GENERIC_SECRET.finditer(stripped):
                failures.append(
                    f"{relative(path)}:{line_number(stripped, match.start())}: "
                    "direct Secret<T>/Secret:: use is forbidden; use "
                    "AllowlistedSecret<T, Policy>"
                )

        for name, pattern in LIFECYCLE_ESCAPES:
            for match in pattern.finditer(stripped):
                failures.append(
                    f"{relative(path)}:{line_number(stripped, match.start())}: "
                    f"destructor-bypass primitive {name} is forbidden in a sensitive root"
                )

        if path in policy_files:
            declarations = list(POLICY_DECLARATION.finditer(stripped))
            policy_count += len(declarations)
            if not declarations:
                failures.append(
                    f"{relative(path)}: no define_secret_storage_policy! declaration found"
                )
            for declaration in declarations:
                visibility = (declaration.group("visibility") or "").strip()
                if visibility not in {"", "pub(crate)"}:
                    failures.append(
                        f"{relative(path)}:{line_number(source, declaration.start())}: "
                        f"policy {declaration.group('name')} must be private or pub(crate)"
                    )

    if failures:
        for failure in failures:
            print(f"storage-policy lint: {failure}", file=sys.stderr)
        return 1

    print(
        f"storage-policy lint passed ({len(files)} Rust files, {policy_count} private policies)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
