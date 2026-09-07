#!/usr/bin/env python3
"""Capture or verify the frozen sanitization 1.2.5 baseline for 2.0 work."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BASELINE_REF = "v1.2.5"
OUTPUT = ROOT / "docs" / "baselines" / "2.0" / "baseline-1.2.5.json"
EXPECTED_CODEGEN_SHA256 = (
    "30d9f42f77035d4527bfcd1ff1a5cf16"
    "aca2ba5d5635c7e969c92b17df38bcb8"
)
SOURCE_MATCH_PATHS = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "crates",
    "scripts/verify-codegen.sh",
]
PACKAGES = [
    "sanitization-derive",
    "sanitization",
    "sanitization-arrayvec",
    "sanitization-bytes",
    "sanitization-crypto-interop",
]
PACKAGE_DIRS = {
    "sanitization": "crates/sanitization",
    "sanitization-arrayvec": "crates/sanitization-arrayvec",
    "sanitization-bytes": "crates/sanitization-bytes",
    "sanitization-crypto-interop": "crates/sanitization-crypto-interop",
    "sanitization-derive": "crates/sanitization-derive",
}

PUBLIC_DECLARATION = re.compile(
    r"^\s*pub\s+(?:unsafe\s+)?(?:const\s+)?(?:async\s+)?"
    r"(?:fn|struct|enum|trait|type|const|static|mod|use)\b"
)
UNSAFE_SITE = re.compile(r"\bunsafe\b")
MACRO_NAME = re.compile(r"^\s*macro_rules!\s+([A-Za-z_][A-Za-z0-9_]*)")


def fail(message: str) -> None:
    print(f"capture-2.0-baseline: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(
    command: list[str],
    *,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )
    if check and process.returncode != 0:
        stderr = process.stderr.strip() if process.stderr else ""
        stdout = process.stdout.strip() if process.stdout else ""
        fail(f"{' '.join(command)} failed: {stderr or stdout}")
    return process


def git_output(*args: str) -> str:
    return run(["git", *args]).stdout.strip()


def ref_file(path: str) -> bytes:
    process = subprocess.run(
        ["git", "show", f"{BASELINE_REF}:{path}"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        fail(f"could not read {path} from {BASELINE_REF}")
    return process.stdout


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def assert_source_matches_ref() -> None:
    process = run(
        ["git", "diff", "--quiet", BASELINE_REF, "--", *SOURCE_MATCH_PATHS],
        check=False,
    )
    if process.returncode != 0:
        fail(
            "current source/manifests do not match v1.2.5; "
            "capture the baseline before 2.0 production edits"
        )


def tracked_source_files() -> list[str]:
    output = git_output(
        "ls-tree",
        "-r",
        "--name-only",
        BASELINE_REF,
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "crates",
    )
    return sorted(line for line in output.splitlines() if line)


def source_hashes() -> dict[str, str]:
    return {path: sha256(ref_file(path)) for path in tracked_source_files()}


def manifest(path: str) -> dict[str, Any]:
    return tomllib.loads(ref_file(path).decode("utf-8"))


def workspace_snapshot() -> dict[str, Any]:
    root_manifest = manifest("Cargo.toml")
    workspace_package = root_manifest["workspace"]["package"]
    members = root_manifest["workspace"]["members"]

    packages: list[dict[str, Any]] = []
    for member in members:
        package_manifest = manifest(f"{member}/Cargo.toml")
        package = package_manifest["package"]
        packages.append(
            {
                "name": package["name"],
                "manifest": f"{member}/Cargo.toml",
                "features": package_manifest.get("features", {}),
                "dependencies": sorted(package_manifest.get("dependencies", {}).keys()),
            }
        )

    return {
        "version": workspace_package["version"],
        "edition": workspace_package["edition"],
        "rust_version": workspace_package["rust-version"],
        "resolver": root_manifest["workspace"]["resolver"],
        "members": members,
        "packages": packages,
    }


def source_inventory() -> tuple[list[str], list[str]]:
    public_declarations: list[str] = []
    unsafe_sites: list[str] = []

    source_paths = [
        path
        for path in tracked_source_files()
        if path.startswith("crates/") and path.endswith(".rs") and "/src/" in path
    ]

    for path in source_paths:
        lines = ref_file(path).decode("utf-8").splitlines()
        macro_export_pending = False
        for line_number, line in enumerate(lines, start=1):
            stripped = " ".join(line.strip().split())
            if "#[macro_export]" in line:
                macro_export_pending = True
            elif macro_export_pending:
                macro = MACRO_NAME.match(line)
                if macro:
                    public_declarations.append(
                        f"{path}:{line_number}:macro_rules! {macro.group(1)}"
                    )
                    macro_export_pending = False
                elif stripped and not stripped.startswith("#["):
                    macro_export_pending = False

            if PUBLIC_DECLARATION.match(line):
                public_declarations.append(f"{path}:{line_number}:{stripped}")

            if UNSAFE_SITE.search(line):
                unsafe_sites.append(f"{path}:{line_number}:{stripped}")

    return sorted(public_declarations), sorted(unsafe_sites)


def matches_include(path: str, pattern: str) -> bool:
    if fnmatch.fnmatchcase(path, pattern):
        return True
    if "/**/" in pattern:
        return fnmatch.fnmatchcase(path, pattern.replace("/**/", "/"))
    return False


def package_contents() -> dict[str, list[str]]:
    contents: dict[str, list[str]] = {}
    for package in PACKAGES:
        package_dir = PACKAGE_DIRS[package]
        package_manifest = manifest(f"{package_dir}/Cargo.toml")
        include = package_manifest["package"].get("include", [])
        tree = git_output(
            "ls-tree", "-r", "--name-only", BASELINE_REF, package_dir
        ).splitlines()

        selected = {
            ".cargo_vcs_info.json",
            "Cargo.lock",
            "Cargo.toml",
            "Cargo.toml.orig",
        }
        for path in tree:
            relative = path.removeprefix(f"{package_dir}/")
            if any(matches_include(relative, pattern) for pattern in include):
                selected.add(relative)

        readme = package_manifest["package"].get("readme")
        if readme:
            selected.add(Path(readme).name)

        contents[package] = sorted(selected)
    return contents


def command_output(command: list[str]) -> str:
    return run(command).stdout.strip()


def rustc_metadata() -> dict[str, str]:
    metadata: dict[str, str] = {}
    output = command_output(["rustc", "-vV"])
    for line in output.splitlines():
        if line.startswith("rustc "):
            metadata["version"] = line
        elif ":" in line:
            key, value = line.split(":", 1)
            metadata[key.strip().replace(" ", "_")] = value.strip()
    return metadata


def installed_targets() -> list[str]:
    output = command_output(["rustup", "target", "list", "--installed"])
    return sorted(line for line in output.splitlines() if line)


def first_matching_line(path: Path, pattern: str) -> str:
    regex = re.compile(pattern)
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if regex.search(line):
                return " ".join(line.strip().split())[:500]
    return ""


def codegen_snapshot() -> dict[str, Any]:
    run(["scripts/verify-codegen.sh"])

    ir_path = ROOT / "target/release/deps/sanitization-verify-codegen.ll"
    asm_path = ROOT / "target/release/deps/sanitization-verify-codegen.s"
    if not ir_path.is_file() or not asm_path.is_file():
        fail("verify-codegen did not produce the expected baseline artifacts")

    samples = {
        "volatile_wipe_symbol": first_matching_line(
            ir_path, r"sanitization::wipe::volatile_wipe"
        ),
        "volatile_zero_store": first_matching_line(ir_path, r"store volatile i8 0"),
        "conditional_copy": first_matching_line(
            ir_path, r"sanitization::ct::conditional_copy"
        ),
        "conditional_swap": first_matching_line(
            ir_path, r"sanitization::ct::conditional_swap"
        ),
        "select_slice": first_matching_line(
            ir_path, r"sanitization::ct::select_slice"
        ),
        "optimizer_barrier": first_matching_line(
            ir_path, r'asm sideeffect "", "r,~\{memory\}"'
        ),
        "mask_generation": first_matching_line(ir_path, r"sub i8 0"),
        "assembly_compare": first_matching_line(asm_path, r"compare_asm"),
        "cache_flush": first_matching_line(asm_path, r"clflush"),
        "cache_fence": first_matching_line(asm_path, r"mfence"),
    }

    required = [
        "volatile_wipe_symbol",
        "volatile_zero_store",
        "conditional_copy",
        "conditional_swap",
        "select_slice",
        "optimizer_barrier",
        "mask_generation",
    ]
    missing = [name for name in required if not samples[name]]
    if missing:
        fail(f"missing required codegen samples: {', '.join(missing)}")

    return {
        "host": rustc_metadata().get("host", ""),
        "llvm_ir_sha256": sha256(ir_path.read_bytes()),
        "assembly_sha256": sha256(asm_path.read_bytes()),
        "memcmp_or_bcmp_absent": not any(
            re.search(rb"\b(?:memcmp|bcmp)\b", path.read_bytes())
            for path in (ir_path, asm_path)
        ),
        "samples": samples,
    }


def deterministic_snapshot() -> dict[str, Any]:
    public_declarations, unsafe_sites = source_inventory()
    commit = git_output("rev-list", "-n", "1", BASELINE_REF)

    return {
        "schema_version": 1,
        "baseline": "sanitization-1.2.5",
        "baseline_ref": BASELINE_REF,
        "baseline_commit": commit,
        "purpose": "Frozen pre-2.0 comparison baseline; not a security certification.",
        "workspace": workspace_snapshot(),
        "package_contents": package_contents(),
        "public_source_declarations": public_declarations,
        "unsafe_source_sites": unsafe_sites,
        "source_sha256": source_hashes(),
        "evidence_documents": {
            path: sha256(ref_file(path))
            for path in (
                "docs/BARRIERS.md",
                "docs/EVIDENCE.md",
                "docs/GUARANTEES.md",
                "docs/LEAKAGE_TESTS.md",
                "docs/NON_GUARANTEES.md",
                "docs/SAFETY.md",
                "docs/TARGETS.md",
                "docs/THREAT_MODEL.md",
                "docs/ct-evidence.json",
            )
        },
        "limitations": [
            "Public declarations are a source-level inventory, not a semantic semver proof.",
            "Codegen hashes and samples are specific to the recorded rustc host and profile.",
            "Installed targets record availability, not proof that every target ran natively.",
            "The baseline does not certify the security of version 1.2.5.",
        ],
    }


def capture() -> dict[str, Any]:
    assert_source_matches_ref()
    data = deterministic_snapshot()
    data["codegen"] = codegen_snapshot()
    data["environment"] = {
        "rustc": rustc_metadata(),
        "installed_targets": installed_targets(),
    }
    return data


def verify() -> None:
    if not OUTPUT.is_file():
        fail(f"missing baseline: {OUTPUT.relative_to(ROOT)}")

    recorded = json.loads(OUTPUT.read_text(encoding="utf-8"))
    current = deterministic_snapshot()
    if any(recorded.get(key) != value for key, value in current.items()):
        fail("committed 1.2.5 baseline does not reproduce from the tagged source")

    codegen = recorded.get("codegen")
    if not isinstance(codegen, dict):
        fail("committed baseline has no codegen object")
    canonical_codegen = json.dumps(
        codegen,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if sha256(canonical_codegen) != EXPECTED_CODEGEN_SHA256:
        fail("frozen codegen evidence was modified")
    if not codegen.get("memcmp_or_bcmp_absent"):
        fail("recorded baseline codegen contains memcmp or bcmp")
    for key in (
        "host",
        "llvm_ir_sha256",
        "assembly_sha256",
        "samples",
    ):
        if not codegen.get(key):
            fail(f"recorded baseline codegen is missing {key}")

    environment = recorded.get("environment")
    if not isinstance(environment, dict) or not environment.get("rustc"):
        fail("recorded baseline has no rustc environment metadata")

    print(f"verified {OUTPUT.relative_to(ROOT)}")


def main() -> int:
    global OUTPUT

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="reproduce and validate stable baseline sections",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT,
        help="baseline JSON output path",
    )
    args = parser.parse_args()

    OUTPUT = args.output if args.output.is_absolute() else ROOT / args.output

    if args.check:
        verify()
        return 0

    data = capture()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
