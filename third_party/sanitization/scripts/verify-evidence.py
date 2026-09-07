#!/usr/bin/env python3
"""Validate the machine-readable CT evidence draft."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (
    Path(sys.argv[1]).resolve()
    if len(sys.argv) == 2
    else ROOT / "docs/ct-evidence.json"
)
SOURCE_ROOT = ROOT / "crates" / "sanitization" / "src"
RELEASE_EVIDENCE = ROOT / "docs" / "release-evidence-2.0.0.json"

REQUIRED_TOP_LEVEL = {
    "schema_version",
    "crate",
    "release_line",
    "status",
    "rust_min_version",
    "claim",
    "targets",
    "checks",
    "proofs",
    "release_candidate_requirements",
}


def fail(message: str) -> None:
    print(f"verify-evidence: {message}", file=sys.stderr)
    sys.exit(1)


def require_string(value: Any, path: str) -> None:
    if not isinstance(value, str) or not value:
        fail(f"{path} must be a non-empty string")


def require_string_list(value: Any, path: str) -> None:
    if not isinstance(value, list) or not value:
        fail(f"{path} must be a non-empty list")
    for index, item in enumerate(value):
        require_string(item, f"{path}[{index}]")


def kani_proofs() -> set[str]:
    proofs: set[str] = set()
    for path in SOURCE_ROOT.rglob("*.rs"):
        source = path.read_text(encoding="utf-8")
        proofs.update(re.findall(r"fn\s+(prove_[A-Za-z0-9_]+)\s*\(", source))
    return proofs


def require_check_coverage(checks: list[dict[str, Any]], name: str, needles: list[str]) -> None:
    for check in checks:
        if check.get("name") == name:
            coverage = " ".join(check.get("coverage", []))
            for needle in needles:
                if needle not in coverage:
                    fail(f"checks[{name}].coverage must mention {needle!r}")
            return
    fail(f"missing required check entry: {name}")


def verify_release_evidence() -> None:
    try:
        release = json.loads(RELEASE_EVIDENCE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{RELEASE_EVIDENCE.name} is unavailable or invalid: {error}")

    if release.get("schema_version") != 1 or release.get("release") != "2.0.0":
        fail("2.0 release evidence has an invalid schema or release version")
    commit = release.get("implementation_commit")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        fail("2.0 release evidence has an invalid implementation commit")

    compiler = release.get("compiler")
    if not isinstance(compiler, dict) or compiler.get("release") != "1.97.1":
        fail("2.0 release evidence has an invalid compiler record")
    if re.fullmatch(r"[0-9a-f]{40}", str(compiler.get("commit_hash"))) is None:
        fail("2.0 release evidence has an invalid compiler commit")

    targets = release.get("target_matrix")
    expected_targets = {
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
        "aarch64-apple-darwin",
        "x86_64-unknown-freebsd",
        "aarch64-linux-android",
        "aarch64-apple-ios",
        "thumbv7em-none-eabihf",
        "riscv32imac-unknown-none-elf",
        "wasm32-unknown-unknown",
        "wasm32-wasip1",
        "wasm32-wasip2",
    }
    if not isinstance(targets, list) or len(targets) != len(expected_targets):
        fail("2.0 release evidence target matrix is incomplete")
    target_names: set[str] = set()
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            fail(f"release target_matrix[{index}] must be an object")
        for key in ("target", "host", "tier", "evidence_kind", "features"):
            require_string(target.get(key), f"release target_matrix[{index}].{key}")
        target_names.add(target["target"])
    if target_names != expected_targets:
        fail("2.0 release evidence target matrix has missing or unexpected targets")

    workflows = release.get("workflow_runs")
    if not isinstance(workflows, list) or len(workflows) != 5:
        fail("2.0 release evidence must record all five accepted workflow runs")
    workflow_names: set[str] = set()
    for index, workflow in enumerate(workflows):
        if not isinstance(workflow, dict):
            fail(f"release workflow_runs[{index}] must be an object")
        name = workflow.get("name")
        url = workflow.get("url")
        if not isinstance(name, str) or not name:
            fail(f"release workflow_runs[{index}].name must be non-empty")
        if not isinstance(url, str) or re.fullmatch(
            r"https://github\.com/valkyoth/sanitization/actions/runs/[0-9]+", url
        ) is None:
            fail(f"release workflow_runs[{index}].url is invalid")
        if workflow.get("conclusion") != "success":
            fail(f"release workflow {name!r} was not successful")
        workflow_names.add(name)
    required_workflows = {
        "CP-20 target evidence",
        "Security evidence tooling",
        "Miri Verification",
        "Kani Verification",
        "Rust CI",
    }
    if workflow_names != required_workflows:
        fail("2.0 release evidence workflow set is incomplete")

    artifacts = release.get("target_evidence_artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 15:
        fail("2.0 release evidence must record all 15 CP-20 artifacts")
    artifact_names: set[str] = set()
    artifact_ids: set[int] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            fail(f"release target_evidence_artifacts[{index}] must be an object")
        name = artifact.get("name")
        artifact_id = artifact.get("id")
        size = artifact.get("size_in_bytes")
        digest = artifact.get("digest")
        if not isinstance(name, str) or not name.startswith("cp20-"):
            fail(f"release artifact {index} has an invalid name")
        if not isinstance(artifact_id, int) or artifact_id <= 0:
            fail(f"release artifact {name!r} has an invalid id")
        if not isinstance(size, int) or size <= 0:
            fail(f"release artifact {name!r} has an invalid size")
        if not isinstance(digest, str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", digest
        ) is None:
            fail(f"release artifact {name!r} has an invalid digest")
        artifact_names.add(name)
        artifact_ids.add(artifact_id)
    if len(artifact_names) != len(artifacts) or len(artifact_ids) != len(artifacts):
        fail("2.0 release evidence contains duplicate artifact names or ids")


def main() -> int:
    try:
        data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"{EVIDENCE.name} is invalid JSON: {error}")

    if not isinstance(data, dict):
        fail("docs/ct-evidence.json must contain a JSON object")

    missing = REQUIRED_TOP_LEVEL.difference(data)
    if missing:
        fail(f"missing required top-level keys: {', '.join(sorted(missing))}")

    if data["schema_version"] != 1:
        fail("schema_version must be 1")
    if data["crate"] != "sanitization":
        fail("crate must be sanitization")
    require_string(data["release_line"], "release_line")
    require_string(data["status"], "status")
    require_string(data["rust_min_version"], "rust_min_version")

    claim = data["claim"]
    if not isinstance(claim, dict):
        fail("claim must be an object")
    require_string(claim.get("summary"), "claim.summary")
    require_string_list(claim.get("claimed"), "claim.claimed")
    require_string_list(claim.get("not_claimed"), "claim.not_claimed")

    targets = data["targets"]
    if not isinstance(targets, list) or not targets:
        fail("targets must be a non-empty list")
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            fail(f"targets[{index}] must be an object")
        for key in ("target", "tier"):
            require_string(target.get(key), f"targets[{index}].{key}")
        for key in ("features", "barrier_strategy", "evidence", "limitations"):
            value = target.get(key)
            if not isinstance(value, list):
                fail(f"targets[{index}].{key} must be a list")
            for item_index, item in enumerate(value):
                require_string(item, f"targets[{index}].{key}[{item_index}]")

    checks = data["checks"]
    if not isinstance(checks, list) or not checks:
        fail("checks must be a non-empty list")
    for index, check in enumerate(checks):
        if not isinstance(check, dict):
            fail(f"checks[{index}] must be an object")
        require_string(check.get("name"), f"checks[{index}].name")
        require_string(check.get("command"), f"checks[{index}].command")
        require_string_list(check.get("coverage"), f"checks[{index}].coverage")

    require_check_coverage(
        checks,
        "codegen",
        [
            "release LLVM IR",
            "native ct",
            "optimizer-barrier",
            "mask-generation",
            "memcmp/bcmp",
        ],
    )
    require_check_coverage(
        checks,
        "workspace-checks",
        [
            "derive macro tests",
            "derive rejection checks",
            "leakage-harness smoke testing",
            "package listing",
        ],
    )
    require_check_coverage(
        checks,
        "derive-failures",
        ["enum native ct", "skipped conditionally selectable", "strict enum"],
    )
    require_check_coverage(
        checks,
        "leakage-smoke",
        ["ct leakage harness", "JSON output", "not release timing evidence"],
    )
    require_check_coverage(
        checks,
        "multi-seed-leakage",
        ["three distinct default", "three distinct strict", "hashed per-run"],
    )
    require_check_coverage(
        checks,
        "performance-baseline",
        ["scaling threshold", "specialized bulk wipe", "SecretBytes"],
    )
    require_check_coverage(
        checks,
        "target-evidence",
        ["native versus compile-only", "Tier C WASM", "dirty and failed"],
    )
    require_check_coverage(checks, "kani", ["clearing", "equality", "ordering"])
    require_check_coverage(checks, "miri", ["safe and unsafe-boundary"])

    listed_proofs = data["proofs"]
    require_string_list(listed_proofs, "proofs")
    actual_proofs = kani_proofs()
    listed_set = set(listed_proofs)
    missing_from_json = actual_proofs.difference(listed_set)
    missing_from_code = listed_set.difference(actual_proofs)
    if missing_from_json:
        fail(f"Kani proofs missing from JSON: {', '.join(sorted(missing_from_json))}")
    if missing_from_code:
        fail(f"JSON proofs missing from code: {', '.join(sorted(missing_from_code))}")

    require_string_list(
        data["release_candidate_requirements"], "release_candidate_requirements"
    )
    verify_release_evidence()

    print("docs/ct-evidence.json and 2.0 release evidence validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
