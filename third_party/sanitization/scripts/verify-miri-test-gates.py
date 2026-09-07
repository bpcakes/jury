#!/usr/bin/env python3
"""Reject Miri-only behavior that can be selected outside crate unit tests."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "crates" / "sanitization" / "src"
MAPPED_BACKEND = SOURCE_ROOT / "mapped" / "memory_lock_native.rs"
CANARY_BACKEND = SOURCE_ROOT / "canary.rs"
DOWNSTREAM_MIRI_COMPARE_PATHS = {
    Path("crates/sanitization/src/ct.rs"),
    Path("crates/sanitization/src/lib.rs"),
    Path("crates/sanitization/src/owned.rs"),
    Path("crates/sanitization/src/platform.rs"),
}


def fail(message: str) -> None:
    print(f"Miri test-backend gate failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def compact(value: str) -> str:
    return re.sub(r"\s+", "", value)


def cfg_expressions(source: str) -> list[str]:
    attributes = [
        match.group(1)
        for match in re.finditer(r"#\[cfg(?:_attr)?\((.*?)\)\]", source, re.DOTALL)
    ]
    expressions = [
        match.group(1)
        for match in re.finditer(r"(?<!#\[)cfg!\((.*?)\)", source, re.DOTALL)
    ]
    return attributes + expressions


def function_cfgs(source: str, name: str) -> list[str]:
    pattern = re.compile(
        rf"(?P<attrs>(?:\s*#\[[^\]]+\]\s*)+)"
        rf"(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+{re.escape(name)}\s*\("
    )
    return [compact(match.group("attrs")) for match in pattern.finditer(source)]


def is_downstream_miri_comparison_gate(path: Path, expression: str) -> bool:
    relative = path.relative_to(ROOT)
    if relative not in DOWNSTREAM_MIRI_COMPARE_PATHS:
        return False
    if 'feature="asm-compare"' in expression and "not(miri)" in expression:
        return True
    return (
        relative == Path("crates/sanitization/src/lib.rs")
        and 'feature="strict-compare"' in expression
        and "not(miri)" in expression
    )


def verify_source_gates() -> None:
    for path in sorted(SOURCE_ROOT.rglob("*.rs")):
        if path.name == "tests.rs":
            continue
        source = path.read_text(encoding="utf-8")
        for expression in cfg_expressions(source):
            normalized = compact(expression)
            if (
                "miri" in normalized
                and "test" not in normalized
                and not is_downstream_miri_comparison_gate(path, normalized)
            ):
                fail(
                    f"{path.relative_to(ROOT)} has a Miri behavior gate without "
                    f"the crate-unit-test condition: cfg({normalized})"
                )

    backend = MAPPED_BACKEND.read_text(encoding="utf-8")
    for name in (
        "backend_page_granule",
        "backend_map_private",
        "backend_lock_mapping",
        "backend_mark_dontdump",
        "backend_mark_dontfork",
        "backend_mark_wipeonfork",
        "backend_unlock_mapping",
        "backend_unmap_private",
    ):
        cfgs = function_cfgs(backend, name)
        if len(cfgs) != 2:
            fail(f"expected native and modeled definitions for {name}, found {len(cfgs)}")
        if not any("#[cfg(all(miri,test))]" in cfg for cfg in cfgs):
            fail(f"{name} has no cfg(all(miri, test)) model definition")
        if not any("#[cfg(not(all(miri,test)))]" in cfg for cfg in cfgs):
            fail(f"{name} has no native complement to the unit-test model")

    canary = compact(CANARY_BACKEND.read_text(encoding="utf-8"))
    if "#[cfg(all(miri,test))]fnfill_for_miri" not in canary:
        fail("the deterministic canary generator is not restricted to Miri unit tests")
    if "#[cfg(not(all(miri,test)))]fill_inner(bytes)" not in canary:
        fail("normal builds do not unconditionally retain the native canary backend")


def forged_cfg_environment(*cfgs: str) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    env["RUSTFLAGS"] = " ".join(f"--cfg {cfg}" for cfg in cfgs)
    return env


def forged_cfg_command(target_dir: str) -> list[str]:
    return [
        "cargo",
        "check",
        "--release",
        "-p",
        "sanitization",
        "--no-default-features",
        "--features",
        "memory-lock,random-canary,asm-compare,cache-flush,register-scrub",
        "--lib",
        "--target-dir",
        target_dir,
    ]


def verify_forged_cfg_builds() -> None:
    env = forged_cfg_environment("miri")
    command = forged_cfg_command("target/miri-production-gate")
    result = subprocess.run(command, cwd=ROOT, env=env, check=False)
    if result.returncode != 0:
        fail("a normal release build with --cfg miri did not retain native protection paths")

    env = forged_cfg_environment("miri", "test")
    command = forged_cfg_command("target/miri-forged-test-gate")
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    expected = "the Miri protection simulator is restricted to debug test artifacts"
    if result.returncode == 0:
        fail("a forged release build with --cfg miri --cfg test selected the simulator")
    if expected not in result.stdout:
        fail("the forged release build failed for an unexpected reason")


def verify_release_flags_rejected() -> None:
    command = [
        sys.executable,
        "scripts/release_crates.py",
        "--dry-run",
        "--yes",
    ]
    for name, value in (
        ("RUSTFLAGS", "--cfg miri"),
        ("CARGO_ENCODED_RUSTFLAGS", "--cfg\x1fmiri"),
    ):
        env = os.environ.copy()
        env.pop("RUSTFLAGS", None)
        env.pop("CARGO_ENCODED_RUSTFLAGS", None)
        env[name] = value
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if result.returncode == 0:
            fail(f"release helper accepted ambient {name}")
        if "refusing release with ambient Rust compiler flags" not in result.stdout:
            fail(f"release helper rejected {name} for an unexpected reason")


def main() -> int:
    verify_source_gates()
    verify_forged_cfg_builds()
    verify_release_flags_rejected()
    print("Miri simulators are restricted to debug crate unit-test artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
