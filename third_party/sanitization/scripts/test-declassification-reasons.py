#!/usr/bin/env python3
"""Exercise fail-closed fixtures for the declassification reason lint."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LINTER = ROOT / "scripts" / "lint-declassification-reasons.py"


def run_fixture(name: str, source: str, *, succeeds: bool, message: str = "") -> None:
    with tempfile.TemporaryDirectory(prefix=f"sanitization-declassify-{name}-") as directory:
        path = Path(directory) / "fixture.rs"
        path.write_text(source, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(LINTER), str(path)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    if succeeds and result.returncode != 0:
        raise SystemExit(f"{name} unexpectedly failed:\n{result.stderr}")
    if not succeeds and result.returncode == 0:
        raise SystemExit(f"{name} unexpectedly passed")
    if message and message not in result.stderr:
        raise SystemExit(f"{name} did not report {message!r}:\n{result.stderr}")


run_fixture(
    "meaningful",
    'fn check(choice: Choice) { choice.declassify("authentication result is public"); }\n',
    succeeds=True,
)
run_fixture(
    "meaningful-raw",
    'fn check(choice: Choice) { choice.declassify_u8(r#"wire flag is public"#); }\n',
    succeeds=True,
)
run_fixture(
    "meaningful-ufcs",
    'fn check(choice: Choice) { Choice::declassify(choice, "protocol decision is public"); }\n',
    succeeds=True,
)
run_fixture(
    "meaningful-high-level-boundary",
    'fn check(a: &[u8; 4], b: &[u8; 4]) { let _ = ct::declassified_eq_fixed(a, b, "authentication result is public"); }\n',
    succeeds=True,
)
run_fixture(
    "meaningful-high-level-boundary-turbofish",
    'fn check(a: &[u8; 4], b: &[u8; 4]) { let _ = ct::declassified_eq_fixed::<4>(a, b, "authentication result is public"); }\n',
    succeeds=True,
)
run_fixture(
    "meaningful-export",
    'fn check(secret: SecretBytes<4>) { let _ = secret.export_byte("wire header exposes public key byte", 0); }\n',
    succeeds=True,
)
run_fixture(
    "comments-and-strings",
    '// choice.declassify("todo");\nconst TEXT: &str = ".declassify(\\\"todo\\\")";\n',
    succeeds=True,
)
run_fixture(
    "todo",
    'fn check(choice: Choice) { choice.declassify("todo"); }\n',
    succeeds=False,
    message="placeholder word",
)
run_fixture(
    "disguised-todo",
    'fn check(choice: Choice) { choice.declassify("authentication TODO is public"); }\n',
    succeeds=False,
    message="placeholder word",
)
run_fixture(
    "generic",
    'fn check(choice: Choice) { choice.declassify("result is public"); }\n',
    succeeds=False,
    message="generic placeholder",
)
run_fixture(
    "dynamic",
    'fn check(choice: Choice, reason: &\'static str) { choice.declassify(reason); }\n',
    succeeds=False,
    message="direct string literal",
)
run_fixture(
    "dynamic-high-level-boundary",
    'fn check(a: &[u8; 4], b: &[u8; 4], reason: &\'static str) { let _ = declassified_eq_fixed(a, b, reason); }\n',
    succeeds=False,
    message="direct string literal",
)
run_fixture(
    "macro",
    'fn check(choice: Choice) { choice.declassify(concat!("result", " is public")); }\n',
    succeeds=False,
    message="direct string literal",
)
run_fixture(
    "ufcs-todo",
    'fn check(choice: Choice) { Choice::declassify(choice, "todo"); }\n',
    succeeds=False,
    message="placeholder word",
)
run_fixture(
    "high-level-boundary-todo",
    'fn check(a: &[u8; 4], b: &[u8; 4]) { let _ = declassified_cmp_fixed(a, b, "todo"); }\n',
    succeeds=False,
    message="placeholder word",
)
run_fixture(
    "high-level-boundary-turbofish-todo",
    'fn check(a: &[u8; 4], b: &[u8; 4]) { let _ = declassified_eq_fixed::<4>(a, b, "todo"); }\n',
    succeeds=False,
    message="placeholder word",
)
run_fixture(
    "export-todo",
    'fn check(secret: SecretBytes<4>) { let _ = secret.export_to_slice("todo", &mut [0; 4]); }\n',
    succeeds=False,
    message="placeholder word",
)

print("declassification and export reason lint fixtures passed")
