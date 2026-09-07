#!/usr/bin/env python3
"""Regression tests for lint-fail-closed-initialization.py."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LINT = ROOT / "scripts" / "lint-fail-closed-initialization.py"


def run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(LINT), "--root", str(root)],
        check=False,
        capture_output=True,
        text=True,
    )


def require_failure(result: subprocess.CompletedProcess[str], text: str) -> None:
    if result.returncode == 0 or text not in result.stderr:
        raise AssertionError(
            f"expected failure containing {text!r}; status={result.returncode}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sanitization-fail-closed-") as temporary:
        source = Path(temporary) / "lib.rs"

        source.write_text(
            "fn checked(pool: &Pool) -> Result<(), Error> {\n"
            "    let _slot = pool.try_allocate()?;\n"
            "    Ok(())\n"
            "}\n",
            encoding="utf-8",
        )
        result = run(source)
        if result.returncode != 0:
            raise AssertionError(result.stderr)

        source.write_text(
            "fn checked(pool: &Pool) {\n"
            "    let _slot = pool.try_allocate().expect(\"allocation checked\");\n"
            "}\n",
            encoding="utf-8",
        )
        result = run(source)
        if result.returncode != 0:
            raise AssertionError(result.stderr)

        source.write_text(
            "fn lossy(pool: &Pool) { let _ = pool.try_allocate(); }\n",
            encoding="utf-8",
        )
        require_failure(result=run(source), text="underscore name")

        source.write_text(
            "fn lossy(pool: &Pool) { let _ignored = pool.try_allocate(); }\n",
            encoding="utf-8",
        )
        require_failure(result=run(source), text="underscore name")

        source.write_text(
            "fn lossy(pool: &Pool) { drop(pool.try_allocate()); }\n",
            encoding="utf-8",
        )
        require_failure(result=run(source), text="dropping a try_* result")

        source.write_text(
            "fn lossy(pool: &Pool) { pool.try_allocate().ok(); }\n",
            encoding="utf-8",
        )
        require_failure(result=run(source), text="with .ok() discards its error")

        source.write_text(
            "fn lossy(pool: &Pool) { let _slot = pool.allocate(); }\n",
            encoding="utf-8",
        )
        require_failure(result=run(source), text="lossy allocate() is forbidden")

        source.write_text(
            "// let _ = pool.try_allocate();\n"
            "const NOTE: &str = \"pool.allocate()\";\n",
            encoding="utf-8",
        )
        result = run(source)
        if result.returncode != 0:
            raise AssertionError(result.stderr)

    print("fail-closed initialization lint fixture tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
