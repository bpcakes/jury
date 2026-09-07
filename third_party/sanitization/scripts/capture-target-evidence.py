#!/usr/bin/env python3
"""Capture a dated target manifest after an evidence job has passed."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KINDS = {"native-functional", "compile-only", "wasm-compatibility"}


def output(command: list[str]) -> str:
    result = subprocess.run(
        command, cwd=ROOT, text=True, capture_output=True, check=False
    )
    if result.returncode != 0:
        raise SystemExit(result.stderr.strip() or f"{' '.join(command)} failed")
    return result.stdout.strip()


def rustc_host() -> str:
    for line in output(["rustc", "-vV"]).splitlines():
        if line.startswith("host: "):
            return line.removeprefix("host: ")
    raise SystemExit("rustc -vV did not report a host target")


def workflow_url() -> str:
    values = (
        os.environ.get("GITHUB_SERVER_URL"),
        os.environ.get("GITHUB_REPOSITORY"),
        os.environ.get("GITHUB_RUN_ID"),
    )
    if all(values):
        return f"{values[0]}/{values[1]}/actions/runs/{values[2]}"
    return "local"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--tier", required=True)
    parser.add_argument("--kind", choices=sorted(KINDS), required=True)
    parser.add_argument("--features", default="default")
    parser.add_argument("--completed-check", action="append", default=[])
    args = parser.parse_args()

    host = rustc_host()
    native = args.target == host
    if args.kind == "native-functional" and not native:
        raise SystemExit("native-functional evidence requires target == rustc host")
    if args.kind != "native-functional" and native:
        raise SystemExit("compile-only evidence must not be labeled native")
    if args.kind == "wasm-compatibility":
        if not args.target.startswith("wasm32-") or args.tier != "C":
            raise SystemExit("WASM compatibility evidence must use a wasm32 target and Tier C")
    if not args.completed_check:
        raise SystemExit("at least one --completed-check is required")

    status = output(["git", "status", "--short"])
    manifest = {
        "schema_version": 1,
        "tool": "sanitization-target-manifest",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "passed",
        "git_commit": output(["git", "rev-parse", "HEAD"]),
        "git_dirty": bool(status),
        "target": args.target,
        "host": host,
        "native": native,
        "tier": args.tier,
        "evidence_kind": args.kind,
        "features": args.features,
        "completed_checks": args.completed_check,
        "rustc": output(["rustc", "-vV"]),
        "runner": {
            "name": os.environ.get("RUNNER_NAME", "local"),
            "os": os.environ.get("RUNNER_OS", platform.system()),
            "arch": os.environ.get("RUNNER_ARCH", platform.machine()),
            "image": os.environ.get("ImageOS", "unknown"),
            "platform": platform.platform(),
        },
        "workflow_run": workflow_url(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
