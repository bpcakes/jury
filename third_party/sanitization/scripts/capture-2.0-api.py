#!/usr/bin/env python3
"""Capture or verify the current 2.0 source-level public API inventory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from source_api_inventory import ROOT, snapshot


OUTPUT = ROOT / "docs" / "baselines" / "2.0" / "current-source-api.json"


def fail(message: str) -> None:
    print(f"capture-2.0-api: {message}", file=sys.stderr)
    raise SystemExit(1)


parser = argparse.ArgumentParser()
parser.add_argument("--check", action="store_true")
parser.add_argument("--output", type=Path, default=OUTPUT)
arguments = parser.parse_args()
output = arguments.output.resolve()
current = snapshot()

if arguments.check:
    if not output.is_file():
        fail(f"missing source API inventory: {output}")
    recorded = json.loads(output.read_text(encoding="utf-8"))
    if recorded != current:
        fail("current source API inventory is stale; regenerate after reviewed API changes")
    print("current 2.0 source API inventory verified")
else:
    output.write_text(
        json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {output}")
