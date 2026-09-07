#!/usr/bin/env python3
"""Validate the complete 1.2.5-to-2.0 migration inventory."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs" / "migration-2.0.json"


def fail(message: str) -> None:
    print(f"verify-migration-2.0: {message}", file=sys.stderr)
    raise SystemExit(1)


data = json.loads(INVENTORY.read_text(encoding="utf-8"))
if data.get("schema_version") != 1:
    fail("schema_version must be 1")
if data.get("baseline") != "1.2.5" or data.get("target") != "2.0.0":
    fail("inventory must describe 1.2.5 to 2.0.0")

guide_path = ROOT / data.get("guide", "")
if not guide_path.is_file():
    fail("guide path does not exist")
guide = guide_path.read_text(encoding="utf-8")
anchors = {
    re.sub(r"[^a-z0-9 -]", "", heading.lower()).replace(" ", "-")
    for heading in re.findall(r"^## (.+)$", guide, flags=re.MULTILINE)
}

changes = data.get("changes")
if not isinstance(changes, list) or not changes:
    fail("changes must be a non-empty list")

legacy_names: set[str] = set()
for index, change in enumerate(changes):
    if not isinstance(change, dict):
        fail(f"changes[{index}] must be an object")
    for key in ("legacy", "replacement", "anchor"):
        value = change.get(key)
        if not isinstance(value, str) or not value.strip():
            fail(f"changes[{index}].{key} must be a non-empty string")
    legacy = change["legacy"]
    if legacy in legacy_names:
        fail(f"duplicate legacy entry: {legacy}")
    legacy_names.add(legacy)
    if change["anchor"] not in anchors:
        fail(f"unknown guide anchor for {legacy}: {change['anchor']}")
required = {
    "SecretBytes::copy_to_slice",
    "SecretBytes::read_byte",
    "ExpiringSecretBytes::try_copy_to_slice",
    "MonotonicExpiringSecretBytes::try_copy_to_slice",
    "Choice::unwrap_u8",
    "Choice Eq and PartialEq",
    "CtOrdering Eq and PartialEq",
    "Mask::expose",
    "Mask Eq and PartialEq",
    "ct::Secret<T>",
    "strict-ct feature",
    "empty default feature set",
    "#[sanitization(skip)]",
    "sanitize_bytes",
    "sanitize_bytes_best_effort",
    "unsafe_wipe::VolatileSanitize",
    "unsafe-wipe feature",
    "ReadOnceSecret<T>",
    "ReadOnceSecret::consume_mut",
    "CacheFlushSanitize::cache_flush_sanitize returning unit",
    "infallible cache flush APIs",
    "infallible mapped canary operations",
    "LockedSecretBytesCheckedCopyError enum",
    "MemoryLockOperation exhaustive variants",
    "GuardPageOperation exhaustive variants",
}
missing = required.difference(legacy_names)
if missing:
    fail(f"required migration entries missing: {', '.join(sorted(missing))}")

print(f"validated {len(changes)} migration entries")
