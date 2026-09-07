#!/usr/bin/env python3
"""Exercise 2.0 APIs from crates outside the publishable workspace."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "crates" / "sanitization"
TOOL = ROOT / "tools" / "downstream-migration" / "Cargo.toml"


def run(command: list[str], cwd: Path = ROOT) -> None:
    process = subprocess.run(command, cwd=cwd, text=True, check=False)
    if process.returncode != 0:
        print(
            f"verify-downstream-migration: {' '.join(command)} failed",
            file=sys.stderr,
        )
        raise SystemExit(process.returncode)


def check_fixture(name: str, features: str, source: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"sanitization-{name}-") as directory:
        root = Path(directory)
        (root / "src").mkdir()
        feature_line = f', features = [{features}]' if features else ""
        manifest = f'''[package]
name = "{name}"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
sanitization = {{ path = "{CORE}", default-features = false{feature_line} }}
'''
        (root / "Cargo.toml").write_text(manifest, encoding="utf-8")
        (root / "src" / "lib.rs").write_text(source, encoding="utf-8")
        run(["cargo", "check", "--quiet"], root)


run(["cargo", "test", "--manifest-path", str(TOOL)])

check_fixture(
    "migration_no_std",
    "",
    '''#![no_std]
use sanitization::SecretBytes;

pub fn compare(secret: &SecretBytes<4>, other: &[u8; 4]) -> bool {
    secret.constant_time_eq(other)
}
''',
)

check_fixture(
    "migration_alloc_derive",
    '"alloc", "derive"',
    '''#![no_std]
extern crate alloc;
use sanitization::{SecretVec, SecureSanitize};

#[derive(SecureSanitize)]
pub struct Credentials {
    token: SecretVec,
    #[sanitization(skip, reason = "public protocol version")]
    pub version: u8,
}
''',
)

print("downstream 2.0 migration consumers verified")
