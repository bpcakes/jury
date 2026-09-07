#!/usr/bin/env python3
"""Regression tests for lint-storage-policies.py."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LINT = ROOT / "scripts" / "lint-storage-policies.py"


def run(root: Path, policy: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(LINT), "--root", str(root), "--policy-file", str(policy), *extra],
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
    with tempfile.TemporaryDirectory(prefix="sanitization-storage-policy-") as temporary:
        root = Path(temporary)
        policy = root / "policy.rs"
        module = root / "sensitive.rs"

        policy.write_text(
            "use sanitization::{define_secret_storage_policy, SecretBytes};\n"
            "define_secret_storage_policy! {\n"
            "    pub(crate) Approved {\n"
            "        SecretBytes<32> => \"fixed inline key with reviewed access\",\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        module.write_text(
            "use sanitization::{AllowlistedSecret, SecretBytes};\n"
            "type Key = AllowlistedSecret<SecretBytes<32>, crate::policy::Approved>;\n",
            encoding="utf-8",
        )
        result = run(root, policy)
        if result.returncode != 0:
            raise AssertionError(result.stderr)

        module.write_text(
            "use sanitization::Secret;\n"
            "type Key = Secret<[u8; 32]>;\n",
            encoding="utf-8",
        )
        require_failure(run(root, policy), "direct Secret<T>/Secret:: use is forbidden")

        module.write_text(
            "use sanitization::Secret as HiddenSecret;\n"
            "type Key = HiddenSecret<[u8; 32]>;\n",
            encoding="utf-8",
        )
        require_failure(run(root, policy), "direct Secret<T>/Secret:: use is forbidden")

        module.write_text(
            "use sanitization::{SecureSanitize, StableSharedSecretStorage};\n"
            "struct Local([u8; 32]);\n"
            "impl SecureSanitize for Local { fn secure_sanitize(&mut self) {} }\n"
            "impl StableSharedSecretStorage for Local {}\n",
            encoding="utf-8",
        )
        require_failure(run(root, policy), "storage marker implementation is outside")
        result = run(root, policy, "--allow-marker-file", str(module))
        if result.returncode != 0:
            raise AssertionError(result.stderr)

        for expression, name in (
            ("core::mem::forget(key);", "forget"),
            ("Box::leak(Box::new(key));", "Box::leak"),
            (
                "let _held = core::mem::ManuallyDrop::new(key);",
                "ManuallyDrop",
            ),
        ):
            module.write_text(
                "use sanitization::{AllowlistedSecret, SecretBytes};\n"
                "type Key = AllowlistedSecret<SecretBytes<32>, crate::policy::Approved>;\n"
                "fn retain(key: Key) { "
                + expression
                + " }\n",
                encoding="utf-8",
            )
            require_failure(
                run(root, policy),
                f"destructor-bypass primitive {name} is forbidden",
            )

        policy.write_text(
            "use sanitization::{define_secret_storage_policy, SecretBytes};\n"
            "define_secret_storage_policy! {\n"
            "    pub Exported {\n"
            "        SecretBytes<32> => \"fixed inline key with reviewed access\",\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        require_failure(run(root, policy, "--allow-marker-file", str(module)), "must be private")

    print("storage-policy lint fixture tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
