#!/usr/bin/env python3
"""Negative controls for the actual J18 suite-2 input binding verifier."""
import copy
import json
from pathlib import Path
import runpy
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = runpy.run_path(str(ROOT / "scripts/check-suite2-inputs"))
VERIFY = MODULE["verify_bindings"]


class Bindings(unittest.TestCase):
    def test_each_input_and_acceptance_dimension(self):
        with (ROOT / "docs/security/jury-v2-crypto-gate.toml").open("rb") as source:
            gate = tomllib.load(source)
        with tempfile.TemporaryDirectory(prefix="jury-suite2-bindings-") as directory:
            root = Path(directory)
            for binding in gate["bindings"]:
                target = root / binding["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / binding["path"]).read_bytes())
            VERIFY(root, gate)
            for binding in gate["bindings"]:
                target = root / binding["path"]
                original = target.read_bytes()
                target.write_bytes(original + b"\n")
                with self.assertRaisesRegex(ValueError, "hash differs"):
                    VERIFY(root, gate)
                target.write_bytes(original)
            for key, value in (("status", "pending"), ("consumer", "unrelated"),
                               ("pre_alpha", False), ("independently_reviewed", True)):
                changed = copy.deepcopy(gate)
                changed[key] = value
                with self.assertRaisesRegex(ValueError, "not accepted"):
                    VERIFY(root, changed)
            for key in gate["suite"]:
                changed = copy.deepcopy(gate)
                changed["suite"][key] += 1
                with self.assertRaisesRegex(ValueError, "algorithms differ"):
                    VERIFY(root, changed)
            for key in ("hpke_revision", "boringssl_revision"):
                changed = copy.deepcopy(gate)
                changed[key] = "0" * 40
                with self.assertRaisesRegex(ValueError, "revision differs"):
                    VERIFY(root, changed)
            for kind in ("missing", "duplicate", "extra"):
                changed = copy.deepcopy(gate)
                if kind == "missing":
                    changed["bindings"].pop()
                elif kind == "duplicate":
                    changed["bindings"][0] = changed["bindings"][1]
                else:
                    changed["bindings"].append({"path": "unexpected", "sha256": "0" * 64})
                with self.assertRaisesRegex(ValueError, "inventory differs"):
                    VERIFY(root, changed)


class RuntimeProviders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metadata = json.loads(MODULE["command"]([
            "cargo", "metadata", "--format-version", "1", "--locked",
            "--manifest-path", str(ROOT / "crates/jury-core/Cargo.toml"),
        ]))

    def test_actual_graph_and_removed_cleanup_features(self):
        verify = MODULE["verify_runtime_graph"]
        verify(self.metadata)
        for name in ("aes", "aes-gcm", "ghash", "polyval"):
            changed = copy.deepcopy(self.metadata)
            ids = {package["id"] for package in changed["packages"] if package["name"] == name}
            for node in changed["resolve"]["nodes"]:
                if node["id"] in ids:
                    node["features"] = [feature for feature in node["features"] if feature != "zeroize"]
            with self.subTest(provider=name), self.assertRaisesRegex(ValueError, "version/features differ"):
                verify(changed)

    def test_runtime_hpke_selection_and_rng_refuse_drift(self):
        verify = MODULE["verify_runtime_graph"]
        for kind in ("revision", "feature", "rng"):
            changed = copy.deepcopy(self.metadata)
            package = next(package for package in changed["packages"] if package["name"] == "hpke")
            node = next(node for node in changed["resolve"]["nodes"] if node["id"] == package["id"])
            if kind == "revision":
                package["source"] = "git+https://example.invalid/provider#" + "0" * 40
            elif kind == "feature":
                node["features"].remove("aes")
            else:
                node["features"].append("getrandom")
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                verify(changed)


if __name__ == "__main__":
    unittest.main()
