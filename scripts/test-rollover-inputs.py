#!/usr/bin/env python3
"""Negative controls for J18's actual input binding verifier."""
import copy
import hashlib
from pathlib import Path
import runpy
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = runpy.run_path(str(ROOT / 'scripts/check-rollover-inputs'))['verify_bindings']


class RolloverBindings(unittest.TestCase):
    def test_each_bound_input_and_inventory_mutation_is_rejected(self):
        with (ROOT / 'docs/security/jury-rollover-v1-gate.toml').open('rb') as source:
            gate = tomllib.load(source)
        with tempfile.TemporaryDirectory(prefix='jury-rollover-inputs-') as directory:
            root = Path(directory)
            for binding in gate['bindings']:
                target = root / binding['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / binding['path']).read_bytes())
            VERIFIER(root, gate)
            for binding in gate['bindings']:
                path = root / binding['path']
                original = path.read_bytes()
                path.write_bytes(original + b'\n')
                with self.assertRaisesRegex(ValueError, 'hash differs'):
                    VERIFIER(root, gate)
                path.write_bytes(original)
            for kind in ('missing', 'duplicate', 'extra'):
                changed = copy.deepcopy(gate)
                if kind == 'missing':
                    changed['bindings'].pop()
                elif kind == 'duplicate':
                    changed['bindings'][0] = changed['bindings'][1]
                else:
                    changed['bindings'].append({'path': 'unexpected', 'sha256': '0' * 64})
                with self.assertRaisesRegex(ValueError, 'inventory differs'):
                    VERIFIER(root, changed)
            for key, value in (('status', 'pending'), ('suite', 2),
                               ('bootstrap_versions', [2]), ('supersedes_gate_sha256', '0' * 64),
                               ('independently_reviewed', True), ('pre_alpha', False)):
                changed = copy.deepcopy(gate)
                changed[key] = value
                with self.assertRaisesRegex(ValueError, 'not accepted'):
                    VERIFIER(root, changed)
            # Updating a gate entry alongside a changed old vector must not
            # turn a compatibility regression into an accepted new golden.
            changed = copy.deepcopy(gate)
            binding = next(entry for entry in changed['bindings']
                           if entry['path'] == 'conformance/rollover-v1/vectors.json')
            path = root / binding['path']
            path.write_bytes(path.read_bytes() + b'\n')
            binding['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, 'v1 compatibility hash differs'):
                VERIFIER(root, changed)


if __name__ == '__main__':
    unittest.main()
