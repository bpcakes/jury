#!/usr/bin/env python3
"""Exercise the source-inventory gate against real temporary Git histories."""
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest


class SourceInventory(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='jury-gate-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.gate = runpy.run_path(str(Path(__file__).with_name('check-witness-gate')))
        self.check = self.gate['check_conformance_source_inventory']
        self.check.__globals__['ROOT'] = self.root
        self.error = self.gate['GateError']
        self.prefix = 'conformance/witness-v1/'
        self.bound = [self.prefix+'src/lib.rs']
        self.git('init', '-q', '--initial-branch=main')
        self.write('src/lib.rs')
        self.revision = self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], text=True).strip()

    def write(self, relative):
        path = self.root/self.prefix/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('// Example public source fixture.\n')
        return path

    def commit(self):
        self.git('add', '.')
        self.git('-c', 'user.name=ExampleContributor', '-c', 'user.email=example@example.test',
                 'commit', '-qm', 'Example source snapshot')
        return self.git('rev-parse', 'HEAD')

    def test_exact_disk_revision_and_binding_inventory_passes(self):
        self.check(self.revision, self.bound)
        self.write('target/ExampleGenerated.rs')
        self.check(self.revision, self.bound)

    def test_missing_disk_source_is_rejected(self):
        (self.root/self.bound[0]).unlink()
        with self.assertRaisesRegex(self.error, 'source binding inventory changed'):
            self.check(self.revision, self.bound)

    def test_unbound_source_and_automatically_discovered_targets_are_rejected(self):
        for relative in ('src/ExampleExtra.rs', 'build.rs', 'tests/ExampleTest.rs',
                         'benches/ExampleBench.rs', 'examples/ExampleProgram.rs'):
            path = self.write(relative)
            with self.assertRaisesRegex(self.error, 'source binding inventory changed'):
                self.check(self.revision, self.bound)
            path.unlink()
        with self.assertRaisesRegex(self.error, 'source binding inventory changed'):
            self.check(self.revision, [])

    def test_unbound_source_hidden_from_disk_still_exists_in_frozen_revision(self):
        path = self.write('src/ExampleHidden.rs')
        revision = self.commit()
        path.unlink()
        with self.assertRaisesRegex(self.error, 'source binding inventory changed'):
            self.check(revision, self.bound)


if __name__ == '__main__':
    unittest.main()
