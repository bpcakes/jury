#!/usr/bin/env python3
"""Fast filesystem regression tests; live Docker/CLI proof is in the build recipe."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile
import tomllib
import runpy
import subprocess
import shutil
import unittest
from urllib.parse import unquote, urlsplit

from linux_release_support import (collect_notices, collect_provider_notices, extract_vendor, snapshot_files,
                                   vendor_config, verify_packaged_binaries, normalize_sbom,
                                   package_documentation, package_container_documentation,
                                   verify_documentation_links)
from linux_sbom_tool import extract_source


class SbomToolSource(unittest.TestCase):
    @staticmethod
    def archive_bytes(extra=None):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as archive:
            directory = tarfile.TarInfo('ExamplePackage')
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            archive.addfile(directory)
            member = tarfile.TarInfo('ExamplePackage/README.md')
            contents = b'ExampleSource'
            member.size = len(contents)
            archive.addfile(member, io.BytesIO(contents))
            if extra is not None:
                archive.addfile(extra)
        return data.getvalue()

    def test_verified_regular_source_extracts(self):
        data = self.archive_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            extract_source(data, hashlib.sha256(data).hexdigest(), root)
            self.assertEqual((root/'ExamplePackage/README.md').read_bytes(), b'ExampleSource')

    def test_checksum_mismatch_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, 'pinned checksum'):
                extract_source(self.archive_bytes(), '0'*64, root)
            self.assertEqual(list(root.iterdir()), [])

    def test_unsafe_member_rejects_the_entire_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent/'source'
            root.mkdir()
            outside = parent/'ExampleOutside'
            outside.write_bytes(b'ExampleSentinel')
            for name, kind in [
                ('../ExampleOutside', tarfile.REGTYPE),
                (str(outside), tarfile.REGTYPE),
                (str(root/'ExampleAbsolute'), tarfile.REGTYPE),
                ('ExamplePackage/link', tarfile.SYMTYPE),
                ('ExamplePackage/link', tarfile.LNKTYPE),
                ('ExamplePackage/fifo', tarfile.FIFOTYPE),
                ('ExamplePackage/device', tarfile.CHRTYPE),
                ('ExamplePackage/device', tarfile.BLKTYPE),
            ]:
                with self.subTest(name=name, kind=kind):
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = str(outside)
                    data = self.archive_bytes(member)
                    with self.assertRaisesRegex(ValueError, 'unsafe member'):
                        extract_source(data, hashlib.sha256(data).hexdigest(), root)
                    self.assertEqual(list(root.iterdir()), [])
                    self.assertEqual(outside.read_bytes(), b'ExampleSentinel')

    def test_checksum_valid_but_malformed_archive_writes_nothing(self):
        data = b'ExampleMalformedArchive'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(tarfile.ReadError):
                extract_source(data, hashlib.sha256(data).hexdigest(), root)
            self.assertEqual(list(root.iterdir()), [])


class ReleaseInputs(unittest.TestCase):
    def test_container_document_links_preserve_local_and_source_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'source'
            bundle = Path(directory)/'bundle'
            (source/'docs').mkdir(parents=True)
            (source/'README.md').write_text(
                'Example pre-alpha prose. [Security](SECURITY.md#scope) '
                '[Encoded security](%53ECURITY.md?view=1#scope) '
                '[Guide](docs/Example%20Guide.md#setup) [Section](#section) '
                '[External](https://example.com/reference).\n')
            (source/'SECURITY.md').write_text('Example pre-alpha. [Release](docs/linux-release.md).\n')
            (source/'docs/linux-release.md').write_text(
                'Example pre-alpha. [README](../README.md) [Guide](Example%20Guide.md#setup).\n')
            (source/'docs/Example Guide.md').write_text('Example guide.\n')
            revision = '1'*40
            package_container_documentation(source, bundle, revision)
            self.assertEqual((bundle/'README.md').read_text(),
                'Example pre-alpha prose. [Security](SECURITY.md#scope) '
                '[Encoded security](%53ECURITY.md?view=1#scope) '
                f'[Guide](https://github.com/bpcakes/jury/blob/{revision}/docs/Example%20Guide.md#setup) '
                '[Section](#section) [External](https://example.com/reference).\n')
            self.assertEqual((bundle/'SECURITY.md').read_bytes(), (source/'SECURITY.md').read_bytes())
            self.assertEqual((bundle/'docs/linux-release.md').read_text(),
                'Example pre-alpha. [README](../README.md) '
                f'[Guide](https://github.com/bpcakes/jury/blob/{revision}/docs/Example%20Guide.md#setup).\n')

    def test_documentation_verifier_decodes_local_url_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle/'docs').mkdir()
            (bundle/'docs/Example Guide.md').write_text('Example guide.\n')
            (bundle/'docs/README.md').write_text(
                '[Example guide](%45xample%20Guide.md?view=1#setup)\n')
            verify_documentation_links(bundle)

    def test_documentation_verifier_rejects_encoded_missing_and_escaping_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root/'bundle'
            (bundle/'docs').mkdir(parents=True)
            (root/'ExampleOutside.md').write_text('Example outside guide.\n')
            for target in ('%4dissing.md', '%2e%2e/%2e%2e/ExampleOutside.md'):
                with self.subTest(target=target):
                    (bundle/'docs/README.md').write_text(f'[Example guide]({target}#setup)\n')
                    with self.assertRaisesRegex(ValueError, 'missing local target'):
                        verify_documentation_links(bundle)

    def test_container_documentation_refuses_missing_source_targets(self):
        for target in ('SECURITY.md', 'docs/Example%20Missing.md'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                source = Path(directory)/'source'
                (source/'docs').mkdir(parents=True)
                (source/'README.md').write_text(f'[Example guide]({target}#setup)\n')
                (source/'docs/linux-release.md').write_text('Example release.\n')
                if target != 'SECURITY.md':
                    (source/'SECURITY.md').write_text('Example security.\n')
                with self.assertRaisesRegex(ValueError, 'missing source target'):
                    package_container_documentation(source, Path(directory)/'bundle', '1'*40)

    def test_container_documentation_requires_an_immutable_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for revision in ('', 'main', 'v0.0.1', '123abcd', 'g'*40, '1'*40+'/../main'):
                with self.subTest(revision=revision):
                    with self.assertRaisesRegex(ValueError, 'full source commit SHA'):
                        package_container_documentation(root, root/'bundle', revision)

    @unittest.skipUnless(os.environ.get('JURYD_TEST_IMAGE'), 'set JURYD_TEST_IMAGE to a built juryd image')
    def test_container_ships_canonical_supported_use_documents(self):
        source = Path(__file__).resolve().parents[1]
        names = ('README.md', 'SECURITY.md', 'docs/linux-release.md')
        revision = os.environ.get('JURYD_TEST_REVISION') or subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
        image_metadata = json.loads(subprocess.check_output(
            ['docker', 'image', 'inspect', os.environ['JURYD_TEST_IMAGE']], text=True))[0]
        self.assertEqual(image_metadata['Config']['Labels']['org.opencontainers.image.revision'], revision)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            for name in names:
                with self.subTest(document=name):
                    actual = subprocess.check_output([
                        'docker', 'run', '--rm', '--network', 'none', '--read-only',
                        '--entrypoint', 'cat', os.environ['JURYD_TEST_IMAGE'],
                        '/usr/share/doc/jury/'+name,
                    ]).decode()
                    # Packaging may relocate links; all canonical prose stays verbatim.
                    prose = lambda text: re.sub(r'(\[[^\]]+\]\()([^)]+)(\))', r'\1LINK\3', text)
                    self.assertEqual(prose(actual), prose((source/name).read_text()))
                    # Check each destination separately; prose normalization above
                    # must not hide missing paths or a moving branch in image links.
                    original_targets = re.findall(r'\[[^\]]+\]\(([^)]+)\)', (source/name).read_text())
                    actual_targets = re.findall(r'\[[^\]]+\]\(([^)]+)\)', actual)
                    self.assertEqual(len(actual_targets), len(original_targets))
                    for original, packaged in zip(original_targets, actual_targets):
                        target_url = urlsplit(original)
                        if target_url.scheme or target_url.netloc or not target_url.path:
                            self.assertEqual(packaged, original)
                            continue
                        target_path = (source/name).parent/unquote(target_url.path)
                        target_path = target_path.resolve()
                        self.assertTrue(target_path.exists(), original)
                        relative = target_path.relative_to(source).as_posix()
                        if relative in names:
                            self.assertEqual(packaged, original)
                        else:
                            packaged_url = urlsplit(packaged)
                            self.assertEqual((packaged_url.scheme, packaged_url.netloc), ('https', 'github.com'))
                            self.assertEqual(unquote(packaged_url.path), f'/bpcakes/jury/blob/{revision}/{relative}')
                            self.assertEqual((packaged_url.query, packaged_url.fragment),
                                             (target_url.query, target_url.fragment))
                    self.assertIn('pre-alpha', actual)
                    target = bundle/name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(actual)
            verify_documentation_links(bundle, [bundle/name for name in names])

    def test_sbom_tool_uses_the_pinned_release_and_non_yanked_xml_parser(self):
        recipe = runpy.run_path(str(Path(__file__).with_name('build-linux-release')))
        recipe['verify_sbom_tool_lock']()
        packages = tomllib.loads(recipe['SBOM_TOOL_LOCK'].read_text())['package']
        xml = [package for package in packages if package['name'] == 'xml-rs']
        self.assertEqual([(package['version'], package['checksum']) for package in xml], [
            ('0.8.29', 'e450f9b2ed1dff33c94c12589a87338689467b9c4f5d8a5710bd09a847d2c8a7')
        ])

    def test_local_provider_notices_ship_without_a_vendor_entry(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)/'notices'
            record = collect_provider_notices(source, destination)
            self.assertEqual(record['name'], 'sanitization')
            self.assertEqual(record['license'], 'MIT OR Apache-2.0')
            self.assertEqual(record['source'], 'third_party/sanitization')
            for name in record['files']:
                self.assertEqual((destination/f"sanitization-{record['version']}"/name).read_bytes(),
                                 (source/'third_party/sanitization'/name).read_bytes())
            isolated = Path(directory)/'source'
            shutil.copytree(source/'third_party/sanitization', isolated/'third_party/sanitization',
                            ignore=shutil.ignore_patterns('target'))
            (isolated/'third_party/sanitization/LICENSE-MIT').unlink()
            with self.assertRaisesRegex(ValueError, 'local provider license is absent'):
                collect_provider_notices(isolated, Path(directory)/'missing-notices')

    def test_real_operator_guides_ship_their_setup_files_and_resolve_local_links(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            for name in ('LICENSE.md', 'NOTICE.md', 'SECURITY.md'):
                shutil.copy2(source/name, bundle/name)
            package_documentation(source, bundle)
            for name in ('witness.example.json', 'anchor.example.json', 'juryd.service',
                         'juryd-anchor.service', 'README.md', 'Dockerfile'):
                self.assertEqual((bundle/'deploy/juryd'/name).read_bytes(),
                                 (source/'deploy/juryd'/name).read_bytes())
            for name in ('witness.example.json', 'anchor.example.json'):
                self.assertIsInstance(json.loads((bundle/'deploy/juryd'/name).read_bytes()), dict)
            (bundle/'deploy/juryd/witness.example.json').unlink()
            with self.assertRaisesRegex(ValueError, 'missing local target'):
                verify_documentation_links(bundle)

    def test_vendor_archive_requires_exact_bytes_and_safe_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root/'vendor.tar'
            for name, valid in [('vendor/ExamplePackage/Cargo.toml', True), ('../outside', False), ('/vendor/file', False)]:
                with tarfile.open(archive, 'w') as target:
                    member = tarfile.TarInfo(name)
                    member.size = 7
                    target.addfile(member, io.BytesIO(b'Example'))
                expected = hashlib.sha256(archive.read_bytes()).hexdigest()
                if valid:
                    extract_vendor(archive, expected.upper(), root/'extracted')
                    self.assertEqual((root/'extracted/vendor/ExamplePackage/Cargo.toml').read_bytes(), b'Example')
                else:
                    with self.assertRaisesRegex(ValueError, 'only regular files'):
                        extract_vendor(archive, expected, root/'invalid')
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    extract_vendor(archive, '0'*64, root/'invalid')
            self.assertFalse((root/'outside').exists())

    def test_snapshot_observes_mutations_modes_symlinks_and_extra_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root/'ExampleFile'
            target.write_bytes(b'ExampleBefore')
            (root/'ExampleLink').symlink_to('ExampleFile')
            initial_mode = target.stat().st_mode & 0o777
            before = snapshot_files(root)
            target.write_bytes(b'ExampleAfter')
            self.assertNotEqual(snapshot_files(root), before)
            target.write_bytes(b'ExampleBefore')
            target.chmod(initial_mode | 0o111)
            self.assertNotEqual(snapshot_files(root), before)
            target.chmod(initial_mode)
            (root/'extra').write_bytes(b'ExampleExtra')
            self.assertNotEqual(snapshot_files(root), before)
            (root/'extra').unlink()
            self.assertEqual(snapshot_files(root), before)
            (root/'ExampleLink').unlink()
            (root/'ExampleLink').symlink_to('../outside')
            with self.assertRaisesRegex(ValueError, 'escapes its root'):
                snapshot_files(root)

    def test_vendor_configuration_tracks_the_locked_git_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory)/'Cargo.lock'
            revision = '1'*40
            lock.write_text(f'[[package]]\nname="ExampleProvider"\nversion="1.0.0"\nsource="git+https://example.test/provider?rev={revision}#{revision}"\n')
            config = vendor_config(lock)
            self.assertIn('git = "https://example.test/provider"', config)
            self.assertIn(f'rev = "{revision}"', config)
            lock.write_text(lock.read_text().replace('#'+revision, '#'+'2'*40))
            with self.assertRaisesRegex(ValueError, 'exact revision'):
                vendor_config(lock)
            lock.write_text(lock.read_text().replace(revision, 'g'*40).replace('2'*40, 'g'*40))
            with self.assertRaisesRegex(ValueError, 'exact revision'):
                vendor_config(lock)

    def test_notice_collection_covers_nonprefix_names_and_refuses_missing_terms(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root/'vendor/ExamplePackage-1.0.0'
            package.mkdir(parents=True)
            (package/'Cargo.toml').write_text('[package]\nname="ExamplePackage"\nversion="1.0.0"\nlicense="MIT"\n')
            supplements = root/'supplements'
            supplements.mkdir()
            (supplements/'sources.json').write_text('[]')
            with self.assertRaisesRegex(ValueError, 'no license notices'):
                collect_notices(root/'vendor', supplements, root/'absent')
            (package/'src').mkdir()
            (package/'src/license.rs').write_text('fn example() {}')
            (package/'NOTICE-TEMPLATE.md').write_text('ExamplePlaceholder')
            with self.assertRaisesRegex(ValueError, 'no license notices'):
                collect_notices(root/'vendor', supplements, root/'false-positive')
            (package/'MIT-LICENSE.txt').write_text('ExampleLicenseText')
            inventory = collect_notices(root/'vendor', supplements, root/'present')
            self.assertEqual(inventory[0]['files'], ['MIT-LICENSE.txt'])
            self.assertEqual((root/'present/ExamplePackage-1.0.0/MIT-LICENSE.txt').read_text(), 'ExampleLicenseText')

    def test_packaged_binary_hashes_are_checked_after_archive_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory)/'package.tar'
            expected = {name: hashlib.sha256(name.encode()).hexdigest() for name in ('jury', 'juryd')}
            for altered in (False, True):
                with tarfile.open(archive, 'w') as target:
                    for name in expected:
                        data = (name+'-altered' if altered and name == 'jury' else name).encode()
                        member = tarfile.TarInfo('jury-0.0.1-x86_64-unknown-linux-gnu/'+name)
                        member.mode = 0o755
                        member.size = len(data)
                        target.addfile(member, io.BytesIO(data))
                if altered:
                    with self.assertRaisesRegex(ValueError, 'packaged binary digest mismatch'):
                        verify_packaged_binaries(archive, '0.0.1', 'x86_64-unknown-linux-gnu', expected)
                else:
                    verify_packaged_binaries(archive, '0.0.1', 'x86_64-unknown-linux-gnu', expected)

    def test_sbom_normalization_preserves_upstream_urls_and_matches_edges(self):
        source = {'bom-ref': 'path+file:///src/ExamplePackage',
                  'externalReferences': [{'url': 'https://example.test/src/LICENSE'}],
                  'dependencies': [{'ref': 'path+file:///src/ExamplePackage',
                                    'dependsOn': ['path+file:///src/ExampleDependency']}],
                  'description': 'file:///src/ExampleText'}
        actual = normalize_sbom(source)
        self.assertEqual(actual['bom-ref'], 'path+file:///jury-source/ExamplePackage')
        self.assertEqual(actual['dependencies'][0]['ref'], actual['bom-ref'])
        self.assertEqual(actual['dependencies'][0]['dependsOn'], ['path+file:///jury-source/ExampleDependency'])
        self.assertEqual(actual['externalReferences'], source['externalReferences'])
        self.assertEqual(actual['description'], source['description'])

    def test_archive_is_deterministic_and_preserves_internal_links(self):
        recipe = runpy.run_path(str(Path(__file__).with_name('build-linux-release')))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'source'
            source.mkdir()
            (source/'ExampleFile').write_bytes(b'ExampleData')
            (source/'ExampleFile').chmod(0o755)
            (source/'ExampleLink').symlink_to('ExampleFile')
            for name in ('first.tar.gz', 'second.tar.gz'):
                recipe['archive'](source, root/name, 'ExampleRoot')
            self.assertEqual((root/'first.tar.gz').read_bytes(), (root/'second.tar.gz').read_bytes())
            with tarfile.open(root/'first.tar.gz') as archive:
                regular, link = archive.getmembers()
                self.assertEqual((regular.uid, regular.gid, regular.mtime, regular.mode), (0, 0, 0, 0o755))
                self.assertTrue(link.issym())
                self.assertEqual(link.linkname, 'ExampleFile')

    def test_verifier_requires_external_digest_and_detects_artifact_and_source_drift(self):
        recipe = runpy.run_path(str(Path(__file__).with_name('build-linux-release')))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source, output = root/'source', root/'output'
            source.mkdir()
            output.mkdir()
            subprocess.run(['git', 'init', '-q', str(source)], check=True)
            (source/'Cargo.toml').write_text('[workspace.package]\nversion="0.0.1"\n')
            subprocess.run(['git', '-C', str(source), 'add', 'Cargo.toml'], check=True)
            recipe['verify'].__globals__['ROOT'] = source
            target = recipe['TARGET']
            bundle = root/'bundle'
            bundle.mkdir()
            expected = {}
            for name in ('jury', 'juryd'):
                (bundle/name).write_bytes(b'ExampleUnitFixture')
                (bundle/name).chmod(0o755)
                expected[name] = recipe['digest'](bundle/name)
            package_name = f'jury-0.0.1-{target}.tar.gz'
            recipe['archive'](bundle, output/package_name, f'jury-0.0.1-{target}')
            manifest = {'schema': 'jury-linux-build-v1', 'version': '0.0.1', 'target': target,
                        'source_files': recipe['source_files'](), 'dirty_candidate': True,
                        'reproduced_binaries': expected,
                        'artifacts': {package_name: recipe['digest'](output/package_name)}}
            (output/'provenance.json').write_bytes(recipe['json_bytes'](manifest))
            (output/'SHA256SUMS').write_text(''.join(f"{recipe['digest'](p)}  {p.name}\n" for p in sorted(output.iterdir())))
            authenticated_digest = recipe['digest'](output/'SHA256SUMS')
            recipe['verify'](output, authenticated_digest)
            with self.assertRaisesRegex(ValueError, 'expected checksum digest mismatch'):
                recipe['verify'](output, '0'*64)
            (output/'extra').write_bytes(b'ExampleExtra')
            with self.assertRaisesRegex(ValueError, 'inventory drifted'):
                recipe['verify'](output, authenticated_digest)
            (output/'extra').unlink()
            package = output/package_name
            original = package.read_bytes()
            package.write_bytes(original+b'ExampleAlteration')
            with self.assertRaisesRegex(ValueError, 'artifact drifted'):
                recipe['verify'](output, authenticated_digest)
            package.write_bytes(original)
            (source/'Cargo.toml').write_text('[workspace.package]\nversion="0.0.2"\n')
            with self.assertRaisesRegex(ValueError, 'source bytes'):
                recipe['verify'](output, authenticated_digest)


if __name__ == '__main__':
    unittest.main()
