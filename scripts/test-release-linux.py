#!/usr/bin/env python3
"""Recovery and remote-orchestration regressions; remote doubles are not live release proof."""
import json
import io
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from linux_release_support import digest
import release_remote as remote
from release_state import State, git, run

runner = runpy.run_path(str(Path(__file__).with_name('release-linux')), run_name='fixture')


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ExampleRelease-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root/'repo'
        self.repo.mkdir()
        git(self.repo, 'init', '-q')
        git(self.repo, 'config', 'user.name', 'ExampleMaintainer')
        git(self.repo, 'config', 'user.email', 'example@example.invalid')
        (self.repo/'README.md').write_text('Example source\n')
        git(self.repo, 'add', '.')
        git(self.repo, 'commit', '-qm', 'Example baseline')
        self.state = State(self.root/'state')
        self.addCleanup(self.state.close)
        self.state.initialize(self.repo, 'HEAD')

    def test_successful_stage_resumes_without_reexecution(self):
        output = self.root/'actual-output'
        def execute():
            run(['python3', '-c', 'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text("ExampleResult")', output])
        self.state.stage('example', execute)
        self.state.stage('example', lambda: self.fail('successful stage reexecuted'))
        self.assertEqual(output.read_text(), 'ExampleResult')
        self.assertEqual(json.loads(self.state.path.read_text())['stages']['example'], 'passed')

    def test_failed_command_is_retried_and_cannot_become_passed(self):
        with self.assertRaises(RuntimeError):
            self.state.stage('example', lambda: self.state.command('example', ['python3', '-c',
                              'import sys; print("ExampleDiagnostic", file=sys.stderr); sys.exit(7)']))
        self.assertEqual(self.state.data['stages']['example'], 'incomplete')
        self.assertIn('ExampleDiagnostic', (self.state.root/'example.log').read_text())
        self.state.stage('example', lambda: self.state.command('example', ['python3', '-c', 'pass']))
        self.assertEqual(self.state.data['stages']['example'], 'passed')

    def test_running_checkpoint_after_crash_is_retried(self):
        self.state.data['stages']['example'] = 'running'
        self.state.save()
        action = Mock()
        self.state.stage('example', action)
        action.assert_called_once()

    def test_source_changes_reject_cached_success(self):
        self.state.stage('example', lambda: None)
        (self.state.source/'README.md').write_text('Example changed documentation')
        with self.assertRaisesRegex(ValueError, 'frozen source changed'):
            self.state.stage('example', lambda: self.fail('must not execute'))

    def test_source_mutation_during_check_is_not_passed(self):
        with self.assertRaisesRegex(ValueError, 'frozen source changed'):
            self.state.stage('example', lambda: (self.state.source/'README.md').unlink())
        self.assertEqual(self.state.data['stages']['example'], 'incomplete')

    def test_other_revision_cannot_reuse_state(self):
        (self.repo/'README.md').write_text('Example successor')
        git(self.repo, 'commit', '-qam', 'Example successor')
        with self.assertRaisesRegex(ValueError, 'another source revision'):
            self.state.initialize(self.repo, 'HEAD')

    def test_changed_command_rejects_checkpoint(self):
        with patch('release_state.automation_digest', return_value='changed'):
            # Use a checkpoint copy so the real lock remains held.
            copy = self.root/'copy'
            copy.mkdir(mode=0o700)
            (copy/'state.json').write_bytes(self.state.path.read_bytes())
            with self.assertRaisesRegex(ValueError, 'release command changed'):
                State(copy)

    def test_concurrent_invocation_cannot_acquire_lock(self):
        with self.assertRaises(BlockingIOError):
            State(self.state.root)

    def test_shared_or_symlink_state_refused(self):
        shared = self.root/'shared'
        shared.mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError, 'mode 0700'):
            State(shared)
        link = self.root/'link'
        link.symlink_to(self.state.root)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            State(link)


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.state = Mock()
        self.state.data = dict(source_sha='a'*40, manifest_sha256='b'*64, notes='Example notes', release_id=31)
        self.state.verify_artifacts.return_value = {'version': '0.0.2'}

    def run_record(self, ident=12, conclusion='success', status='completed', attempt=1):
        return dict(id=ident, head_sha='a'*40, event='workflow_dispatch',
                    path='.github/workflows/release-validation.yml', run_attempt=attempt,
                    conclusion=conclusion, status=status)

    def test_latest_failed_ci_cannot_borrow_older_success(self):
        with patch.object(remote, 'api', return_value={'workflow_runs':
                [self.run_record(), self.run_record(13, 'failure')]}):
            with self.assertRaisesRegex(ValueError, '13.*failure'):
                remote.ci(self.state)

    def test_same_run_rerun_invalidates_previous_success(self):
        with patch.object(remote, 'api', side_effect=[{'workflow_runs': [self.run_record()]},
                self.run_record(status='in_progress', conclusion=None, attempt=2)]):
            with self.assertRaisesRegex(ValueError, 'attempt changed'):
                remote.ci(self.state)

    def test_wrong_source_or_workflow_is_refused(self):
        for field, value in [('head_sha', 'c'*40), ('event', 'push'), ('path', '.github/workflows/rust-tests.yml')]:
            candidate = self.run_record()
            candidate[field] = value
            with self.subTest(field=field), patch.object(remote, 'api', return_value={'workflow_runs': [candidate]}):
                with self.assertRaisesRegex(ValueError, 'unexpected CI'):
                    remote.ci(self.state)

    def test_tag_target_mismatch_never_mutates(self):
        with patch.object(remote, 'api', return_value=[dict(ref='refs/tags/v0.0.2',
                object=dict(type='commit', sha='c'*40))]) as api:
            with self.assertRaisesRegex(ValueError, 'ref already exists'):
                remote.ensure_ref('tags', 'v0.0.2', 'a'*40)
            self.assertEqual(api.call_count, 1)

    def test_signature_uses_exact_identity_and_issuer(self):
        with patch.object(remote, 'run', side_effect=subprocess.CalledProcessError(1, 'cosign')) as command:
            with self.assertRaises(subprocess.CalledProcessError):
                remote.signature(Path('/ExampleCandidate'))
            argv = command.call_args.args[0]
            self.assertEqual(argv[argv.index('--certificate-identity')+1], remote.IDENTITY)
            self.assertEqual(argv[argv.index('--certificate-oidc-issuer')+1], remote.ISSUER)

    def test_changed_signature_checkpoint_blocks_draft_assets(self):
        with tempfile.TemporaryDirectory(prefix='ExampleSignature-') as temporary:
            self.state.artifacts = Path(temporary)
            bundle = self.state.artifacts/'SHA256SUMS.sigstore.json'
            bundle.write_text('Example original signature')
            self.state.data['signature_sha256'] = digest(bundle)
            bundle.write_text('Example replacement signature')
            with patch.object(remote, 'signature'):
                with self.assertRaisesRegex(ValueError, 'signature checkpoint'):
                    remote.local_assets(self.state)

    def test_public_download_rejects_dot_and_traversal_asset_names(self):
        for name in ('..', '.', '../ExampleFile', '/ExampleFile', 'Example/Child'):
            item = dict(draft=False, prerelease=True, tag_name='v0.0.2', assets=[dict(name=name)])
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix='ExampleDownload-') as output, \
                 patch('urllib.request.urlopen', return_value=io.BytesIO(json.dumps(item).encode())) as request:
                with self.assertRaisesRegex(ValueError, 'asset inventory'):
                    remote.verify_public('v0.0.2', Path(output))
                self.assertEqual(request.call_count, 1)
                self.assertEqual(list(Path(output).iterdir()), [])

    def test_api_strings_never_use_file_expansion(self):
        with patch.object(remote, 'run', return_value=b'{}') as command:
            remote.api('releases', 'POST', body='@ExampleNotes', draft=True)
            argv = command.call_args.args[0]
            self.assertIn('-f', argv)
            self.assertEqual(argv[argv.index('body=@ExampleNotes')-1], '-f')
            self.assertEqual(argv[argv.index('draft=true')-1], '-F')

    def test_partial_draft_upload_only_adds_missing_assets(self):
        with tempfile.TemporaryDirectory(prefix='ExampleDraft-') as temporary:
            root = Path(temporary)
            body = f"Unreviewed pre-alpha\n{'a'*40}\n{'b'*64}"
            (root/'notes').write_text(body)
            self.state.data['notes'] = body
            self.state.artifacts = root
            item = dict(id=31, draft=True, prerelease=True, body=body, html_url='https://example.invalid/draft')
            with patch.object(remote, 'local_assets', return_value={'ExampleA': '1', 'ExampleB': '2'}), \
                 patch.object(remote, 'ci'), patch.object(remote, 'release', return_value=item), \
                 patch.object(remote, 'ensure_ref'), patch.object(remote, 'pages', return_value=[dict(name='ExampleA')]), \
                 patch.object(remote, 'upload_asset') as upload, patch.object(remote, 'verify_remote_assets') as verify:
                remote.draft(self.state, root/'notes')
                upload.assert_called_once_with(31, root/'ExampleB')
                self.assertEqual(verify.call_count, 2)
                verify.assert_called_with(item, {'ExampleA': '1', 'ExampleB': '2'})

    def test_upload_streams_exact_bytes_without_exposing_host_path_to_gh(self):
        with tempfile.TemporaryDirectory(prefix='ExampleUpload-') as temporary:
            path = Path(temporary)/'Example artifact.json'
            content = b'Example upload bytes\x00\n'
            path.write_bytes(content)
            def consume(argv, *, stdin, stdout, check):
                self.assertEqual(stdin.read(), content)
                self.assertTrue(check)
                self.assertNotIn(str(path), argv)
                self.assertIn('https://uploads.github.com/repos/'+remote.REPO+'/releases/31/assets?name=Example%20artifact.json', argv)
                self.assertEqual(argv[-2:], ['--input', '-'])
            with patch('subprocess.run', side_effect=consume) as command:
                remote.upload_asset(31, path)
                command.assert_called_once()

    def test_publication_requires_exact_approval_before_network(self):
        with patch.object(remote, 'local_assets') as verify:
            with self.assertRaisesRegex(ValueError, 'approval must name'):
                remote.publish(self.state, 'c'*64)
            verify.assert_not_called()

    def test_draft_drift_stops_publication(self):
        item = dict(id=31, draft=True, prerelease=True, body='Changed notes')
        with patch.object(remote, 'local_assets', return_value={}), patch.object(remote, 'ci'), \
             patch.object(remote, 'release', return_value=item), patch.object(remote, 'api') as api:
            with self.assertRaisesRegex(ValueError, 'notes or maturity changed'):
                remote.publish(self.state, 'b'*64)
            api.assert_not_called()

    def test_publication_retry_reconciles_already_public_release(self):
        item = dict(id=31, draft=False, prerelease=True, body='Example notes')
        with patch.object(remote, 'local_assets', return_value={}), patch.object(remote, 'ci'), \
             patch.object(remote, 'release', return_value=item), \
             patch.object(remote, 'api', return_value={'object': {'type': 'commit', 'sha': 'a'*40}}) as api, \
             patch.object(remote, 'verify_remote_assets'), patch.object(remote, 'verify_public') as download:
            self.state.root = Path('/ExampleRelease')
            remote.publish(self.state, 'b'*64)
            self.assertEqual(api.call_count, 1)  # Read the tag; never publish again.
            download.assert_called_once()
            self.assertTrue(self.state.data['published'])


if __name__ == '__main__':
    unittest.main()
