"""Exact-source GitHub validation and immutable release publication."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import quote

from linux_release_support import digest, require
from release_state import run

REPO = 'bpcakes/jury'
WORKFLOW = 'release-validation.yml'
IDENTITY = '96315340+featherenvy@users.noreply.github.com'
ISSUER = 'https://github.com/login/oauth'


def api(path, method='GET', **fields):
    argv = ['gh', 'api', f'repos/{REPO}/{path}', '--method', method]
    for key, value in fields.items():
        if isinstance(value, bool):
            argv += ['-F', f'{key}={str(value).lower()}']
        else:
            argv += ['-f', f'{key}={value}']
    result = run(argv, capture=True)
    return json.loads(result) if result else None


def pages(path):
    result = run(['gh', 'api', f'repos/{REPO}/{path}', '--paginate', '--slurp'], capture=True)
    return [item for page in json.loads(result) for item in page]


def signature(directory):
    run(['cosign', 'verify-blob', directory/'SHA256SUMS', '--bundle',
         directory/'SHA256SUMS.sigstore.json', '--certificate-identity', IDENTITY,
         '--certificate-oidc-issuer', ISSUER])


def latest_run(sha):
    result = api(f'actions/workflows/{WORKFLOW}/runs?event=workflow_dispatch&head_sha={sha}&per_page=100')
    runs = result['workflow_runs']
    for candidate in runs:
        require(candidate['head_sha'] == sha and candidate['event'] == 'workflow_dispatch'
                and candidate['path'] == '.github/workflows/'+WORKFLOW, 'unexpected CI source or workflow')
    return max(runs, key=lambda item: (item['id'], item['run_attempt']), default=None)


def ensure_ref(kind, name, sha):
    refs = api(f'git/matching-refs/{kind}/{name}')
    existing = [ref for ref in refs if ref['ref'] == f'refs/{kind}/{name}']
    if existing:
        require(existing[0]['object']['type'] == 'commit' and existing[0]['object']['sha'] == sha,
                'remote ref already exists with another target or is annotated; refusing replacement')
    else:
        api('git/refs', 'POST', ref=f'refs/{kind}/{name}', sha=sha)


def ci(state, *, dispatch=False, wait=False):
    state.check_source()
    sha = state.data['source_sha']
    candidate = latest_run(sha)
    if dispatch:
        if candidate is None or candidate['status'] == 'completed' and candidate['conclusion'] != 'success':
            branch = 'release-validation/'+sha
            ensure_ref('heads', branch, sha)
            api(f'actions/workflows/{WORKFLOW}/dispatches', 'POST', ref=branch)
            prior = candidate['id'] if candidate else 0
            for _ in range(30):
                candidate = latest_run(sha)
                if candidate and candidate['id'] > prior:
                    break
                time.sleep(2)
            require(candidate and candidate['id'] > prior, 'dispatch not visible yet; retry ci')
    require(candidate, 'no release-validation run exists; run ci --dispatch')
    if wait and candidate['status'] != 'completed':
        run(['gh', 'run', 'watch', str(candidate['id']), '--repo', REPO, '--exit-status', '--interval', '30'])
        candidate = latest_run(sha)
    state.data['ci_run_id'] = candidate['id']
    state.save()
    require(candidate['status'] == 'completed' and candidate['conclusion'] == 'success',
            f"latest release-validation run {candidate['id']} is {candidate['status']}/{candidate['conclusion']}")
    # Query this exact run again: a rerun invalidates a previously green attempt.
    current = api(f"actions/runs/{candidate['id']}")
    require(current['run_attempt'] == candidate['run_attempt'] and current['status'] == 'completed'
            and current['conclusion'] == 'success', 'CI attempt changed during verification')
    return candidate


def release(tag):
    matches = [item for item in pages('releases?per_page=100') if item['tag_name'] == tag]
    require(len(matches) <= 1, 'ambiguous release tag')
    return matches[0] if matches else None


def local_assets(state):
    state.prepared()
    signature(state.artifacts)
    require(state.data.get('signature_sha256') == digest(state.artifacts/'SHA256SUMS.sigstore.json'),
            'signature checkpoint is absent or changed; run sign to authenticate and bind it')
    return {path.name: digest(path) for path in state.artifacts.iterdir()}


def verify_remote_assets(item, expected):
    assets = pages(f"releases/{item['id']}/assets?per_page=100")
    require(len(assets) == len(expected) and {asset['name'] for asset in assets} == set(expected),
            'remote release asset inventory differs')
    # Verify the actual bytes, including the unsigned signature bundle itself.
    for asset in assets:
        with tempfile.TemporaryDirectory(prefix='jury-release-download-') as temporary:
            target = Path(temporary)/asset['name']
            with target.open('wb') as out:
                subprocess.run(['gh', 'api', f"repos/{REPO}/releases/assets/{asset['id']}",
                                '-H', 'Accept: application/octet-stream'], stdout=out, check=True)
            require(digest(target) == expected[asset['name']], 'remote asset bytes differ: '+asset['name'])


def upload_asset(release_id, path):
    # Pass bytes through stdin so packaged gh installations do not need access
    # to the host's private temporary directory namespace.
    with path.open('rb') as source:
        subprocess.run(['gh', 'api', f'https://uploads.github.com/repos/{REPO}/releases/{release_id}/assets?name={quote(path.name, safe="")}',
                        '--method', 'POST', '-H', 'Content-Type: application/octet-stream', '--input', '-'],
                       stdin=source, stdout=subprocess.PIPE, check=True)


def draft(state, notes):
    expected = local_assets(state)
    ci(state)
    provenance = state.verify_artifacts()
    tag = 'v'+provenance['version']
    body = Path(notes).read_text()
    require('pre-alpha' in body.lower() and 'unreviewed' in body.lower()
            and state.data['source_sha'] in body and state.data['manifest_sha256'] in body,
            'notes must include pre-alpha/unreviewed warning, exact source SHA and manifest SHA-256')
    if 'notes' in state.data:
        require(state.data['notes'] == body, 'release notes changed; use a fresh state directory')
    state.data['notes'] = body
    state.save()
    item = release(tag)
    if item:
        require(item['draft'] and item['prerelease'] and item['body'] == body,
                'existing release is public or has different notes/maturity; refusing replacement')
    ensure_ref('tags', tag, state.data['source_sha'])
    if item is None:
        item = api('releases', 'POST', tag_name=tag, target_commitish=state.data['source_sha'],
                   name=f'Jury {tag} — experimental pre-alpha', body=body, draft=True, prerelease=True)
    state.data['release_id'] = item['id']
    state.save()
    existing = pages(f"releases/{item['id']}/assets?per_page=100")
    require(len({asset['name'] for asset in existing}) == len(existing)
            and {asset['name'] for asset in existing} <= set(expected), 'unexpected remote assets')
    verify_remote_assets(item, {asset['name']: expected[asset['name']] for asset in existing})
    for name in expected:
        if name not in {asset['name'] for asset in existing}:
            upload_asset(item['id'], state.artifacts/name)
    verify_remote_assets(item, expected)
    print(f"Verified draft {item['html_url']}")


def publish(state, approval):
    require(approval == state.data.get('manifest_sha256'), 'approval must name this manifest SHA-256')
    expected = local_assets(state)
    ci(state)
    tag = 'v'+state.verify_artifacts()['version']
    item = release(tag)
    require(item and item['id'] == state.data.get('release_id') and item['prerelease']
            and item['body'] == state.data.get('notes'), 'draft identity, notes or maturity changed')
    # This must already exist; publication never creates or moves a tag.
    ref = api('git/ref/tags/'+tag)
    require(ref['object']['type'] == 'commit' and ref['object']['sha'] == state.data['source_sha'],
            'release tag changed')
    verify_remote_assets(item, expected)
    if item['draft']:
        api(f"releases/{item['id']}", 'PATCH', draft=False, prerelease=True)
    verify_public(tag, state.root/'published', expected_manifest=approval,
                  expected_source=state.data['source_sha'])
    state.data['published'] = True
    state.save()


def verify_public(tag, destination, *, expected_manifest=None, expected_source=None):
    require(tag.startswith('v0.') and all(c.isalnum() or c in '.-' for c in tag), 'invalid release tag')
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    # No gh, auth token, or credential-bearing environment is used for public downloads.
    with urllib.request.urlopen(f'https://api.github.com/repos/{REPO}/releases/tags/{tag}') as response:
        item = json.load(response)
    require(not item['draft'] and item['prerelease'] and item['tag_name'] == tag,
            'expected a public experimental prerelease')
    assets = item['assets']
    names = [asset['name'] for asset in assets]
    require(len(names) == len(set(names)) and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,254}', name)
                                                for name in names),
            'invalid public asset inventory')
    # Stage complete downloads privately; an interrupted transfer never replaces a verified file.
    for asset in assets:
        name = asset['name']
        url = f'https://github.com/{REPO}/releases/download/{tag}/{name}'
        require(asset['browser_download_url'] == url, 'unexpected public download URL')
        with tempfile.NamedTemporaryFile(dir=destination, delete=False) as out:
            temporary = Path(out.name)
            try:
                with urllib.request.urlopen(url) as response:
                    import shutil
                    shutil.copyfileobj(response, out)
                out.flush()
                temporary.replace(destination/name)
            finally:
                temporary.unlink(missing_ok=True)
    signature(destination)
    manifest = digest(destination/'SHA256SUMS')
    require(expected_manifest is None or manifest == expected_manifest, 'published manifest mismatch')
    entries = {}
    for line in (destination/'SHA256SUMS').read_text().splitlines():
        value, name = line.split('  ', 1)
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,254}', name)
                and re.fullmatch(r'[0-9a-f]{64}', value) and name not in entries, 'invalid checksum entry')
        entries[name] = value
        require(digest(destination/name) == value, 'published checksum mismatch: '+name)
    require(set(names) == set(entries) | {'SHA256SUMS', 'SHA256SUMS.sigstore.json'},
            'published checksum inventory mismatch')
    provenance = json.loads((destination/'provenance.json').read_text())
    require(provenance['version'] == tag[1:] and provenance['dirty_candidate'] is False
            and (expected_source is None or provenance['source_commit'] == expected_source),
            'published source/version mismatch')
    with urllib.request.urlopen(f'https://api.github.com/repos/{REPO}/git/ref/tags/{tag}') as response:
        ref = json.load(response)
    require(ref['object']['type'] == 'commit' and ref['object']['sha'] == provenance['source_commit'],
            'published tag no longer names the signed source commit')
    print(f"Verified public {tag}: source {provenance['source_commit']}; SHA256SUMS {manifest}")
