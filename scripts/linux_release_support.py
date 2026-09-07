"""Filesystem and Cargo input checks for the Linux release recipe."""
import hashlib
import json
import re
from pathlib import Path
import shutil
import tarfile
import tomllib
from urllib.parse import parse_qs, urlsplit, urlunsplit


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def file_record(path):
    import os
    return {'sha256': digest(path), 'executable': bool(path.stat().st_mode & 0o111),
            'symlink': os.readlink(path) if path.is_symlink() else None}


def snapshot_files(root):
    result = {}
    for path in sorted(root.rglob('*')):
        require(path.resolve().is_relative_to(root.resolve()), 'snapshot entry escapes its root')
        if path.is_file():
            result[str(path.relative_to(root))] = file_record(path)
        elif path.is_symlink() or not path.is_dir():
            raise ValueError('unsupported snapshot entry')
    return result


def package_documentation(source, bundle):
    """Keep the shipped guides and their local setup/reference files together."""
    (bundle/'docs').mkdir()
    for name in ('self-hosting-juryd.md', 'witness-operator-walkthrough.md', 'recovery.md',
                 'owner-changes.md', 'item-creation.md', 'linux-release.md', 'architecture.md',
                 'jury-v1-master-plan.md', 'jig-cutover-plan.md'):
        shutil.copy2(source/'docs'/name, bundle/'docs'/name)
    shutil.copytree(source/'docs/security', bundle/'docs/security')
    shutil.copytree(source/'deploy/juryd', bundle/'deploy/juryd')
    shutil.copytree(source/'conformance/direct-crypto', bundle/'conformance/direct-crypto',
                    ignore=shutil.ignore_patterns('target', '__pycache__'))
    verify_documentation_links(bundle)


def verify_documentation_links(bundle):
    # Owned guides only: preserve upstream notices verbatim. Source references
    # are included for reading; builds still require the full source archive.
    for document in (bundle/'docs').rglob('*.md'):
        for target in re.findall(r'\[[^\]]+\]\(([^)]+)\)', document.read_text()):
            if urlsplit(target).scheme or target.startswith('#'):
                continue
            path = (document.parent/target.split('#', 1)[0]).resolve()
            require(path.is_relative_to(bundle.resolve()) and path.exists(),
                    f'shipped guide has a missing local target: {document.relative_to(bundle)} -> {target}')


def vendor_config(lockfile):
    config = '[source.crates-io]\nreplace-with = "vendored-sources"\n'
    sources = {p.get('source') for p in tomllib.loads(lockfile.read_text())['package']}
    for source in sorted(s for s in sources if s):
        if source.startswith('git+'):
            parsed = urlsplit(source[4:])
            query = parse_qs(parsed.query)
            require(set(query) == {'rev'} and query['rev'] == [parsed.fragment] and re.fullmatch(r'[0-9a-f]{40}', parsed.fragment),
                    'git provider must use an exact revision')
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', ''))
            key = source.split('#')[0]
            config += f'[source.{json.dumps(key)}]\ngit = {json.dumps(url)}\nrev = {json.dumps(parsed.fragment)}\nreplace-with = "vendored-sources"\n'
        else:
            require(source == 'registry+https://github.com/rust-lang/crates.io-index', 'unsupported registry source')
    return config + '[source.vendored-sources]\ndirectory = "/vendor"\n'


def extract_vendor(archive, expected, destination):
    expected = normalized_sha256(expected)
    require(digest(archive) == expected, 'vendor archive digest mismatch')
    with tarfile.open(archive) as source:
        for entry in source.getmembers():
            path = Path(entry.name)
            require(entry.isfile() and path.parts and path.parts[0] == 'vendor' and '..' not in path.parts,
                    'vendor archive must contain only regular files under vendor/')
        source.extractall(destination, filter='data')
    require((destination/'vendor').is_dir(), 'vendor archive is empty')


def normalized_sha256(value):
    require(bool(re.fullmatch(r'[0-9a-fA-F]{64}', value)), 'malformed expected SHA-256 digest')
    return value.lower()


def notice_file(path):
    # Exact notice names, including licenses embedded by native providers.
    name = path.name.lower()
    return bool(re.fullmatch(
        r'(?:license|licence|unlicense|copying|copyright|notices?)'
        r'(?:[-.](?:apache(?:-2\.0(?:_with_llvm-exception)?)?|mit|boost|bsd(?:-1)?|'
        r'boringssl|isc|third-party|unicode|zlib|other-bits|httprouter))?'
        r'(?:\.(?:md|txt|rst|html))?|(?:mit|apache)-license(?:\.(?:txt|md))?', name))


def normalize_sbom(value, key=None):
    # References are opaque identifiers; rewrite matching declarations and edges.
    # Keep upstream URLs and license text byte-for-byte as emitted.
    if isinstance(value, dict):
        return {k: normalize_sbom(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize_sbom(v, key) for v in value]
    if isinstance(value, str) and key in ('bom-ref', 'ref', 'dependsOn', 'provides'):
        for prefix in ('path+file:///src/', 'file:///src/', '/src/'):
            if value.startswith(prefix):
                return prefix.replace('/src/', '/jury-source/')+value[len(prefix):]
        return value
    return value


def collect_notices(vendor, supplements, destination):
    records = json.loads((supplements/'sources.json').read_bytes())
    for record in records:
        path = supplements/record['file']
        require(path.resolve().is_relative_to(supplements.resolve()) and digest(path) == record['sha256'],
                'supplemental license binding changed')
    inventory = []
    for package in sorted(vendor.iterdir()):
        if not package.is_dir():
            continue
        metadata = tomllib.loads((package/'Cargo.toml').read_text())['package']
        files = [p for p in package.rglob('*') if p.is_file() and notice_file(p)]
        declared = metadata.get('license-file')
        if declared:
            path = package/declared
            require(path.resolve().is_relative_to(package.resolve()) and path.is_file(), 'declared license file is absent')
            files.append(path)
        supplemental = [r for r in records if (r['package'], r['version']) == (metadata['name'], metadata['version'])]
        require(any(p.parent == package for p in files) or declared or supplemental, f"no license notices for {metadata['name']} {metadata['version']}")
        for path in set(files):
            target = destination/package.name/path.relative_to(package)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        for record in supplemental:
            target = destination/package.name/Path(record['file']).name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(supplements/record['file'], target)
        shutil.copy2(package/'Cargo.toml', destination/package.name/'Cargo.toml')
        inventory.append({'name': metadata['name'], 'version': metadata['version'],
                          'license': metadata.get('license'),
                          'files': sorted({str(p.relative_to(package)) for p in files} | {Path(r['file']).name for r in supplemental})})
    shutil.copy2(supplements/'sources.json', destination/'supplement-sources.json')
    return inventory


def collect_provider_notices(source, destination):
    """The maintained path dependency is in the source archive, not cargo vendor."""
    provider = source/'third_party/sanitization'
    workspace = tomllib.loads((provider/'Cargo.toml').read_text())['workspace']['package']
    package = tomllib.loads((provider/'crates/sanitization/Cargo.toml').read_text())['package']
    require(package['name'] == 'sanitization' and package['version'] == {'workspace': True}
            and package['license'] == {'workspace': True}, 'provider metadata layout changed')
    target = destination/f"sanitization-{workspace['version']}"
    target.mkdir(parents=True, exist_ok=False)
    names = ['LICENSE-MIT', 'LICENSE-APACHE']
    for name in names:
        path = provider/name
        require(path.is_file() and not path.is_symlink(), 'local provider license is absent')
        shutil.copy2(path, target/name)
    shutil.copy2(provider/'Cargo.toml', target/'workspace-Cargo.toml')
    shutil.copy2(provider/'crates/sanitization/Cargo.toml', target/'Cargo.toml')
    return {'name': package['name'], 'version': workspace['version'],
            'license': workspace['license'], 'files': names,
            'source': 'third_party/sanitization'}


def verify_packaged_binaries(archive, version, target, expected):
    with tarfile.open(archive) as package:
        for name, value in expected.items():
            require(name in ('jury', 'juryd'), 'unexpected binary name')
            member = package.getmember(f'jury-{version}-{target}/{name}')
            require(member.isfile() and member.mode & 0o111, 'packaged binary is not executable')
            with package.extractfile(member) as source:
                require(hashlib.file_digest(source, 'sha256').hexdigest() == value, 'packaged binary digest mismatch')
