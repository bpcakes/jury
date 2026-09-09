"""Install the pinned SBOM tool inside the release builder container."""
import hashlib
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


def extract_source(data, expected_sha256, root):
    """Verify all archive members before writing any source files."""
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError('SBOM tool source does not match its pinned checksum')
    root = root.resolve()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive.getmembers():
            name = Path(member.name)
            target = (root/name).resolve()
            if (name.is_absolute() or '..' in name.parts or not target.is_relative_to(root)
                    or not (member.isdir() or member.isfile())):
                raise ValueError('SBOM tool source archive contains an unsafe member')
        # The pinned builder predates extraction filters; the checks above apply
        # on every interpreter. Use the additional stdlib filter when available.
        if hasattr(tarfile, 'data_filter'):
            archive.extractall(root, filter='data')
        else:
            archive.extractall(root)


def main():
    url, expected_sha256, version = sys.argv[1:]
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(10 * 1024 * 1024)
    with tempfile.TemporaryDirectory(prefix='jury-sbom-') as directory:
        root = Path(directory)
        extract_source(data, expected_sha256, root)
        source = root/('cargo-cyclonedx-'+version)
        shutil.copyfile('/tool-lock', source/'Cargo.lock')
        subprocess.run(['cargo', 'install', '--path', source, '--locked',
                        '--root', '/build/tools'], check=True)


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        sys.exit(str(error))
    except tarfile.TarError:
        sys.exit('SBOM tool source archive is invalid')
