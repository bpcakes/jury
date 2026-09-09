"""Private, source-bound crash recovery for the release command."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from linux_release_support import digest, require


def run(argv, *, cwd=None, env=None, capture=False):
    return subprocess.run([str(arg) for arg in argv], cwd=cwd, env=env, check=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def git(root, *args):
    return run(['git', *args], cwd=root, capture=True).decode().strip()


def automation_digest():
    root = Path(__file__).parent
    value = {name: digest(root/name) for name in
             ('release-linux', 'release_state.py', 'release_remote.py', 'linux_release_support.py')}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class State:
    def __init__(self, directory):
        directory = Path(directory).absolute()
        require(not directory.is_symlink(), 'state directory must not be a symlink')
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(directory.stat().st_uid == os.getuid() and directory.stat().st_mode & 0o077 == 0,
                'state directory must be owned by this user with mode 0700')
        self.root = directory.resolve()
        self.lock = os.open(self.root/'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.path = self.root/'state.json'
            require(not self.path.is_symlink(), 'checkpoint must not be a symlink')
            self.data = json.loads(self.path.read_text()) if self.path.exists() else {}
            if self.data:
                require(self.data.get('schema') == 1 and self.data['automation'] == automation_digest(),
                        'release command changed: create a fresh state directory and revalidate')
        except BaseException:
            os.close(self.lock)
            raise

    def close(self):
        os.close(self.lock)

    def save(self):
        with tempfile.NamedTemporaryFile(mode='w', dir=self.root, delete=False) as out:
            json.dump(self.data, out, sort_keys=True, indent=2)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(out.name, self.path)
        fd = os.open(self.root, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @property
    def source(self):
        return self.root/'source'

    @property
    def artifacts(self):
        return self.root/'artifacts'

    def initialize(self, repository, revision):
        sha = git(repository, 'rev-parse', '--verify', revision+'^{commit}')
        if self.data:
            require(self.data['source_sha'] == sha, 'state belongs to another source revision')
        else:
            self.data = dict(schema=1, source_sha=sha, automation=automation_digest(), stages={})
            self.save()
        if not self.source.exists():
            run(['git', 'worktree', 'add', '--detach', self.source, sha], cwd=repository)
        self.check_source()

    def check_source(self):
        require(self.data and not self.source.is_symlink(), 'initialize with prepare first')
        require(git(self.source, 'rev-parse', 'HEAD') == self.data['source_sha'], 'source HEAD changed')
        require(not git(self.source, 'status', '--porcelain', '--untracked-files=all'),
                'frozen source changed; restore it or use a fresh state directory')

    def stage(self, name, action):
        self.check_source()
        if self.data['stages'].get(name) == 'passed':
            print(f'Reusing {name}', flush=True)
            return
        self.data['stages'][name] = 'running'
        self.save()
        try:
            action()
            self.check_source()
        except BaseException:
            self.data['stages'][name] = 'incomplete'
            self.save()
            raise
        self.data['stages'][name] = 'passed'
        self.save()

    def command(self, name, argv, env=None):
        """Keep both output streams in a private log and stream them to the caller."""
        print(f'Running {name}', flush=True)
        with (self.root/(name+'.log')).open('ab') as log:
            with subprocess.Popen([str(x) for x in argv], cwd=self.source, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as child:
                for line in iter(child.stdout.readline, b''):
                    log.write(line)
                    log.flush()
                    os.write(1, line)
                result = child.wait()
        if result:
            raise RuntimeError(f'{name} failed ({result}); see {name}.log')

    def verify_artifacts(self):
        self.check_source()
        expected = self.data.get('manifest_sha256')
        require(expected, 'prepare has not produced verified artifacts')
        run(['python3', 'scripts/build-linux-release', 'verify', self.artifacts,
             '--checksums-sha256', expected], cwd=self.source)
        provenance = json.loads((self.artifacts/'provenance.json').read_text())
        require(provenance['source_commit'] == self.data['source_sha'] and
                provenance['dirty_candidate'] is False, 'candidate is not bound to clean release source')
        return provenance

    def prepared(self):
        provenance = self.verify_artifacts()
        require(self.data['stages'].get('qa-complete') == 'passed', 'complete packaged QA first')
        return provenance
