#!/usr/bin/env sh
set -eu

tag="${1:-}"
case "$tag" in
    v[0-9]*.[0-9]*.[0-9]* | v[0-9]*.[0-9]*.[0-9]*-*) ;;
    *)
        echo "usage: scripts/validate-release-readiness.sh vX.Y.Z" >&2
        exit 2
        ;;
esac

version="${tag#v}"
release_notes="release-notes/RELEASE_NOTES_${version}.md"
pentest_report="security/pentest/${tag}.md"

scripts/check-latest-rust.py

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    echo "tag already exists locally: ${tag}" >&2
    exit 1
fi

if [ -f PENTEST.md ]; then
    echo "root PENTEST.md is temporary scratch input and must be removed" >&2
    exit 1
fi

if [ ! -f "$release_notes" ]; then
    echo "missing release notes: ${release_notes}" >&2
    exit 1
fi

if [ ! -f "$pentest_report" ]; then
    echo "missing pentest report: ${pentest_report}" >&2
    exit 1
fi

if ! git cat-file -e "HEAD:${pentest_report}" 2>/dev/null; then
    echo "pentest report must be committed in tag candidate: ${pentest_report}" >&2
    exit 1
fi

grep -q '^Status: PASS$' "$pentest_report"
grep -Eq '^Reviewed-Commit: [0-9a-f]{40}$' "$pentest_report"
grep -Eq '^Tester: .+' "$pentest_report"
grep -Eq '^Scope: .+' "$pentest_report"
grep -Eq '^Date: [0-9]{4}-[0-9]{2}-[0-9]{2}$' "$pentest_report"

reviewed_commit="$(sed -n 's/^Reviewed-Commit: //p' "$pentest_report")"
if ! git cat-file -e "${reviewed_commit}^{commit}" 2>/dev/null; then
    echo "reviewed commit ${reviewed_commit} was not found" >&2
    exit 1
fi

head_parent="$(git rev-parse HEAD^)"
if [ "$reviewed_commit" != "$head_parent" ]; then
    echo "reviewed commit ${reviewed_commit} does not match first parent ${head_parent}" >&2
    exit 1
fi

changed_paths="$(git diff --name-only "$reviewed_commit" HEAD)"
if [ "$changed_paths" != "$pentest_report" ]; then
    echo "release report commit may only change ${pentest_report}" >&2
    echo "$changed_paths" >&2
    exit 1
fi
