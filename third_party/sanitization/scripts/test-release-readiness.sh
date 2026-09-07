#!/usr/bin/env sh
set -eu

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

source_script="$(pwd)/scripts/validate-release-readiness.sh"

make_fixture() {
    name="$1"
    repo="$tmp/$name"

    mkdir -p "$repo/scripts" "$repo/release-notes" "$repo/security/pentest"
    cp "$source_script" "$repo/scripts/validate-release-readiness.sh"
    chmod +x "$repo/scripts/validate-release-readiness.sh"
    cat >"$repo/scripts/check-latest-rust.py" <<'EOF'
#!/usr/bin/env sh
if [ "${FAIL_LATEST_RUST_CHECK:-0}" = "1" ]; then
    echo "latest Rust check failed: fixture requested failure" >&2
    exit 1
fi
EOF
    chmod +x "$repo/scripts/check-latest-rust.py"

    (
        cd "$repo"
        git init -q
        git config user.email "release-readiness@example.invalid"
        git config user.name "Release Readiness Test"
        printf 'fixture\n' >README.md
        git add README.md
        git commit -q -m "fixture"
    )

    printf '%s\n' "$repo"
}

assert_fails_with() {
    expected="$1"
    shift

    if "$@" >"$tmp/stdout" 2>"$tmp/stderr"; then
        echo "expected command to fail: $*" >&2
        exit 1
    fi

    if ! grep -q "$expected" "$tmp/stderr"; then
        echo "expected stderr to contain: $expected" >&2
        echo "actual stderr:" >&2
        cat "$tmp/stderr" >&2
        exit 1
    fi
}

write_release_notes() {
    version="$1"
    printf '# Release %s\n' "$version" >"release-notes/RELEASE_NOTES_${version}.md"
}

write_pentest() {
    tag="$1"
    reviewed_commit="$2"
    cat >"security/pentest/${tag}.md" <<EOF
Status: PASS
Reviewed-Commit: ${reviewed_commit}
Tester: Release Readiness Test
Scope: Fixture release metadata.
Date: 2026-07-09
EOF
}

repo="$(make_fixture bad-tag)"
(
    cd "$repo"
    assert_fails_with "usage: scripts/validate-release-readiness.sh vX.Y.Z" \
        scripts/validate-release-readiness.sh "1.2.3"
)

repo="$(make_fixture existing-tag)"
(
    cd "$repo"
    git tag v9.9.9
    assert_fails_with "tag already exists locally: v9.9.9" \
        scripts/validate-release-readiness.sh "v9.9.9"
)

repo="$(make_fixture stale-rust)"
(
    cd "$repo"
    FAIL_LATEST_RUST_CHECK=1 \
        assert_fails_with "latest Rust check failed: fixture requested failure" \
        scripts/validate-release-readiness.sh "v0.2.0"
)

repo="$(make_fixture scratch-pentest)"
(
    cd "$repo"
    printf 'scratch\n' >PENTEST.md
    assert_fails_with "root PENTEST.md is temporary scratch input" \
        scripts/validate-release-readiness.sh "v0.2.0"
)

repo="$(make_fixture missing-release-notes)"
(
    cd "$repo"
    assert_fails_with "missing release notes: release-notes/RELEASE_NOTES_0.2.0.md" \
        scripts/validate-release-readiness.sh "v0.2.0"
)

repo="$(make_fixture missing-report)"
(
    cd "$repo"
    write_release_notes "0.2.0"
    assert_fails_with "missing pentest report: security/pentest/v0.2.0.md" \
        scripts/validate-release-readiness.sh "v0.2.0"
)

repo="$(make_fixture uncommitted-report)"
(
    cd "$repo"
    reviewed_commit="$(git rev-parse HEAD)"
    write_release_notes "0.2.0"
    write_pentest "v0.2.0" "$reviewed_commit"
    assert_fails_with "pentest report must be committed in tag candidate" \
        scripts/validate-release-readiness.sh "v0.2.0"
)

repo="$(make_fixture wrong-reviewed-commit)"
(
    cd "$repo"
    base_branch="$(git symbolic-ref --short HEAD)"
    git checkout -q -b side
    printf 'side\n' >side.txt
    git add side.txt
    git commit -q -m "side"
    side_commit="$(git rev-parse HEAD)"
    git checkout -q "$base_branch"

    write_release_notes "0.2.0"
    write_pentest "v0.2.0" "$side_commit"
    git add "security/pentest/v0.2.0.md"
    git commit -q -m "report"

    assert_fails_with "does not match first parent" \
        scripts/validate-release-readiness.sh "v0.2.0"
)

repo="$(make_fixture mixed-report-commit)"
(
    cd "$repo"
    reviewed_commit="$(git rev-parse HEAD)"
    write_release_notes "0.2.0"
    write_pentest "v0.2.0" "$reviewed_commit"
    printf 'changed\n' >>README.md
    git add README.md "security/pentest/v0.2.0.md"
    git commit -q -m "report plus code"

    assert_fails_with "release report commit may only change security/pentest/v0.2.0.md" \
        scripts/validate-release-readiness.sh "v0.2.0"
)

repo="$(make_fixture ready)"
(
    cd "$repo"
    reviewed_commit="$(git rev-parse HEAD)"
    write_release_notes "0.2.0"
    write_pentest "v0.2.0" "$reviewed_commit"
    git add "security/pentest/v0.2.0.md"
    git commit -q -m "report"

    scripts/validate-release-readiness.sh "v0.2.0"
)

repo="$(make_fixture prerelease-ready)"
(
    cd "$repo"
    reviewed_commit="$(git rev-parse HEAD)"
    write_release_notes "1.2.0-alpha.1"
    write_pentest "v1.2.0-alpha.1" "$reviewed_commit"
    git add "security/pentest/v1.2.0-alpha.1.md"
    git commit -q -m "alpha report"

    scripts/validate-release-readiness.sh "v1.2.0-alpha.1"
)
