#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

run_expected_failure() {
    name="$1"
    features="$2"
    needle="$3"
    source="$4"
    case_dir="${tmpdir}/${name}"
    mkdir -p "${case_dir}/src"

    cat >"${case_dir}/Cargo.toml" <<EOF
[package]
name = "${name}"
version = "0.0.0"
edition = "2021"

[dependencies]
sanitization = { path = "${root}/crates/sanitization", features = [${features}] }
EOF

    printf '%s\n' "${source}" >"${case_dir}/src/lib.rs"

    log="${case_dir}/cargo-check.log"
    if cargo check --manifest-path "${case_dir}/Cargo.toml" >"${log}" 2>&1; then
        printf 'expected %s to fail, but it compiled\n' "${name}" >&2
        exit 1
    fi

    if ! grep -Fq "${needle}" "${log}"; then
        printf 'expected %s failure to mention:\n%s\n\nactual output:\n' "${name}" "${needle}" >&2
        cat "${log}" >&2
        exit 1
    fi
}

run_expected_success() {
    name="$1"
    dependency="$2"
    source="$3"
    case_dir="${tmpdir}/${name}"
    mkdir -p "${case_dir}/src"

    cat >"${case_dir}/Cargo.toml" <<EOF
[package]
name = "${name}"
version = "0.0.0"
edition = "2021"

[dependencies]
${dependency}
EOF

    printf '%s\n' "${source}" >"${case_dir}/src/lib.rs"

    log="${case_dir}/cargo-check.log"
    if ! cargo check --manifest-path "${case_dir}/Cargo.toml" >"${log}" 2>&1; then
        printf 'expected %s to compile, but it failed:\n' "${name}" >&2
        cat "${log}" >&2
        exit 1
    fi
}

run_expected_success \
    "renamed-crate-path-accepted" \
    "san = { package = \"sanitization\", path = \"${root}/crates/sanitization\", features = [\"derive\"] }" \
    'use san::{SecretBytes, SecureSanitize};

#[derive(SecureSanitize)]
#[sanitization(crate = "::san")]
pub struct Renamed {
    secret: SecretBytes<4>,
    #[sanitization(skip, reason = "public metadata")]
    public: u8,
}'

run_expected_failure \
    "ct-eq-enum-rejected" \
    '"derive"' \
    "ConstantTimeEq cannot be derived for enums" \
    'use sanitization::ConstantTimeEq;

#[derive(ConstantTimeEq)]
enum Bad {
    A([u8; 4]),
    B,
}'

run_expected_failure \
    "ct-select-skip-rejected" \
    '"derive"' \
    "#[sanitization(skip)] is not supported for ConditionallySelectable derives" \
    'use sanitization::ConditionallySelectable;

#[derive(ConditionallySelectable)]
struct Bad {
    secret: [u8; 4],
    #[sanitization(skip, reason = "public metadata")]
    public: u8,
}'

run_expected_failure \
    "enum-sanitize-rejected" \
    '"derive"' \
    "SecureSanitize cannot be derived for enums because inactive variant bytes are unreachable" \
    'use sanitization::SecureSanitize;

#[derive(SecureSanitize)]
enum Bad {
    A([u8; 4]),
    B,
}'

run_expected_failure \
    "enum-sanitize-on-drop-rejected" \
    '"derive"' \
    "SecureSanitizeOnDrop cannot be derived for enums because final-drop sanitization cannot clear inactive bytes retained by earlier variant transitions" \
    'use sanitization::{SecureSanitize, SecureSanitizeOnDrop};

#[derive(SecureSanitizeOnDrop)]
enum Bad {
    A([u8; 4]),
    B,
}

impl SecureSanitize for Bad {
    fn secure_sanitize(&mut self) {
        if let Self::A(bytes) = self {
            bytes.secure_sanitize();
        }
    }
}'

run_expected_failure \
    "sanitize-skip-reason-required" \
    '"derive"' \
    "#[sanitization(skip)] requires a non-empty reason" \
    'use sanitization::SecureSanitize;

struct Public;

#[derive(SecureSanitize)]
struct Bad {
    secret: [u8; 4],
    #[sanitization(skip)]
    public: Public,
}'

run_expected_failure \
    "ct-eq-skip-reason-required" \
    '"derive"' \
    "#[sanitization(skip)] requires a non-empty reason" \
    'use sanitization::ConstantTimeEq;

#[derive(ConstantTimeEq)]
struct Bad {
    secret: [u8; 4],
    #[sanitization(skip)]
    public: u8,
}'

run_expected_failure \
    "empty-skip-reason-rejected" \
    '"derive"' \
    "sanitization skip reason must not be empty" \
    'use sanitization::SecureSanitize;

#[derive(SecureSanitize)]
struct Bad {
    #[sanitization(skip, reason = "   ")]
    public: u8,
}'

run_expected_failure \
    "reason-without-skip-rejected" \
    '"derive"' \
    "sanitization reason is only valid together with skip" \
    'use sanitization::SecureSanitize;

#[derive(SecureSanitize)]
struct Bad {
    #[sanitization(reason = "not actually skipped")]
    value: u8,
}'

run_expected_failure \
    "duplicate-skip-rejected" \
    '"derive"' \
    "duplicate sanitization skip option" \
    'use sanitization::SecureSanitize;

#[derive(SecureSanitize)]
struct Bad {
    #[sanitization(skip, skip, reason = "public")]
    public: u8,
}'

run_expected_failure \
    "duplicate-reason-rejected" \
    '"derive"' \
    "duplicate sanitization reason option" \
    'use sanitization::SecureSanitize;

#[derive(SecureSanitize)]
struct Bad {
    #[sanitization(skip, reason = "public", reason = "also public")]
    public: u8,
}'

run_expected_failure \
    "duplicate-field-bound-rejected" \
    '"derive"' \
    "duplicate sanitization bound option" \
    'use sanitization::SecureSanitize;

#[derive(SecureSanitize)]
struct Bad<T> {
    #[sanitization(bound = "T: SecureSanitize", bound = "T: SecureSanitize")]
    value: T,
}'

run_expected_failure \
    "duplicate-container-bound-rejected" \
    '"derive"' \
    "duplicate sanitization bound option" \
    'use sanitization::SecureSanitize;

#[derive(SecureSanitize)]
#[sanitization(bound = "T: SecureSanitize", bound = "T: SecureSanitize")]
struct Bad<T> {
    value: T,
}'

run_expected_failure \
    "duplicate-crate-path-rejected" \
    '"derive"' \
    "duplicate sanitization crate option" \
    'use sanitization::SecureSanitize;

#[derive(SecureSanitize)]
#[sanitization(crate = "::sanitization", crate = "::sanitization")]
struct Bad {
    value: u8,
}'

run_expected_failure \
    "union-sanitize-rejected" \
    '"derive"' \
    "SecureSanitize cannot be derived for unions" \
    'use sanitization::SecureSanitize;

#[derive(SecureSanitize)]
union Bad {
    bytes: [u8; 4],
    word: u32,
}'

run_expected_failure \
    "generic-drop-bound-required" \
    '"derive"' \
    "consider restricting type parameter" \
    'use sanitization::{SecureSanitize, SecureSanitizeOnDrop};

#[derive(SecureSanitize, SecureSanitizeOnDrop)]
struct Bad<T> {
    value: T,
}'

run_expected_failure \
    "pinned-sanitize-on-drop-rejected" \
    '"derive"' \
    "Unpin" \
    'use core::marker::PhantomPinned;
use sanitization::{SecureSanitize, SecureSanitizeOnDrop};

#[derive(SecureSanitize, SecureSanitizeOnDrop)]
struct Bad {
    secret: [u8; 4],
    #[sanitization(skip, reason = "pinning marker owns no secret storage")]
    pinned: PhantomPinned,
}'

run_expected_failure \
    "manual-sanitize-on-drop-contract-required" \
    '"derive"' \
    "DropSafeSanitize" \
    'use sanitization::{SecureSanitize, SecureSanitizeOnDrop};

#[derive(SecureSanitizeOnDrop)]
struct Bad {
    value: u8,
}

impl SecureSanitize for Bad {
    fn secure_sanitize(&mut self) {
        let old = core::mem::replace(self, Self { value: 0 });
        drop(old);
    }
}'

run_expected_failure \
    "pinned-secure-drop-struct-rejected" \
    '' \
    "Unpin" \
    'use core::marker::PhantomPinned;
use sanitization::{secure_drop_struct, SecureSanitize};

struct PinnedField(PhantomPinned);

impl SecureSanitize for PinnedField {
    fn secure_sanitize(&mut self) {}
}

secure_drop_struct! {
    struct Bad {
        pinned: PinnedField,
    }
}'

run_expected_failure \
    "malformed-skip-rejected" \
    '"derive"' \
    'expected `,`' \
    'use sanitization::SecureSanitize;

#[derive(SecureSanitize)]
struct Bad {
    #[sanitization(skip = true)]
    value: u8,
}'

run_expected_failure \
    "unsupported-field-option-rejected" \
    '"derive"' \
    "unsupported sanitization field attribute" \
    'use sanitization::SecureSanitize;

#[derive(SecureSanitize)]
struct Bad {
    #[sanitization(public)]
    value: u8,
}'

printf 'derive failure checks passed\n'
