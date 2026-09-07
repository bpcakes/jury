#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
scripts/verify-action-pins.sh
scripts/verify-feature-profiles.py
scripts/verify-verification-harnesses.py
scripts/verify-miri-test-gates.py
scripts/test-declassification-reasons.py
scripts/lint-declassification-reasons.py
scripts/test-storage-policy-lint.py
scripts/lint-storage-policies.py \
    --root crates/sanitization/examples/high_assurance_policy.rs \
    --policy-file crates/sanitization/examples/high_assurance_policy.rs
scripts/test-fail-closed-initialization-lint.py
scripts/test-leakage-evidence-policy.py
scripts/lint-fail-closed-initialization.py \
    --root crates/sanitization/src \
    --exclude-file crates/sanitization/src/tests.rs
scripts/test-verification-fail-closed.py
scripts/test-latest-rust.py
if cargo audit --version >/dev/null 2>&1; then
    cargo audit --no-fetch --deny warnings
    for lockfile in \
        fuzz/Cargo.lock \
        tools/consume-once-loom/Cargo.lock \
        tools/core-dump-probe/Cargo.lock \
        tools/ct-leakage/Cargo.lock \
        tools/direct-exposure-codegen/Cargo.lock \
        tools/downstream-migration/Cargo.lock \
        tools/lifecycle-probes/Cargo.lock \
        tools/performance-baseline/Cargo.lock
    do
        cargo audit --no-fetch --deny warnings --file "$lockfile"
    done
else
    printf 'skipping cargo audit; cargo-audit is not installed\n'
fi
scripts/verify-dependency-policy.sh
cargo test -p sanitization-derive
cargo test
cargo test --features alloc
cargo test --features std
cargo test --features memory-lock
cargo test --features derive
cargo test --features asm-compare
cargo test --features strict-compare
cargo test --features cache-flush
cargo test --features guard-pages
cargo test --features multi-pass-clear
cargo test --features profile-hardened-native
cargo test --features profile-guarded-native
cargo test --features profile-hardened-linux
cargo test --all-features
cargo test --workspace --all-features
cargo check --examples
cargo check --examples --features alloc
cargo check --examples --features std
cargo check --examples --features memory-lock
cargo check --examples --features derive
cargo check --examples --features asm-compare
cargo check --examples --features strict-compare
cargo check --examples --features cache-flush
cargo check --examples --features guard-pages
cargo check --examples --features multi-pass-clear
cargo check --examples --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy -p sanitization-derive --all-targets -- -D warnings
scripts/check-rust-version-matrix.sh
if cargo metadata --no-deps --format-version 1 >/dev/null 2>&1; then
    cargo test -p sanitization-crypto-interop --all-features
fi
scripts/verify-derive-failures.sh
scripts/verify-secret-exposure-failures.sh
scripts/verify-ct-declassification.sh
scripts/verify-migration-2.0.py
scripts/verify-downstream-migration.py
scripts/capture-2.0-api.py --check
scripts/verify-2.0-api-freeze.py
if cargo public-api --version >/dev/null 2>&1; then
    scripts/capture-2.0-public-api.py
else
    printf 'skipping semantic public API check; cargo-public-api 0.52.0 is not installed\n'
fi
scripts/verify-leakage-smoke.sh
scripts/verify-loom.sh
scripts/verify-core-dump-probe.sh
scripts/verify-codegen-matrix.sh
(
    cargo fmt --manifest-path tools/lifecycle-probes/Cargo.toml --check
    cargo clippy --manifest-path tools/lifecycle-probes/Cargo.toml --all-targets -- -D warnings
    cargo test --manifest-path tools/lifecycle-probes/Cargo.toml -- --test-threads=1
)
(
    cargo fmt --manifest-path tools/performance-baseline/Cargo.toml --check
    cargo clippy --manifest-path tools/performance-baseline/Cargo.toml --all-targets -- -D warnings
    cargo test --manifest-path tools/performance-baseline/Cargo.toml
    cargo run --quiet --release --manifest-path tools/performance-baseline/Cargo.toml -- \
        --samples 11 --inner 5 \
        --output "${TMPDIR:-/tmp}/sanitization-performance-smoke.json"
    scripts/verify-target-evidence.py \
        --allow-dirty \
        --performance "${TMPDIR:-/tmp}/sanitization-performance-smoke.json"
)
(
    cargo check --manifest-path fuzz/Cargo.toml --bins
)
scripts/verify-evidence.py
scripts/test-release-readiness.sh
scripts/capture-2.0-baseline.py --check
scripts/verify-2.0-module-split.py
scripts/evidence-report.py >/dev/null

target_installed() {
    rustup target list --installed | grep -Fxq "$1"
}

check_installed_target() {
    target="$1"
    shift

    if target_installed "$target"; then
        cargo check --target "$target" "$@"
    else
        printf 'skipping target check for %s; target is not installed\n' "$target"
    fi
}

PORTABLE_NATIVE_FEATURES="alloc,std,derive,serde,subtle-interop,zeroize-interop,memory-lock,wasm-compat,canary-check,random-canary,asm-compare,strict-compare,cache-flush,register-scrub,guard-pages,page-seal,strict-canary-check,multi-pass-clear,hardware-secrets,split-secret,profile-hardened-native,profile-guarded-native"

check_installed_target x86_64-unknown-linux-gnu --all-features --lib
check_installed_target aarch64-unknown-linux-gnu --features memory-lock,guard-pages,multi-pass-clear --lib
check_installed_target x86_64-apple-darwin --features "$PORTABLE_NATIVE_FEATURES" --lib
check_installed_target aarch64-apple-darwin --features "$PORTABLE_NATIVE_FEATURES" --lib
check_installed_target aarch64-apple-ios --features "$PORTABLE_NATIVE_FEATURES" --lib
check_installed_target x86_64-apple-ios --features "$PORTABLE_NATIVE_FEATURES" --lib
check_installed_target x86_64-pc-windows-gnu --features "$PORTABLE_NATIVE_FEATURES" --lib
check_installed_target aarch64-linux-android --features "$PORTABLE_NATIVE_FEATURES" --lib
check_installed_target x86_64-linux-android --features "$PORTABLE_NATIVE_FEATURES" --lib
check_installed_target x86_64-unknown-freebsd --features memory-lock,guard-pages,multi-pass-clear --lib
check_installed_target wasm32-unknown-unknown --no-default-features --lib
check_installed_target wasm32-unknown-unknown --features alloc,memory-lock,wasm-compat,random-canary,multi-pass-clear --lib
check_installed_target wasm32-unknown-unknown --features wasm-compat,random-canary --lib
check_installed_target wasm32-wasip1 --features alloc,wasm-compat,random-canary,multi-pass-clear --lib
check_installed_target wasm32-wasip2 --features wasm-compat,random-canary --lib
check_installed_target thumbv7em-none-eabihf --no-default-features --lib

if target_installed wasm32-unknown-unknown; then
    if cargo check --target wasm32-unknown-unknown --features memory-lock --lib >/tmp/sanitization-wasm-memory-lock.log 2>&1; then
        printf 'wasm32 memory-lock without wasm-compat unexpectedly compiled\n'
        exit 1
    fi

    if cargo check --target wasm32-unknown-unknown --features wasm-compat,canary-check --lib >/tmp/sanitization-wasm-canary-check.log 2>&1; then
        printf 'wasm32 canary-check without random-canary unexpectedly compiled\n'
        exit 1
    fi

    if cargo check --target wasm32-unknown-unknown --features guard-pages --lib >/tmp/sanitization-wasm-guard-pages.log 2>&1; then
        printf 'wasm32 guard-pages unexpectedly compiled\n'
        exit 1
    fi

    if cargo check --target wasm32-unknown-unknown --features profile-hardened-native --lib >/tmp/sanitization-wasm-native-profile.log 2>&1; then
        printf 'wasm32 native hardening profile unexpectedly compiled\n'
        exit 1
    fi
fi

scripts/verify-codegen.sh
scripts/verify-kani.sh
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
RUSTDOCFLAGS="-D warnings" cargo doc -p sanitization-derive --no-deps
cargo package -p sanitization-derive --allow-dirty --list >/dev/null
cargo package -p sanitization --allow-dirty --list >/dev/null
cargo package -p sanitization-arrayvec --allow-dirty --list >/dev/null
cargo package -p sanitization-bytes --allow-dirty --list >/dev/null
cargo package -p sanitization-crypto-interop --allow-dirty --list >/dev/null
scripts/verify-release-packages.py
