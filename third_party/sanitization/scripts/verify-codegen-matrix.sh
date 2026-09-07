#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="${root}/tools/direct-exposure-codegen/Cargo.toml"

build_variant() {
    name="$1"
    opt_level="$2"
    lto="$3"
    codegen_units="$4"
    panic="$5"
    target_dir="${root}/target/cp19-codegen/${name}"

    rm -rf "${target_dir}"
    CARGO_TARGET_DIR="${target_dir}" \
    CARGO_PROFILE_RELEASE_OPT_LEVEL="${opt_level}" \
    CARGO_PROFILE_RELEASE_LTO="${lto}" \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${codegen_units}" \
    CARGO_PROFILE_RELEASE_PANIC="${panic}" \
        cargo rustc --manifest-path "${manifest}" --release -- --emit=llvm-ir

    CARGO_TARGET_DIR="${target_dir}" \
    CARGO_PROFILE_RELEASE_OPT_LEVEL="${opt_level}" \
    CARGO_PROFILE_RELEASE_LTO="${lto}" \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${codegen_units}" \
    CARGO_PROFILE_RELEASE_PANIC="${panic}" \
        cargo rustc \
            --manifest-path "${root}/Cargo.toml" \
            -p sanitization-crypto-interop \
            --release \
            --features blake3,hmac-sha2,strict-compare \
            -- \
            --emit=llvm-ir

    mapfile -t ir_files < <(
        find "${target_dir}/release/deps" \
            -maxdepth 1 \
            -type f \
            -name 'direct_exposure_codegen-*.ll' \
            -print
    )
    if [[ "${#ir_files[@]}" -eq 0 ]]; then
        echo "no LLVM IR produced for codegen variant ${name}" >&2
        exit 1
    fi


    mapfile -t crypto_ir_files < <(
        find "${target_dir}/release/deps" \
            -maxdepth 1 \
            -type f \
            -name 'sanitization_crypto_interop-*.ll' \
            -print
    )
    if [[ "${#crypto_ir_files[@]}" -eq 0 ]]; then
        echo "no crypto-interop LLVM IR produced for codegen variant ${name}" >&2
        exit 1
    fi

    "${root}/scripts/verify-codegen-artifact.py" \
        "${ir_files[@]}" \
        "${crypto_ir_files[@]}"
}

# Four builds cover every required dimension without multiplying equivalent
# combinations: opt 2/3/s/z, cgu 1/many, Thin/Fat LTO, and unwind/abort.
build_variant opt2-many-unwind 2 false 16 unwind
build_variant opt3-one-unwind 3 false 1 unwind
build_variant opts-thin-unwind s thin 1 unwind
build_variant optz-fat-abort z fat 1 abort

echo "CP-19 codegen matrix verified"
