#!/usr/bin/env bash
set -euo pipefail

emit_codegen() {
    rm -f \
        target/release/deps/sanitization-verify-codegen.d \
        target/release/deps/sanitization-verify-codegen.ll \
        target/release/deps/sanitization-verify-codegen.s \
        target/release/deps/libsanitization-verify-codegen.rlib \
        target/release/deps/libsanitization-verify-codegen.rmeta

    if [[ "${SANITIZATION_CODEGEN_FEATURES:-all}" == "all" ]]; then
        cargo rustc -p sanitization --lib --release --all-features -- \
            -C extra-filename=-verify-codegen \
            --emit=llvm-ir,asm
    else
        cargo rustc -p sanitization --lib --release \
            --features "${SANITIZATION_CODEGEN_FEATURES}" -- \
            -C extra-filename=-verify-codegen \
            --emit=llvm-ir,asm
    fi
}

emit_codegen

cargo clean --manifest-path tools/direct-exposure-codegen/Cargo.toml
cargo rustc \
    --manifest-path tools/direct-exposure-codegen/Cargo.toml \
    --release \
    -- \
    -C extra-filename=-verify-codegen \
    --emit=llvm-ir

cargo rustc \
    -p sanitization-crypto-interop \
    --release \
    --features blake3,hmac-sha2,strict-compare \
    -- \
    -C extra-filename=-verify-codegen \
    --emit=llvm-ir

ir_file="target/release/deps/sanitization-verify-codegen.ll"
asm_file="target/release/deps/sanitization-verify-codegen.s"
exposure_ir="tools/direct-exposure-codegen/target/release/deps/direct_exposure_codegen-verify-codegen.ll"
crypto_interop_ir="target/release/deps/sanitization_crypto_interop-verify-codegen.ll"

if [[ ! -f "${ir_file}" ]]; then
    echo "no sanitization LLVM IR file found" >&2
    exit 1
fi

if [[ ! -f "${asm_file}" ]]; then
    echo "no sanitization assembly file found" >&2
    exit 1
fi

if [[ -z "${exposure_ir}" || ! -f "${exposure_ir}" ]]; then
    echo "no direct-exposure LLVM IR file found" >&2
    exit 1
fi

if [[ ! -f "${crypto_interop_ir}" ]]; then
    echo "no crypto-interop LLVM IR file found" >&2
    exit 1
fi

"${PYTHON:-python3}" scripts/verify-codegen-artifact.py \
    "${exposure_ir}" \
    "${crypto_interop_ir}"

secret_box_core_clear_body="$(
    awk '
        /; <sanitization::owned::SecretBoxBytes>::clear_secret/ { found = 1; next }
        found && /define / { capture = 1 }
        capture { print }
        capture && /^}/ { exit }
    ' "${ir_file}"
)"

wipe_backend_body="$(
    awk '
        /; sanitization::wipe_backend::ordered_volatile_store/ { found = 1; next }
        found && /define / { capture = 1 }
        capture { print }
        capture && /^}/ { exit }
    ' "${ir_file}"
)"

direct_body="$(
    awk '
        /define .*cp04_direct_exposure/ { capture = 1 }
        capture { print }
        capture && /^}/ { exit }
    ' "${exposure_ir}"
)"

copy_body="$(
    awk '
        /define .*cp04_copy_exposure/ { capture = 1 }
        capture { print }
        capture && /^}/ { exit }
    ' "${exposure_ir}"
)"

secret_box_clear_body="$(
    awk '
        /define .*cp05_clear_secret_box/ { capture = 1 }
        capture { print }
        capture && /^}/ { exit }
    ' "${exposure_ir}"
)"

if [[ -z "${direct_body}" ]]; then
    echo "direct-exposure codegen probe missing from LLVM IR" >&2
    exit 1
fi

if [[ -z "${copy_body}" ]]; then
    echo "copy-exposure codegen probe missing from LLVM IR" >&2
    exit 1
fi

if [[ -z "${secret_box_clear_body}" ]]; then
    echo "SecretBoxBytes clear codegen probe missing from LLVM IR" >&2
    exit 1
fi

if [[ -z "${secret_box_core_clear_body}" ]]; then
    echo "SecretBoxBytes core clear method missing from LLVM IR" >&2
    exit 1
fi

if [[ -z "${wipe_backend_body}" ]]; then
    echo "canonical wipe backend body missing from LLVM IR" >&2
    exit 1
fi

if grep -Eq 'alloca \[4096 x i8\]|llvm\.memcpy' <<<"${direct_body}"; then
    echo "direct fixed-secret exposure constructed a full-size temporary" >&2
    exit 1
fi

if ! grep -Eq 'alloca \[4096 x i8\]|llvm\.memcpy' <<<"${copy_body}"; then
    echo "copy-exposure probe did not retain its explicit full-size copy" >&2
    exit 1
fi

if ! grep -q 'SecretBoxBytes.*clear_secret' <<<"${secret_box_clear_body}"; then
    echo "SecretBoxBytes clear probe does not call the audited clear path" >&2
    exit 1
fi

if grep -Eq 'fence (acquire|release|acq_rel|seq_cst)' <<<"${secret_box_clear_body}"; then
    echo "SecretBoxBytes wrapper introduced per-call hardware fencing" >&2
    exit 1
fi

if [[ "$(grep -Ec '^[[:space:]]+(tail )?call void .*wipe_backend.*erase' <<<"${secret_box_core_clear_body}")" -ne 1 ]]; then
    echo "SecretBoxBytes clear method does not dispatch exactly once" >&2
    exit 1
fi

if [[ "$(grep -c 'fence syncscope("singlethread") seq_cst' <<<"${wipe_backend_body}")" -ne 2 ]]; then
    echo "volatile wipe compiler fences are no longer outside the byte loop" >&2
    exit 1
fi

if [[ "$(grep -c '^  fence seq_cst' <<<"${wipe_backend_body}")" -ne 1 ]]; then
    echo "volatile wipe hardware fence count changed unexpectedly" >&2
    exit 1
fi

if ! grep -q 'sanitization::wipe_backend::ordered_volatile_store' "${ir_file}"; then
    echo "canonical wipe backend function missing from LLVM IR" >&2
    exit 1
fi

if ! grep -q 'store volatile i8 %value' "${ir_file}"; then
    echo "volatile byte stores missing from canonical backend LLVM IR" >&2
    exit 1
fi

if ! grep -Eq 'ordered_volatile_store.*i8 noundef 0' "${ir_file}"; then
    echo "canonical erase backend no longer dispatches a zero fill" >&2
    exit 1
fi

if grep -q 'sanitize_bytes_best_effort' "${ir_file}"; then
    echo "removed best-effort compatibility alias returned to LLVM IR" >&2
    exit 1
fi

for symbol in \
    'sanitization::ct::conditional_copy' \
    'sanitization::ct::conditional_swap' \
    'sanitization::ct::select_slice'
do
    if ! grep -q "${symbol}" "${ir_file}"; then
        echo "native ct helper ${symbol} missing from LLVM IR" >&2
        exit 1
    fi
done

if ! grep -q 'asm sideeffect "", "r,~{memory}"' "${ir_file}"; then
    echo "native ct optimizer barrier missing from LLVM IR" >&2
    exit 1
fi

if ! grep -q 'sub i8 0' "${ir_file}"; then
    echo "native ct mask-generation pattern missing from LLVM IR" >&2
    exit 1
fi

if grep -Eq '\b(memcmp|bcmp)\b' "${ir_file}" "${asm_file}"; then
    echo "memcmp/bcmp call found in release codegen" >&2
    exit 1
fi

host="$(
    rustc -vV \
        | awk '/^host:/ { print $2 }'
)"

if [[ "${host}" == x86_64-* ]]; then
    if ! grep -q 'compare_asm' "${asm_file}"; then
        echo "x86_64 assembly comparison symbol missing from assembly" >&2
        exit 1
    fi

    if ! grep -Eq '\bmovzbl\b|\bmovzx\b' "${asm_file}"; then
        echo "x86_64 byte-load comparison instruction missing from assembly" >&2
        exit 1
    fi

    if ! grep -q 'clflush' "${asm_file}"; then
        echo "x86_64 cache flush instruction missing from assembly" >&2
        exit 1
    fi

    if ! grep -q 'cpuid' "${asm_file}"; then
        echo "x86_64 cache flush capability check missing from assembly" >&2
        exit 1
    fi

    if ! grep -q 'mfence' "${asm_file}"; then
        echo "x86_64 cache flush fence missing from assembly" >&2
        exit 1
    fi

    if ! grep -q 'pxor' "${asm_file}"; then
        echo "x86_64 caller-saved XMM scrub instructions missing from assembly" >&2
        exit 1
    fi

    if ! grep -Eq '\bvzeroall\b|\bvzeroupper\b' "${asm_file}"; then
        echo "x86_64 AVX register scrub instruction missing from assembly" >&2
        exit 1
    fi

    echo "verified x86_64 architecture-specific codegen in ${asm_file}"
elif [[ "${host}" == aarch64-* ]]; then
    if ! grep -Eq 'eor[[:space:]]+v0\.16b|eor\.16b[[:space:]]+v0([[:space:],]|$)' "${asm_file}"; then
        echo "AArch64 V0 register scrub instruction missing from assembly" >&2
        exit 1
    fi

    if ! grep -Eq 'eor[[:space:]]+v31\.16b|eor\.16b[[:space:]]+v31([[:space:],]|$)' "${asm_file}"; then
        echo "AArch64 V31 register scrub instruction missing from assembly" >&2
        exit 1
    fi

    echo "verified AArch64 register-scrub codegen in ${asm_file}"
else
    echo "skipped architecture-specific codegen checks for ${host}"
fi

echo "verified canonical wipe backend codegen in ${ir_file}"
echo "verified native ct helper codegen in ${ir_file}"
echo "verified direct fixed-secret exposure codegen in ${exposure_ir}"
echo "verified fixed-allocation SecretBoxBytes clear dispatch in ${exposure_ir}"
