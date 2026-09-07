# Target Tiers

This document classifies target support for the high-assurance and native
`ct` features. The machine-readable form is `docs/ct-evidence.json`.

## Tier Definitions

| Tier | Meaning |
| --- | --- |
| Tier A | CI-covered release evidence plus target-specific codegen or proof evidence for the listed feature set. |
| Tier B | Source-level discipline and tests, but no complete target-specific timing evidence. |
| Tier C | API compatibility only, with reduced or no strong data-oblivious timing claim. |
| Forbidden | Known-bad or intentionally rejected target/feature combination. |

Tier names are evidence labels, not security certifications.

## Current Target Position

The CP-20 workflow emits a dated manifest for every row. Compiler versions are
the repository toolchain selected by `rust-toolchain.toml`; the exact rustc and
runner image are recorded in each artifact rather than implied by this table.

| Target/profile | Tier | Runner/evidence class | Evidence |
| --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | A | Native `ubuntu-24.04` | All-feature functional tests, path-specific release codegen scan, relative performance baseline, and default/strict multi-seed leakage runs. |
| `aarch64-unknown-linux-gnu` | B native | Native `ubuntu-24.04-arm` | All-feature functional tests, AArch64 release codegen scan, relative performance baseline, and default/strict multi-seed leakage runs. |
| `x86_64-pc-windows-msvc` | B native | Native `windows-2025` | Portable-native feature tests, x86_64 release codegen scan, and relative performance baseline; no timing claim. |
| `aarch64-apple-darwin` | B native | Native `macos-15` | Native default-feature tests, AArch64 release codegen scan, relative performance baseline, and default/strict multi-seed leakage runs. |
| `x86_64-unknown-freebsd` | B compile-only | Cross-compiled on Linux | Memory-lock, guard-page, and multi-pass feature compilation; no native syscall or timing claim. |
| `aarch64-linux-android` | B compile-only | Cross-compiled on Linux | Native-feature compilation only; no device runtime or timing claim. |
| `aarch64-apple-ios` | B compile-only | Cross-compiled on macOS | Native-feature compilation only; no device runtime or timing claim. |
| `thumbv7em-none-eabihf` | B/C compile-only | Cross-compiled on Linux | Core `no_std` compilation; no device-level leakage evidence. |
| `riscv32imac-unknown-none-elf` | B/C compile-only | Cross-compiled on Linux | Core `no_std` compilation; no device-level leakage evidence. |
| `wasm32-unknown-unknown`, `wasm32-wasip1`, `wasm32-wasip2` | C | Cross-compiled compatibility | API/build compatibility with documented volatile, JIT, memory-lock, and page-protection limits. |

## Feature Availability

| Feature area | Native Linux/Android | macOS/iOS/BSD | Windows | WASM |
| --- | --- | --- | --- | --- |
| Default volatile clearing | Yes | Yes | Yes | Best effort, reduced claim |
| `alloc` containers | Yes | Yes | Yes | Yes with allocator |
| `memory-lock` | Yes | Yes where backend supports it | Yes | Only with `wasm-compat`, no host lock |
| `guard-pages` | Yes | Yes where backend supports it | Yes | No |
| `canary-check` | Yes | Yes | Yes | Yes for compat backends where exposed |
| `random-canary` | OS CSPRNG | OS CSPRNG | OS CSPRNG | WASI where host random exists; unsupported otherwise |
| Default `asm-compare` | x86_64/AArch64 where implemented | x86_64/AArch64 where implemented | x86_64/AArch64 where ABI-safe | No strong JIT claim |
| `cache-flush` | Checked x86_64 eviction; other architectures return unsupported after wipe | Checked x86_64 eviction; other architectures return unsupported after wipe | Checked x86_64 eviction | Structured unsupported result |
| `register-scrub` | x86_64/AArch64 reported best effort | x86_64/AArch64 reported best effort | x86_64/AArch64 reported best effort | Structured unsupported result |

## Named Profile Availability

| Profile | Linux x86_64/AArch64 | macOS/iOS x86_64/AArch64 | Windows x86_64/AArch64 | Android x86_64/AArch64 | BSD x86_64/AArch64 | WASM |
| --- | --- | --- | --- | --- | --- | --- |
| `profile-hardened-native` | Yes | Yes | Yes | Yes | Yes where the native backend compiles | Forbidden |
| `profile-guarded-native` | Yes | Yes | Yes | Yes | Yes where guard pages compile | Forbidden |
| `profile-hardened-linux` | Yes | Forbidden | Forbidden | Forbidden | Forbidden | Forbidden |

Profiles describe compiled capability. The matching `ProtectionRequest`
describes required/preferred policy, and each runtime `ProtectionReport`
records achieved controls. See `docs/FEATURE_PROFILES.md`.

## Release Requirements

A stable `2.0.0` release record cites:

- exact rustc version;
- exact target triple;
- exact feature set;
- CI run URL or local command transcript;
- `docs/ct-evidence.json` validation result;
- release codegen check result;
- Kani result when available;
- Miri result when available;
- any known target-specific residual risks.

Use `scripts/evidence-report.py` to capture the local commit, rustc host,
installed targets, and optional Kani/Miri tool availability for this evidence.

Use the `CP-20 target evidence` workflow artifacts for target classification.
Do not describe a cross-compiled manifest as native evidence. Artifact
retention is temporary, so `docs/release-evidence-2.0.0.json` preserves the
accepted workflow run URLs and GitHub artifact digests.

Targets without this evidence should remain Tier B or Tier C rather than being
promoted by assumption.
